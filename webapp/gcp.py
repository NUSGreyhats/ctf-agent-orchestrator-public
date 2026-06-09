"""Minimal async GCP Compute Engine client for the swarm feature.

Authentication uses a service-account JSON key (Compute Admin). The key is used
only to mint short-lived OAuth access tokens via ``google-auth``; all API calls
go over the Compute REST API with ``httpx`` to stay consistent with the platform
plugins and avoid the heavy ``google-cloud-compute`` dependency tree.

The client is intentionally small: it covers exactly the operations the swarm
manager needs (instances: create/get/list/start/stop/delete; images:
create/get; operation polling; instance metadata for SSH keys).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

try:  # httpx is installed by install_scripts/015_install-python-tooling.sh
    import httpx
except ImportError:  # pragma: no cover - exercised only without deps
    httpx = None  # type: ignore

try:
    from google.oauth2 import service_account as _gcp_service_account
    from google.auth.transport.requests import Request as _GoogleAuthRequest
except ImportError:  # pragma: no cover - exercised only without deps
    _gcp_service_account = None  # type: ignore
    _GoogleAuthRequest = None  # type: ignore


COMPUTE_BASE = "https://compute.googleapis.com/compute/v1"
# cloud-platform covers Compute + image management with a single scope.
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
# Default poll cadence / ceiling for long-running operations (image build is
# the slow one; instance lifecycle ops are typically seconds).
_OP_POLL_INTERVAL = 4.0
_OP_TIMEOUT_DEFAULT = 1800.0


class GCPError(RuntimeError):
    """Raised for GCP configuration problems or API failures."""


def _require_deps() -> None:
    missing = []
    if httpx is None:
        missing.append("httpx")
    if _gcp_service_account is None:
        missing.append("google-auth")
    if missing:
        raise GCPError(
            "GCP support requires the following package(s): "
            + ", ".join(missing)
            + ". Install with: uv pip install --system "
            + " ".join(missing)
        )


def zone_to_region(zone: str) -> str:
    """`asia-southeast1-c` -> `asia-southeast1`."""
    return zone.rsplit("-", 1)[0] if "-" in zone else zone


class GCPClient:
    """Thin async wrapper over the Compute v1 REST API for one project."""

    def __init__(
        self,
        service_account_info: dict,
        project: str | None = None,
        zone: str = "",
        *,
        timeout: float = 30.0,
    ):
        _require_deps()
        if not isinstance(service_account_info, dict) or not service_account_info:
            raise GCPError("service account key must be a non-empty JSON object")
        self._info = service_account_info
        self.project = project or service_account_info.get("project_id", "")
        if not self.project:
            raise GCPError("no GCP project_id (set it in settings or the key)")
        self.zone = zone
        self._timeout = timeout
        self._creds = None
        self._token: str = ""
        self._token_expiry: float = 0.0
        self._token_lock = asyncio.Lock()

    # -- auth ---------------------------------------------------------------

    def _refresh_token_sync(self) -> tuple[str, float]:
        creds = _gcp_service_account.Credentials.from_service_account_info(
            self._info, scopes=_SCOPES
        )
        creds.refresh(_GoogleAuthRequest())
        expiry = creds.expiry.timestamp() if creds.expiry else time.time() + 3000
        return creds.token, expiry

    async def _access_token(self) -> str:
        # Refresh ~60s before expiry; refresh in a thread (google-auth is sync).
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        async with self._token_lock:
            if self._token and time.time() < self._token_expiry - 60:
                return self._token
            try:
                token, expiry = await asyncio.to_thread(self._refresh_token_sync)
            except Exception as exc:  # noqa: BLE001 - surface a clean message
                raise GCPError(f"failed to obtain GCP access token: {exc}") from exc
            self._token, self._token_expiry = token, expiry
            return token

    async def _request(
        self, method: str, url: str, *, json_body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        token = await self._access_token()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.request(
                method, url, headers=headers, json=json_body, params=params
            )
        if resp.status_code == 404:
            raise GCPError(f"not found: {url}")
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = resp.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                detail = resp.text[:300]
            raise GCPError(f"GCP API {resp.status_code}: {detail or resp.text[:300]}")
        if not resp.content:
            return {}
        try:
            return resp.json()
        except Exception:  # noqa: BLE001
            return {}

    # -- low-level helpers --------------------------------------------------

    def _project_url(self, suffix: str) -> str:
        return f"{COMPUTE_BASE}/projects/{self.project}/{suffix.lstrip('/')}"

    def _zone_url(self, zone: str, suffix: str = "") -> str:
        base = self._project_url(f"zones/{zone}")
        return f"{base}/{suffix.lstrip('/')}" if suffix else base

    # -- operations ---------------------------------------------------------

    async def wait_for_operation(
        self, operation: dict, *, timeout: float = _OP_TIMEOUT_DEFAULT
    ) -> dict:
        """Poll a zonal/global operation until DONE; raise on operation error."""
        name = operation.get("name")
        if not name:
            return operation
        op_zone = operation.get("zone", "")
        if op_zone:
            zone = op_zone.rsplit("/", 1)[-1]
            poll_url = self._zone_url(zone, f"operations/{name}")
        else:  # global operation (e.g. image insert)
            poll_url = self._project_url(f"global/operations/{name}")

        deadline = time.time() + timeout
        while True:
            op = await self._request("GET", poll_url)
            if op.get("status") == "DONE":
                if op.get("error"):
                    errors = op["error"].get("errors", [])
                    msg = "; ".join(e.get("message", "") for e in errors) or str(
                        op["error"]
                    )
                    raise GCPError(f"operation {name} failed: {msg}")
                return op
            if time.time() > deadline:
                raise GCPError(f"operation {name} timed out after {timeout:.0f}s")
            await asyncio.sleep(_OP_POLL_INTERVAL)

    # -- instances ----------------------------------------------------------

    async def get_instance(self, name: str, zone: str | None = None) -> dict:
        return await self._request(
            "GET", self._zone_url(zone or self.zone, f"instances/{name}")
        )

    async def list_instances(self, zone: str | None = None) -> list[dict]:
        data = await self._request(
            "GET", self._zone_url(zone or self.zone, "instances")
        )
        return data.get("items", []) or []

    async def insert_instance(
        self, body: dict, zone: str | None = None, *, wait: bool = True
    ) -> dict:
        op = await self._request(
            "POST", self._zone_url(zone or self.zone, "instances"), json_body=body
        )
        return await self.wait_for_operation(op) if wait else op

    async def start_instance(
        self, name: str, zone: str | None = None, *, wait: bool = True
    ) -> dict:
        op = await self._request(
            "POST", self._zone_url(zone or self.zone, f"instances/{name}/start")
        )
        return await self.wait_for_operation(op) if wait else op

    async def stop_instance(
        self, name: str, zone: str | None = None, *, wait: bool = True
    ) -> dict:
        op = await self._request(
            "POST", self._zone_url(zone or self.zone, f"instances/{name}/stop")
        )
        return await self.wait_for_operation(op) if wait else op

    async def delete_instance(
        self, name: str, zone: str | None = None, *, wait: bool = True
    ) -> dict:
        op = await self._request(
            "DELETE", self._zone_url(zone or self.zone, f"instances/{name}")
        )
        return await self.wait_for_operation(op) if wait else op

    async def instance_external_ip(
        self, name: str, zone: str | None = None
    ) -> str:
        inst = await self.get_instance(name, zone)
        for nic in inst.get("networkInterfaces", []):
            for cfg in nic.get("accessConfigs", []):
                if cfg.get("natIP"):
                    return cfg["natIP"]
        return ""

    # -- images -------------------------------------------------------------

    async def get_image(self, name: str) -> dict:
        return await self._request("GET", self._project_url(f"global/images/{name}"))

    async def image_exists(self, name: str) -> bool:
        try:
            await self.get_image(name)
            return True
        except GCPError:
            return False

    async def insert_image_from_disk(
        self, name: str, source_disk: str, *, family: str = "", wait: bool = True
    ) -> dict:
        body: dict[str, Any] = {"name": name, "sourceDisk": source_disk}
        if family:
            body["family"] = family
        op = await self._request(
            "POST", self._project_url("global/images"), json_body=body
        )
        return await self.wait_for_operation(op) if wait else op

    async def delete_image(self, name: str, *, wait: bool = True) -> dict:
        op = await self._request(
            "DELETE", self._project_url(f"global/images/{name}")
        )
        return await self.wait_for_operation(op) if wait else op

    # -- connectivity -------------------------------------------------------

    async def test_connection(self) -> dict:
        """Return basic project/zone info; raises GCPError on failure."""
        info = await self._request("GET", self._project_url(""))
        result = {"project": info.get("name", self.project)}
        if self.zone:
            zinfo = await self._request(
                "GET", self._project_url(f"zones/{self.zone}")
            )
            result["zone"] = zinfo.get("name", self.zone)
            result["region"] = zone_to_region(self.zone)
        return result
