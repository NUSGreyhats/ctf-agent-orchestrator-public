"""CTFd platform plugin."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from .base import (
    CTFPlatformPlugin,
    ConfigField,
    RemoteChallenge,
    RemoteFile,
    SubmitResult,
)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


def _require_httpx():
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the CTFd plugin. "
            "Install it with: pip install httpx"
        )


def _base_url(config: dict) -> str:
    url = config.get("url", "").strip().rstrip("/")
    if not url:
        raise ValueError("CTFd URL is required")
    return url


def _headers(config: dict) -> dict:
    token = config.get("token", "").strip()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Token {token}"
    return headers


async def _get_session_cookie(config: dict) -> dict:
    """Login with username/password and return session cookie headers."""
    base = _base_url(config)
    username = config.get("username", "").strip()
    password = config.get("password", "").strip()
    if not username or not password:
        return {}

    _require_httpx()
    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=15
    ) as client:
        # Get nonce from login page
        resp = await client.get(f"{base}/login")
        nonce_match = re.search(
            r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)',
            resp.text,
        )
        nonce = nonce_match.group(1) if nonce_match else ""

        # Login
        resp = await client.post(
            f"{base}/login",
            data={
                "name": username,
                "password": password,
                "nonce": nonce,
            },
        )
        if resp.status_code >= 400:
            raise ValueError(f"Login failed: HTTP {resp.status_code}")

        cookies = dict(client.cookies)
        if not cookies:
            raise ValueError("Login succeeded but no session cookie received")
        return cookies


async def _client(config: dict) -> httpx.AsyncClient:
    _require_httpx()
    headers = _headers(config)
    cookies = {}

    # If no token, try username/password login
    if "Authorization" not in headers:
        cookies = await _get_session_cookie(config)

    return httpx.AsyncClient(
        base_url=_base_url(config),
        headers=headers,
        cookies=cookies,
        verify=False,
        follow_redirects=True,
        timeout=30,
    )


class CTFdPlugin(CTFPlatformPlugin):
    name = "ctfd"
    label = "CTFd"

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="url",
                label="CTFd URL",
                field_type="url",
                placeholder="https://ctf.example.com",
            ),
            ConfigField(
                name="token",
                label="API Token",
                field_type="password",
                required=False,
                placeholder="Optional — use if you have one",
            ),
            ConfigField(
                name="username",
                label="Username",
                field_type="text",
                required=False,
                placeholder="Optional — used if no API token",
            ),
            ConfigField(
                name="password",
                label="Password",
                field_type="password",
                required=False,
                placeholder="Optional — used if no API token",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        async with await _client(config) as client:
            resp = await client.get("/api/v1/users/me")
            if resp.status_code == 200:
                data = resp.json()
                user = data.get("data", {})
                return f"Logged in as {user.get('name', 'unknown')}"
            resp = await client.get("/api/v1/challenges")
            if resp.status_code == 200:
                data = resp.json()
                count = len(data.get("data", []))
                return f"Connected ({count} challenges visible)"
            raise ValueError(
                f"Connection failed: HTTP {resp.status_code}"
            )

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        async with await _client(config) as client:
            resp = await client.get("/api/v1/challenges")
            resp.raise_for_status()
            data = resp.json()
            challenge_list = data.get("data", [])

            results = []
            for ch in challenge_list:
                ch_id = ch.get("id")
                # Fetch detail to get files and description
                detail_resp = await client.get(
                    f"/api/v1/challenges/{ch_id}"
                )
                if detail_resp.status_code != 200:
                    continue
                detail = detail_resp.json().get("data", {})

                # Parse files — CTFd returns file URLs in the detail
                files = []
                for file_url in detail.get("files", []):
                    # File URLs may be relative or absolute
                    if file_url.startswith("/"):
                        file_url = _base_url(config) + file_url
                    elif not file_url.startswith("http"):
                        file_url = _base_url(config) + "/" + file_url
                    name = file_url.split("/")[-1].split("?")[0]
                    files.append(RemoteFile(name=name, url=file_url))

                # Extract description from HTML view or description field
                description = detail.get("description", "")

                tags = [
                    t.get("value", "")
                    for t in ch.get("tags", [])
                    if isinstance(t, dict)
                ]

                results.append(RemoteChallenge(
                    remote_id=str(ch_id),
                    name=ch.get("name", f"Challenge {ch_id}"),
                    description=description,
                    category=ch.get("category", ""),
                    points=ch.get("value", 0),
                    files=files,
                    solved=bool(ch.get("solved_by_me")),
                    tags=tags,
                ))

            return results

    async def download_file(
        self, config: dict, file: RemoteFile
    ) -> bytes:
        async with await _client(config) as client:
            resp = await client.get(file.url)
            resp.raise_for_status()
            return resp.content

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str
    ) -> SubmitResult:
        async with await _client(config) as client:
            resp = await client.post(
                "/api/v1/challenges/attempt",
                json={
                    "challenge_id": int(remote_id),
                    "submission": flag,
                },
            )
            data = resp.json()
            status = data.get("data", {}).get("status", "")
            message = data.get("data", {}).get("message", "")
            return SubmitResult(
                correct=status == "correct",
                message=message or status,
            )
