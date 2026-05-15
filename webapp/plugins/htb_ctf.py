"""Hack The Box CTF platform plugin (ctf.hackthebox.com)."""

from __future__ import annotations

import asyncio
import logging

from .base import (
    CTFPlatformPlugin,
    ConfigField,
    RemoteChallenge,
    RemoteFile,
    SubmitResult,
    read_limited_response,
)

log = logging.getLogger("ctf-solver.htb")

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

# HTB uses numeric category IDs without exposing names via API.
# This mapping covers well-known IDs; unknown IDs fall back to the
# filename prefix or "Category {id}".
_CATEGORY_MAP: dict[int, str] = {
    1: "Fullpwn",
    2: "Web",
    3: "Pwn",
    4: "Crypto",
    5: "Reversing",
    6: "Stego",
    7: "Forensics",
    8: "Mobile",
    9: "Misc",
    10: "Warmup",
    11: "Coding",
    12: "OSINT",
    13: "Threat Intelligence",
    14: "Blockchain",
    15: "Hardware",
    16: "GamePwn",
    17: "Cloud",
    21: "Cloud",
    23: "ML / AI",
    33: "ML / AI",
    36: "Pentest",
}

_PREFIX_TO_CATEGORY: dict[str, str] = {
    "web": "Web",
    "pwn": "Pwn",
    "crypto": "Crypto",
    "rev": "Reversing",
    "forensics": "Forensics",
    "misc": "Misc",
    "blockchain": "Blockchain",
    "hw": "Hardware",
    "ml": "ML / AI",
    "osint": "OSINT",
    "stego": "Stego",
    "mobile": "Mobile",
    "nuclear": "ML / AI",
}


def _require_httpx():
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the HTB CTF plugin. "
            "Install it with: pip install httpx"
        )


def _resolve_category(challenge: dict) -> str:
    cat_id = challenge.get("challenge_category_id")
    if cat_id and cat_id in _CATEGORY_MAP:
        return _CATEGORY_MAP[cat_id]
    filename = challenge.get("filename", "") or ""
    if filename:
        prefix = filename.split("_")[0].lower()
        if prefix in _PREFIX_TO_CATEGORY:
            return _PREFIX_TO_CATEGORY[prefix]
    if cat_id:
        return f"Category {cat_id}"
    return ""


def _client(config: dict) -> httpx.AsyncClient:
    _require_httpx()
    token = config.get("token", "").strip()
    if not token:
        raise ValueError("Bearer token is required")
    return httpx.AsyncClient(
        base_url="https://ctf.hackthebox.com",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        verify=True,
        follow_redirects=True,
        timeout=30,
    )


class HTBCTFPlugin(CTFPlatformPlugin):
    name = "htb_ctf"
    label = "HTB CTF"

    def source_url(self, config: dict) -> str:
        ctf_id = config.get("ctf_id", "").strip()
        return f"https://ctf.hackthebox.com/event/{ctf_id}" if ctf_id else ""

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="ctf_id",
                label="CTF Event ID",
                field_type="text",
                placeholder="3264 (from the URL: ctf.hackthebox.com/event/3264)",
            ),
            ConfigField(
                name="token",
                label="Bearer Token (JWT)",
                field_type="password",
                placeholder="Copy from browser DevTools (Authorization header)",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            raise ValueError("CTF Event ID is required")

        async with _client(config) as client:
            resp = await client.get(f"/api/ctfs/{ctf_id}")
            if resp.status_code == 401:
                raise ValueError("Authentication failed — token may be expired")
            resp.raise_for_status()
            data = resp.json()

            ctf_name = data.get("name", f"CTF {ctf_id}")
            team = data.get("participating_team", {})
            team_name = team.get("name", "")
            n_challenges = len(data.get("challenges", []))
            status = data.get("status", "")

            parts = [f"Connected to {ctf_name}"]
            if team_name:
                parts.append(f"team {team_name}")
            parts.append(f"{n_challenges} challenges")
            if status:
                parts.append(f"({status})")
            return " — ".join(parts)

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            raise ValueError("CTF Event ID is required")

        async with _client(config) as client:
            resp = await client.get(f"/api/ctfs/{ctf_id}")
            resp.raise_for_status()
            data = resp.json()

            results = []
            for ch in data.get("challenges", []):
                ch_id = ch.get("id")
                filename = (ch.get("filename") or "").strip()

                files = []
                if filename:
                    download_url = f"https://ctf.hackthebox.com/api/challenges/{ch_id}/download"
                    files.append(RemoteFile(name=filename, url=download_url))

                tags = []
                difficulty = ch.get("difficulty", "")
                if difficulty:
                    tags.append(difficulty)
                if ch.get("hasMachine"):
                    tags.append("machine")
                if ch.get("hasDocker"):
                    docker_type = ch.get("docker_instance_type") or ""
                    tags.append(f"docker:{docker_type}" if docker_type else "docker")

                results.append(RemoteChallenge(
                    remote_id=str(ch_id),
                    name=ch.get("name", f"Challenge {ch_id}"),
                    description=ch.get("description", ""),
                    category=_resolve_category(ch),
                    points=ch.get("points", 0),
                    solves=ch.get("solves", 0),
                    files=files,
                    solved=bool(ch.get("solved")),
                    tags=tags,
                ))

            return results

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None
    ) -> bytes:
        async with _client(config) as client:
            async with client.stream("GET", file.url) as resp:
                return await read_limited_response(resp, max_bytes)

    async def start_instance(
        self, config: dict, remote_id: str
    ) -> dict | None:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            return None

        async with _client(config) as client:
            # Request container start
            resp = await client.post(
                "/api/challenges/containers/start",
                json={"id": int(remote_id)},
            )
            data = resp.json()
            msg = data.get("message", "")
            log.info("Container start for %s: %s", remote_id, msg)

            # Poll the CTF data until hostname/ports appear (max ~30s)
            for _ in range(12):
                await asyncio.sleep(3)
                resp = await client.get(f"/api/ctfs/{ctf_id}")
                if resp.status_code != 200:
                    continue
                ctf_data = resp.json()
                for ch in ctf_data.get("challenges", []):
                    if str(ch.get("id")) != str(remote_id):
                        continue
                    hostname = ch.get("hostname")
                    ports = ch.get("docker_ports")
                    if hostname and ports:
                        docker_type = ch.get("docker_instance_type") or ""
                        port = ports[0] if isinstance(ports, list) else ports
                        result: dict = {
                            "host": hostname,
                            "port": port,
                        }
                        if docker_type.lower() == "web":
                            result["url"] = f"http://{hostname}:{port}"
                            result["type"] = "web"
                        elif docker_type.lower() == "tcp":
                            result["connection"] = f"nc {hostname} {port}"
                            result["type"] = "tcp"
                        else:
                            result["connection"] = f"{hostname}:{port}"
                            result["type"] = "unknown"
                        log.info(
                            "Container ready for %s: %s",
                            remote_id, result,
                        )
                        return result
                    break

            log.warning("Container for %s did not become ready in time", remote_id)
            return None

    async def stop_instance(
        self, config: dict, remote_id: str
    ) -> None:
        async with _client(config) as client:
            resp = await client.post(
                "/api/challenges/containers/stop",
                json={"id": int(remote_id)},
            )
            log.info(
                "Container stop for %s: %s",
                remote_id, resp.json().get("message", ""),
            )

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str
    ) -> SubmitResult:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            raise ValueError("CTF Event ID is required for flag submission")

        async with _client(config) as client:
            resp = await client.post(
                "/api/flags/global/own",
                json={"flag": flag, "ctf_id": int(ctf_id)},
            )
            data = resp.json()
            message = data.get("message", "")

            message_l = message.lower()
            success_value = data.get("success", data.get("status"))
            if isinstance(success_value, bool):
                correct = success_value
            elif isinstance(success_value, (int, float)):
                correct = success_value == 1
            elif isinstance(success_value, str):
                correct = success_value.strip().lower() in {
                    "1", "true", "ok", "success", "correct", "solved",
                }
            else:
                bad_terms = ("wrong", "incorrect", "invalid", "rate limit", "already")
                good_terms = ("correct", "solved", "success", "congrat")
                correct = (
                    resp.status_code == 200
                    and any(term in message_l for term in good_terms)
                    and not any(term in message_l for term in bad_terms)
                )

            if correct:
                return SubmitResult(correct=True, message=message or "Correct!")
            return SubmitResult(correct=False, message=message or "Incorrect flag")
