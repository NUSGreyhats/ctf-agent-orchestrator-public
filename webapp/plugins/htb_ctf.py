"""Hack The Box CTF platform plugin (ctf.hackthebox.com)."""

from __future__ import annotations

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
        verify=False,
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
        self, config: dict, file: RemoteFile
    ) -> bytes:
        async with _client(config) as client:
            resp = await client.get(file.url)
            resp.raise_for_status()
            return resp.content

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

            if resp.status_code == 200 and "wrong" not in message.lower():
                return SubmitResult(correct=True, message=message or "Correct!")
            return SubmitResult(correct=False, message=message or "Incorrect flag")
