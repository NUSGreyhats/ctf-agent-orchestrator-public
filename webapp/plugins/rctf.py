"""rCTF platform plugin (otter-sec/rctf)."""

from __future__ import annotations

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
            "httpx is required for the rCTF plugin. "
            "Install it with: pip install httpx"
        )


def _base_url(config: dict) -> str:
    url = config.get("url", "").strip().rstrip("/")
    if not url:
        raise ValueError("rCTF URL is required")
    return url


async def _get_auth_token(config: dict) -> str:
    """Authenticate and return a Bearer token."""
    token = config.get("token", "").strip()
    if token:
        return token

    team_token = config.get("team_token", "").strip()
    if not team_token:
        raise ValueError(
            "Either an auth token or team token is required"
        )

    _require_httpx()
    base = _base_url(config)
    async with httpx.AsyncClient(
        verify=False, timeout=15
    ) as client:
        resp = await client.post(
            f"{base}/api/v1/auth/login",
            json={"teamToken": team_token},
        )
        data = resp.json()
        if resp.status_code != 200 or data.get("kind") == "badTokenVerification":
            raise ValueError(
                f"Login failed: {data.get('message', resp.text)}"
            )
        auth_token = data.get("data", {}).get("authToken", "")
        if not auth_token:
            raise ValueError("Login succeeded but no auth token returned")
        return auth_token


async def _client(config: dict) -> tuple:
    """Return (httpx.AsyncClient, auth_token)."""
    _require_httpx()
    auth_token = await _get_auth_token(config)
    client = httpx.AsyncClient(
        base_url=_base_url(config),
        headers={
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        },
        verify=False,
        follow_redirects=True,
        timeout=30,
    )
    return client, auth_token


class RCTFPlugin(CTFPlatformPlugin):
    name = "rctf"
    label = "rCTF"

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="url",
                label="rCTF URL",
                field_type="url",
                placeholder="https://ctf.example.com",
            ),
            ConfigField(
                name="token",
                label="Auth Token",
                field_type="password",
                required=False,
                placeholder="Bearer token (if you have one)",
            ),
            ConfigField(
                name="team_token",
                label="Team Token",
                field_type="password",
                required=False,
                placeholder="Team invite token (used to login)",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        client, _ = await _client(config)
        async with client:
            resp = await client.get("/api/v1/users/me")
            if resp.status_code == 200:
                data = resp.json()
                user = data.get("data", {})
                name = user.get("name", "unknown")
                return f"Logged in as {name}"
            # Fallback: try listing challenges
            resp = await client.get("/api/v1/challs")
            if resp.status_code == 200:
                data = resp.json()
                challs = data.get("data", [])
                return f"Connected ({len(challs)} challenges visible)"
            raise ValueError(
                f"Connection failed: HTTP {resp.status_code}"
            )

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        client, _ = await _client(config)
        async with client:
            resp = await client.get("/api/v1/challs")
            resp.raise_for_status()
            data = resp.json()
            challenge_list = data.get("data", [])

            base = _base_url(config)
            results = []
            for ch in challenge_list:
                ch_id = ch.get("id", "")

                files = []
                for f in ch.get("files", []):
                    if isinstance(f, str):
                        url = f if f.startswith("http") else urljoin(
                            base + "/", f.lstrip("/")
                        )
                        name = url.split("/")[-1].split("?")[0]
                        files.append(RemoteFile(name=name, url=url))
                    elif isinstance(f, dict):
                        url = f.get("url", "")
                        name = f.get("name", url.split("/")[-1].split("?")[0])
                        if url and not url.startswith("http"):
                            url = urljoin(base + "/", url.lstrip("/"))
                        if url:
                            files.append(RemoteFile(name=name, url=url))

                results.append(RemoteChallenge(
                    remote_id=str(ch_id),
                    name=ch.get("name", f"Challenge {ch_id}"),
                    description=ch.get("description", ""),
                    category=ch.get("category", ""),
                    points=ch.get("points", 0),
                    files=files,
                    solved=bool(ch.get("solved", False)),
                    tags=ch.get("tags", []),
                ))

            return results

    async def download_file(
        self, config: dict, file: RemoteFile
    ) -> bytes:
        client, _ = await _client(config)
        async with client:
            resp = await client.get(file.url)
            resp.raise_for_status()
            return resp.content

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str
    ) -> SubmitResult:
        client, _ = await _client(config)
        async with client:
            resp = await client.post(
                f"/api/v1/challs/{remote_id}/submit",
                json={"flag": flag},
            )
            data = resp.json()
            kind = data.get("kind", "")
            message = data.get("message", "")

            correct = kind == "goodFlag"
            if not message:
                if correct:
                    message = "Correct!"
                elif kind == "badFlag":
                    message = "Incorrect flag"
                elif kind == "badAlreadySolvedChallenge":
                    message = "Already solved"
                elif kind == "badRateLimit":
                    message = "Rate limited"
                else:
                    message = kind

            return SubmitResult(correct=correct, message=message)
