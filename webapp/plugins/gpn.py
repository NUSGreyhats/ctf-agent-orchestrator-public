"""GPN CTF / KITchen platform plugin."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import ssl
from urllib.parse import quote, urlparse

from .base import (
    CTFPlatformPlugin,
    ConfigField,
    RemoteChallenge,
    RemoteFile,
    SubmitResult,
    read_limited_response,
)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

try:
    import websockets
except ImportError:
    websockets = None  # type: ignore


log = logging.getLogger("ctf-solver.gpn")

DEFAULT_URL = "https://gpn24.ctf.kitctf.de"
DEFAULT_TIMEOUT = 30
SPAWN_TIMEOUT = 60
INSTANCE_WAIT_SECONDS = 30

_API_MESSAGES = {
    "ChallengeNotFound": "Challenge not found",
    "Forbidden": "Forbidden",
    "InternalServerError": "Internal server error",
    "InvalidCredentials": "Invalid username or password",
    "InvalidFlag": "Invalid flag",
    "InvalidJson": "Invalid JSON",
    "InvalidRequest": "Invalid request",
    "MustBeInTeam": "You must be in a team",
    "NotStarted": "The event has not started",
    "TooManyInstances": "Too many running instances",
    "TooManyRequests": "Too many requests",
    "SystemError": "Instance system error",
    "InvalidTeamToken": "Invalid team token",
    "InstanceNotFound": "Instance not found",
}


def _require_httpx() -> None:
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the GPN plugin. Install it with: pip install httpx"
        )


def _clean(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _base_url(config: dict) -> str:
    raw = _clean(config.get("url")) or DEFAULT_URL
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("GPN URL must be an absolute http(s) URL")
    if parsed.query or parsed.fragment:
        raise ValueError("GPN URL must not include a query string or fragment")
    return raw.rstrip("/")


def _verify_tls(config: dict) -> bool:
    return not _truthy(config.get("insecure_tls"))


def _credentials(config: dict) -> tuple[str, str]:
    username = _clean(config.get("username"))
    password = _clean(config.get("password"))
    if not username or not password:
        raise ValueError("GPN username and password are required")
    return username, password


def _response_json(resp) -> dict | list | None:
    try:
        return resp.json()
    except ValueError:
        return None


def _api_message(data, resp=None) -> str:
    if isinstance(data, str):
        value = _clean(data)
        if value:
            return _API_MESSAGES.get(value, value)
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            code = _clean(error.get("type") or error.get("code"))
            reason = _clean(error.get("reason"))
            message = _clean(error.get("message"))
            if not message and code:
                message = _API_MESSAGES.get(code, code)
            if message and reason:
                return f"{message}: {reason}"
            if message:
                return message
        for key in ("message", "detail", "code", "type", "value"):
            value = _clean(data.get(key))
            if value:
                return _API_MESSAGES.get(value, value)
    if resp is not None:
        text = _clean(getattr(resp, "text", ""))
        if text and len(text) < 300:
            return text
        return f"HTTP {resp.status_code}"
    return "unknown error"


def _submit_result_from_response(resp, data) -> SubmitResult:
    message = _api_message(data, resp)
    normalized = message.casefold()
    if normalized == "submitted":
        return SubmitResult(correct=True, message="Submitted")
    if normalized == "invalid flag":
        return SubmitResult(correct=False, message="Invalid flag")

    if isinstance(data, dict):
        solved_by_me = data.get("solvedByMe")
        if isinstance(solved_by_me, bool):
            return SubmitResult(
                correct=solved_by_me,
                message="Submitted" if solved_by_me else (message or "Invalid flag"),
            )
        for key in ("status", "result", "type", "message", "value"):
            value = _clean(data.get(key))
            value_l = value.casefold()
            if value_l == "submitted":
                return SubmitResult(correct=True, message="Submitted")
            if value_l in {"invalidflag", "invalid flag"}:
                return SubmitResult(correct=False, message="Invalid flag")

    if resp.status_code >= 400:
        return SubmitResult(correct=False, message=message or "Invalid flag")
    return SubmitResult(correct=True, message=message or "Submitted")


async def _raise_for_api_error(resp) -> dict | list | None:
    data = _response_json(resp)
    if resp.status_code >= 400:
        raise ValueError(_api_message(data, resp))
    return data


@asynccontextmanager
async def _client(config: dict):
    _require_httpx()
    username, password = _credentials(config)
    client = httpx.AsyncClient(
        base_url=_base_url(config),
        follow_redirects=True,
        timeout=DEFAULT_TIMEOUT,
        verify=_verify_tls(config),
        headers={"Accept": "application/json"},
    )
    try:
        resp = await client.post(
            "/api/users/login",
            json={"username": username, "password": password},
        )
        data = await _raise_for_api_error(resp)
        if not isinstance(data, dict):
            raise ValueError("GPN login returned an unexpected response")
        if not isinstance(data.get("user"), dict):
            raise ValueError("GPN login did not return a user")
        yield client, data
    finally:
        await client.aclose()


async def _fetch_challenges(client) -> list[dict]:
    resp = await client.get("/api/challenges")
    data = await _raise_for_api_error(resp)
    if not isinstance(data, list):
        raise ValueError("GPN challenges endpoint returned an unexpected response")
    return [item for item in data if isinstance(item, dict)]


async def _fetch_tags(client) -> dict[str, dict]:
    resp = await client.get("/api/challenges/tags")
    data = await _raise_for_api_error(resp)
    if not isinstance(data, list):
        return {}
    tags = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        tag_id = _clean(item.get("id"))
        if tag_id:
            tags[tag_id] = item
    return tags


def _tag_label(tag_id: str, tags: dict[str, dict]) -> str:
    info = tags.get(tag_id) or {}
    return _clean(info.get("longName") or info.get("name") or tag_id)


def _challenge_category(challenge: dict, tags: dict[str, dict]) -> str:
    categories = []
    for tag_id in challenge.get("tags", []) or []:
        tag_id = _clean(tag_id)
        if tag_id and (tags.get(tag_id) or {}).get("isCategory"):
            categories.append(_tag_label(tag_id, tags))
    return ", ".join(categories)


def _challenge_tags(challenge: dict) -> list[str]:
    tags = []
    for tag in challenge.get("tags", []) or []:
        value = _clean(tag)
        if value and value not in tags:
            tags.append(value)

    extra = challenge.get("extraData") or {}
    if isinstance(extra, dict) and _clean(extra.get("connectUrl")):
        # Reuse the app's existing instance-start trigger.
        tags.append("docker:gpn")
        connect_type = _clean(extra.get("connectType")).lower()
        if connect_type:
            tags.append(f"connect:{connect_type}")
    return tags


def _challenge_description(challenge: dict) -> str:
    parts = []
    description = _clean(challenge.get("description"))
    if description:
        parts.append(description)

    extra = challenge.get("extraData") or {}
    if isinstance(extra, dict):
        authors = extra.get("authors")
        if isinstance(authors, list):
            author_text = ", ".join(_clean(author) for author in authors if _clean(author))
            if author_text:
                parts.append(f"Authors: {author_text}")
        elif _clean(authors):
            parts.append(f"Authors: {_clean(authors)}")

    return "\n\n".join(parts)


def _challenge_solves(challenge: dict) -> int:
    solve_counts = challenge.get("solveCounts") or {}
    if not isinstance(solve_counts, dict):
        return 0
    total = 0
    for value in solve_counts.values():
        try:
            total += int(value)
        except (TypeError, ValueError):
            continue
    return total


def _challenge_points(challenge: dict) -> int:
    try:
        return int(round(float(challenge.get("points") or 0)))
    except (TypeError, ValueError):
        return 0


def _handout_file(base_url: str, challenge: dict) -> RemoteFile | None:
    if not _clean(challenge.get("handoutType")):
        return None
    remote_id = _clean(challenge.get("id"))
    if not remote_id:
        return None
    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in remote_id)
    return RemoteFile(
        name=f"{safe_name or 'handout'}.tar.gz",
        url=f"{base_url}/api/challenges/handout/{quote(remote_id, safe='')}",
    )


def _find_challenge(challenges: list[dict], remote_id: str) -> dict | None:
    remote_id = str(remote_id)
    for challenge in challenges:
        if str(challenge.get("id")) == remote_id:
            return challenge
    return None


def _connect_base(connect_url: str) -> str:
    raw = _clean(connect_url)
    if not raw:
        raise ValueError("Missing GPN instance connection URL")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid GPN instance connection URL: {connect_url}")
    return raw.rstrip("/")


def _instances_ws_url(connect_url: str) -> str:
    base = _connect_base(connect_url)
    parsed = urlparse(base)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    path = parsed.path.rstrip("/")
    return f"{scheme}://{parsed.netloc}{path}/instances"


def _team_token(login_data: dict) -> str:
    team = login_data.get("team") or {}
    if not isinstance(team, dict):
        raise ValueError("GPN login did not return team details")
    token = _clean(team.get("teamToken"))
    if not token:
        raise ValueError("GPN login did not return a team token")
    return token


def _connect_details(challenge: dict) -> tuple[str, str]:
    extra = challenge.get("extraData") or {}
    if not isinstance(extra, dict):
        return "", ""
    return _clean(extra.get("connectUrl")), _clean(extra.get("connectType"))


def _pick_instance(instances: list[dict]) -> dict | None:
    valid = [item for item in instances if isinstance(item, dict) and _clean(item.get("uri"))]
    if not valid:
        return None

    ready_statuses = {"", "ready", "running", "active", "started"}
    for instance in valid:
        if _clean(instance.get("status")).lower() in ready_statuses:
            return instance
    return None


def _instances_from_payload(payload) -> list[dict]:
    if not isinstance(payload, dict):
        return []

    direct = payload.get("instance")
    if isinstance(direct, dict):
        return [direct]

    instances = payload.get("instances")
    if isinstance(instances, list):
        return [item for item in instances if isinstance(item, dict)]

    value = payload.get("value")
    if isinstance(value, dict):
        nested = _instances_from_payload(value)
        if nested:
            return nested

    error = payload.get("error")
    if isinstance(error, dict):
        return _instances_from_payload(error)

    return []


def _instance_error(payload) -> str:
    if not isinstance(payload, dict):
        return ""
    if _clean(payload.get("type")) == "Error":
        return _api_message(payload)
    error = payload.get("error")
    if isinstance(error, dict):
        return _api_message({"error": error})
    return ""


def _instance_error_code(payload) -> str:
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if not isinstance(error, dict):
        return ""
    return _clean(error.get("type") or error.get("code"))


def _format_instance_time(value) -> str:
    text = _clean(value)
    return text


def _instance_info(instance: dict, connect_type: str) -> dict | None:
    uri = _clean(instance.get("uri"))
    if not uri:
        return None

    kind = _clean(connect_type).lower()
    result: dict = {"host": uri, "raw_uri": uri}
    status = _clean(instance.get("status"))
    if status:
        result["status"] = status

    lifetime = _format_instance_time(
        instance.get("lifetime")
        or instance.get("expiresAt")
        or instance.get("expires_at")
    )
    if lifetime:
        result["expires_at"] = lifetime

    if kind == "browser":
        result["type"] = "browser"
        result["url"] = uri if uri.startswith(("http://", "https://")) else f"https://{uri}"
    elif kind == "socket":
        result["type"] = "socket"
        result["port"] = 443
        result["connection"] = f"ncat --ssl {uri} 443"
    else:
        result["type"] = kind or "gpn"
        result["connection"] = uri
    return result


async def _spawn_instance(connect_url: str, team_token: str, verify_tls: bool) -> dict | None:
    async with httpx.AsyncClient(
        base_url=_connect_base(connect_url),
        timeout=SPAWN_TIMEOUT,
        follow_redirects=True,
        verify=verify_tls,
        headers={"Accept": "application/json"},
    ) as client:
        resp = await client.post("/spawn", json={"teamToken": team_token})
        payload = await _raise_for_api_error(resp)

    instances = _instances_from_payload(payload)
    instance = _pick_instance(instances)
    if instance:
        return instance

    error = _instance_error(payload)
    if error:
        if _instance_error_code(payload) == "TooManyInstances":
            return None
        raise ValueError(error)
    return None


async def _instances_from_websocket(
    connect_url: str,
    team_token: str,
    verify_tls: bool,
    *,
    wait_seconds: int = INSTANCE_WAIT_SECONDS,
) -> list[dict]:
    if websockets is None:
        return []

    ws_url = _instances_ws_url(connect_url)
    connect_kwargs = {}
    if not verify_tls and ws_url.startswith("wss://"):
        connect_kwargs["ssl"] = ssl._create_unverified_context()

    deadline = asyncio.get_running_loop().time() + wait_seconds
    instances: list[dict] = []
    async with websockets.connect(ws_url, **connect_kwargs) as ws:
        await ws.send(json.dumps({"teamToken": team_token}))
        while asyncio.get_running_loop().time() < deadline:
            remaining = max(0.1, deadline - asyncio.get_running_loop().time())
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError):
                continue
            instances = _instances_from_payload(payload)
            if _pick_instance(instances):
                return instances
    return instances


async def _terminate_instances(
    connect_url: str,
    team_token: str,
    instances: list[dict],
    verify_tls: bool,
) -> None:
    async with httpx.AsyncClient(
        base_url=_connect_base(connect_url),
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        verify=verify_tls,
        headers={"Accept": "application/json"},
    ) as client:
        for instance in instances:
            uri = _clean(instance.get("uri"))
            if not uri:
                continue
            resp = await client.post(
                "/instances/terminate",
                json={"uri": uri, "teamToken": team_token},
            )
            if resp.status_code >= 400:
                log.warning(
                    "GPN instance terminate failed for %s: %s",
                    uri,
                    _api_message(_response_json(resp), resp),
                )


class GPNPlugin(CTFPlatformPlugin):
    name = "gpn"
    label = "GPN CTF / KITchen"

    def source_url(self, config: dict) -> str:
        return _base_url(config)

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="url",
                label="Platform URL",
                field_type="url",
                default=DEFAULT_URL,
                placeholder=DEFAULT_URL,
            ),
            ConfigField(
                name="username",
                label="Username",
                field_type="text",
                placeholder="rina",
            ),
            ConfigField(
                name="password",
                label="Password",
                field_type="password",
            ),
            ConfigField(
                name="insecure_tls",
                label="Disable TLS verification",
                field_type="checkbox",
                required=False,
                default="false",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        async with _client(config) as (client, login_data):
            challenges = await _fetch_challenges(client)
            user = login_data.get("user") or {}
            team = login_data.get("team") or {}
            username = _clean(user.get("id")) if isinstance(user, dict) else ""
            team_name = (
                _clean(team.get("caption") or team.get("teamId"))
                if isinstance(team, dict)
                else ""
            )
            parts = [f"Connected as {username or 'user'}"]
            if team_name:
                parts.append(f"team {team_name}")
            parts.append(f"{len(challenges)} challenges")
            return " - ".join(parts)

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        base_url = _base_url(config)
        async with _client(config) as (client, _login_data):
            challenges = await _fetch_challenges(client)
            tags = await _fetch_tags(client)

        results: list[RemoteChallenge] = []
        for challenge in challenges:
            remote_id = _clean(challenge.get("id"))
            if not remote_id:
                continue
            files = []
            handout = _handout_file(base_url, challenge)
            if handout:
                files.append(handout)
            results.append(RemoteChallenge(
                remote_id=remote_id,
                name=_clean(challenge.get("name")) or remote_id,
                description=_challenge_description(challenge),
                category=_challenge_category(challenge, tags),
                points=_challenge_points(challenge),
                files=files,
                solves=_challenge_solves(challenge),
                solved=bool(challenge.get("solvedByMe")),
                tags=_challenge_tags(challenge),
            ))
        return results

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None,
        progress_cb=None,
    ) -> bytes:
        async with _client(config) as (client, _login_data):
            async with client.stream("GET", file.url) as resp:
                return await read_limited_response(resp, max_bytes, progress_cb)

    async def start_instance(
        self, config: dict, remote_id: str
    ) -> dict | None:
        async with _client(config) as (client, login_data):
            challenge = _find_challenge(await _fetch_challenges(client), remote_id)
            if not challenge:
                raise ValueError(f"GPN challenge {remote_id} not found")
            connect_url, connect_type = _connect_details(challenge)
            if not connect_url:
                return None
            token = _team_token(login_data)

        verify_tls = _verify_tls(config)
        instance = await _spawn_instance(connect_url, token, verify_tls)
        if not instance:
            instances = await _instances_from_websocket(connect_url, token, verify_tls)
            instance = _pick_instance(instances)
        if not instance:
            return None
        return _instance_info(instance, connect_type)

    async def stop_instance(
        self, config: dict, remote_id: str
    ) -> None:
        async with _client(config) as (client, login_data):
            challenge = _find_challenge(await _fetch_challenges(client), remote_id)
            if not challenge:
                return
            connect_url, _connect_type = _connect_details(challenge)
            if not connect_url:
                return
            token = _team_token(login_data)

        if websockets is None:
            log.warning("websockets is required to discover GPN instances for stop")
            return

        instances = await _instances_from_websocket(
            connect_url,
            token,
            _verify_tls(config),
            wait_seconds=10,
        )
        await _terminate_instances(connect_url, token, instances, _verify_tls(config))

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str,
        flag_id: str | int | None = None,
    ) -> SubmitResult:
        del flag_id
        async with _client(config) as (client, _login_data):
            resp = await client.post(
                "/api/challenges/submit",
                json={"challengeId": str(remote_id), "flag": flag},
            )
            data = _response_json(resp)
            return _submit_result_from_response(resp, data)
