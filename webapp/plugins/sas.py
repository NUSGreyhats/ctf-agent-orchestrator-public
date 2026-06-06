"""SAS CTF platform plugin."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import html
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

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


DEFAULT_URL = "https://ctf.thesascon.com"
DEFAULT_TIMEOUT = 30
INSTANCE_WAIT_SECONDS = 180
INSTANCE_POLL_SECONDS = 3
READY_STATUS = 2
FAILED_STATUS = -1


def _require_httpx() -> None:
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the SAS CTF plugin. "
            "Install it with: pip install httpx"
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
        raise ValueError("SAS CTF URL must be an absolute http(s) URL")
    if parsed.query or parsed.fragment:
        raise ValueError("SAS CTF URL must not include a query string or fragment")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _verify_tls(config: dict) -> bool:
    return not _truthy(config.get("insecure_tls", True))


def _session_cookie(config: dict) -> str:
    raw = _clean(config.get("session_cookie"))
    if not raw:
        return ""
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("session="):
            return part.split("=", 1)[1].strip()
    return raw


def _response_json(resp) -> dict | list | None:
    try:
        return resp.json()
    except ValueError:
        return None


def _api_message(data, resp=None) -> str:
    if isinstance(data, dict):
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            return ", ".join(str(err) for err in errors if err)
        message = _clean(data.get("message"))
        if message:
            return message
        status = _clean(data.get("status"))
        if status and status != "success":
            return status
    if resp is not None:
        text = _clean(getattr(resp, "text", ""))
        content_type = getattr(resp, "headers", {}).get("content-type", "")
        if text and "text/html" not in content_type and len(text) < 300:
            return text
        return f"HTTP {resp.status_code}"
    return "unknown error"


async def _raise_for_api_error(resp) -> dict | list | None:
    data = _response_json(resp)
    if resp.status_code >= 400:
        raise ValueError(_api_message(data, resp))
    if isinstance(data, dict):
        status = _clean(data.get("status")).casefold()
        if status == "error":
            raise ValueError(_api_message(data, resp))
    return data


@asynccontextmanager
async def _client(config: dict):
    _require_httpx()
    cookies = {}
    session = _session_cookie(config)
    if session:
        cookies["session"] = session
    client = httpx.AsyncClient(
        base_url=f"{_base_url(config)}/public-api/",
        cookies=cookies,
        follow_redirects=True,
        timeout=DEFAULT_TIMEOUT,
        verify=_verify_tls(config),
        headers={"Accept": "application/json"},
    )
    try:
        if not session:
            username = _clean(config.get("username"))
            password = _clean(config.get("password"))
            if username and password:
                resp = await client.post(
                    "login",
                    data={"name": username, "password": password},
                )
                data = await _raise_for_api_error(resp)
                if not (isinstance(data, dict) and data.get("status") == "success"):
                    message = _api_message(data, resp)
                    raise ValueError(message)
        yield client
    except Exception as exc:
        message = str(exc)
        if "recaptcha" in message.casefold():
            raise ValueError(
                "SAS username/password login requires browser reCAPTCHA; "
                "log in in a browser and paste the session cookie instead."
            ) from exc
        raise
    finally:
        await client.aclose()


async def _fetch_json(client, method: str, path: str, **kwargs):
    resp = await client.request(method, path, **kwargs)
    return await _raise_for_api_error(resp)


def _connection_entries(challenge: dict) -> list[tuple[int | None, str, str]]:
    raw = _clean(challenge.get("connection_info"))
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except ValueError:
        return [(None, "", raw)]
    items = parsed.get("d") if isinstance(parsed, dict) else parsed
    if not isinstance(items, list):
        return []
    entries = []
    for item in items:
        if not isinstance(item, list) or len(item) < 3:
            continue
        kind = item[0]
        try:
            kind = int(kind)
        except (TypeError, ValueError):
            kind = None
        entries.append((kind, _clean(item[1]), _clean(item[2])))
    return entries


def _filename(label: str, url: str, index: int) -> str:
    name = label or Path(unquote(urlparse(url).path)).name
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name or f"file-{index}"


def _is_file_entry(kind: int | None, label: str, value: str) -> bool:
    if not value:
        return False
    if kind == 0:
        return True
    parsed = urlparse(value)
    if parsed.netloc == "storage.yandexcloud.net":
        return True
    suffix = Path(unquote(parsed.path)).suffix.lower()
    return bool(
        suffix
        and parsed.scheme in {"http", "https"}
        and parsed.netloc
        and not parsed.netloc.endswith("task.sasc.tf")
        and label
    )


def _challenge_files(challenge: dict) -> list[RemoteFile]:
    files = []
    seen = set()
    for index, (kind, label, value) in enumerate(_connection_entries(challenge), 1):
        if not _is_file_entry(kind, label, value):
            continue
        if value in seen:
            continue
        seen.add(value)
        files.append(RemoteFile(name=_filename(label, value, index), url=value))
    return files


def _connection_lines(challenge: dict) -> list[str]:
    lines = []
    for kind, label, value in _connection_entries(challenge):
        if _is_file_entry(kind, label, value):
            continue
        if not value:
            continue
        if label and not value.startswith(label):
            lines.append(f"{label}: {value}")
        else:
            lines.append(value)
    return lines


def _challenge_description(challenge: dict) -> str:
    description = _clean(challenge.get("description"))
    parts = [description] if description else []
    lines = _connection_lines(challenge)
    if lines:
        parts.append("Connection info:")
        parts.extend(f"- {line}" for line in lines)
    return "\n\n".join(parts)


def _challenge_tags(challenge: dict) -> list[str]:
    tags = ["platform:sas", f"type:{_clean(challenge.get('type'))}"]
    if _clean(challenge.get("type")) == "dynamic_docker":
        tags.append("docker:sas")
    for category in _clean(challenge.get("category")).split(","):
        category = category.strip()
        if category:
            tags.append(category)
    return [tag for tag in dict.fromkeys(tags) if tag]


def _int_value(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_access_entry(item, index: int) -> dict | None:
    label = f"connect {index + 1}"
    text = ""
    url = ""
    if isinstance(item, str):
        text = html.unescape(re.sub(r"<[^>]+>", "", item)).strip()
        match = re.search(r"href=[\"']([^\"']+)", item)
        if match:
            url = html.unescape(match.group(1)).strip()
        elif re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I):
            url = text
    elif isinstance(item, dict):
        url = _clean(
            item.get("url")
            or item.get("href")
            or item.get("link")
            or item.get("access")
        )
        text = _clean(item.get("text") or item.get("name") or item.get("label") or url)
        label = _clean(item.get("name") or item.get("label")) or label
    elif isinstance(item, list) and len(item) >= 3:
        label = _clean(item[1]) or label
        text = _clean(item[2])
        if re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I):
            url = text
    else:
        return None

    value = url or text
    if not value:
        return None
    if url:
        return {"type": "web", "url": url}

    match = re.match(r"^\s*nc\s+([^\s]+)\s+(\d+)\s*$", text)
    if match:
        return {
            "type": "tcp",
            "host": match.group(1),
            "port": int(match.group(2)),
            "connection": text,
        }
    if label and label not in text:
        text = f"{label}: {text}"
    return {"type": "connection", "connection": text}


def _container_instance_info(payload: dict | None) -> dict | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    if _int_value(data.get("container_status")) != READY_STATUS:
        return None
    access = data.get("user_access")
    access_items = access if isinstance(access, list) else ([access] if access else [])
    remotes = [
        remote
        for idx, item in enumerate(access_items)
        if (remote := _normalize_access_entry(item, idx))
    ]
    if not remotes:
        return None
    if len(remotes) == 1:
        return remotes[0]
    return {"type": "sas_container", "remotes": remotes}


def _container_error(payload: dict | None) -> str:
    if not isinstance(payload, dict):
        return "unexpected container response"
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    return (
        _clean(data.get("last_error"))
        or _clean(payload.get("message"))
        or "container failed"
    )


class SASCTFPlugin(CTFPlatformPlugin):
    name = "sas"
    label = "SAS CTF"

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
                name="session_cookie",
                label="Session Cookie",
                field_type="password",
                required=False,
                placeholder="Paste session=... or the raw session cookie value",
            ),
            ConfigField(
                name="username",
                label="Username",
                field_type="text",
                required=False,
                placeholder="Optional; browser reCAPTCHA may block this",
            ),
            ConfigField(
                name="password",
                label="Password",
                field_type="password",
                required=False,
                placeholder="Optional; prefer session cookie",
            ),
            ConfigField(
                name="insecure_tls",
                label="Disable TLS certificate verification",
                field_type="checkbox",
                required=False,
                default="true",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        async with _client(config) as client:
            login = await _fetch_json(client, "GET", "login")
            if not isinstance(login, dict) or not login.get("authorized"):
                raise ValueError("SAS CTF session is not authorized")
            team = await _fetch_json(client, "GET", "current_team")
            challenges = await _fetch_json(client, "GET", "challenges")
            team_data = team.get("data", {}) if isinstance(team, dict) else {}
            challenge_data = (
                challenges.get("data", []) if isinstance(challenges, dict) else []
            )
            return (
                f"Connected as {_clean(team_data.get('name')) or 'team'} "
                f"({len(challenge_data)} challenges)"
            )

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        async with _client(config) as client:
            data = await _fetch_json(client, "GET", "challenges")
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise ValueError("SAS CTF challenges endpoint returned an unexpected response")

        results = []
        for challenge in data["data"]:
            if not isinstance(challenge, dict):
                continue
            remote_id = _clean(challenge.get("id"))
            if not remote_id:
                continue
            results.append(RemoteChallenge(
                remote_id=remote_id,
                name=_clean(challenge.get("name")) or f"Challenge {remote_id}",
                description=_challenge_description(challenge),
                category=_clean(challenge.get("category")),
                points=_int_value(challenge.get("value")),
                files=_challenge_files(challenge),
                solves=_int_value(challenge.get("solves")),
                solved=bool(challenge.get("solved_by_me")),
                tags=_challenge_tags(challenge),
            ))
        return results

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None,
        progress_cb=None,
    ) -> bytes:
        async with _client(config) as client:
            async with client.stream("GET", file.url) as resp:
                return await read_limited_response(resp, max_bytes, progress_cb)

    async def start_instance(
        self, config: dict, remote_id: str
    ) -> dict | None:
        async with _client(config) as client:
            params = {"challenge_id": str(remote_id)}
            payload = await _fetch_json(client, "GET", "container", params=params)
            instance = _container_instance_info(payload)
            if instance:
                return instance

            data = payload.get("data") if isinstance(payload, dict) else {}
            status = _int_value(data.get("container_status")) if isinstance(data, dict) else 0
            if status not in {1, 3}:
                payload = await _fetch_json(
                    client, "POST", "container", params=params, json={}
                )
                if isinstance(payload, dict) and not payload.get("success", True):
                    raise ValueError(_container_error(payload))

            deadline = asyncio.get_running_loop().time() + INSTANCE_WAIT_SECONDS
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(INSTANCE_POLL_SECONDS)
                payload = await _fetch_json(client, "GET", "container", params=params)
                instance = _container_instance_info(payload)
                if instance:
                    return instance
                data = payload.get("data") if isinstance(payload, dict) else {}
                status = (
                    _int_value(data.get("container_status"))
                    if isinstance(data, dict)
                    else 0
                )
                if status == FAILED_STATUS:
                    raise ValueError(_container_error(payload))
                if not status:
                    payload = await _fetch_json(
                        client, "POST", "container", params=params, json={}
                    )
                    if isinstance(payload, dict) and not payload.get("success", True):
                        raise ValueError(_container_error(payload))
            return None

    async def stop_instance(
        self, config: dict, remote_id: str
    ) -> None:
        async with _client(config) as client:
            params = {"challenge_id": str(remote_id)}
            try:
                await _fetch_json(client, "DELETE", "container", params=params, json={})
            except ValueError:
                return

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str,
        flag_id: str | int | None = None,
    ) -> SubmitResult:
        del flag_id
        async with _client(config) as client:
            data = await _fetch_json(
                client,
                "POST",
                "challenges/attempt",
                json={"challenge_id": int(remote_id), "submission": flag},
            )
        status = _clean(data.get("status") if isinstance(data, dict) else "")
        message = _api_message(data)
        correct = status.casefold() == "correct"
        return SubmitResult(
            correct=correct,
            message=message if message != "unknown error" else status,
        )
