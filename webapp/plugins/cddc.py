"""CDDC platform plugin (dstacddc.com)."""

from __future__ import annotations

import asyncio
import base64
import html
import re
from urllib.parse import parse_qs, unquote_plus, urljoin, urlparse, urlunparse

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


def _require_httpx():
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the CDDC plugin. "
            "Install it with: pip install httpx"
        )


def _base_url(config: dict) -> str:
    raw_url = config.get("url", "").strip() or "https://dstacddc.com"
    if raw_url.startswith("https:/") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url.removeprefix("https:/").lstrip("/")
    if raw_url.startswith("http:/") and not raw_url.startswith("http://"):
        raw_url = "http://" + raw_url.removeprefix("http:/").lstrip("/")

    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("CDDC URL must be an absolute http(s) URL")

    path = parsed.path.rstrip("/")
    if not path or path == "/":
        path = "/CDDC"
    parsed = parsed._replace(path=path, params="", query="", fragment="")
    return urlunparse(parsed).rstrip("/") + "/"


def _verify_tls(config: dict) -> bool:
    value = config.get("insecure_tls", False)
    if isinstance(value, str):
        value = value.strip().lower() in {"1", "true", "yes", "on"}
    return not bool(value)


def _credentials(config: dict) -> tuple[str, str]:
    username = config.get("username", "").strip()
    password = config.get("password", "").strip()
    if not username or not password:
        raise ValueError("CDDC email and password are required")
    return username, password


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _ajax_headers(config: dict, page: str = "challenge") -> dict:
    base = _base_url(config)
    return {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": _origin(base),
        "Referer": f"{base}?p={page}",
    }


def _parse_challenge_ids(html_text: str) -> list[str]:
    ids = re.findall(r"open_wargame\((\d+)\)", html_text)
    seen: set[str] = set()
    return [cid for cid in ids if not (cid in seen or seen.add(cid))]


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _strip_category_prefix(category: str) -> str:
    return re.sub(r"^\s*\d+\.\s*", "", category or "").strip()


def _clean_description(value) -> str:
    description = str(value or "")
    if description:
        description = description[1:]
    return description.strip()


def _file_name_from_url(url: str, title: str, challenge_id: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    if "drive.google.com" in host and "/file/d/" in path:
        return f"{title or 'challenge'}-{challenge_id}.bin"

    basename = path.rsplit("/", 1)[-1]
    if basename and basename not in {"view", "download"}:
        return unquote_plus(basename)

    qs = parse_qs(parsed.query)
    for key in ("filename", "file", "name"):
        values = qs.get(key)
        if values and values[0]:
            return unquote_plus(values[0])
    return f"{title or 'challenge'}-{challenge_id}.bin"


def _remote_file_from_detail(detail: dict) -> RemoteFile | None:
    file_url = str(detail.get("files") or "").strip()
    if not file_url:
        return None
    title = str(detail.get("title") or "challenge").strip()
    challenge_id = str(detail.get("idx") or "").strip()
    return RemoteFile(
        name=_file_name_from_url(file_url, title, challenge_id),
        url=file_url,
    )


def _google_drive_confirm_url(page_text: str) -> str:
    match = re.search(
        r'href="(https://drive\.usercontent\.google\.com/download[^"]+)"',
        page_text,
    )
    if match:
        return html.unescape(match.group(1))

    form = re.search(
        r'<form[^>]+action="([^"]*drive\.usercontent\.google\.com/download[^"]*)"'
        r"[^>]*>(.*?)</form>",
        page_text,
        re.DOTALL | re.IGNORECASE,
    )
    if not form:
        return ""
    action = html.unescape(form.group(1))
    fields = re.findall(
        r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"',
        form.group(2),
        re.IGNORECASE,
    )
    if not fields:
        return action
    query = "&".join(
        f"{html.unescape(name)}={html.unescape(value)}"
        for name, value in fields
    )
    return f"{action}?{query}"


def _is_google_drive_view_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.netloc.lower().endswith("drive.google.com")
        and "/file/d/" in parsed.path
    )


def _google_drive_download_url(url: str) -> str:
    parsed = urlparse(url)
    match = re.search(r"/file/d/([^/]+)", parsed.path)
    if not match:
        return url
    return f"https://drive.google.com/uc?export=download&id={match.group(1)}"


async def _post_json(client: httpx.AsyncClient, config: dict, command: str, data=None):
    resp = await client.post(
        f"api/?c={command}",
        data=data or {},
        headers=_ajax_headers(config),
    )
    resp.raise_for_status()
    try:
        return resp.json()
    except ValueError as exc:
        raise ValueError(
            f"CDDC API {command} returned non-JSON response: {resp.text[:120]}"
        ) from exc


async def _client(config: dict) -> httpx.AsyncClient:
    _require_httpx()
    username, password = _credentials(config)
    base = _base_url(config)
    client = httpx.AsyncClient(
        base_url=base,
        verify=_verify_tls(config),
        follow_redirects=True,
        timeout=30,
        headers={
            "User-Agent": "ctf-solver/1.0",
        },
    )

    try:
        await client.get("?p=login")
        parsed_base = urlparse(base)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        result = None
        for attempt in range(5):
            resp = await client.post(
                "api/?c=login",
                data={"id": username, "ps": password},
                headers={**_ajax_headers(config, "login"), "Origin": origin},
            )
            resp.raise_for_status()
            try:
                result = resp.json()
            except ValueError:
                result = resp.text.strip()
            if result != "fast" or attempt == 4:
                break
            await asyncio.sleep(2 * (attempt + 1))

        if result is True:
            return client
        if result == "nameset":
            return client
        if result == "fast":
            raise ValueError("Login rate limited; try again in a moment")
        if result == "failed":
            raise ValueError("Login failed: email or password did not match")
        if result == "ban":
            raise ValueError("Login failed: account is blocked")
        raise ValueError(f"Login failed: unexpected response {result!r}")
    except Exception:
        await client.aclose()
        raise


class CDDCPlugin(CTFPlatformPlugin):
    name = "cddc"
    label = "CDDC"

    def source_url(self, config: dict) -> str:
        return _base_url(config)

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="url",
                label="CDDC URL",
                field_type="url",
                placeholder="https://dstacddc.com",
                default="https://dstacddc.com",
            ),
            ConfigField(
                name="username",
                label="Email",
                field_type="text",
                placeholder="Registration email",
            ),
            ConfigField(
                name="password",
                label="Password",
                field_type="password",
            ),
            ConfigField(
                name="insecure_tls",
                label="Disable TLS certificate verification",
                field_type="checkbox",
                required=False,
                default=False,
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        client = await _client(config)
        try:
            resp = await client.get("?p=challenge")
            resp.raise_for_status()
            if "logout.php" not in resp.text:
                raise ValueError("Login appeared to succeed but no session was established")
            challenge_ids = _parse_challenge_ids(resp.text)
            if challenge_ids:
                return f"Logged in to CDDC ({len(challenge_ids)} challenges visible)"
            if "Qualifier" in resp.text and "opentimerW" in resp.text:
                return "Logged in to CDDC; challenge area is not open yet"
            return "Logged in to CDDC"
        finally:
            await client.aclose()

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        client = await _client(config)
        try:
            resp = await client.get("?p=challenge")
            resp.raise_for_status()
            challenge_ids = _parse_challenge_ids(resp.text)
            if not challenge_ids:
                raise ValueError(
                    "Logged in, but CDDC challenge endpoints are not visible yet. "
                    "Retry after the CTF challenge page opens."
                )

            cleared_data = await _post_json(client, config, "cleared")
            cleared = {
                str(item.get("cidx"))
                for item in cleared_data
                if isinstance(item, dict) and item.get("cidx") is not None
            }

            results = []
            for challenge_id in challenge_ids:
                data = await _post_json(
                    client, config, "get_challenge", {"i": challenge_id}
                )
                if not isinstance(data, list) or not data or not isinstance(data[0], dict):
                    continue
                detail = data[0]
                remote_id = str(detail.get("idx") or challenge_id)
                category = _strip_category_prefix(str(detail.get("cate2") or ""))
                tags = [
                    tag.strip()
                    for tag in str(detail.get("tags") or "").split(",")
                    if tag.strip()
                ]
                stat = str(detail.get("stat") or "").strip()
                if stat and stat != "open":
                    tags.append(stat)

                files = []
                remote_file = _remote_file_from_detail(detail)
                if remote_file:
                    files.append(remote_file)

                results.append(RemoteChallenge(
                    remote_id=remote_id,
                    name=str(detail.get("title") or f"Challenge {remote_id}"),
                    description=_clean_description(detail.get("description")),
                    category=category,
                    points=_as_int(detail.get("point")),
                    solves=_as_int(detail.get("solved")),
                    files=files,
                    solved=remote_id in cleared,
                    tags=tags,
                ))

            return results
        finally:
            await client.aclose()

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None,
        progress_cb=None,
    ) -> bytes:
        url = file.url
        if _is_google_drive_view_url(url):
            url = _google_drive_download_url(url)

        parsed_file = urlparse(url)
        parsed_base = urlparse(_base_url(config))
        same_origin = (
            parsed_file.scheme in {"", parsed_base.scheme}
            and parsed_file.netloc.lower() in {"", parsed_base.netloc.lower()}
        )

        if same_origin:
            client = await _client(config)
            try:
                target = urljoin(_base_url(config), url)
                async with client.stream("GET", target) as resp:
                    return await read_limited_response(resp, max_bytes, progress_cb)
            finally:
                await client.aclose()

        _require_httpx()
        async with httpx.AsyncClient(
            verify=_verify_tls(config),
            follow_redirects=True,
            timeout=60,
            headers={"User-Agent": "ctf-solver/1.0"},
        ) as client:
            async with client.stream("GET", url) as resp:
                data = await read_limited_response(resp, max_bytes, progress_cb)
                content_type = resp.headers.get("content-type", "")
                content_disposition = resp.headers.get("content-disposition", "")

            if (
                "drive.google.com" in urlparse(url).netloc.lower()
                and "text/html" in content_type
                and "attachment" not in content_disposition.lower()
            ):
                confirm_url = _google_drive_confirm_url(
                    data.decode("utf-8", errors="ignore")
                )
                if confirm_url:
                    async with client.stream("GET", confirm_url) as resp:
                        return await read_limited_response(
                            resp, max_bytes, progress_cb
                        )
            return data

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str,
        flag_id: str | int | None = None,
    ) -> SubmitResult:
        encoded_flag = base64.b64encode(flag.encode()).decode()
        client = await _client(config)
        try:
            result = await _post_json(
                client,
                config,
                "submit_flag",
                {"i": remote_id, "f": encoded_flag},
            )
        finally:
            await client.aclose()

        if result == "o":
            return SubmitResult(correct=True, message="Correct")
        if result == "a":
            return SubmitResult(correct=True, message="Already solved")
        if result == "x":
            return SubmitResult(correct=False, message="Incorrect")
        if result == "f":
            return SubmitResult(correct=False, message="Try again in a moment")
        return SubmitResult(correct=False, message=f"Unexpected response: {result!r}")
