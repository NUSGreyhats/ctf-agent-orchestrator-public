"""Cywaria/Cympire cyber range platform plugin."""

from __future__ import annotations

import asyncio
from urllib.parse import unquote_plus, urlparse

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


DEFAULT_URL = "https://csasgco.cywaria.net"
FLAG_ID_PROGRAM_SEP = "|program:"
NA_VALUES = {"", "N/A", "n/a", "NA", "na", "None", "none", "null", "NULL"}
GOOD_SUBMIT_TERMS = ("correct", "solved", "success", "well done", "congrat")
BAD_SUBMIT_TERMS = ("wrong", "incorrect", "invalid", "try again", "failed")
FILE_EXTENSIONS = {
    ".7z",
    ".bin",
    ".bmp",
    ".csv",
    ".doc",
    ".docx",
    ".elf",
    ".gif",
    ".gz",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".json",
    ".log",
    ".mp3",
    ".mp4",
    ".pcap",
    ".pcapng",
    ".pdf",
    ".png",
    ".py",
    ".rar",
    ".tar",
    ".tgz",
    ".txt",
    ".wav",
    ".xz",
    ".zip",
}


def _require_httpx():
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the Cywaria plugin. "
            "Install it with: pip install httpx"
        )


def _clean(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text in NA_VALUES else text


def _clean_port(value) -> int | str | None:
    if value is None or isinstance(value, bool):
        return None
    text = _clean(value)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return text


def _normal_url(config: dict) -> str:
    raw = _clean(config.get("url")) or DEFAULT_URL
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Cywaria URL must be an absolute http(s) URL")
    return raw.rstrip("/")


def _tenant_api_url(config: dict) -> tuple[str, str, str]:
    url = _normal_url(config)
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    tenant = host.split(".", 1)[0]
    if not tenant:
        raise ValueError("Could not derive Cywaria tenant from URL")

    api_url = _clean(config.get("api_url"))
    if not api_url:
        if host.endswith(".cywaria.net"):
            api_url = "https://api-v3.cywaria.net"
        elif host.endswith(".cympire.net"):
            api_url = "https://api-v3.cympire.net"
        elif host.endswith(".cyber-range.live"):
            api_url = "https://api-v3.cyber-range.live"
        else:
            raise ValueError(
                "Could not derive Cywaria API URL; use a cywaria.net, "
                "cympire.net, or cyber-range.live tenant URL"
            )
    return tenant, api_url.rstrip("/"), url


def _credentials(config: dict) -> tuple[str, str]:
    username = _clean(config.get("username"))
    password = _clean(config.get("password"))
    if not username or not password:
        raise ValueError("Cywaria username and password are required")
    return username, password


async def _auth_token(config: dict) -> tuple[str, str]:
    _require_httpx()
    tenant, api_url, _ = _tenant_api_url(config)
    username, password = _credentials(config)
    async with httpx.AsyncClient(base_url=api_url, timeout=30) as client:
        resp = await client.post(
            "/auth",
            json={
                "tenant": tenant,
                "username": username,
                "password": password,
                "all_fields": True,
            },
        )
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code >= 400:
        raise ValueError(f"Cywaria login failed: {_api_message(data, resp)}")
    token = _clean(data.get("IdToken"))
    status = _clean(data.get("status")).upper()
    if not token or status not in {"OK", "SUCCESS", ""}:
        raise ValueError(f"Cywaria login failed: {_api_message(data, resp)}")
    return api_url, token


async def _client(config: dict) -> httpx.AsyncClient:
    api_url, token = await _auth_token(config)
    return httpx.AsyncClient(
        base_url=api_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        timeout=30,
        follow_redirects=True,
    )


def _api_message(data, resp=None) -> str:
    if isinstance(data, dict):
        for key in ("message", "error", "status", "code"):
            value = _clean(data.get(key))
            if value:
                return value
    if resp is not None:
        return f"HTTP {resp.status_code}"
    return "unknown error"


async def _post_json(
    client: httpx.AsyncClient,
    path: str,
    payload: dict,
    *,
    allow_error: bool = False,
) -> dict:
    resp = await client.post(path, json=payload)
    try:
        data = resp.json()
    except ValueError:
        data = {}
    status = _clean(data.get("status")).upper() if isinstance(data, dict) else ""
    code = data.get("code") if isinstance(data, dict) else None
    if (
        not allow_error
        and (
            resp.status_code >= 400
            or status in {"UNAUTHORIZED", "ERROR", "FAILED", "FAIL"}
            or code in {401, 403}
        )
    ):
        raise ValueError(f"{path} failed: {_api_message(data, resp)}")
    return data if isinstance(data, dict) else {}


def _campaigns_from_response(data: dict) -> list[dict]:
    campaigns = data.get("campaigns", [])
    if not isinstance(campaigns, list):
        nested = data.get("data", {}) if isinstance(data, dict) else {}
        if isinstance(nested, dict):
            campaigns = nested.get("campaigns", [])
    return [item for item in campaigns if isinstance(item, dict)]


async def _fetch_campaigns(client: httpx.AsyncClient, tenant: str) -> list[dict]:
    campaigns: list[dict] = []
    seen: set[str] = set()
    total = None
    page = 1
    while True:
        data = await _post_json(
            client,
            "/player/campaigns",
            {"tenant": tenant, "page": page},
        )
        page_items = _campaigns_from_response(data)
        for item in page_items:
            cid = _clean(item.get("id"))
            if cid and cid not in seen:
                seen.add(cid)
                campaigns.append(item)
        if total is None:
            try:
                total = int(data.get("total"))
            except (TypeError, ValueError):
                total = None
        if not page_items or (total is not None and len(campaigns) >= total):
            break
        page += 1
        if page > 100:
            break
    return campaigns


async def _active_programs(
    client: httpx.AsyncClient, tenant: str
) -> tuple[dict[str, str], dict[str, dict]]:
    data = await _post_json(client, "/player/events", {"tenant": tenant})
    blogs = data.get("data", {}).get("blogs", [])
    program_by_campaign: dict[str, str] = {}
    blog_by_campaign: dict[str, dict] = {}
    if not isinstance(blogs, list):
        return program_by_campaign, blog_by_campaign
    for blog in blogs:
        if not isinstance(blog, dict):
            continue
        campaign_id = _clean(blog.get("campaign"))
        if not campaign_id:
            continue
        blog_by_campaign[campaign_id] = blog
        program_id = _clean(blog.get("program_id"))
        if program_id:
            program_by_campaign[campaign_id] = program_id
    return program_by_campaign, blog_by_campaign


async def _fetch_blog(
    client: httpx.AsyncClient,
    tenant: str,
    campaign_id: str,
    program_id: str = "",
) -> dict:
    payload = {"tenant": tenant, "campaign": campaign_id}
    if _clean(program_id):
        payload["program"] = _clean(program_id)
    data = await _post_json(client, "/player/blog", payload)
    detail = data.get("data", {})
    return detail if isinstance(detail, dict) else {}


def _paragraph_questions(paragraphs: list, program_id: str = "") -> list[dict]:
    questions: list[dict] = []
    if not isinstance(paragraphs, list):
        return questions
    for item in paragraphs:
        if not isinstance(item, dict):
            continue
        if _clean(item.get("ptype")).upper() != "QUESTION":
            continue
        paragraph_id = _clean(item.get("id"))
        question = _clean(item.get("content"))
        if not paragraph_id or not question:
            continue
        answered_correctly = False
        accuracy = item.get("answer_accuracy")
        if isinstance(accuracy, (int, float)) and not isinstance(accuracy, bool):
            answered_correctly = accuracy > 0
        if item.get("correct") is True or item.get("all_correct") is True:
            answered_correctly = True
        questions.append({
            "flag_id": _encode_flag_id(paragraph_id, program_id),
            "identifier": paragraph_id,
            "question": question,
            "solved": answered_correctly,
        })
    return questions


def _encode_flag_id(paragraph_id: str, program_id: str = "") -> str:
    paragraph_id = _clean(paragraph_id)
    program_id = _clean(program_id)
    if program_id:
        return f"{paragraph_id}{FLAG_ID_PROGRAM_SEP}{program_id}"
    return paragraph_id


def _decode_flag_id(flag_id: str | int | None) -> tuple[str, str]:
    if flag_id in (None, ""):
        return "", ""
    text = str(flag_id).strip()
    if FLAG_ID_PROGRAM_SEP in text:
        paragraph_id, program_id = text.split(FLAG_ID_PROGRAM_SEP, 1)
        return _clean(paragraph_id), _clean(program_id)
    return _clean(text), ""


def _question_points(paragraphs: list) -> int:
    total = 0
    if not isinstance(paragraphs, list):
        return total
    for item in paragraphs:
        if not isinstance(item, dict):
            continue
        if _clean(item.get("ptype")).upper() != "QUESTION":
            continue
        points = item.get("points")
        if isinstance(points, (int, float)) and not isinstance(points, bool):
            total += int(points)
    return total


def _link_filename(link: dict) -> str:
    for key in ("description", "title", "name"):
        value = _clean(link.get(key))
        if value and value.lower() != "web link":
            return value.rsplit("/", 1)[-1]
    url = _clean(link.get("link"))
    path = urlparse(url).path
    name = path.rsplit("/", 1)[-1]
    return unquote_plus(name) or "download"


def _looks_like_file(url: str, name: str = "") -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if "cympire-files" in parsed.netloc.lower():
        return True
    for ext in FILE_EXTENSIONS:
        if path.endswith(ext) or name.lower().endswith(ext):
            return True
    return False


def _files_from_arsenal(arsenal: dict) -> list[RemoteFile]:
    links = arsenal.get("links", []) if isinstance(arsenal, dict) else []
    files: list[RemoteFile] = []
    if not isinstance(links, list):
        return files
    seen: set[str] = set()
    for link in links:
        if not isinstance(link, dict):
            continue
        url = _clean(link.get("link"))
        if not url or not url.startswith(("http://", "https://")):
            continue
        name = _link_filename(link)
        if not _looks_like_file(url, name):
            continue
        if url in seen:
            continue
        seen.add(url)
        files.append(RemoteFile(name=name, url=url))
    return files


def _non_file_links(arsenal: dict) -> list[str]:
    links = arsenal.get("links", []) if isinstance(arsenal, dict) else []
    results: list[str] = []
    if not isinstance(links, list):
        return results
    for link in links:
        if not isinstance(link, dict):
            continue
        url = _clean(link.get("link"))
        if not url:
            continue
        name = _link_filename(link)
        if _looks_like_file(url, name):
            continue
        title = _clean(link.get("title")) or name or "Link"
        results.append(f"{title}: {url}")
    return results


def _cloud_credentials_from_arsenal(arsenal: dict) -> list[dict]:
    credentials = (
        arsenal.get("cloud_credentials", []) if isinstance(arsenal, dict) else []
    )
    remotes: list[dict] = []
    if not isinstance(credentials, list):
        return remotes
    for idx, item in enumerate(credentials, 1):
        entries = []
        if isinstance(item, dict):
            if all(isinstance(value, dict) for value in item.values()):
                entries = list(item.items())
            else:
                entries = [(f"Cloud {idx}", item)]
        for title, value in entries:
            if not isinstance(value, dict):
                continue
            title_text = _clean(title) or f"Cloud {idx}"
            url = _clean(value.get("link"))
            username = _clean(value.get("username"))
            password = _clean(value.get("password"))
            if not any((url, username, password)):
                continue
            parts = [title_text]
            if url:
                parts.append(f"url={url}")
            if username:
                parts.append(f"username={username}")
            if password:
                parts.append(f"password={password}")
            remote = {
                "type": "cywaria-cloud",
                "connection": ", ".join(parts),
            }
            if url:
                remote["url"] = url
            remotes.append(remote)
    return remotes


def _remote_from_vm(vm: dict) -> dict | None:
    ip_address = _clean(vm.get("ip_address"))
    url = _clean(vm.get("url"))
    hostname = _clean(vm.get("hostname")) or _clean(vm.get("name"))
    username = _clean(vm.get("username"))
    password = _clean(vm.get("password"))
    port = _clean_port(vm.get("port"))

    if not url and not ip_address:
        return None

    remote: dict = {"type": "cywaria"}
    connection_parts = []
    if hostname:
        connection_parts.append(hostname)
    if url:
        remote["url"] = url
        connection_parts.append(f"url={url}")
    if ip_address:
        remote["host"] = ip_address
        connection_parts.append(f"host={ip_address}")
    if port is not None:
        remote["port"] = port
        connection_parts.append(f"port={port}")
    if username:
        connection_parts.append(f"username={username}")
    if password:
        connection_parts.append(f"password={password}")
    if connection_parts:
        remote["connection"] = ", ".join(connection_parts)
    return remote


def _environment_running(detail: dict) -> bool:
    environment = detail.get("environment", {}) if isinstance(detail, dict) else {}
    if not isinstance(environment, dict):
        return False
    return _clean(environment.get("status")).upper() == "RUNNING"


def _instance_info_from_blog(detail: dict) -> dict | None:
    if not isinstance(detail, dict):
        return None
    arsenal = detail.get("arsenal", {})
    if not isinstance(arsenal, dict):
        return None
    remotes = []
    vms = arsenal.get("vms", [])
    if isinstance(vms, list):
        for vm in vms:
            if not isinstance(vm, dict):
                continue
            remote = _remote_from_vm(vm)
            if remote:
                remotes.append(remote)
    links = _non_file_links(arsenal)
    for link in links:
        remotes.append({
            "type": "cywaria",
            "url": link.split(": ", 1)[-1],
            "connection": link,
        })
    remotes.extend(_cloud_credentials_from_arsenal(arsenal))
    if not remotes:
        return None
    result = dict(remotes[0])
    result["remotes"] = remotes
    result["type"] = "cywaria"
    return result


def _description(campaign: dict, detail: dict, questions: list[dict]) -> str:
    parts: list[str] = []
    brief = _clean(detail.get("brief_summary")) or _clean(
        campaign.get("brief_summary")
    )
    if brief:
        parts.append(brief)
    category = _clean(detail.get("description")) or _clean(
        campaign.get("description")
    )
    body = _clean(detail.get("content")) or _clean(campaign.get("content"))
    if body and body != category and body not in parts:
        parts.append(body)
    if questions:
        parts.append(
            "Questions:\n"
            + "\n".join(f"- {question['question']}" for question in questions)
        )
    instance_info = _instance_info_from_blog(detail)
    if instance_info:
        remote_lines = []
        for remote in instance_info.get("remotes", []):
            connection = _clean(remote.get("connection"))
            if connection:
                remote_lines.append(f"- {connection}")
        if remote_lines:
            parts.append("Current Arsenal connection info:\n" + "\n".join(remote_lines))
    return "\n\n".join(parts)


def _tags(campaign: dict, detail: dict) -> list[str]:
    tags: list[str] = []
    for key in ("ctype", "difficulty", "complexity"):
        value = _clean(campaign.get(key)) or _clean(detail.get(key))
        if value:
            tags.append(f"{key}:{value}" if key != "ctype" else value)
    if campaign.get("completed"):
        tags.append("completed")
    if campaign.get("all_correct"):
        tags.append("solved")
    arsenal = detail.get("arsenal", {}) if isinstance(detail, dict) else {}
    vms = arsenal.get("vms", []) if isinstance(arsenal, dict) else []
    cloud_credentials = (
        arsenal.get("cloud_credentials", []) if isinstance(arsenal, dict) else []
    )
    if _environment_running(detail) or (isinstance(vms, list) and vms):
        tags.append("machine")
    if isinstance(cloud_credentials, list) and cloud_credentials:
        tags.append("cloud")
    if _environment_running(detail):
        tags.append("running")
    deduped: list[str] = []
    for tag in tags:
        if tag and tag not in deduped:
            deduped.append(tag)
    return deduped


def _is_correct_submit(data: dict) -> bool:
    candidates = []
    if isinstance(data, dict):
        candidates.append(data)
        inner = data.get("data")
        if isinstance(inner, dict):
            candidates.append(inner)
    for item in candidates:
        for key in ("correct", "is_correct", "all_correct", "success"):
            value = item.get(key)
            if isinstance(value, bool):
                return value
        for key in ("answer_accuracy", "accuracy", "grade"):
            value = item.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return value > 0
    message = _submit_message(data).lower()
    if any(term in message for term in BAD_SUBMIT_TERMS):
        return False
    return any(term in message for term in GOOD_SUBMIT_TERMS)


def _submit_message(data: dict) -> str:
    values = []
    if isinstance(data, dict):
        for key in ("message", "status", "answer_feedback"):
            value = _clean(data.get(key))
            if value:
                values.append(value)
        inner = data.get("data")
        if isinstance(inner, dict):
            for key in ("message", "status", "answer_feedback"):
                value = _clean(inner.get(key))
                if value:
                    values.append(value)
    return " ".join(values) or "No submission message returned"


def _paragraph_submit_result(
    detail: dict, paragraph_id: str, submitted_answer: str = ""
) -> SubmitResult | None:
    paragraphs = detail.get("paragraphs", []) if isinstance(detail, dict) else []
    if not isinstance(paragraphs, list):
        return None
    submitted_answer = _clean(submitted_answer)
    for item in paragraphs:
        if not isinstance(item, dict):
            continue
        if _clean(item.get("id")) != paragraph_id:
            continue
        user_answer = _clean(item.get("user_answer"))
        if submitted_answer and user_answer and user_answer != submitted_answer:
            return None
        feedback = _clean(item.get("answer_feedback"))
        accuracy = item.get("answer_accuracy")
        if isinstance(accuracy, (int, float)) and not isinstance(accuracy, bool):
            correct = accuracy > 0
            message = feedback or ("Correct" if correct else "Incorrect")
            return SubmitResult(correct=correct, message=message)
        if item.get("correct") is True or item.get("all_correct") is True:
            return SubmitResult(correct=True, message=feedback or "Correct")
        if feedback:
            return SubmitResult(
                correct=not any(
                    term in feedback.lower() for term in BAD_SUBMIT_TERMS
                ),
                message=feedback,
            )
    return None


def _exam_ready_to_submit(detail: dict) -> bool:
    if not isinstance(detail, dict) or not bool(detail.get("submit_exam")):
        return False
    paragraphs = detail.get("paragraphs", [])
    if not isinstance(paragraphs, list):
        return False
    questions = [
        item
        for item in paragraphs
        if isinstance(item, dict) and "QUESTION" in _clean(item.get("ptype")).upper()
    ]
    return bool(questions) and all(_clean(item.get("user_answer")) for item in questions)


async def _submit_exam_if_ready(
    client: httpx.AsyncClient, tenant: str, campaign_id: str, detail: dict
) -> str:
    if not _exam_ready_to_submit(detail):
        return ""
    data = await _post_json(
        client,
        "/player/exam/submit",
        {"tenant": tenant, "campaign": campaign_id},
        allow_error=True,
    )
    status = _clean(data.get("status")).upper()
    code = data.get("code")
    if status in {"UNAUTHORIZED", "ERROR", "FAILED", "FAIL"} or code in {401, 403}:
        return f"Final submit failed: {_api_message(data)}"
    return "Final exam submitted"


class CywariaPlugin(CTFPlatformPlugin):
    name = "cywaria"
    label = "Cywaria"

    def source_url(self, config: dict) -> str:
        return _normal_url(config)

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="url",
                label="Platform URL",
                field_type="url",
                placeholder=DEFAULT_URL,
                default=DEFAULT_URL,
            ),
            ConfigField(
                name="username",
                label="Username",
                field_type="text",
                placeholder="Cywaria username",
            ),
            ConfigField(
                name="password",
                label="Password",
                field_type="password",
                placeholder="Cywaria password",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        tenant, _, _ = _tenant_api_url(config)
        async with await _client(config) as client:
            user_data = await _post_json(client, "/user/details", {"tenant": tenant})
            campaigns = await _post_json(
                client,
                "/player/campaigns",
                {"tenant": tenant, "page": 1},
            )
        user = user_data.get("data", {}) if isinstance(user_data, dict) else {}
        name = "unknown user"
        if isinstance(user, dict):
            full_name = " ".join(
                part
                for part in (
                    _clean(user.get("first_name")),
                    _clean(user.get("last_name")),
                )
                if part
            )
            name = full_name or _clean(user.get("email")) or name
        total = campaigns.get("total")
        if total is None:
            total = len(_campaigns_from_response(campaigns))
        return f"Logged in as {name}; {total} campaign(s) visible"

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        tenant, _, _ = _tenant_api_url(config)
        async with await _client(config) as client:
            program_by_campaign, blog_by_campaign = await _active_programs(
                client, tenant
            )
            campaigns = await _fetch_campaigns(client, tenant)
            results: list[RemoteChallenge] = []
            for campaign in campaigns:
                campaign_id = _clean(campaign.get("id"))
                if not campaign_id:
                    continue
                program_id = program_by_campaign.get(campaign_id, "")
                try:
                    detail = await _fetch_blog(
                        client, tenant, campaign_id, program_id
                    )
                except Exception:
                    detail = {}
                active_blog = blog_by_campaign.get(campaign_id, {})
                if not _clean(detail.get("name")) and isinstance(active_blog, dict):
                    detail["name"] = _clean(active_blog.get("name"))
                arsenal = detail.get("arsenal", {})
                if not isinstance(arsenal, dict):
                    arsenal = {}
                paragraphs = detail.get("paragraphs", [])
                questions = _paragraph_questions(paragraphs, program_id)
                points = _question_points(paragraphs)
                if not points:
                    grade = campaign.get("grade")
                    if isinstance(grade, (int, float)) and not isinstance(grade, bool):
                        points = int(grade)
                solved = bool(campaign.get("all_correct"))
                if questions and all(q.get("solved") for q in questions):
                    solved = True
                results.append(RemoteChallenge(
                    remote_id=campaign_id,
                    name=(
                        _clean(detail.get("name"))
                        or _clean(campaign.get("name"))
                        or f"Campaign {campaign_id}"
                    ),
                    description=_description(campaign, detail, questions),
                    category=(
                        _clean(detail.get("description"))
                        or _clean(campaign.get("description"))
                    ),
                    points=points,
                    files=_files_from_arsenal(arsenal),
                    solves=1 if solved else 0,
                    solved=solved,
                    tags=_tags(campaign, detail),
                    flag_questions=questions,
                ))
            return results

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None,
        progress_cb=None,
    ) -> bytes:
        _require_httpx()
        async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
            async with client.stream("GET", file.url) as resp:
                return await read_limited_response(resp, max_bytes, progress_cb)

    async def start_instance(
        self, config: dict, remote_id: str
    ) -> dict | None:
        tenant, _, _ = _tenant_api_url(config)
        start_errors: list[str] = []
        async with await _client(config) as client:
            program_by_campaign, _ = await _active_programs(client, tenant)
            program_id = program_by_campaign.get(str(remote_id), "")
            detail = await _fetch_blog(client, tenant, str(remote_id), program_id)
            instance_info = _instance_info_from_blog(detail)
            if instance_info and _environment_running(detail):
                return instance_info

            payload = {"tenant": tenant, "campaign": str(remote_id)}
            if program_id:
                payload["program"] = program_id

            start_requested = False
            for path in ("/player/event/create", "/player/blog/env/start"):
                data = await _post_json(client, path, payload, allow_error=True)
                status = _clean(data.get("status")).upper()
                code = data.get("code")
                if status in {"UNAUTHORIZED", "ERROR", "FAILED", "FAIL"} or code in {
                    401,
                    403,
                }:
                    start_errors.append(f"{path}: {_api_message(data)}")
                elif status in {"OK", "SUCCESS", ""} and code not in {400, 404, 500}:
                    start_requested = True

            if start_errors and not start_requested and not instance_info:
                raise ValueError(
                    "Cywaria did not allow starting this environment: "
                    + "; ".join(start_errors)
                )

            for _ in range(20):
                await asyncio.sleep(3)
                detail = await _fetch_blog(client, tenant, str(remote_id), program_id)
                instance_info = _instance_info_from_blog(detail)
                if instance_info and _environment_running(detail):
                    return instance_info

            if instance_info:
                return instance_info

        if start_errors:
            raise ValueError(
                "Cywaria did not allow starting this environment: "
                + "; ".join(start_errors)
            )
        return None

    async def stop_instance(
        self, config: dict, remote_id: str
    ) -> None:
        tenant, _, _ = _tenant_api_url(config)
        async with await _client(config) as client:
            payload = {"tenant": tenant, "campaign": str(remote_id)}
            await _post_json(
                client,
                "/player/blog/env/terminate",
                payload,
                allow_error=True,
            )

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str,
        flag_id: str | int | None = None,
    ) -> SubmitResult:
        tenant, _, _ = _tenant_api_url(config)
        paragraph_id, program_id = _decode_flag_id(flag_id)
        async with await _client(config) as client:
            if not paragraph_id:
                program_by_campaign, _ = await _active_programs(client, tenant)
                program_id = program_id or program_by_campaign.get(str(remote_id), "")
                detail = await _fetch_blog(
                    client, tenant, str(remote_id), program_id
                )
                questions = _paragraph_questions(
                    detail.get("paragraphs", []), program_id
                )
                unsolved = next(
                    (q for q in questions if not q.get("solved")),
                    questions[0] if questions else None,
                )
                if unsolved:
                    paragraph_id, parsed_program = _decode_flag_id(
                        unsolved.get("flag_id")
                    )
                    program_id = program_id or parsed_program
            if not paragraph_id:
                raise ValueError("Could not identify Cywaria question paragraph")

            payload = {
                "tenant": tenant,
                "campaign": str(remote_id),
                "paragraph": paragraph_id,
                "answer": flag,
            }
            if program_id:
                payload["program"] = program_id
            data = await _post_json(
                client,
                "/player/exam/answer/submit",
                payload,
                allow_error=True,
            )
            detail = await _fetch_blog(client, tenant, str(remote_id), program_id)
            paragraph_result = _paragraph_submit_result(detail, paragraph_id, flag)
            if paragraph_result:
                if paragraph_result.correct:
                    final_message = await _submit_exam_if_ready(
                        client, tenant, str(remote_id), detail
                    )
                    if final_message:
                        paragraph_result.message = (
                            f"{paragraph_result.message}; {final_message}"
                        )
                return paragraph_result
        correct = _is_correct_submit(data)
        return SubmitResult(
            correct=correct,
            message=_submit_message(data) or ("Correct" if correct else "Incorrect"),
        )
