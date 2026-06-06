from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import tomllib
from collections.abc import AsyncIterator
from pathlib import Path

from .base import AgentProvider

log = logging.getLogger("ctf-solver.codex")

CODEX_AUTH_FILE = Path.home() / ".codex" / "auth.json"
CODEX_CONFIG_FILE = Path.home() / ".codex" / "config.toml"
CODEX_MODELS_CACHE_FILE = Path.home() / ".codex" / "models_cache.json"
CODEX_SESSIONS_DIR = Path.home() / ".codex" / "sessions"
CODEX_USAGE_API = "https://chatgpt.com/backend-api/wham/usage"
REASONING_LEVEL_ORDER = ("minimal", "low", "medium", "high", "xhigh")
REASONING_LABELS = {
    "minimal": "Minimal",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "xhigh": "XHigh",
}
DEFAULT_COMMON_REASONING_LEVELS = {"low", "medium", "high", "xhigh"}


def _read_skill_name(skill_file: Path, fallback: str) -> str:
    try:
        lines = skill_file.read_text(errors="replace").splitlines()
    except OSError:
        return fallback
    if not lines or lines[0].strip() != "---":
        return fallback
    for line in lines[1:80]:
        stripped = line.strip()
        if stripped == "---":
            break
        if not stripped.startswith("name:"):
            continue
        name = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        return name or fallback
    return fallback


def _workspace_skill_inputs(cwd: str | Path) -> list[dict]:
    """Return Codex structured skill inputs selected for this run workspace."""
    skills_dir = Path(cwd) / ".codex" / "skills"
    if not skills_dir.is_dir():
        return []

    inputs = []
    try:
        children = sorted(skills_dir.iterdir(), key=lambda path: path.name.lower())
    except OSError:
        return []

    seen: set[str] = set()
    for child in children:
        skill_file = child / "SKILL.md"
        if not skill_file.is_file():
            continue
        name = _read_skill_name(skill_file, child.name)
        if name in seen:
            continue
        seen.add(name)
        inputs.append({
            "type": "skill",
            "name": name,
            "path": str(skill_file),
        })
    return inputs


def _skill_inputs_from_list_result(result: object) -> list[dict]:
    if not isinstance(result, dict):
        return []
    inputs: list[dict] = []
    seen: set[str] = set()
    for entry in result.get("data", []):
        if not isinstance(entry, dict):
            continue
        errors = entry.get("errors", [])
        if isinstance(errors, list):
            for error in errors:
                if isinstance(error, dict):
                    log.warning(
                        "Codex skill load error for %s: %s",
                        error.get("path", "unknown"),
                        error.get("message", error),
                    )
        for skill in entry.get("skills", []):
            if not isinstance(skill, dict):
                continue
            if skill.get("scope") != "repo" or not skill.get("enabled", False):
                continue
            name = skill.get("name")
            path = skill.get("path")
            if not isinstance(name, str) or not isinstance(path, str):
                continue
            if not name or not path or name in seen:
                continue
            seen.add(name)
            inputs.append({
                "type": "skill",
                "name": name,
                "path": path,
            })
    return inputs


def _normalize_skill_mentions(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    mentions: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = str(item).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        mentions.append(name)
    return mentions


def _skill_mention_tokens(
    skill_inputs: list[dict],
    requested_mentions: list[str],
) -> list[str]:
    if not requested_mentions:
        return []
    available = {
        item.get("name")
        for item in skill_inputs
        if isinstance(item.get("name"), str)
    }
    mentions: list[str] = []
    for name in requested_mentions:
        if name in available:
            mentions.append(f"${name}")
    return mentions


def _text_elements_for_skill_mentions(
    text: str,
    mention_tokens: list[str],
) -> list[dict]:
    elements: list[dict] = []
    search_start = 0
    for token in mention_tokens:
        idx = text.find(token, search_start)
        if idx < 0:
            idx = text.find(token)
        if idx < 0:
            continue
        start = len(text[:idx].encode("utf-8"))
        end = start + len(token.encode("utf-8"))
        elements.append({
            "byteRange": {"start": start, "end": end},
            "placeholder": token,
        })
        search_start = idx + len(token)
    return elements


def _model_reasoning_map() -> dict[str, set[str]]:
    if not CODEX_MODELS_CACHE_FILE.exists():
        return {}
    try:
        cache = json.loads(CODEX_MODELS_CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    mapping: dict[str, set[str]] = {}
    for entry in cache.get("models", []):
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug")
        if not isinstance(slug, str) or not slug:
            continue
        levels: set[str] = set()
        for raw in entry.get("supported_reasoning_levels", []) or []:
            effort = ""
            if isinstance(raw, dict):
                value = raw.get("effort")
                if isinstance(value, str):
                    effort = value
            elif isinstance(raw, str):
                effort = raw
            effort = effort.strip().lower()
            if effort in REASONING_LEVEL_ORDER:
                levels.add(effort)
        if levels:
            mapping[slug] = levels
    return mapping


def _common_supported_efforts(
    mapping: dict[str, set[str]] | None = None,
) -> set[str]:
    if mapping is None:
        mapping = _model_reasoning_map()
    if not mapping:
        return set(DEFAULT_COMMON_REASONING_LEVELS)
    values = list(mapping.values())
    common = set(values[0])
    for levels in values[1:]:
        common &= levels
    return common or set(DEFAULT_COMMON_REASONING_LEVELS)


def _resolve_effort(model: str, effort: str) -> str:
    effort = (effort or "").strip().lower()
    if effort not in REASONING_LEVEL_ORDER:
        return ""
    mapping = _model_reasoning_map()
    common = _common_supported_efforts(mapping)

    model = (model or "").strip()
    if model:
        supported = mapping.get(model)
        if supported:
            return effort if effort in supported else ""
        return effort if effort in common else ""

    return effort if effort in common else ""


def _discover_effort_levels() -> tuple[tuple[str, str], ...]:
    allowed = set()
    for levels in _model_reasoning_map().values():
        allowed |= levels
    if not allowed:
        allowed = set(DEFAULT_COMMON_REASONING_LEVELS)

    options: list[tuple[str, str]] = [("", "Provider default")]
    for level in REASONING_LEVEL_ORDER:
        if level in allowed:
            options.append((level, REASONING_LABELS[level]))
    return tuple(options)


def _item_text(item: dict) -> str:
    text = item.get("text")
    if isinstance(text, str) and text:
        return text

    content = item.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            value = block.get("text") or block.get("content")
            if isinstance(value, str) and value:
                parts.append(value)
        if parts:
            return "".join(parts)

    value = item.get("message")
    if isinstance(value, str):
        return value
    return ""


def _item_call_id(item: dict) -> str:
    for key in ("call_id", "tool_call_id", "id"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _item_tool_name(item: dict) -> str:
    for key in ("name", "tool", "tool_name"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    invocation = item.get("invocation", {})
    if isinstance(invocation, dict):
        value = invocation.get("tool")
        if isinstance(value, str) and value:
            return value
    return "tool"


def _item_tool_input(item: dict) -> dict:
    for key in ("input", "arguments"):
        value = item.get(key)
        if isinstance(value, dict):
            return value
    invocation = item.get("invocation", {})
    if isinstance(invocation, dict):
        value = invocation.get("arguments")
        if isinstance(value, dict):
            return value
    return {}


def _item_tool_result(item: dict) -> tuple[object, bool]:
    if "error" in item:
        return item.get("error"), True
    if "result" in item:
        return item.get("result"), False
    if "output" in item:
        return item.get("output"), False
    status = item.get("status")
    if isinstance(status, str) and status not in {"completed", "ok"}:
        return item, True
    return item, False


def _is_tool_item(item: dict) -> bool:
    item_type = item.get("type")
    if isinstance(item_type, str) and item_type in {
        "tool_call",
        "function_call",
        "custom_tool_call",
        "exec_command",
        "mcp_tool_call",
        "patch_apply",
        "web_search",
    }:
        return True
    return bool(_item_call_id(item) and _item_tool_name(item) != "tool")


def _build_command(
    challenge: dict, prompt: str, is_continue: bool
) -> list[str]:
    model = challenge.get("model", "")
    effort = _resolve_effort(model, challenge.get("effort", ""))

    if is_continue:
        cmd = [
            "codex",
            "exec",
            "resume",
        ]
        if challenge.get("_codex_thread_id"):
            cmd.append(challenge["_codex_thread_id"])
        else:
            cmd.append("--last")
        cmd.extend([
            "--json",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
        ])
        if model:
            cmd.extend(["--model", model])
        if effort:
            cmd.extend(["-c", f'model_reasoning_effort="{effort}"'])
        cmd.append(prompt)
        return cmd

    cmd = [
        "codex",
        "exec",
        "--json",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "--cd",
        ".",
    ]
    if model:
        cmd.extend(["--model", model])
    if effort:
        cmd.extend(["-c", f'model_reasoning_effort="{effort}"'])
    cmd.append(prompt)
    return cmd


def _configured_model() -> str:
    if not CODEX_CONFIG_FILE.exists():
        return ""
    try:
        config = tomllib.loads(CODEX_CONFIG_FILE.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    value = config.get("model")
    return value if isinstance(value, str) else ""


def _discover_models() -> tuple[tuple[str, str], ...]:
    models: list[tuple[str, str]] = [("", "Provider default")]
    seen = {""}

    configured = _configured_model()
    if configured:
        seen.add(configured)
        models.append((configured, configured))

    if CODEX_MODELS_CACHE_FILE.exists():
        try:
            cache = json.loads(CODEX_MODELS_CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            cache = {}

        for entry in cache.get("models", []):
            if not isinstance(entry, dict):
                continue
            if entry.get("visibility") not in {None, "list"}:
                continue
            slug = entry.get("slug")
            if isinstance(slug, str) and slug and slug not in seen:
                seen.add(slug)
                label = entry.get("display_name")
                models.append((
                    slug,
                    label if isinstance(label, str) and label else slug,
                ))

    if len(models) <= 1:
        for slug in (
            "gpt-5.5", "gpt-5.4", "gpt-5.4-mini",
            "gpt-5.3-codex", "gpt-5.3-codex-spark",
            "gpt-5.2",
        ):
            if slug not in seen:
                seen.add(slug)
                models.append((slug, slug))

    return tuple(models)


def _normalize_saved_events(events: list[dict]) -> list[dict]:
    return events


def _get_event_type(event: dict) -> tuple[str | None, dict]:
    if isinstance(event.get("msg"), dict):
        msg = event["msg"]
        return msg.get("type"), msg
    payload = event.get("payload")
    if isinstance(payload, dict):
        if isinstance(payload.get("msg"), dict):
            msg = payload["msg"]
            return msg.get("type"), msg
        event_type = payload.get("type")
        if isinstance(event_type, str):
            return event_type, payload
    return event.get("type"), event


def _tool_name(event_type: str, payload: dict) -> str:
    if event_type.startswith("mcp_tool_call_"):
        invocation = payload.get("invocation", {})
        return invocation.get("tool", "mcp_tool")
    if event_type.startswith("exec_command_"):
        return "exec"
    if event_type.startswith("web_search_"):
        return "web_search"
    if event_type.startswith("patch_apply_"):
        return "patch"
    return event_type


def _decode_exec_chunk(payload: dict) -> str:
    chunk = payload.get("chunk")
    if not chunk:
        return ""
    try:
        return base64.b64decode(chunk).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _usage_number(usage: dict, *keys: str) -> int:
    for key in keys:
        value = usage.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
    return 0


def _normalize_token_usage(usage: dict | None) -> dict | None:
    if not isinstance(usage, dict):
        return None

    input_details = (
        usage.get("input_token_details")
        or usage.get("inputTokenDetails")
        or {}
    )
    if not isinstance(input_details, dict):
        input_details = {}

    normalized = {
        "input_tokens": _usage_number(
            usage, "input_tokens", "inputTokens",
            "prompt_tokens", "promptTokens",
        ),
        "output_tokens": _usage_number(
            usage, "output_tokens", "outputTokens",
            "completion_tokens", "completionTokens",
        ),
        "cached_input_tokens": _usage_number(
            usage, "cached_input_tokens", "cachedInputTokens",
            "cache_read_input_tokens", "cacheReadInputTokens",
        ) or _usage_number(
            input_details, "cached_tokens", "cachedTokens"
        ),
        "reasoning_output_tokens": _usage_number(
            usage, "reasoning_output_tokens", "reasoningOutputTokens",
        ),
        "total_tokens": _usage_number(
            usage, "total_tokens", "totalTokens",
        ),
    }
    if not any(normalized.values()):
        return None
    return normalized


def _extract_token_usage(*containers: dict) -> dict | None:
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in ("token_usage", "tokenUsage"):
            token_usage = container.get(key)
            if not isinstance(token_usage, dict):
                continue
            for nested_key in (
                "total",
                "total_token_usage",
                "totalTokenUsage",
                "last",
                "last_token_usage",
                "lastTokenUsage",
            ):
                normalized = _normalize_token_usage(
                    token_usage.get(nested_key)
                )
                if normalized:
                    return normalized
            normalized = _normalize_token_usage(token_usage)
            if normalized:
                return normalized
        for key in (
            "usage",
            "token_usage",
            "tokenUsage",
            "last_token_usage",
            "lastTokenUsage",
            "total_token_usage",
            "totalTokenUsage",
        ):
            normalized = _normalize_token_usage(container.get(key))
            if normalized:
                return normalized
        normalized = _normalize_token_usage(container)
        if normalized:
            return normalized
    return None


def _codex_session_path(thread_id: str) -> Path | None:
    thread_id = (thread_id or "").strip()
    if not thread_id or not CODEX_SESSIONS_DIR.is_dir():
        return None
    matches = [
        path for path in CODEX_SESSIONS_DIR.rglob(f"*{thread_id}.jsonl")
        if path.is_file()
    ]
    if not matches:
        return None
    return max(matches, key=lambda path: path.stat().st_mtime)


def get_thread_token_usage(thread_id: str) -> dict | None:
    """Return the latest persisted token totals for a Codex thread."""
    path = _codex_session_path(thread_id)
    if not path:
        return None

    latest: dict | None = None
    try:
        with path.open(errors="replace") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    continue
                if payload.get("type") != "token_count":
                    continue
                info = payload.get("info")
                if not isinstance(info, dict):
                    continue
                total = _normalize_token_usage(info.get("total_token_usage"))
                if total:
                    latest = total
    except OSError:
        return None
    return latest


def _normalize_live_event(event: dict, challenge: dict) -> dict | None:
    event_type, payload = _get_event_type(event)
    if not event_type:
        return None

    tool_output = challenge.setdefault("_codex_tool_output", {})

    if event_type == "token_count":
        info = payload.get("info")
        if isinstance(info, dict):
            usage = _normalize_token_usage(info.get("last_token_usage"))
            if usage:
                return {"type": "codex_usage", "usage": usage}
        return None

    if event_type in {"agent_reasoning", "agent_reasoning_delta"}:
        text = payload.get("text") or payload.get("content", "")
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "thinking",
                "thinking": text,
            }]},
        }

    if event_type in {"agent_message", "agent_message_delta"}:
        text = payload.get("message") or payload.get("content", "")
        if not text:
            return None
        challenge["_codex_last_text"] = text
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "text",
                "text": text,
            }]},
        }

    if event_type in {
        "exec_command_begin",
        "mcp_tool_call_begin",
        "patch_apply_begin",
        "web_search_begin",
    }:
        call_id = payload.get("call_id", "")
        if not call_id:
            # Generate and track a fallback ID
            counter = challenge.setdefault("_codex_call_counter", 0)
            challenge["_codex_call_counter"] = counter + 1
            call_id = f"codex-tool-{counter}"
            # Store as "last anonymous call" so _end/_delta can find it
            challenge["_codex_anon_call_id"] = call_id

        if event_type == "exec_command_begin":
            input_data = {
                "command": payload.get("command", []),
                "cwd": payload.get("cwd", ""),
                "parsed_cmd": payload.get("parsed_cmd"),
            }
        elif event_type == "mcp_tool_call_begin":
            invocation = payload.get("invocation", {})
            input_data = {
                "server": invocation.get("server", ""),
                "arguments": invocation.get("arguments", {}),
            }
        elif event_type == "patch_apply_begin":
            input_data = {
                "auto_approved": payload.get("auto_approved", False),
                "changes": payload.get("changes", {}),
            }
        else:
            input_data = {}

        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "id": call_id,
                "name": _tool_name(event_type, payload),
                "input": input_data,
            }]},
        }

    if event_type == "exec_command_output_delta":
        call_id = payload.get("call_id", "") or challenge.get("_codex_anon_call_id", "")
        if not call_id:
            return None
        chunk = _decode_exec_chunk(payload)
        if not chunk:
            return None
        stream_name = payload.get("stream", "stdout")
        bucket = tool_output.setdefault(call_id, {"stdout": "", "stderr": ""})
        bucket[stream_name] = bucket.get(stream_name, "") + chunk
        return None

    if event_type in {
        "exec_command_end",
        "mcp_tool_call_end",
        "patch_apply_end",
        "web_search_end",
    }:
        call_id = payload.get("call_id", "") or challenge.get("_codex_anon_call_id", "")
        if not call_id:
            return None
        # Clear the anonymous call ID after the end event
        challenge.pop("_codex_anon_call_id", None)

        buffered = tool_output.pop(call_id, {"stdout": "", "stderr": ""})
        if event_type == "exec_command_end":
            result = {
                "status": payload.get("status"),
                "stdout": payload.get("stdout") or buffered.get("stdout", ""),
                "stderr": payload.get("stderr") or buffered.get("stderr", ""),
                "aggregated_output": payload.get("aggregated_output", ""),
                "exit_code": payload.get("exit_code"),
            }
            is_error = payload.get("status") != "completed"
            if payload.get("exit_code") not in (None, 0):
                is_error = True
        elif event_type == "mcp_tool_call_end":
            result = payload.get("result", {})
            if "Ok" in result:
                result = result["Ok"]
                is_error = False
            elif "Err" in result:
                result = {"error": result["Err"]}
                is_error = True
            else:
                is_error = False
        elif event_type == "patch_apply_end":
            result = {
                "status": payload.get("status"),
                "stdout": payload.get("stdout", ""),
                "stderr": payload.get("stderr", ""),
            }
            is_error = payload.get("status") != "completed"
        else:
            result = payload
            is_error = False

        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": call_id,
                "content": json.dumps(result, indent=2, default=str),
                "is_error": is_error,
            }]},
        }

    if event_type in {
        "exec_approval_request",
        "apply_patch_approval_request",
    }:
        return {
            "type": "system",
            "message": (
                "Codex requested an approval despite running in bypass mode."
            ),
        }

    if event_type in {"turn_complete", "turn.completed", "task_complete"}:
        text = payload.get("last_agent_message")
        if text and text != challenge.get("_codex_last_text"):
            challenge["_codex_last_text"] = text
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "text",
                    "text": text,
                }]},
            }
        return None

    if event_type == "turn.failed":
        error = payload.get("error", {})
        message = ""
        if isinstance(error, dict):
            message = error.get("message", "")
        return {
            "type": "error",
            "message": message or "Codex turn failed",
        }

    if event_type == "thread.started":
        thread_id = payload.get("thread_id")
        if thread_id:
            challenge["_codex_thread_id"] = thread_id
        return None

    if event_type == "item.completed":
        item = payload.get("item", {})
        item_type = item.get("type")
        if _is_tool_item(item):
            call_id = _item_call_id(item) or challenge.pop("_codex_anon_item_id", "")
            if not call_id:
                return None
            result, is_error = _item_tool_result(item)
            return {
                "type": "user",
                "message": {"content": [{
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": json.dumps(result, indent=2, default=str),
                    "is_error": is_error,
                }]},
            }
        if item_type in {"agent_message", "assistant_message"} or (
            item_type == "message"
            and item.get("role") == "assistant"
        ):
            text = _item_text(item)
            if not text or text == challenge.get("_codex_last_text"):
                return None
            challenge["_codex_last_text"] = text
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "text",
                    "text": text,
                }]},
            }
        if item_type in {"reasoning", "reasoning_text"}:
            text = _item_text(item)
            if not text:
                return None
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "thinking",
                    "thinking": text,
                }]},
            }
        if item_type == "error":
            return {
                "type": "error",
                "message": item.get("message", "Codex item error"),
            }
        return None

    if event_type in {
        "thread.updated",
        "task_started",
        "turn_started",
        "stream_info",
    }:
        return None

    if event_type == "item.started":
        item = payload.get("item", {})
        if not _is_tool_item(item):
            return None
        call_id = _item_call_id(item)
        if not call_id:
            counter = challenge.setdefault("_codex_call_counter", 0)
            challenge["_codex_call_counter"] = counter + 1
            call_id = f"codex-item-{counter}"
            challenge["_codex_anon_item_id"] = call_id
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "id": call_id,
                "name": _item_tool_name(item),
                "input": _item_tool_input(item),
            }]},
        }

    if event_type == "stream_error":
        return {
            "type": "error",
            "message": payload.get("message", "Codex stream error"),
        }

    return event


def _detect_auth_method(value: object) -> str | None:
    if isinstance(value, dict):
        keys = {str(k).lower() for k in value}
        if {"access_token", "refresh_token"} & keys:
            return "ChatGPT"
        if {"api_key", "openai_api_key"} & keys:
            return "API key"
        for nested in value.values():
            detected = _detect_auth_method(nested)
            if detected:
                return detected
    elif isinstance(value, list):
        for nested in value:
            detected = _detect_auth_method(nested)
            if detected:
                return detected
    return None


def _get_session_count() -> int:
    if not CODEX_SESSIONS_DIR.is_dir():
        return 0
    return sum(
        1
        for path in CODEX_SESSIONS_DIR.rglob("rollout-*.jsonl")
        if path.is_file()
    )


def _get_codex_token() -> str | None:
    if not CODEX_AUTH_FILE.exists():
        return None
    try:
        auth = json.loads(CODEX_AUTH_FILE.read_text())
        return auth.get("tokens", {}).get("access_token")
    except (json.JSONDecodeError, OSError):
        return None


def _fetch_codex_usage() -> dict | None:
    import requests

    token = _get_codex_token()
    if not token:
        return None
    try:
        resp = requests.get(
            CODEX_USAGE_API,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        log.debug("Failed to fetch Codex usage API", exc_info=True)
    return None


def _format_reset_seconds(secs: int | None) -> str:
    if not secs or secs <= 0:
        return "now"
    hours, remainder = divmod(secs, 3600)
    minutes = remainder // 60
    if hours > 24:
        days = hours // 24
        hours = hours % 24
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _get_usage_data() -> dict | None:
    if not CODEX_AUTH_FILE.exists():
        return None

    auth_method = "Configured"
    try:
        auth_file = json.loads(CODEX_AUTH_FILE.read_text())
        auth_method = _detect_auth_method(auth_file) or auth_method
    except (json.JSONDecodeError, OSError):
        pass

    data = {
        "auth_rows": [
            {"label": "Status", "value": "Configured"},
            {"label": "Method", "value": auth_method},
        ],
        "stat_rows": [],
        "daily_activity": [],
        "daily_activity_title": None,
    }

    usage = _fetch_codex_usage()
    if usage:
        if usage.get("email"):
            data["auth_rows"].insert(0, {
                "label": "Account",
                "value": usage["email"],
            })
        if usage.get("plan_type"):
            data["auth_rows"].append({
                "label": "Plan",
                "value": usage["plan_type"].title(),
            })

        rl = usage.get("rate_limit") or {}
        pw = rl.get("primary_window") or {}
        sw = rl.get("secondary_window") or {}

        if "used_percent" in pw:
            reset = _format_reset_seconds(pw.get("reset_after_seconds"))
            label = "5h usage"
            if reset:
                label += f" (resets in {reset})"
            data["stat_rows"].append({
                "label": label,
                "value": f"{pw['used_percent']}%",
                "bar": pw["used_percent"],
            })
        if "used_percent" in sw:
            reset = _format_reset_seconds(sw.get("reset_after_seconds"))
            label = "Weekly usage"
            if reset:
                label += f" (resets in {reset})"
            data["stat_rows"].append({
                "label": label,
                "value": f"{sw['used_percent']}%",
                "bar": sw["used_percent"],
            })

        for extra in usage.get("additional_rate_limits") or []:
            name = extra.get("limit_name", "")
            erl = extra.get("rate_limit") or {}
            epw = erl.get("primary_window") or {}
            esw = erl.get("secondary_window") or {}
            if "used_percent" in epw and name:
                reset = _format_reset_seconds(
                    epw.get("reset_after_seconds")
                )
                label = f"{name} 5h"
                if reset:
                    label += f" (resets in {reset})"
                data["stat_rows"].append({
                    "label": label,
                    "value": f"{epw['used_percent']}%",
                    "bar": epw["used_percent"],
                })

        credits_info = usage.get("credits") or {}
        if credits_info.get("has_credits"):
            data["stat_rows"].append({
                "label": "Credits",
                "value": f"${credits_info.get('balance', '0')}",
            })

    data["stat_rows"].append({
        "label": "Sessions",
        "value": str(_get_session_count()),
    })

    return data


# ---------------------------------------------------------------------------
# SDK-based agent runner via codex app-server JSON-RPC over stdio
# ---------------------------------------------------------------------------

# Server request methods that require approval responses
_APPROVAL_METHODS = {
    # v2 approval requests
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/permissions/requestApproval",
    # v1 legacy approval requests
    "execCommandApproval",
    "applyPatchApproval",
}

# Methods with v2-style decision responses
_V2_DECISION_METHODS = {
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
}

# Methods with v1-style decision responses
_V1_DECISION_METHODS = {
    "execCommandApproval",
    "applyPatchApproval",
}


def _json_text(value: object) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, indent=2, default=str)
    except TypeError:
        return str(value)


def _content_items_text(items: object) -> str:
    if not isinstance(items, list):
        return ""
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        text = item.get("text") or item.get("content")
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts)


def _decode_base64_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _stream_buffer_text(streams: dict | None) -> str:
    if not isinstance(streams, dict):
        return ""
    stdout = streams.get("stdout", "")
    stderr = streams.get("stderr", "")
    if stdout and stderr:
        return f"{stdout}\n{stderr}"
    return stdout or stderr or ""


def _append_stream_buffer(
    buffers: dict[str, dict[str, str]],
    key: str,
    stream: object,
    text: str,
) -> None:
    if not key or not text:
        return
    stream_name = stream if isinstance(stream, str) and stream else "stdout"
    bucket = buffers.setdefault(key, {"stdout": "", "stderr": ""})
    bucket[stream_name] = bucket.get(stream_name, "") + text


def _format_patch_changes(changes: object) -> str:
    if not isinstance(changes, list):
        return ""
    diffs = []
    fallback = []
    for change in changes:
        if not isinstance(change, dict):
            continue
        diff = change.get("diff")
        if isinstance(diff, str) and diff:
            diffs.append(diff)
            continue
        path = change.get("path")
        kind = change.get("kind")
        if isinstance(kind, dict):
            kind = kind.get("type")
        if path:
            fallback.append(f"{path} ({kind or 'changed'})")
    return "\n".join(diffs or fallback)


def _format_plan_update(params: dict) -> str:
    explanation = params.get("explanation")
    plan = params.get("plan")
    lines: list[str] = []
    if isinstance(explanation, str) and explanation.strip():
        lines.append(explanation.strip())
    if isinstance(plan, list):
        for step in plan:
            if not isinstance(step, dict):
                continue
            text = step.get("step")
            if not isinstance(text, str) or not text:
                continue
            status = step.get("status") or "pending"
            lines.append(f"[{status}] {text}")
    return "\n".join(lines)


def _format_goal(goal: object) -> str:
    if not isinstance(goal, dict):
        return ""
    objective = goal.get("objective")
    status = goal.get("status")
    parts = []
    if isinstance(status, str) and status:
        parts.append(status)
    if isinstance(objective, str) and objective:
        parts.append(objective)
    token_budget = goal.get("tokenBudget")
    tokens_used = goal.get("tokensUsed")
    if isinstance(token_budget, (int, float)):
        parts.append(f"{int(tokens_used or 0)}/{int(token_budget)} tokens")
    elif isinstance(tokens_used, (int, float)) and tokens_used:
        parts.append(f"{int(tokens_used)} tokens")
    return " - ".join(parts)


def _normalize_goal(goal: object) -> dict | None:
    if not isinstance(goal, dict):
        return None

    def text_field(name: str, camel_name: str | None = None) -> str:
        value = goal.get(name)
        if value is None and camel_name:
            value = goal.get(camel_name)
        return value.strip() if isinstance(value, str) else ""

    def int_field(name: str, camel_name: str | None = None) -> int | None:
        value = goal.get(name)
        if value is None and camel_name:
            value = goal.get(camel_name)
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return int(value)
        return None

    normalized = {
        "provider": "codex",
        "thread_id": text_field("thread_id", "threadId"),
        "objective": text_field("objective"),
        "status": text_field("status"),
        "token_budget": int_field("token_budget", "tokenBudget"),
        "tokens_used": int_field("tokens_used", "tokensUsed"),
        "time_used_seconds": int_field("time_used_seconds", "timeUsedSeconds"),
        "created_at": int_field("created_at", "createdAt"),
        "updated_at": int_field("updated_at", "updatedAt"),
    }
    return {
        key: value for key, value in normalized.items()
        if value not in ("", None)
    }


def _goal_event_key(goal: object) -> tuple:
    normalized = _normalize_goal(goal) or {}
    return (
        normalized.get("thread_id"),
        normalized.get("objective"),
        normalized.get("status"),
        normalized.get("token_budget"),
        normalized.get("tokens_used"),
        normalized.get("time_used_seconds"),
    )


async def _codex_app_server_request(
    method: str,
    params: dict,
    cwd: str | Path,
    *,
    resume_thread_id: str = "",
) -> dict:
    """Run a short-lived Codex app-server request for idle thread updates."""
    cwd_str = str(Path(cwd).resolve())
    proc = await asyncio.create_subprocess_exec(
        "codex", "app-server", "--listen", "stdio://",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd_str,
        limit=2 ** 24,
    )

    async def _drain_stderr() -> None:
        if proc.stderr is None:
            return
        async for raw in proc.stderr:
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                log.debug("codex app-server stderr: %s", line[:2000])

    stderr_task = asyncio.create_task(_drain_stderr())
    request_id = 0

    async def _send(msg: dict) -> None:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(msg, separators=(",", ":")).encode() + b"\n")
        await proc.stdin.drain()

    async def _send_request(req_method: str, req_params: dict | None) -> int:
        nonlocal request_id
        request_id += 1
        msg: dict = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": req_method,
        }
        if req_params is not None:
            msg["params"] = req_params
        await _send(msg)
        return request_id

    async def _read_response(expected_id: int) -> dict:
        assert proc.stdout is not None
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                return {}
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict) or msg.get("id") != expected_id:
                continue
            if "error" in msg:
                err = msg["error"]
                if isinstance(err, dict):
                    raise RuntimeError(str(err.get("message") or err))
                raise RuntimeError(str(err))
            return msg.get("result", {})

    try:
        rid = await _send_request(
            "initialize",
            {
                "clientInfo": {
                    "name": "ctf-agent-wrapper",
                    "version": "1.0.0",
                },
                "capabilities": {
                    "experimentalApi": True,
                    "requestAttestation": False,
                },
            },
        )
        await _read_response(rid)
        await _send({"jsonrpc": "2.0", "method": "initialized"})

        if resume_thread_id:
            rid = await _send_request(
                "thread/resume",
                {
                    "threadId": resume_thread_id,
                    "approvalPolicy": "never",
                    "sandbox": "danger-full-access",
                    "cwd": cwd_str,
                    "runtimeWorkspaceRoots": [cwd_str],
                },
            )
            await _read_response(rid)

        rid = await _send_request(method, params)
        return await _read_response(rid)
    finally:
        if stderr_task and not stderr_task.done():
            stderr_task.cancel()
        try:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass


async def _set_thread_goal(
    thread_id: str,
    objective: str,
    cwd: str | Path = ".",
) -> dict | None:
    result = await _codex_app_server_request(
        "thread/goal/set",
        {
            "threadId": thread_id,
            "objective": objective,
            "status": "active",
        },
        cwd,
        resume_thread_id=thread_id,
    )
    return _normalize_goal(result.get("goal"))


async def _clear_thread_goal(thread_id: str, cwd: str | Path = ".") -> bool:
    result = await _codex_app_server_request(
        "thread/goal/clear",
        {"threadId": thread_id},
        cwd,
        resume_thread_id=thread_id,
    )
    return bool(result.get("cleared", True))


def _copy_permission_profile(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    granted: dict = {}
    network = value.get("network")
    if isinstance(network, dict):
        granted["network"] = network
    file_system = value.get("fileSystem")
    if isinstance(file_system, dict):
        granted["fileSystem"] = file_system
    return granted


def _make_approval_result(method: str, params: dict | None = None) -> dict:
    """Build the JSON-RPC result payload to auto-approve a server request."""
    params = params if isinstance(params, dict) else {}
    if method in _V2_DECISION_METHODS:
        return {"decision": "accept"}
    if method in _V1_DECISION_METHODS:
        return {"decision": "approved"}
    if method == "item/permissions/requestApproval":
        permissions = _copy_permission_profile(params.get("permissions"))
        if not permissions:
            permissions = _copy_permission_profile(
                params.get("additionalPermissions")
            )
        return {
            "permissions": permissions,
            "scope": "session",
            "strictAutoReview": False,
        }
    # Default: empty result (best-effort approve)
    return {}


def _make_user_input_result(params: dict) -> dict:
    answers: dict[str, dict[str, list[str]]] = {}
    questions = params.get("questions") if isinstance(params, dict) else None
    if isinstance(questions, list):
        for question in questions:
            if not isinstance(question, dict):
                continue
            qid = question.get("id")
            if isinstance(qid, str) and qid:
                answers[qid] = {"answers": []}
    return {"answers": answers}


def _make_elicitation_result() -> dict:
    return {"action": "accept", "content": {}, "_meta": None}


def _make_token_refresh_result(params: dict) -> dict | None:
    if not CODEX_AUTH_FILE.exists():
        return None
    try:
        auth = json.loads(CODEX_AUTH_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    tokens = auth.get("tokens")
    if not isinstance(tokens, dict):
        return None
    access_token = tokens.get("access_token")
    account_id = (
        tokens.get("account_id")
        or params.get("previousAccountId")
        or auth.get("chatgpt_account_id")
    )
    if not isinstance(access_token, str) or not access_token:
        return None
    if not isinstance(account_id, str) or not account_id:
        return None
    plan_type = auth.get("plan_type")
    if not isinstance(plan_type, str):
        plan_type = None
    return {
        "accessToken": access_token,
        "chatgptAccountId": account_id,
        "chatgptPlanType": plan_type,
    }


def _normalize_thread_item(
    item: dict,
    item_event_type: str,
    *,
    agent_texts: dict[str, str] | None = None,
    command_outputs: dict[str, dict[str, str]] | None = None,
    file_patches: dict[str, str] | None = None,
) -> dict | None:
    """Normalize a ThreadItem from item/started or item/completed."""
    item_type = item.get("type", "")
    item_id = item.get("id", "")

    if item_type == "agentMessage":
        text = item.get("text", "")
        if not text and agent_texts is not None:
            text = agent_texts.get(item_id, "")
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": text}]},
        }

    if item_type == "reasoning":
        parts = item.get("content", [])
        summary = item.get("summary", [])
        text = "\n".join(parts) if parts else "\n".join(summary)
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "thinking",
                "thinking": text,
            }]},
        }

    if item_type == "commandExecution":
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "exec",
                    "input": {
                        "command": item.get("command", ""),
                        "cwd": item.get("cwd", ""),
                    },
                }]},
            }
        # completed
        output = item.get("aggregatedOutput", "") or ""
        if not output and command_outputs is not None:
            output = _stream_buffer_text(command_outputs.get(item_id))
        exit_code = item.get("exitCode")
        status = item.get("status", "")
        is_error = status != "completed" or (
            exit_code is not None and exit_code != 0
        )
        result = {
            "status": status,
            "exit_code": exit_code,
            "output": output,
            "duration_ms": item.get("durationMs"),
        }
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": json.dumps(result, indent=2, default=str),
                "is_error": is_error,
            }]},
        }

    if item_type == "fileChange":
        changes = item.get("changes", [])
        paths = [c.get("path", "") for c in changes if c.get("path")]
        diffs = [c.get("diff", "") for c in changes if c.get("diff")]
        kinds = [c.get("kind", "") for c in changes]
        kind_str = kinds[0] if kinds else ""
        if isinstance(kind_str, dict):
            kind_str = kind_str.get("type", "")
        file_path = paths[0] if paths else ""
        diff = "\n".join(diffs)
        if not diff and file_patches is not None:
            diff = file_patches.get(item_id, "")
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "Edit",
                    "input": {
                        "file_path": file_path,
                        "kind": kind_str,
                    },
                }]},
            }
        # completed
        status = item.get("status", "")
        is_error = status not in {"completed", "applied", "inProgress"}
        display = diff if diff else f"{file_path} ({status})"
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": display,
                "is_error": is_error,
            }]},
        }

    if item_type == "mcpToolCall":
        # Spec: direct fields server, tool, arguments, result, error, status
        server_name = item.get("server", "") or item.get("invocation", {}).get("serverName", "")
        tool_name = item.get("tool", "") or item.get("invocation", {}).get("tool", "")
        display_name = f"{server_name}:{tool_name}" if server_name else tool_name or "mcp_tool"
        arguments = item.get("arguments", {}) or item.get("invocation", {}).get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"input": arguments}
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": display_name,
                    "input": arguments,
                }]},
            }
        # completed
        status = item.get("status", "")
        is_error = status == "failed"
        mcp_error = item.get("error")
        mcp_result = item.get("result", {})
        if mcp_error:
            result_str = str(mcp_error)
            is_error = True
        elif isinstance(mcp_result, dict):
            if "Err" in mcp_result:
                result_str = str(mcp_result["Err"])
                is_error = True
            elif "Ok" in mcp_result:
                mcp_result = mcp_result["Ok"]
                if isinstance(mcp_result, dict) and "content" in mcp_result:
                    content_parts = mcp_result["content"]
                    if isinstance(content_parts, list):
                        text_parts = [p.get("text", "") for p in content_parts
                                      if isinstance(p, dict) and p.get("type") == "text"]
                        if text_parts:
                            result_str = "\n".join(text_parts)
                        else:
                            result_str = json.dumps(mcp_result, indent=2, default=str)
                    else:
                        result_str = json.dumps(mcp_result, indent=2, default=str)
                else:
                    result_str = json.dumps(mcp_result, indent=2, default=str)
            else:
                result_str = json.dumps(mcp_result, indent=2, default=str)
        else:
            result_str = str(mcp_result)
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": result_str,
                "is_error": is_error,
            }]},
        }

    if item_type == "webSearch":
        action = item.get("action")
        query = item.get("query", "")
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "web_search",
                    "input": {
                        "query": query,
                        "action": action,
                    },
                }]},
            }
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": json.dumps(item, indent=2, default=str),
                "is_error": False,
            }]},
        }

    if item_type == "plan":
        text = item.get("text", "")
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "thinking",
                "thinking": text,
            }]},
        }

    if item_type == "dynamicToolCall":
        # Spec: tool, arguments, status, contentItems, success, durationMs
        tool_name = item.get("tool", "tool")
        namespace = item.get("namespace")
        if isinstance(namespace, str) and namespace:
            tool_name = f"{namespace}:{tool_name}"
        arguments = item.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"input": arguments}
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": tool_name,
                    "input": arguments,
                }]},
            }
        is_error = not item.get("success", True)
        content_items = item.get("contentItems", [])
        if content_items:
            text_parts = [ci.get("text", "") for ci in content_items
                          if isinstance(ci, dict) and ci.get("type") in ("inputText", "text")]
            result_str = "\n".join(text_parts) if text_parts else json.dumps(content_items, default=str)
        else:
            result_str = item.get("status", "completed")
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": result_str,
                "is_error": is_error,
            }]},
        }

    if item_type == "collabAgentToolCall":
        tool_name = item.get("tool", "agent")
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": f"agent:{tool_name}",
                    "input": {
                        "prompt": item.get("prompt"),
                        "model": item.get("model"),
                        "receiver_thread_ids": item.get("receiverThreadIds", []),
                    },
                }]},
            }
        status = item.get("status", "")
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": json.dumps(item, indent=2, default=str),
                "is_error": status == "failed",
            }]},
        }

    if item_type == "imageView":
        path = item.get("path", "") or item.get("url", "")
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "view_image",
                    "input": {"path": path},
                }]},
            }
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": f"Image viewed: {path}",
                "is_error": False,
            }]},
        }

    if item_type == "imageGeneration":
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "image_generation",
                    "input": {
                        "status": item.get("status", ""),
                        "revised_prompt": item.get("revisedPrompt"),
                    },
                }]},
            }
        result = {
            "status": item.get("status", ""),
            "revised_prompt": item.get("revisedPrompt"),
            "result": item.get("result", ""),
            "saved_path": item.get("savedPath"),
        }
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": json.dumps(result, indent=2, default=str),
                "is_error": item.get("status") == "failed",
            }]},
        }

    if item_type == "contextCompaction":
        if item_event_type == "started":
            return {"type": "system", "message": "Context compaction in progress..."}
        return {"type": "system", "message": "Context compacted"}

    if item_type == "hookPrompt":
        fragments = item.get("fragments", [])
        text = _content_items_text(fragments)
        if text:
            return {"type": "system", "message": f"Hook prompt: {text}"}
        return None

    if item_type == "enteredReviewMode":
        review = item.get("review", "")
        return {"type": "system", "message": f"Entered review mode: {review}"}

    if item_type == "exitedReviewMode":
        review = item.get("review", "")
        return {"type": "system", "message": f"Exited review mode: {review}"}

    if item_type == "userMessage":
        return None

    log.debug("Unrecognized item type: %s (%s): %s", item_type, item_event_type, json.dumps(item, default=str)[:300])
    return None


def _normalize_raw_response_item(item: dict) -> dict | None:
    item_type = item.get("type", "")

    if item_type == "message":
        if item.get("role") != "assistant":
            return None
        text = _content_items_text(item.get("content", []))
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": text}]},
        }

    if item_type == "reasoning":
        parts = []
        for key in ("summary", "content"):
            value = item.get(key)
            if not isinstance(value, list):
                continue
            for block in value:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    text = block.get("text") or block.get("content")
                    if isinstance(text, str):
                        parts.append(text)
        text = "\n".join(part for part in parts if part)
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "thinking",
                "thinking": text,
            }]},
        }

    if item_type in {
        "function_call",
        "custom_tool_call",
        "tool_search_call",
        "web_search_call",
        "image_generation_call",
    }:
        call_id = item.get("call_id") or item.get("id") or item_type
        name = (
            item.get("name")
            or item.get("execution")
            or item_type.removesuffix("_call")
        )
        arguments = item.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"input": arguments}
        if arguments is None:
            arguments = item.get("action") or {}
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "id": str(call_id),
                "name": str(name),
                "input": arguments if isinstance(arguments, dict) else {
                    "input": arguments
                },
            }]},
        }

    if item_type in {
        "function_call_output",
        "custom_tool_call_output",
        "tool_search_output",
    }:
        call_id = item.get("call_id") or item.get("id") or item_type
        output = item.get("output")
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": str(call_id),
                "content": _json_text(output),
                "is_error": item.get("status") == "failed",
            }]},
        }

    if item_type == "local_shell_call":
        action = item.get("action", {})
        call_id = item.get("call_id") or "local_shell_call"
        if item.get("status") in {"completed", "incomplete"}:
            return {
                "type": "user",
                "message": {"content": [{
                    "type": "tool_result",
                    "tool_use_id": str(call_id),
                    "content": json.dumps(item, indent=2, default=str),
                    "is_error": item.get("status") == "incomplete",
                }]},
            }
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "id": str(call_id),
                "name": "exec",
                "input": action if isinstance(action, dict) else {},
            }]},
        }

    if item_type in {"compaction", "compaction_trigger", "context_compaction"}:
        return {"type": "system", "message": "Context compaction completed"}

    return None


async def _run_agent_sdk(
    prompt: str,
    model: str = "",
    effort: str = "",
    cwd: str | Path = ".",
    continue_session: bool = False,
    session_state: dict | None = None,
    challenge_id: str = "",
    run_id: str = "",
    **kwargs,
) -> AsyncIterator[dict]:
    """Run Codex via the app-server JSON-RPC protocol over stdio."""
    if session_state is None:
        session_state = {}
    run_ref = kwargs.get("_run")
    if not isinstance(run_ref, dict):
        run_ref = None
    requested_skill_mentions = _normalize_skill_mentions(
        kwargs.get("_codex_skill_mentions")
    )
    goal_command_queue: asyncio.Queue | None = None
    if run_ref is not None:
        existing_queue = run_ref.get("_codex_goal_commands")
        if isinstance(existing_queue, asyncio.Queue):
            goal_command_queue = existing_queue
        else:
            goal_command_queue = asyncio.Queue()
            run_ref["_codex_goal_commands"] = goal_command_queue

    cwd_str = str(Path(cwd).resolve())

    # Build the command to spawn
    cmd = ["codex", "app-server", "--listen", "stdio://"]

    log.info("Spawning codex app-server: %s (cwd=%s)", cmd, cwd_str)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd_str,
        start_new_session=True,
        limit=2 ** 24,  # 16 MB — default 64 KB is too small for large JSON-RPC messages
    )
    if run_ref is not None:
        run_ref["_agent_root_pid"] = proc.pid
        try:
            run_ref["_agent_pgid"] = os.getpgid(proc.pid)
        except OSError:
            run_ref["_agent_pgid"] = None

    async def _drain_stderr() -> None:
        if proc.stderr is None:
            return
        async for raw in proc.stderr:
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                log.debug("codex app-server stderr: %s", line[:2000])

    _stderr_task = asyncio.create_task(_drain_stderr())
    request_id = 0

    def _next_id() -> int:
        nonlocal request_id
        request_id += 1
        return request_id

    async def _send(msg: dict) -> None:
        """Send a JSON-RPC message (newline-delimited)."""
        assert proc.stdin is not None
        line = json.dumps(msg, separators=(",", ":")) + "\n"
        proc.stdin.write(line.encode())
        await proc.stdin.drain()

    async def _send_request(method: str, params: dict) -> int:
        """Send a JSON-RPC request, return its id."""
        rid = _next_id()
        await _send({
            "jsonrpc": "2.0",
            "id": rid,
            "method": method,
            "params": params,
        })
        return rid

    async def _read_response(expected_id: int) -> dict:
        """Read lines from stdout until we get the response for expected_id.

        Notifications and server requests received while waiting are
        queued in *deferred_msgs* for later processing.
        """
        assert proc.stdout is not None
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                return {}
            line_s = raw.decode("utf-8", errors="replace").strip()
            if not line_s:
                continue
            try:
                m = json.loads(line_s)
            except json.JSONDecodeError:
                continue
            if not isinstance(m, dict):
                continue
            # Check if this is the response we want
            if m.get("id") == expected_id and (
                "result" in m or "error" in m
            ):
                if "error" in m:
                    err = m["error"]
                    if isinstance(err, dict):
                        raise RuntimeError(
                            f"JSON-RPC error for {expected_id}: "
                            f"{err.get('message', err)}"
                        )
                    raise RuntimeError(
                        f"JSON-RPC error for {expected_id}: {err}"
                    )
                return m.get("result", {})
            # Otherwise queue it for the event loop
            deferred_msgs.append(m)

    async def _notify(method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no id)."""
        m: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            m["params"] = params
        await _send(m)

    async def _respond(rid, result: dict) -> None:
        """Send a JSON-RPC response to a server request."""
        await _send({
            "jsonrpc": "2.0",
            "id": rid,
            "result": result,
        })

    async def _respond_error(rid, message: str, code: int = -32000) -> None:
        await _send({
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": code, "message": message},
        })

    # Messages received during handshake that need processing later
    deferred_msgs: list[dict] = []

    # Accumulator for agent message deltas
    delta_texts: dict[str, str] = {}
    completed_item_ids: set[str] = set()
    command_output_buffers: dict[str, dict[str, str]] = {}
    process_output_buffers: dict[str, dict[str, str]] = {}
    file_patch_buffers: dict[str, str] = {}
    last_turn_diff = ""
    emitted_file_change = False
    emitted_goal_event_keys: set[tuple] = set()
    # Accumulator for reasoning deltas — flush as one block
    reasoning_buffer: list[str] = []
    _inject_task: asyncio.Task | None = None

    def _flush_reasoning_event() -> dict | None:
        if not reasoning_buffer:
            return None
        combined = "".join(reasoning_buffer)
        reasoning_buffer.clear()
        if not combined.strip():
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "thinking",
                "thinking": combined,
            }]},
        }

    def _flush_agent_delta_events() -> list[dict]:
        events = []
        for item_id, text in list(delta_texts.items()):
            if item_id in completed_item_ids:
                continue
            if text.strip():
                events.append({
                    "type": "assistant",
                    "message": {"content": [{
                        "type": "text",
                        "text": text,
                    }]},
                })
            completed_item_ids.add(item_id)
        delta_texts.clear()
        return events

    def _flush_turn_diff_event() -> dict | None:
        nonlocal emitted_file_change, last_turn_diff
        if not last_turn_diff or emitted_file_change:
            return None
        diff = last_turn_diff
        last_turn_diff = ""
        emitted_file_change = True
        return {"type": "system", "message": f"Turn diff:\n{diff}"}

    try:
        # --- Handshake (sequential request/response) ---
        init_params: dict = {
            "clientInfo": {
                "name": "ctf-agent-wrapper",
                "version": "1.0.0",
            },
            "capabilities": {
                "experimentalApi": True,
                "requestAttestation": False,
            },
        }
        rid = await _send_request("initialize", init_params)
        init_result = await _read_response(rid)
        log.info("Codex app-server initialized: %s",
                 json.dumps(init_result)[:200])

        await _notify("initialized")

        # --- Start or resume thread ---
        thread_id = session_state.get("codex_thread_id") if continue_session else None

        if thread_id:
            # Resume existing thread from disk
            log.info("Resuming existing thread: %s", thread_id)
            resume_params: dict = {
                "threadId": thread_id,
                "approvalPolicy": "never",
                "sandbox": "danger-full-access",
                "cwd": cwd_str,
                "runtimeWorkspaceRoots": [cwd_str],
            }
            if model:
                resume_params["model"] = model
            if effort:
                resolved = _resolve_effort(model, effort)
                if resolved:
                    resume_params["config"] = {
                        "model_reasoning_effort": resolved,
                    }
            try:
                rid = await _send_request("thread/resume", resume_params)
                resume_result = await _read_response(rid)
                resumed_id = (
                    resume_result.get("thread", {}).get("id", "")
                    or thread_id
                )
                log.info("Resumed Codex thread: %s", resumed_id)
                # Discard notifications from the resume handshake —
                # stale "idle" status would prematurely end the next turn.
                if deferred_msgs:
                    log.debug(
                        "Clearing %d deferred msgs from resume handshake",
                        len(deferred_msgs),
                    )
                    deferred_msgs.clear()
            except Exception as exc:
                log.warning(
                    "thread/resume failed for %s: %s — starting fresh",
                    thread_id, exc,
                )
                thread_id = None

        if not thread_id:
            # Start a new thread (persisted to disk for future resume)
            thread_params: dict = {
                "cwd": cwd_str,
                "runtimeWorkspaceRoots": [cwd_str],
                "ephemeral": False,
                "approvalPolicy": "never",
                "sandbox": "danger-full-access",
            }
            # Add notify_teammates dynamic tool for parallel mode
            if challenge_id and run_id:
                thread_params["dynamicTools"] = [{
                    "name": "notify_teammates",
                    "description": (
                        "Broadcast a validated breakthrough to all "
                        "teammates. Only call for confirmed findings."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "The breakthrough finding",
                            },
                        },
                        "required": ["message"],
                    },
                }]
            if model:
                thread_params["model"] = model
            if effort:
                resolved = _resolve_effort(model, effort)
                if resolved:
                    thread_params["config"] = {
                        "model_reasoning_effort": resolved,
                    }

            rid = await _send_request("thread/start", thread_params)
            thread_result = await _read_response(rid)
            thread_data = thread_result.get("thread", {})
            thread_id = thread_data.get("id", "")
            if not thread_id:
                yield {
                    "type": "error",
                    "message": "Failed to get thread ID from thread/start",
                }
                return

            session_state["codex_thread_id"] = thread_id
            log.info("Started new Codex thread: %s", thread_id)

            goal_objective = prompt.strip() if not continue_session else ""
            if goal_objective:
                try:
                    rid = await _send_request(
                        "thread/goal/set",
                        {
                            "threadId": thread_id,
                            "objective": goal_objective,
                            "status": "active",
                        },
                    )
                    goal_result = await _read_response(rid)
                    raw_goal = goal_result.get("goal")
                    goal = _normalize_goal(raw_goal)
                    if goal:
                        emitted_goal_event_keys.add(_goal_event_key(raw_goal))
                        text = _format_goal(raw_goal)
                        yield {
                            "type": "run_goal",
                            "provider": "codex",
                            "goal": goal,
                            "message": (
                                f"Goal updated: {text}"
                                if text else "Goal updated"
                            ),
                        }
                except Exception as exc:
                    log.warning(
                        "Failed to set Codex thread goal for %s: %s",
                        thread_id,
                        exc,
                    )

        # --- Send turn ---
        skills_dir = Path(cwd_str) / ".codex" / "skills"
        skill_inputs = _workspace_skill_inputs(cwd_str)
        if skills_dir.is_dir():
            try:
                rid = await _send_request(
                    "skills/list",
                    {"cwds": [cwd_str], "forceReload": True},
                )
                skills_result = await _read_response(rid)
                canonical_inputs = _skill_inputs_from_list_result(
                    skills_result
                )
                if canonical_inputs:
                    skill_inputs = canonical_inputs
            except Exception as exc:
                log.warning("Codex skills/list forceReload failed: %s", exc)
        if skill_inputs:
            log.info(
                "Attaching %d Codex workspace skill input(s): %s",
                len(skill_inputs),
                ", ".join(item["name"] for item in skill_inputs),
            )
        skill_mention_tokens = _skill_mention_tokens(
            skill_inputs,
            requested_skill_mentions,
        )
        text_elements = _text_elements_for_skill_mentions(
            prompt,
            skill_mention_tokens,
        )
        if skill_mention_tokens:
            log.info(
                "Explicitly invoking Codex skill mention(s): %s",
                ", ".join(skill_mention_tokens),
            )
        turn_params: dict = {
            "threadId": thread_id,
            "cwd": cwd_str,
            "runtimeWorkspaceRoots": [cwd_str],
            "input": [
                *skill_inputs,
                {
                    "type": "text",
                    "text": prompt,
                    "text_elements": text_elements,
                },
            ],
        }
        if model:
            turn_params["model"] = model
        if effort:
            resolved = _resolve_effort(model, effort)
            if resolved:
                turn_params["effort"] = resolved
        # Full access sandbox for CTF work
        turn_params["sandboxPolicy"] = {"type": "dangerFullAccess"}

        rid = await _send_request("turn/start", turn_params)
        turn_result = await _read_response(rid)
        log.info("Turn started: %s", json.dumps(turn_result)[:200])

        # --- Background broadcast injection ---
        _inject_task: asyncio.Task | None = None
        _broadcast_ui_events: asyncio.Queue[dict] = asyncio.Queue()

        async def _inject_broadcasts():
            """Poll for broadcasts and inject them into the thread mid-turn."""
            while True:
                await asyncio.sleep(5)
                if not challenge_id or not run_id:
                    continue
                try:
                    from .broadcast import get_pending_broadcast
                    pending = await get_pending_broadcast(
                        challenge_id, run_id
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
                if not pending:
                    continue
                log.info("Injecting broadcast into Codex thread via inject_items")
                _broadcast_ui_events.put_nowait({
                    "type": "system",
                    "subtype": "teammate_broadcast",
                    "message": f"[Teammate breakthrough]: {pending}",
                })
                try:
                    # Write request to stdin only; the response will be
                    # consumed by the main event loop as a regular message.
                    rid = _next_id()
                    request = {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "method": "thread/inject_items",
                        "params": {
                            "threadId": thread_id,
                            "items": [{
                                "type": "message",
                                "role": "user",
                                "content": [{
                                    "type": "input_text",
                                    "text": (
                                        f"[Teammate breakthrough]:\n{pending}\n\n"
                                        "Incorporate this into your approach "
                                        "if relevant. Continue working."
                                    ),
                                }],
                            }],
                        },
                    }
                    proc.stdin.write(
                        json.dumps(request).encode() + b"\n"
                    )
                    await proc.stdin.drain()
                except Exception as exc:
                    log.warning("Failed to inject broadcast into Codex: %s", exc)

        if challenge_id and run_id:
            _inject_task = asyncio.create_task(_inject_broadcasts())

        # --- Event loop: read JSON-RPC messages from stdout ---
        assert proc.stdout is not None

        # Move any deferred messages from handshake into a queue
        msg_queue: list[dict] = list(deferred_msgs)
        deferred_msgs.clear()
        done_seen = False
        done_drain_seconds = 0.5

        async def _process_goal_command(command: dict) -> dict | None:
            action = command.get("action")
            future = command.get("future")
            try:
                if action == "set":
                    objective = str(command.get("objective") or "").strip()
                    if not objective:
                        raise ValueError("objective required")
                    rid = await _send_request(
                        "thread/goal/set",
                        {
                            "threadId": thread_id,
                            "objective": objective,
                            "status": "active",
                        },
                    )
                    goal_result = await _read_response(rid)
                    raw_goal = goal_result.get("goal")
                    goal = _normalize_goal(raw_goal)
                    emitted_goal_event_keys.add(_goal_event_key(raw_goal))
                    event = {
                        "type": "run_goal",
                        "provider": "codex",
                        "goal": goal,
                        "message": "Goal updated",
                    }
                elif action == "clear":
                    rid = await _send_request(
                        "thread/goal/clear",
                        {"threadId": thread_id},
                    )
                    await _read_response(rid)
                    event = {
                        "type": "run_goal",
                        "provider": "codex",
                        "goal": None,
                        "message": "Goal cleared",
                    }
                else:
                    raise ValueError(f"unknown goal action: {action}")

                if isinstance(future, asyncio.Future) and not future.done():
                    future.set_result(event)
                return event
            except Exception as exc:
                if isinstance(future, asyncio.Future) and not future.done():
                    future.set_exception(exc)
                log.warning("Codex goal command failed: %s", exc)
                return None

        while True:
            # Drain broadcast UI events from inject task
            while not _broadcast_ui_events.empty():
                yield _broadcast_ui_events.get_nowait()

            if goal_command_queue is not None:
                while True:
                    try:
                        goal_command = goal_command_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    event = await _process_goal_command(goal_command)
                    if deferred_msgs:
                        msg_queue.extend(deferred_msgs)
                        deferred_msgs.clear()
                    if event:
                        yield event

            # Drain queued messages first
            if msg_queue:
                msg = msg_queue.pop(0)
            else:
                try:
                    if done_seen:
                        raw_line = await asyncio.wait_for(
                            proc.stdout.readline(),
                            timeout=done_drain_seconds,
                        )
                    elif goal_command_queue is not None:
                        raw_line = await asyncio.wait_for(
                            proc.stdout.readline(),
                            timeout=0.25,
                        )
                    else:
                        raw_line = await proc.stdout.readline()
                except asyncio.TimeoutError:
                    if not done_seen:
                        continue
                    event = _flush_reasoning_event()
                    if event:
                        yield event
                    for event in _flush_agent_delta_events():
                        yield event
                    event = _flush_turn_diff_event()
                    if event:
                        yield event
                    break
                if not raw_line:
                    # Process exited or stdout closed — flush reasoning
                    event = _flush_reasoning_event()
                    if event:
                        yield event
                    for event in _flush_agent_delta_events():
                        yield event
                    event = _flush_turn_diff_event()
                    if event:
                        yield event
                    log.info("Codex app-server stdout closed")
                    break

                line_str = raw_line.decode(
                    "utf-8", errors="replace"
                ).strip()
                if not line_str:
                    continue

                try:
                    msg = json.loads(line_str)
                except json.JSONDecodeError:
                    log.debug(
                        "Non-JSON line from app-server: %s",
                        line_str[:200],
                    )
                    continue

                if not isinstance(msg, dict):
                    continue

            # --- JSON-RPC Response (unexpected at this point) ---
            if "id" in msg and ("result" in msg or "error" in msg):
                # Responses to our requests — during the event loop we
                # don't send requests, so just log and skip.
                log.debug("Unexpected response: id=%s", msg.get("id"))
                continue

            # --- Server Request (has id + method) ---
            if "id" in msg and "method" in msg:
                server_method = msg["method"]
                server_id = msg["id"]
                server_params = msg.get("params", {})
                if not isinstance(server_params, dict):
                    server_params = {}

                if server_method in _APPROVAL_METHODS:
                    # Auto-approve
                    log.debug("Auto-approving %s (id=%s)",
                              server_method, server_id)
                    await _respond(
                        server_id,
                        _make_approval_result(server_method, server_params),
                    )
                    # Yield a system note about the approval
                    yield {
                        "type": "system",
                        "message": (
                            f"Auto-approved: {server_method}"
                        ),
                    }
                elif server_method == "item/tool/call":
                    # Dynamic tool call
                    tc_tool = server_params.get("tool", "")
                    tc_args = server_params.get("arguments", {})
                    if not isinstance(tc_args, dict):
                        tc_args = {}

                    if tc_tool == "notify_teammates" and challenge_id and run_id:
                        from .broadcast import broadcast_to_teammates
                        tc_msg = tc_args.get("message", "")
                        count = await broadcast_to_teammates(
                            challenge_id, run_id, tc_msg
                        )
                        await _respond(server_id, {
                            "contentItems": [{
                                "type": "inputText",
                                "text": f"Broadcast sent to {count} teammate(s)",
                            }],
                            "success": True,
                        })
                    else:
                        await _respond(server_id, {
                            "contentItems": [{
                                "type": "inputText",
                                "text": f"Unknown dynamic tool: {tc_tool}",
                            }],
                            "success": False,
                        })
                elif server_method == "item/tool/requestUserInput":
                    # Tool requesting user input — auto-respond empty
                    await _respond(
                        server_id,
                        _make_user_input_result(server_params),
                    )
                elif server_method == "mcpServer/elicitation/request":
                    # MCP elicitation — auto-confirm
                    await _respond(server_id, _make_elicitation_result())
                elif server_method == "account/chatgptAuthTokens/refresh":
                    token_result = _make_token_refresh_result(server_params)
                    if token_result:
                        await _respond(server_id, token_result)
                    else:
                        await _respond_error(
                            server_id,
                            "Unable to refresh ChatGPT tokens from local Codex auth",
                        )
                elif server_method == "attestation/generate":
                    await _respond_error(
                        server_id,
                        "Client attestation is not supported by ctf-agent-wrapper",
                    )
                else:
                    # Unknown server request — respond with empty result
                    log.warning(
                        "Unknown server request: %s", server_method
                    )
                    await _respond_error(
                        server_id,
                        f"Unsupported Codex server request: {server_method}",
                    )
                continue

            # --- Server Notification (has method, no id) ---
            method = msg.get("method", "")
            params = msg.get("params", {})

            # Flush accumulated reasoning before non-reasoning events
            if reasoning_buffer and method not in (
                "item/reasoning/textDelta",
                "item/reasoning/summaryTextDelta",
                "item/reasoning/summaryPartAdded",
            ):
                event = _flush_reasoning_event()
                if event:
                    yield event

            # Detect turn completion. We keep draining briefly after a done
            # signal because Codex may send final items/usage just after idle.
            if method == "turn/completed":
                turn = params.get("turn", {})
                if not isinstance(turn, dict):
                    turn = {}
                status = turn.get("status", "")
                error = turn.get("error")
                if isinstance(error, dict):
                    message = error.get("message") or "Codex turn error"
                    info = error.get("codexErrorInfo")
                    details = error.get("additionalDetails")
                    suffix = ""
                    if info and info != "other":
                        suffix = f" ({_json_text(info)})"
                    if details:
                        suffix += f": {details}"
                    yield {
                        "type": "error",
                        "message": f"{message}{suffix}",
                    }
                for item in turn.get("items", []) or []:
                    if not isinstance(item, dict):
                        continue
                    item_id = item.get("id", "")
                    if item_id and item_id in completed_item_ids:
                        continue
                    if item.get("type") == "fileChange":
                        emitted_file_change = True
                    event = _normalize_thread_item(
                        item,
                        "completed",
                        agent_texts=delta_texts,
                        command_outputs=command_output_buffers,
                        file_patches=file_patch_buffers,
                    )
                    if event:
                        yield event
                    if item_id:
                        completed_item_ids.add(item_id)
                        delta_texts.pop(item_id, None)
                        command_output_buffers.pop(item_id, None)
                        file_patch_buffers.pop(item_id, None)
                usage = _extract_token_usage(params, turn)
                if usage:
                    yield {
                        "type": "codex_usage",
                        "usage": usage,
                    }
                log.info(
                    "Turn completed (status=%s)", status
                )
                done_seen = True

            elif method == "thread/status/changed":
                status_obj = params.get("status", {})
                status_type = (
                    status_obj.get("type", "")
                    if isinstance(status_obj, dict)
                    else str(status_obj)
                )
                if status_type == "idle":
                    log.info("Turn completed (thread idle)")
                    done_seen = True
                elif status_type == "systemError":
                    yield {
                        "type": "error",
                        "message": "Codex thread entered systemError state",
                    }

            if method == "thread/tokenUsage/updated":
                usage = _extract_token_usage(params)
                if usage:
                    yield {
                        "type": "codex_usage",
                        "usage": usage,
                    }
                continue

            if method == "turn/completed":
                continue

            if method == "item/started":
                item = params.get("item", {})
                event = _normalize_thread_item(
                    item,
                    "started",
                    agent_texts=delta_texts,
                    command_outputs=command_output_buffers,
                    file_patches=file_patch_buffers,
                )
                if event:
                    yield event
                continue

            if method == "item/completed":
                item = params.get("item", {})
                if item.get("type") == "fileChange":
                    emitted_file_change = True
                event = _normalize_thread_item(
                    item,
                    "completed",
                    agent_texts=delta_texts,
                    command_outputs=command_output_buffers,
                    file_patches=file_patch_buffers,
                )
                if event:
                    yield event
                item_id = item.get("id", "")
                if item_id:
                    completed_item_ids.add(item_id)
                    delta_texts.pop(item_id, None)
                    command_output_buffers.pop(item_id, None)
                    file_patch_buffers.pop(item_id, None)
                continue

            if method == "item/agentMessage/delta":
                # Streaming text delta — accumulate
                delta = params.get("delta", "")
                item_id = params.get("itemId", "")
                if delta and item_id:
                    delta_texts[item_id] = (
                        delta_texts.get(item_id, "") + delta
                    )
                continue

            if method in (
                "item/reasoning/textDelta",
                "item/reasoning/summaryTextDelta",
            ):
                delta = params.get("delta", "")
                if delta:
                    reasoning_buffer.append(delta)
                continue

            if method == "item/reasoning/summaryPartAdded":
                continue

            if method == "item/commandExecution/outputDelta":
                item_id = params.get("itemId", "")
                delta = params.get("delta", "")
                _append_stream_buffer(
                    command_output_buffers,
                    item_id,
                    "stdout",
                    delta if isinstance(delta, str) else "",
                )
                continue

            if method == "item/commandExecution/terminalInteraction":
                call_id = params.get("itemId", "")
                content = params.get("stdin", "")
                if content:
                    yield {
                        "type": "user",
                        "message": {"content": [{
                            "type": "tool_result",
                            "tool_use_id": call_id,
                            "content": f"[stdin] {content}",
                            "is_error": False,
                        }]},
                    }
                continue

            if method == "item/fileChange/outputDelta":
                item_id = params.get("itemId", "")
                delta = params.get("delta", "")
                if item_id and isinstance(delta, str) and delta:
                    file_patch_buffers[item_id] = (
                        file_patch_buffers.get(item_id, "") + delta
                    )
                continue

            if method == "item/fileChange/patchUpdated":
                item_id = params.get("itemId", "")
                diff = _format_patch_changes(params.get("changes", []))
                if item_id and diff:
                    file_patch_buffers[item_id] = diff
                continue

            if method == "command/exec/outputDelta":
                process_id = params.get("processId", "")
                text = _decode_base64_text(params.get("deltaBase64"))
                _append_stream_buffer(
                    process_output_buffers,
                    process_id,
                    params.get("stream", "stdout"),
                    text,
                )
                continue

            if method == "process/outputDelta":
                process_handle = params.get("processHandle", "")
                text = _decode_base64_text(params.get("deltaBase64"))
                _append_stream_buffer(
                    process_output_buffers,
                    process_handle,
                    params.get("stream", "stdout"),
                    text,
                )
                continue

            if method == "process/exited":
                process_handle = params.get("processHandle", "")
                stdout = params.get("stdout", "")
                stderr = params.get("stderr", "")
                buffered = process_output_buffers.pop(process_handle, {})
                result = {
                    "exit_code": params.get("exitCode"),
                    "stdout": stdout or buffered.get("stdout", ""),
                    "stderr": stderr or buffered.get("stderr", ""),
                    "stdout_cap_reached": params.get("stdoutCapReached", False),
                    "stderr_cap_reached": params.get("stderrCapReached", False),
                }
                yield {
                    "type": "user",
                    "message": {"content": [{
                        "type": "tool_result",
                        "tool_use_id": process_handle or "process",
                        "content": json.dumps(result, indent=2, default=str),
                        "is_error": params.get("exitCode") not in (None, 0),
                    }]},
                }
                continue

            if method == "error":
                error = params.get("error")
                if isinstance(error, dict):
                    err_msg = error.get("message", "")
                    info = error.get("codexErrorInfo")
                    details = error.get("additionalDetails")
                    if info and info != "other":
                        err_msg = f"{err_msg} ({_json_text(info)})"
                    if details:
                        err_msg = f"{err_msg}: {details}"
                else:
                    err_msg = params.get("message", "")
                will_retry = params.get("willRetry")
                yield {
                    "type": "error",
                    "message": (
                        f"{err_msg} (will retry)"
                        if err_msg and will_retry
                        else err_msg or "Codex error"
                    ),
                }
                continue

            if method == "thread/started":
                # Thread started notification — extract thread_id
                thread_data = params.get("thread", {})
                tid = thread_data.get("id", "")
                if tid:
                    session_state["codex_thread_id"] = tid
                continue

            if method == "turn/started":
                continue

            if method == "thread/status/changed":
                continue

            if method == "thread/tokenUsage/updated":
                usage = _extract_token_usage(params)
                if usage:
                    yield {
                        "type": "codex_usage",
                        "usage": usage,
                    }
                continue

            if method == "thread/name/updated":
                continue

            if method == "thread/closed":
                log.info("Thread closed notification received")
                break

            if method == "rawResponseItem/completed":
                item = params.get("item", {})
                if isinstance(item, dict):
                    event = _normalize_raw_response_item(item)
                    if event:
                        yield event
                continue

            if method == "turn/diff/updated":
                diff = params.get("diff", "")
                if isinstance(diff, str):
                    last_turn_diff = diff
                continue

            if method == "turn/plan/updated":
                text = _format_plan_update(params)
                if text:
                    yield {
                        "type": "assistant",
                        "message": {"content": [{
                            "type": "thinking",
                            "thinking": text,
                        }]},
                    }
                continue

            if method == "item/plan/delta":
                delta = params.get("delta", "")
                if delta:
                    yield {
                        "type": "assistant",
                        "message": {"content": [{
                            "type": "thinking",
                            "thinking": delta,
                        }]},
                    }
                continue

            if method == "thread/goal/updated":
                raw_goal = params.get("goal")
                goal = _normalize_goal(raw_goal)
                key = _goal_event_key(raw_goal)
                if key in emitted_goal_event_keys:
                    emitted_goal_event_keys.discard(key)
                    continue
                text = _format_goal(raw_goal)
                yield {
                    "type": "run_goal",
                    "provider": "codex",
                    "goal": goal,
                    "message": f"Goal updated: {text}" if text else "Goal updated",
                }
                continue

            if method == "thread/goal/cleared":
                yield {
                    "type": "run_goal",
                    "provider": "codex",
                    "goal": None,
                    "message": "Goal cleared",
                }
                continue

            if method in {"warning", "guardianWarning"}:
                message = params.get("message", "")
                if message:
                    yield {
                        "type": "system",
                        "subtype": "codex_warning",
                        "message": message,
                    }
                continue

            if method == "configWarning":
                summary = params.get("summary", "")
                details = params.get("details")
                path = params.get("path")
                message = summary or "Codex config warning"
                if details:
                    message = f"{message}: {details}"
                if path:
                    message = f"{message} ({path})"
                yield {
                    "type": "system",
                    "subtype": "codex_warning",
                    "message": message,
                }
                continue

            if method == "deprecationNotice":
                summary = params.get("summary", "")
                details = params.get("details")
                message = summary or "Codex deprecation notice"
                if details:
                    message = f"{message}: {details}"
                yield {
                    "type": "system",
                    "subtype": "codex_warning",
                    "message": message,
                }
                continue

            if method == "model/rerouted":
                yield {
                    "type": "system",
                    "subtype": "codex_model",
                    "message": (
                        "Model rerouted: "
                        f"{params.get('fromModel', '')} -> "
                        f"{params.get('toModel', '')} "
                        f"({params.get('reason', 'unknown')})"
                    ),
                }
                continue

            if method == "model/verification":
                verifications = params.get("verifications", [])
                if verifications:
                    yield {
                        "type": "system",
                        "subtype": "codex_model",
                        "message": (
                            "Model verification: "
                            + ", ".join(str(v) for v in verifications)
                        ),
                    }
                continue

            if method == "item/mcpToolCall/progress":
                message = params.get("message", "")
                if message:
                    yield {
                        "type": "system",
                        "subtype": "codex_tool_progress",
                        "message": f"MCP progress: {message}",
                    }
                continue

            if method == "thread/compacted":
                yield {"type": "system", "message": "Context compacted"}
                continue

            if method == "mcpServer/oauthLogin/completed":
                if not params.get("success", False):
                    yield {
                        "type": "error",
                        "message": (
                            f"MCP OAuth login failed for {params.get('name', '')}: "
                            f"{params.get('error', '')}"
                        ),
                    }
                continue

            if method == "account/login/completed":
                if not params.get("success", False):
                    yield {
                        "type": "error",
                        "message": (
                            "Codex account login failed: "
                            f"{params.get('error', '')}"
                        ),
                    }
                continue

            if method == "windows/worldWritableWarning":
                paths = params.get("samplePaths", [])
                if not isinstance(paths, list):
                    paths = []
                extra = params.get("extraCount", 0)
                yield {
                    "type": "system",
                    "subtype": "codex_warning",
                    "message": (
                        "World-writable Windows paths detected: "
                        + ", ".join(str(p) for p in paths[:5])
                        + (f" (+{extra} more)" if extra else "")
                    ),
                }
                continue

            if method == "windowsSandbox/setupCompleted":
                if not params.get("success", False):
                    yield {
                        "type": "error",
                        "message": (
                            "Windows sandbox setup failed: "
                            f"{params.get('error', '')}"
                        ),
                    }
                continue

            if method == "thread/realtime/transcript/delta":
                delta = params.get("delta", "")
                role = params.get("role", "")
                if delta:
                    event_type = "assistant" if role == "assistant" else "system"
                    if event_type == "assistant":
                        yield {
                            "type": "assistant",
                            "message": {"content": [{
                                "type": "text",
                                "text": delta,
                            }]},
                        }
                    else:
                        yield {
                            "type": "system",
                            "subtype": "codex_realtime",
                            "message": f"Realtime {role}: {delta}",
                        }
                continue

            if method == "thread/realtime/error":
                yield {
                    "type": "error",
                    "message": params.get("message", "Codex realtime error"),
                }
                continue

            if method in {
                "item/autoApprovalReview/started",
                "item/autoApprovalReview/completed",
                "serverRequest/resolved",
                "hook/started",
                "hook/completed",
                "skills/changed",
                "fs/changed",
                "thread/archived",
                "thread/unarchived",
                "thread/settings/updated",
                "account/updated",
                "account/rateLimits/updated",
                "app/list/updated",
                "mcpServer/startupStatus/updated",
                "externalAgentConfig/import/completed",
                "remoteControl/status/changed",
                "fuzzyFileSearch/sessionUpdated",
                "fuzzyFileSearch/sessionCompleted",
                "thread/realtime/started",
                "thread/realtime/itemAdded",
                "thread/realtime/transcript/done",
                "thread/realtime/outputAudio/delta",
                "thread/realtime/sdp",
                "thread/realtime/closed",
            }:
                # Known but not interesting for our event stream
                continue

            # Unknown notification — log and skip
            log.debug("Unhandled notification: %s", method)

    except asyncio.CancelledError:
        log.info("Codex SDK run cancelled")
        raise
    except Exception as exc:
        log.error("Codex app-server error: %s", exc, exc_info=True)
        yield {"type": "error", "message": str(exc)}
    finally:
        if _inject_task and not _inject_task.done():
            _inject_task.cancel()
        if _stderr_task and not _stderr_task.done():
            _stderr_task.cancel()
        # Clean up the subprocess
        try:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception as exc:
            log.debug("stdin close error: %s", exc)
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        if run_ref is not None and run_ref.get("_codex_goal_commands") is goal_command_queue:
            run_ref.pop("_codex_goal_commands", None)
        log.info("Codex app-server subprocess cleaned up")


provider = AgentProvider(
    name="codex",
    label="Codex",
    models=_discover_models(),
    default_model="",
    auth_connect_command="codex login --device-auth",
    badge_mode="model",
    build_command=_build_command,
    normalize_saved_events=_normalize_saved_events,
    normalize_live_event=_normalize_live_event,
    get_usage_data=_get_usage_data,
    get_models=_discover_models,
    effort_levels=_discover_effort_levels(),
    default_effort="xhigh",
    run_agent=_run_agent_sdk,
    set_thread_goal=_set_thread_goal,
    clear_thread_goal=_clear_thread_goal,
)
