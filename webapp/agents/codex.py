from __future__ import annotations

import base64
import json
import tomllib
from pathlib import Path

from .base import AgentProvider

CODEX_AUTH_FILE = Path.home() / ".codex" / "auth.json"
CODEX_CONFIG_FILE = Path.home() / ".codex" / "config.toml"
CODEX_MODELS_CACHE_FILE = Path.home() / ".codex" / "models_cache.json"
CODEX_SESSIONS_DIR = Path.home() / ".codex" / "sessions"
REASONING_LEVEL_ORDER = ("minimal", "low", "medium", "high", "xhigh")
REASONING_LABELS = {
    "minimal": "Minimal",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "xhigh": "XHigh",
}
DEFAULT_COMMON_REASONING_LEVELS = {"medium", "high"}


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


def _normalize_live_event(event: dict, challenge: dict) -> dict | None:
    event_type, payload = _get_event_type(event)
    if not event_type:
        return None

    tool_output = challenge.setdefault("_codex_tool_output", {})

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
        "token_count",
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


def _get_usage_data() -> dict | None:
    if not CODEX_AUTH_FILE.exists():
        return None

    auth_method = "Configured"
    try:
        auth = json.loads(CODEX_AUTH_FILE.read_text())
        auth_method = _detect_auth_method(auth) or auth_method
    except (json.JSONDecodeError, OSError):
        pass

    return {
        "auth_rows": [
            {"label": "Status", "value": "Configured"},
            {"label": "Method", "value": auth_method},
        ],
        "stat_rows": [{
            "label": "Sessions",
            "value": str(_get_session_count()),
        }],
        "daily_activity": [],
        "daily_activity_title": None,
    }


provider = AgentProvider(
    name="codex",
    label="Codex",
    models=(),
    default_model="",
    auth_connect_command="codex login",
    autonomous_default=False,
    badge_mode="model",
    build_command=_build_command,
    normalize_saved_events=_normalize_saved_events,
    normalize_live_event=_normalize_live_event,
    get_usage_data=_get_usage_data,
    get_models=_discover_models,
    effort_levels=_discover_effort_levels(),
    default_effort="medium",
)
