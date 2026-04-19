from __future__ import annotations

import asyncio
import base64
import json
import logging
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

    if len(models) <= 1:
        for slug in (
            "gpt-5.4", "gpt-5.4-mini",
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


def _make_approval_result(method: str) -> dict:
    """Build the JSON-RPC result payload to auto-approve a server request."""
    if method in _V2_DECISION_METHODS:
        return {"decision": "accept"}
    if method in _V1_DECISION_METHODS:
        return {"decision": "approved"}
    if method == "item/permissions/requestApproval":
        return {
            "permissions": {"type": "dangerFullAccess"},
            "scope": "session",
        }
    # Default: empty result (best-effort approve)
    return {}


def _normalize_thread_item(item: dict, item_event_type: str) -> dict | None:
    """Normalize a ThreadItem from item/started or item/completed."""
    item_type = item.get("type", "")
    item_id = item.get("id", "")

    if item_type == "agentMessage":
        text = item.get("text", "")
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
        exit_code = item.get("exitCode")
        status = item.get("status", "")
        is_error = status != "completed" or (
            exit_code is not None and exit_code != 0
        )
        result = {
            "status": status,
            "exit_code": exit_code,
            "output": output,
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
        log.debug("fileChange item (%s): %s", item_event_type, json.dumps(item, default=str)[:500])
        file_path = item.get("filePath", "") or item.get("path", "") or item.get("file", "")
        diff = item.get("patch", "") or item.get("diff", "") or item.get("content", "")
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "Edit",
                    "input": {
                        "file_path": file_path,
                        "diff": diff,
                    },
                }]},
            }
        # completed
        if not file_path:
            file_path = item.get("filePath", "") or item.get("path", "") or ""
        if not diff:
            diff = item.get("patch", "") or item.get("diff", "") or item.get("content", "")
        status = item.get("status", "")
        is_error = status not in {"completed", "applied"}
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
        log.debug("mcpToolCall item (%s): %s", item_event_type, json.dumps(item, default=str)[:500])
        invocation = item.get("invocation", {})
        server_name = invocation.get("serverName", "") or invocation.get("server", "")
        tool_name = invocation.get("tool", "") or invocation.get("toolName", "") or invocation.get("name", "")
        display_name = f"{server_name}:{tool_name}" if server_name else tool_name or "mcp_tool"
        arguments = invocation.get("arguments", {}) or invocation.get("input", {})
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
        mcp_result = item.get("result", {})
        is_error = False
        if isinstance(mcp_result, dict):
            if "Err" in mcp_result:
                mcp_result = {"error": mcp_result["Err"]}
                is_error = True
            elif "Ok" in mcp_result:
                mcp_result = mcp_result["Ok"]
        # Extract text content from MCP result
        if isinstance(mcp_result, dict) and "content" in mcp_result:
            content_parts = mcp_result["content"]
            if isinstance(content_parts, list):
                text_parts = [p.get("text", "") for p in content_parts if isinstance(p, dict) and p.get("type") == "text"]
                if text_parts:
                    mcp_result = "\n".join(text_parts)
        result_str = mcp_result if isinstance(mcp_result, str) else json.dumps(mcp_result, indent=2, default=str)
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
        if item_event_type == "started":
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": item_id,
                    "name": "web_search",
                    "input": {},
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
        log.debug("dynamicToolCall item (%s): %s", item_event_type, json.dumps(item, default=str)[:500])
        tool_name = item.get("name", "") or item.get("tool", "tool")
        arguments = item.get("arguments", {}) or item.get("input", {})
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
        result = item.get("result", item.get("output", ""))
        is_error = item.get("status", "") not in {"completed", ""}
        result_str = result if isinstance(result, str) else json.dumps(result, indent=2, default=str)
        return {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": item_id,
                "content": result_str,
                "is_error": is_error,
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

    log.debug("Unrecognized item type: %s (%s): %s", item_type, item_event_type, json.dumps(item, default=str)[:300])
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
        limit=2 ** 24,  # 16 MB — default 64 KB is too small for large JSON-RPC messages
    )

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

    # Messages received during handshake that need processing later
    deferred_msgs: list[dict] = []

    # Accumulator for agent message deltas
    delta_texts: dict[str, str] = {}
    last_yielded_text = ""
    # Accumulator for reasoning deltas — flush as one block
    reasoning_buffer: list[str] = []

    try:
        # --- Handshake (sequential request/response) ---
        init_params: dict = {
            "clientInfo": {
                "name": "ctf-agent-wrapper",
                "version": "1.0.0",
            },
        }
        if challenge_id and run_id:
            init_params["capabilities"] = {"experimentalApi": True}
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

        # --- Send turn ---
        turn_params: dict = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": prompt}],
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

        while True:
            # Drain broadcast UI events from inject task
            while not _broadcast_ui_events.empty():
                yield _broadcast_ui_events.get_nowait()

            # Drain queued messages first
            if msg_queue:
                msg = msg_queue.pop(0)
            else:
                raw_line = await proc.stdout.readline()
                if not raw_line:
                    # Process exited or stdout closed — flush reasoning
                    if reasoning_buffer:
                        combined = "".join(reasoning_buffer)
                        reasoning_buffer.clear()
                        if combined.strip():
                            yield {
                                "type": "assistant",
                                "message": {"content": [{
                                    "type": "thinking",
                                    "thinking": combined,
                                }]},
                            }
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

                if server_method in _APPROVAL_METHODS:
                    # Auto-approve
                    log.debug("Auto-approving %s (id=%s)",
                              server_method, server_id)
                    await _respond(
                        server_id,
                        _make_approval_result(server_method),
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
                    tc_params = msg.get("params", {})
                    tc_tool = tc_params.get("tool", "")
                    tc_args = tc_params.get("arguments", {})

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
                            "error": f"Unknown dynamic tool: {tc_tool}",
                        })
                elif server_method == "item/tool/requestUserInput":
                    # Tool requesting user input — auto-respond empty
                    await _respond(server_id, {"input": ""})
                elif server_method == "mcpServer/elicitation/request":
                    # MCP elicitation — auto-confirm
                    await _respond(server_id, {"action": "confirm"})
                else:
                    # Unknown server request — respond with empty result
                    log.warning(
                        "Unknown server request: %s", server_method
                    )
                    await _respond(server_id, {})
                continue

            # --- Server Notification (has method, no id) ---
            method = msg.get("method", "")
            params = msg.get("params", {})

            # Flush accumulated reasoning before non-reasoning events
            if reasoning_buffer and method not in (
                "item/reasoning/textDelta",
                "item/reasoning/summaryTextDelta",
            ):
                combined = "".join(reasoning_buffer)
                reasoning_buffer.clear()
                if combined.strip():
                    yield {
                        "type": "assistant",
                        "message": {"content": [{
                            "type": "thinking",
                            "thinking": combined,
                        }]},
                    }

            # Detect turn completion — v0.118+ uses thread/status/changed
            # with status.type=="idle", older versions use turn/completed
            turn_done = False
            if method == "turn/completed":
                turn = params.get("turn", {})
                status = turn.get("status", "")
                error_info = turn.get("codexErrorInfo")
                if isinstance(error_info, str) and error_info not in {
                    "", "other"
                }:
                    yield {
                        "type": "error",
                        "message": f"Codex turn error: {error_info}",
                    }
                elif isinstance(error_info, dict):
                    yield {
                        "type": "error",
                        "message": f"Codex turn error: "
                                   f"{json.dumps(error_info)}",
                    }
                log.info(
                    "Turn completed (status=%s)", status
                )
                turn_done = True

            elif method == "thread/status/changed":
                status_obj = params.get("status", {})
                status_type = (
                    status_obj.get("type", "")
                    if isinstance(status_obj, dict)
                    else str(status_obj)
                )
                if status_type == "idle":
                    log.info("Turn completed (thread idle)")
                    turn_done = True

            if turn_done:
                break

            if method == "item/started":
                item = params.get("item", {})
                event = _normalize_thread_item(item, "started")
                if event:
                    yield event
                continue

            if method == "item/completed":
                item = params.get("item", {})
                event = _normalize_thread_item(item, "completed")
                if event:
                    # Track last assistant text for dedup
                    if event.get("type") == "assistant":
                        content = event.get("message", {}).get(
                            "content", []
                        )
                        for block in content:
                            if block.get("type") == "text":
                                last_yielded_text = block.get(
                                    "text", ""
                                )
                    yield event
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

            if method == "item/commandExecution/outputDelta":
                # Streaming command output — accumulate but don't yield
                # (will come in item/completed)
                continue

            if method == "item/commandExecution/terminalInteraction":
                call_id = params.get("itemId", "")
                interaction = params.get("interaction", {})
                content = interaction.get("content", "")
                itype = interaction.get("type", "")
                if content:
                    label = "stdin" if itype == "stdin" else itype or "terminal"
                    yield {
                        "type": "user",
                        "message": {"content": [{
                            "type": "tool_result",
                            "tool_use_id": call_id,
                            "content": f"[{label}] {content}",
                            "is_error": False,
                        }]},
                    }
                continue

            if method == "item/fileChange/outputDelta":
                # Streaming file change diff output — accumulate
                continue

            if method == "command/exec/outputDelta":
                # Legacy command output delta
                continue

            if method == "error":
                err_msg = params.get("message", "")
                code = params.get("code", "")
                yield {
                    "type": "error",
                    "message": err_msg or f"Codex error: {code}",
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
                continue

            if method == "thread/name/updated":
                continue

            if method == "thread/closed":
                log.info("Thread closed notification received")
                break

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

            if method in {
                "turn/diff/updated",
                "turn/plan/updated",
                "item/autoApprovalReview/started",
                "item/autoApprovalReview/completed",
                "item/mcpToolCall/progress",
                "serverRequest/resolved",
                "hook/started",
                "hook/completed",
                "skills/changed",
                "fs/changed",
                "thread/compacted",
                "model/rerouted",
                "deprecationNotice",
                "configWarning",
                "account/updated",
                "account/rateLimits/updated",
                "app/list/updated",
                "mcpServer/startupStatus/updated",
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
        # Clean up the subprocess
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
        log.info("Codex app-server subprocess cleaned up")


provider = AgentProvider(
    name="codex",
    label="Codex",
    models=_discover_models(),
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
    default_effort="xhigh",
    run_agent=_run_agent_sdk,
)
