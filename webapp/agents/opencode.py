from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .base import AgentProvider

OPENCODE_AUTH_FILE = (
    Path.home() / ".local" / "share" / "opencode" / "auth.json"
)
OPENCODE_PROJECTS_DIR = (
    Path.home() / ".local" / "share" / "opencode" / "project"
)


def _build_command(
    challenge: dict, prompt: str, is_continue: bool
) -> list[str]:
    cmd = [
        "opencode",
        "run",
        "--format",
        "json",
    ]
    if challenge.get("model"):
        cmd.extend(["--model", challenge["model"]])
    if is_continue:
        if challenge.get("_opencode_session_id"):
            cmd.extend(["--session", challenge["_opencode_session_id"]])
        else:
            cmd.append("--continue")
    cmd.append(prompt)
    return cmd


def _normalize_saved_events(events: list[dict]) -> list[dict]:
    return events


def _extract_error_message(value: object, depth: int = 0) -> str:
    if depth > 6:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("message", "error", "detail", "name"):
            msg = value.get(key)
            if isinstance(msg, str) and msg:
                return msg
        for nested in value.values():
            msg = _extract_error_message(nested, depth + 1)
            if msg:
                return msg
    if isinstance(value, list):
        for nested in value:
            msg = _extract_error_message(nested, depth + 1)
            if msg:
                return msg
    return ""


def _part_call_id(part: dict) -> str:
    for key in ("callID", "callId", "call_id", "id"):
        value = part.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _normalize_part_event(part: dict, challenge: dict) -> dict | None:
    if not isinstance(part, dict):
        return None

    message_id = part.get("messageID", "")
    role = (
        challenge.setdefault("_opencode_roles", {}).get(message_id)
        or part.get("role")
        or ""
    )
    if role and role != "assistant":
        return None

    part_type = part.get("type", "")
    if part_type == "text":
        text = part.get("text", "")
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "text",
                "text": text,
            }]},
        }

    if part_type == "reasoning":
        text = part.get("text", "")
        if not text:
            return None
        return {
            "type": "assistant",
            "message": {"content": [{
                "type": "thinking",
                "thinking": text,
            }]},
        }

    if part_type == "tool":
        tool_name = part.get("tool", "tool")
        state = part.get("state", {})
        status = state.get("status", "")
        call_id = _part_call_id(part)
        if not call_id:
            return None

        seen = challenge.setdefault("_opencode_tool_status", {})
        previous = seen.get(call_id)
        seen[call_id] = status

        if status in {"pending", "running"}:
            if previous in {"pending", "running"}:
                return None
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "tool_use",
                    "id": call_id,
                    "name": tool_name,
                    "input": state.get("input", {}),
                }]},
            }

        if status in {"completed", "error"}:
            raw = (
                state.get("output")
                if status == "completed"
                else state.get("error", "")
            )
            content = raw if isinstance(raw, str) else json.dumps(raw)
            return {
                "type": "user",
                "message": {"content": [{
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": content,
                    "is_error": status == "error",
                    "name": tool_name,
                    "input": state.get("input", {}),
                }]},
            }

    return None


def _normalize_final_object(event: dict) -> dict | None:
    if not isinstance(event, dict):
        return None
    if "type" in event or "payload" in event:
        return None

    err = event.get("error")
    if isinstance(err, str) and err:
        return {"type": "error", "message": err}
    if isinstance(err, dict):
        msg = err.get("message") or err.get("name")
        if isinstance(msg, str) and msg:
            return {"type": "error", "message": msg}

    for key in ("output", "text", "message", "response", "result", "content"):
        value = event.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            text = value.strip()
        else:
            text = json.dumps(value, indent=2, default=str)
        if text:
            return {
                "type": "assistant",
                "message": {"content": [{
                    "type": "text",
                    "text": text,
                }]},
            }

    return None


def _normalize_live_event(event: dict, challenge: dict) -> dict | None:
    normalized = _normalize_final_object(event)
    if normalized is not None:
        return normalized

    payload = event.get("payload", event)
    event_type = payload.get("type")
    props = payload.get("properties", {})
    part = payload.get("part")
    if not isinstance(part, dict):
        part = props.get("part", {})
    event_type_lower = (
        event_type.lower() if isinstance(event_type, str) else ""
    )

    status = props.get("status") or payload.get("status", "")
    status = status.lower() if isinstance(status, str) else ""
    error_message = (
        _extract_error_message(payload.get("error", {}))
        or _extract_error_message(props.get("error", {}))
    )

    if error_message and (
        "error" in event_type_lower
        or status in {"error", "failed"}
    ):
        return {
            "type": "error",
            "message": error_message,
        }

    if event_type == "error":
        return {
            "type": "error",
            "message": error_message or "OpenCode error",
        }

    if event_type in {"session.created", "session.updated"}:
        info = props.get("info", {})
        session_id = info.get("id")
        if session_id:
            challenge["_opencode_session_id"] = session_id
        return None

    if event_type == "session.status":
        if status in {"error", "failed"}:
            return {
                "type": "error",
                "message": error_message or f"OpenCode session {status}",
            }
        return None

    if event_type == "message.updated":
        info = props.get("info", {})
        message_id = info.get("id")
        if message_id:
            challenge.setdefault("_opencode_roles", {})[message_id] = (
                info.get("role", "")
            )
        return None

    if event_type in {"text", "reasoning", "tool_use", "tool_result"}:
        normalized_part = _normalize_part_event(part, challenge)
        if normalized_part is not None:
            return normalized_part

    if event_type == "message.part.updated":
        delta = props.get("delta")
        if isinstance(delta, str) and delta and part.get("type") in {
            "text",
            "reasoning",
        }:
            part = dict(part)
            part["text"] = delta
        return _normalize_part_event(part, challenge)

    if event_type == "session.error":
        error = props.get("error", {})
        message = _extract_error_message(error)
        return {
            "type": "error",
            "message": message or "OpenCode session error",
        }

    if event_type in {
        "session.idle",
        "command.executed",
        "todo.updated",
        "file.edited",
        "step_start",
        "step_finish",
    }:
        return None

    return event


def _project_count() -> int:
    if not OPENCODE_PROJECTS_DIR.is_dir():
        return 0
    return sum(
        1 for path in OPENCODE_PROJECTS_DIR.iterdir()
        if path.is_dir()
    )


def _discover_models() -> tuple[tuple[str, str], ...]:
    try:
        result = subprocess.run(
            ["opencode", "models"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        OSError,
    ):
        return (("", "Provider default"),)

    text = "\n".join(
        part for part in (result.stdout, result.stderr) if part
    )
    seen: set[str] = set()
    models: list[tuple[str, str]] = []
    for match in re.finditer(
        r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._:-]+)\b", text
    ):
        model = match.group(1)
        if model in seen:
            continue
        seen.add(model)
        models.append((model, model))

    if models:
        return tuple(models)
    return (("", "Provider default"),)


def _get_usage_data() -> dict | None:
    if not OPENCODE_AUTH_FILE.exists():
        return None

    providers: list[str] = []
    try:
        auth = json.loads(OPENCODE_AUTH_FILE.read_text())
        if isinstance(auth, dict):
            providers = sorted(str(key) for key in auth if auth[key])
    except (json.JSONDecodeError, OSError):
        pass

    auth_rows = [{"label": "Status", "value": "Configured"}]
    if providers:
        auth_rows.append({
            "label": "Providers",
            "value": ", ".join(providers),
        })

    return {
        "auth_rows": auth_rows,
        "stat_rows": [{
            "label": "Projects",
            "value": str(_project_count()),
        }],
        "daily_activity": [],
        "daily_activity_title": None,
    }


provider = AgentProvider(
    name="opencode",
    label="OpenCode",
    models=(),
    default_model="",
    auth_connect_command="opencode auth login",
    autonomous_default=False,
    badge_mode="model",
    build_command=_build_command,
    normalize_saved_events=_normalize_saved_events,
    normalize_live_event=_normalize_live_event,
    get_usage_data=_get_usage_data,
    get_models=_discover_models,
)
