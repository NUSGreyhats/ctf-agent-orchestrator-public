from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time

if sys.platform != "win32":
    import pty
    import select
from pathlib import Path

from .base import AgentProvider

COPILOT_CONFIG_FILE = Path.home() / ".copilot" / "config.json"
COPILOT_SESSIONS_DIR = Path.home() / ".copilot" / "session-state"
PTY_CACHE_TTL_SECONDS = 300
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MODEL_TOKEN_RE = re.compile(
    r"\b("
    r"(?:claude|gpt|gemini|grok|raptor)"
    r"(?:[- ][a-z0-9.+]+){1,6}"
    r")\b",
    re.IGNORECASE,
)
_pty_model_cache: tuple[float, tuple[tuple[str, str], ...]] | None = None

COPILOT_MODEL_MAP = {
    "opus": "claude-opus-4.6",
    "sonnet": "claude-sonnet-4.6",
    "haiku": "claude-haiku-4.5",
}
_supports_json_output_cache: bool | None = None


def _supports_json_output() -> bool:
    global _supports_json_output_cache
    if _supports_json_output_cache is not None:
        return _supports_json_output_cache

    try:
        result = subprocess.run(
            ["copilot", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        OSError,
    ):
        _supports_json_output_cache = False
        return False

    text = "\n".join(part for part in (result.stdout, result.stderr) if part)
    normalized = text.lower()
    _supports_json_output_cache = (
        "--output-format" in normalized and "json" in normalized
    )
    return _supports_json_output_cache


def _read_tail(path: Path, max_bytes: int = 262_144) -> str:
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(size - max_bytes, 0))
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _canonical_model_slug(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    value = ANSI_RE.sub("", value)
    value = value.replace("_", "-").strip().lower()
    value = re.sub(r"\s+", "-", value)
    value = re.sub(r"[^a-z0-9.+-]", "", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value


def _add_model(
    models: list[tuple[str, str]], seen: set[str], value: object
) -> None:
    if not isinstance(value, str):
        return
    label = value.strip()
    slug = _canonical_model_slug(label)
    if not slug or slug in seen:
        return
    seen.add(slug)
    models.append((slug, label))


def _merge_models(
    target: list[tuple[str, str]],
    seen: set[str],
    source: tuple[tuple[str, str], ...],
) -> None:
    for value, label in source:
        slug = _canonical_model_slug(value)
        if not slug or slug in seen:
            continue
        seen.add(slug)
        target.append((slug, label))


def _discover_models_from_files() -> tuple[tuple[str, str], ...]:
    models: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        _add_model(models, seen, value)

    if COPILOT_CONFIG_FILE.exists():
        try:
            cfg = json.loads(COPILOT_CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            cfg = {}
        for key in (
            "model",
            "default_model",
            "defaultModel",
            "selected_model",
            "selectedModel",
        ):
            add(cfg.get(key))

    if COPILOT_SESSIONS_DIR.is_dir():
        patterns = (
            re.compile(r'"model"\s*:\s*"([^"]+)"'),
            re.compile(r'(?m)^\s*model:\s*["\']?([^"\'#\s]+)'),
            re.compile(r'Using "([^"]+)" instead'),
            re.compile(r'Breakdown by AI model:\s*\n([^\s]+)'),
        )
        files = sorted(
            (
                *COPILOT_SESSIONS_DIR.glob("*/workspace.yaml"),
                *COPILOT_SESSIONS_DIR.glob("*/events.jsonl"),
            ),
            key=_mtime,
            reverse=True,
        )
        for path in files[:20]:
            text = _read_tail(path)
            for pattern in patterns:
                for match in pattern.finditer(text):
                    add(match.group(1).strip())
    return tuple(models)


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r", "\n")


def _parse_models_from_pty_output(text: str) -> tuple[tuple[str, str], ...]:
    models: list[tuple[str, str]] = []
    seen: set[str] = set()
    text = _strip_ansi(text)

    for match in MODEL_TOKEN_RE.finditer(text):
        token = match.group(1).strip(" .,:;()[]{}")
        if token.lower() in {"provider-default", "auto-model-selection"}:
            continue
        _add_model(models, seen, token)

    return tuple(models)


def _discover_models_via_pty() -> tuple[tuple[str, str], ...]:
    global _pty_model_cache
    now = time.monotonic()
    if _pty_model_cache and _pty_model_cache[0] > now:
        return _pty_model_cache[1]

    master_fd: int | None = None
    slave_fd: int | None = None
    proc: subprocess.Popen[bytes] | None = None
    chunks: list[str] = []
    models: tuple[tuple[str, str], ...] = ()

    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            ["copilot"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            start_new_session=True,
        )
        os.close(slave_fd)
        slave_fd = None

        start = time.monotonic()
        deadline = start + 8.0
        actions = [
            (start + 1.0, b"/model\r"),
            (start + 4.0, b"/exit\r"),
            (start + 6.0, b"\x03"),
        ]

        while time.monotonic() < deadline:
            if proc.poll() is not None and not chunks:
                break

            now = time.monotonic()
            while actions and now >= actions[0][0]:
                if master_fd is not None:
                    _, data = actions.pop(0)
                    try:
                        os.write(master_fd, data)
                    except OSError:
                        break

            timeout = 0.2
            if actions:
                timeout = max(0.0, min(timeout, actions[0][0] - now))

            if master_fd is None:
                break

            ready, _, _ = select.select([master_fd], [], [], timeout)
            if ready:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="replace"))

            text = "".join(chunks)
            if "/model" in text and ("gpt" in text.lower() or "claude" in text.lower()):
                if actions and actions[0][1] == b"/exit\r":
                    actions[0] = (time.monotonic() + 0.5, actions[0][1])

            if proc.poll() is not None and not ready:
                break
    except (
        FileNotFoundError,
        OSError,
        subprocess.SubprocessError,
    ):
        models = ()
    finally:
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        if slave_fd is not None:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass

    if chunks:
        models = _parse_models_from_pty_output("".join(chunks))

    _pty_model_cache = (time.monotonic() + PTY_CACHE_TTL_SECONDS, models)
    return models


def _discover_models() -> tuple[tuple[str, str], ...]:
    models: list[tuple[str, str]] = [("", "Provider default")]
    seen = {""}

    if sys.platform != "win32":
        _merge_models(models, seen, _discover_models_via_pty())
    _merge_models(models, seen, _discover_models_from_files())

    return tuple(models)


def _normalize_saved_events(events: list[dict]) -> list[dict]:
    task_descs: dict[str, str] = {}
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        msg = ev.get("message", {})
        for block in msg.get("content", []):
            if (
                block.get("type") == "tool_use"
                and block.get("name") == "task"
            ):
                inp = block.get("input", {})
                task_descs[block["id"]] = inp.get(
                    "description", "Subagent"
                )

    result = []
    for ev in events:
        etype = ev.get("type", "")

        if etype == "subagent.started":
            data = ev.get("data", {})
            tool_id = data.get("toolCallId", "")
            desc = task_descs.get(
                tool_id,
                data.get("agentDisplayName", "Subagent"),
            )
            result.append({
                "type": "system",
                "subtype": "task_started",
                "tool_use_id": tool_id,
                "description": desc,
            })
        elif etype in ("subagent.completed", "subagent.failed"):
            data = ev.get("data", {})
            result.append({
                "type": "system",
                "subtype": "task_notification",
                "tool_use_id": data.get("toolCallId", ""),
                "status": (
                    "completed"
                    if etype == "subagent.completed"
                    else "failed"
                ),
            })
        else:
            result.append(ev)

    return result


def _normalize_live_event(event: dict, challenge: dict) -> dict | None:
    etype = event.get("type", "")

    if etype == "assistant.message":
        data = event.get("data", {})
        content = []
        if data.get("reasoningText"):
            content.append({
                "type": "thinking",
                "thinking": data["reasoningText"],
            })
        if data.get("content", "").strip():
            content.append({
                "type": "text",
                "text": data["content"],
            })
        for req in data.get("toolRequests", []):
            content.append({
                "type": "tool_use",
                "id": req.get("toolCallId", ""),
                "name": req.get("name", ""),
                "input": req.get("arguments", {}),
            })
        if not content:
            return None
        descs = challenge.setdefault("_task_descs", {})
        for block in content:
            if (
                block.get("type") == "tool_use"
                and block.get("name") == "task"
            ):
                inp = block.get("input", {})
                descs[block["id"]] = inp.get(
                    "description", "Subagent"
                )
        result = {"type": "assistant", "message": {"content": content}}
        if data.get("outputTokens"):
            result["message"]["usage"] = {
                "output_tokens": data["outputTokens"]
            }
        if data.get("parentToolCallId"):
            result["parent_tool_use_id"] = data[
                "parentToolCallId"
            ]
        return result

    if etype == "tool.execution_complete":
        data = event.get("data", {})
        res = data.get("result", {})
        result = {
            "type": "user",
            "message": {
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": data.get("toolCallId", ""),
                    "content": res.get("content", ""),
                    "is_error": not res.get("success", True),
                }],
            },
        }
        if data.get("parentToolCallId"):
            result["parent_tool_use_id"] = data[
                "parentToolCallId"
            ]
        return result

    if etype == "subagent.started":
        data = event.get("data", {})
        tool_id = data.get("toolCallId", "")
        descs = challenge.get("_task_descs", {})
        desc = descs.get(
            tool_id,
            data.get("agentDisplayName", "Subagent"),
        )
        return {
            "type": "system",
            "subtype": "task_started",
            "tool_use_id": tool_id,
            "description": desc,
        }

    if etype in ("subagent.completed", "subagent.failed"):
        data = event.get("data", {})
        return {
            "type": "system",
            "subtype": "task_notification",
            "tool_use_id": data.get("toolCallId", ""),
            "status": (
                "completed"
                if etype == "subagent.completed"
                else "failed"
            ),
        }

    if etype in (
        "assistant.message_delta",
        "assistant.reasoning_delta",
        "assistant.reasoning",
        "assistant.turn_start",
        "assistant.turn_end",
        "tool.execution_start",
        "tool.execution_partial_result",
        "user.message",
    ):
        return None

    return event


def _build_command(
    challenge: dict, prompt: str, is_continue: bool
) -> list[str]:
    model = challenge["model"]
    model = COPILOT_MODEL_MAP.get(model, model)
    cmd = [
        "copilot",
        "--yolo",
    ]
    if _supports_json_output():
        cmd.extend(["--output-format", "json"])
    if model:
        cmd.extend(["--model", model])
    if is_continue:
        cmd.append("--continue")
    cmd.extend(["-p", prompt])
    return cmd


def _get_auth() -> dict | None:
    if COPILOT_CONFIG_FILE.exists():
        try:
            cfg = json.loads(COPILOT_CONFIG_FILE.read_text())
            user = cfg.get("last_logged_in_user", {})
            if user:
                return {
                    "loggedIn": True,
                    "login": user.get("login", ""),
                    "host": user.get("host", ""),
                    "model": cfg.get("model", ""),
                }
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _get_session_count() -> int:
    if COPILOT_SESSIONS_DIR.is_dir():
        return sum(
            1 for d in COPILOT_SESSIONS_DIR.iterdir()
            if d.is_dir()
        )
    return 0


def _get_usage_data() -> dict | None:
    auth = _get_auth()
    if not auth or not auth.get("loggedIn"):
        return None
    auth_rows = [
        {"label": "User", "value": auth.get("login", "")},
        {"label": "Host", "value": auth.get("host", "")},
    ]
    if auth.get("model"):
        auth_rows.append({
            "label": "Model",
            "value": auth["model"],
        })
    return {
        "auth_rows": auth_rows,
        "stat_rows": [{
            "label": "Sessions",
            "value": str(_get_session_count()),
        }],
        "daily_activity": [],
        "daily_activity_title": None,
    }


provider = AgentProvider(
    name="copilot",
    label="Copilot",
    models=(
        ("", "Provider default"),
        ("gpt-5.4", "gpt-5.4"),
        ("gpt-5.4-mini", "gpt-5.4-mini"),
        ("gpt-5.3-codex", "gpt-5.3-codex"),
        ("gpt-5.2", "gpt-5.2"),
        ("gpt-5.2-codex", "gpt-5.2-codex"),
        ("gpt-5.1", "gpt-5.1"),
        ("gpt-5.1-codex", "gpt-5.1-codex"),
        ("gpt-5.1-codex-mini", "gpt-5.1-codex-mini"),
        ("gpt-5.1-codex-max", "gpt-5.1-codex-max"),
        ("claude-opus-4.6", "claude-opus-4.6"),
        ("claude-sonnet-4.6", "claude-sonnet-4.6"),
        ("claude-haiku-4.5", "claude-haiku-4.5"),
        ("gemini-2.5-pro", "gemini-2.5-pro"),
        ("gemini-3-pro", "gemini-3-pro"),
        ("gemini-3-flash", "gemini-3-flash"),
    ),
    default_model="gpt-5.3-codex",
    auth_connect_command="copilot login",
    autonomous_default=True,
    badge_mode="label",
    build_command=_build_command,
    normalize_saved_events=_normalize_saved_events,
    normalize_live_event=_normalize_live_event,
    get_usage_data=_get_usage_data,
)
