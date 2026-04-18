from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

from .base import AgentProvider

log = logging.getLogger("ctf-solver.copilot")

COPILOT_CONFIG_FILE = Path.home() / ".copilot" / "config.json"
COPILOT_SESSIONS_DIR = Path.home() / ".copilot" / "session-state"
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

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


def _discover_models() -> tuple[tuple[str, str], ...]:
    models: list[tuple[str, str]] = [("", "Provider default")]
    seen = {""}

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


# ---------------------------------------------------------------------------
# SDK-based agent runner
# ---------------------------------------------------------------------------

_SENTINEL = object()


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
    """Run Copilot via the copilot SDK, yielding normalized events."""
    from copilot import (
        CopilotClient,
        CopilotSession,
        SessionEvent,
        PermissionRequestResult,
    )

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def _on_event(event: SessionEvent) -> None:
        """Sync callback from SDK — push event dict onto the async queue."""
        try:
            event_dict = event.to_dict() if hasattr(event, "to_dict") else {}
            loop.call_soon_threadsafe(queue.put_nowait, event_dict)
        except Exception:
            pass

    def _on_permission(req, ctx):
        return PermissionRequestResult(allow=True)

    resolved_model = COPILOT_MODEL_MAP.get(model, model) if model else ""

    client: CopilotClient | None = None
    session: CopilotSession | None = None

    try:
        client = CopilotClient()

        # Define notify_teammates tool for parallel mode
        custom_tools = []
        _pending_broadcasts: list[tuple[str, str, str]] = []
        if challenge_id and run_id:
            from copilot import define_tool, ToolInvocation

            @define_tool(
                name="notify_teammates",
                description=(
                    "Broadcast a validated breakthrough to all teammates. "
                    "Only call for confirmed, significant findings."
                ),
            )
            def notify_tool(session_ctx, invocation: ToolInvocation):
                msg = ""
                if hasattr(invocation, "args") and invocation.args:
                    msg = invocation.args.get("message", "")
                elif hasattr(invocation, "input") and invocation.input:
                    msg = invocation.input.get("message", "")
                _pending_broadcasts.append(
                    (challenge_id, run_id, msg)
                )
                return "Broadcast queued for teammates"

            custom_tools.append(notify_tool)

        session_kwargs: dict = {
            "on_permission_request": _on_permission,
            "on_event": _on_event,
            "working_directory": str(Path(cwd).resolve()),
        }
        if custom_tools:
            session_kwargs["tools"] = custom_tools
        if resolved_model:
            session_kwargs["model"] = resolved_model
        if effort and effort in ("low", "medium", "high", "xhigh"):
            session_kwargs["reasoning_effort"] = effort

        # Restore previous session for continue_session
        prev_session_id = None
        if continue_session and session_state:
            prev_session_id = session_state.get("copilot_session_id")
            if prev_session_id:
                session_kwargs["session_id"] = prev_session_id

        session = client.create_session(**session_kwargs)

        # Store session_id for future continuation
        if session_state is not None and hasattr(session, "session_id"):
            session_state["copilot_session_id"] = session.session_id

        # Send prompt (non-blocking — events arrive via on_event callback)
        session.send(prompt)

        # Consume events from the queue until the session signals completion
        done = False
        while not done:
            try:
                event_dict = await asyncio.wait_for(
                    queue.get(), timeout=600.0
                )
            except asyncio.TimeoutError:
                yield {
                    "type": "error",
                    "message": "Copilot session timed out (600s).",
                }
                break

            if event_dict is _SENTINEL:
                break

            normalized = _normalize_sdk_event(event_dict)
            if normalized is not None:
                yield normalized

            # Check for terminal event types
            ev_type = event_dict.get("type", "")
            if ev_type in (
                "result",
                "done",
                "session.end",
                "session.complete",
                "error",
            ):
                # Process outgoing broadcasts
                if _pending_broadcasts:
                    from .broadcast import broadcast_to_teammates
                    for bc_cid, bc_rid, bc_msg in _pending_broadcasts:
                        await broadcast_to_teammates(
                            bc_cid, bc_rid, bc_msg
                        )
                    _pending_broadcasts.clear()

                # Check for incoming broadcasts
                if challenge_id and run_id:
                    from .broadcast import get_pending_broadcast
                    pending = await get_pending_broadcast(
                        challenge_id, run_id
                    )
                    if pending:
                        yield {
                            "type": "system",
                            "subtype": "teammate_broadcast",
                            "message": (
                                f"[Teammate breakthrough]: {pending}"
                            ),
                        }
                        session.send(
                            f"[Teammate breakthrough]:\n{pending}\n\n"
                            "Incorporate this if relevant. "
                            "Continue working.",
                            mode="enqueue",
                        )
                        continue  # Process the new turn

                done = True

    except Exception as exc:
        log.error("Copilot SDK error: %s", exc)
        yield {"type": "error", "message": str(exc)}
    finally:
        # Drain any remaining items so the queue doesn't back-pressure
        while not queue.empty():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        # Clean up client
        if client is not None:
            try:
                if hasattr(client, "close"):
                    client.close()
                elif hasattr(client, "stop"):
                    client.stop()
                elif hasattr(client, "__del__"):
                    del client
            except Exception:
                pass


def _normalize_sdk_event(event_dict: dict) -> dict | None:
    """Convert a raw Copilot SessionEvent dict to our normalized format.

    Normalized events follow the same schema as our Claude SDK output:
      - type=assistant  with message.content blocks
      - type=user       with message.content tool_result blocks
      - type=system     for system messages / task notifications
      - type=error      for errors
      - type=result     for final result
    """
    ev_type = event_dict.get("type", "")

    # --- Assistant message ---
    if ev_type in ("assistant.message", "assistant", "message"):
        content = []
        data = event_dict.get("data", event_dict)

        # Reasoning / thinking
        reasoning = data.get("reasoningText") or data.get("thinking") or ""
        if reasoning:
            content.append({"type": "thinking", "thinking": reasoning})

        # Text content
        text = data.get("content") or data.get("text") or ""
        if isinstance(text, str) and text.strip():
            content.append({"type": "text", "text": text})
        elif isinstance(text, list):
            for block in text:
                if isinstance(block, str):
                    if block.strip():
                        content.append({"type": "text", "text": block})
                elif isinstance(block, dict):
                    content.append(block)

        # Content blocks array (if present directly)
        for block in data.get("contentBlocks", []):
            btype = block.get("type", "")
            if btype == "text" and block.get("text", "").strip():
                content.append({"type": "text", "text": block["text"]})
            elif btype == "thinking" and block.get("thinking"):
                content.append({
                    "type": "thinking",
                    "thinking": block["thinking"],
                })
            elif btype == "tool_use":
                content.append({
                    "type": "tool_use",
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "input": block.get("input", {}),
                })

        # Tool requests
        for req in data.get("toolRequests", []):
            content.append({
                "type": "tool_use",
                "id": req.get("toolCallId", req.get("id", "")),
                "name": req.get("name", ""),
                "input": req.get("arguments", req.get("input", {})),
            })

        if not content:
            return None

        result: dict = {
            "type": "assistant",
            "message": {"content": content},
        }
        output_tokens = data.get("outputTokens") or data.get(
            "usage", {}
        ).get("output_tokens")
        if output_tokens:
            result["message"]["usage"] = {
                "output_tokens": output_tokens
            }
        parent_id = (
            data.get("parentToolCallId")
            or data.get("parent_tool_use_id")
            or event_dict.get("parent_id")
        )
        if parent_id:
            result["parent_tool_use_id"] = parent_id
        return result

    # --- Tool execution result ---
    if ev_type in ("tool.execution_complete", "tool_result"):
        data = event_dict.get("data", event_dict)
        res = data.get("result", data)
        tool_use_id = (
            data.get("toolCallId")
            or data.get("tool_use_id")
            or ""
        )
        content_text = res.get("content", "")
        is_error = not res.get("success", True)
        if "is_error" in res:
            is_error = res["is_error"]

        result = {
            "type": "user",
            "message": {
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": content_text,
                    "is_error": is_error,
                }],
            },
        }
        parent_id = (
            data.get("parentToolCallId")
            or data.get("parent_tool_use_id")
            or event_dict.get("parent_id")
        )
        if parent_id:
            result["parent_tool_use_id"] = parent_id
        return result

    # --- Subagent / task events ---
    if ev_type == "subagent.started":
        data = event_dict.get("data", event_dict)
        return {
            "type": "system",
            "subtype": "task_started",
            "tool_use_id": data.get("toolCallId", ""),
            "description": data.get(
                "agentDisplayName", "Subagent"
            ),
        }

    if ev_type in ("subagent.completed", "subagent.failed"):
        data = event_dict.get("data", event_dict)
        return {
            "type": "system",
            "subtype": "task_notification",
            "tool_use_id": data.get("toolCallId", ""),
            "status": (
                "completed"
                if ev_type == "subagent.completed"
                else "failed"
            ),
        }

    # --- Error events ---
    if ev_type == "error":
        data = event_dict.get("data", event_dict)
        msg = data.get("message") or data.get("error") or str(data)
        return {"type": "error", "message": msg}

    # --- Result / done events ---
    if ev_type in ("result", "done", "session.end", "session.complete"):
        data = event_dict.get("data", event_dict)
        result = {"type": "result"}
        if data.get("result"):
            result["result"] = data["result"]
        if data.get("totalCostUsd") or data.get("total_cost_usd"):
            result["total_cost_usd"] = (
                data.get("totalCostUsd") or data.get("total_cost_usd")
            )
        return result

    # --- System messages ---
    if ev_type == "system":
        data = event_dict.get("data", event_dict)
        msg = data.get("message") or data.get("text") or ""
        if msg:
            return {"type": "system", "message": msg}
        # Pass through subtype-based system events
        if data.get("subtype"):
            return event_dict
        return None

    # --- Skip noisy / intermediate events ---
    if ev_type in (
        "assistant.message_delta",
        "assistant.reasoning_delta",
        "assistant.reasoning",
        "assistant.turn_start",
        "assistant.turn_end",
        "tool.execution_start",
        "tool.execution_partial_result",
        "user.message",
        "ping",
        "heartbeat",
    ):
        return None

    # Pass through unknown events
    return event_dict


# ---------------------------------------------------------------------------
# Auth / usage
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Provider definition
# ---------------------------------------------------------------------------

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
    run_agent=_run_agent_sdk,
    effort_levels=(
        ("", "Provider default"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("xhigh", "XHigh"),
    ),
    default_effort="high",
)
