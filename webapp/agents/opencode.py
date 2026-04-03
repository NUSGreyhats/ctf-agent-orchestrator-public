from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

from .base import AgentProvider

log = logging.getLogger("ctf-solver.opencode")

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


# ---------------------------------------------------------------------------
# SDK-based agent runner
# ---------------------------------------------------------------------------

_OPENCODE_SERVE_PORT = 4096
_OPENCODE_SERVE_PROC: subprocess.Popen | None = None


def _is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def _ensure_opencode_serve() -> None:
    """Start ``opencode serve`` if not already running on the expected port."""
    global _OPENCODE_SERVE_PROC

    if _is_port_open(_OPENCODE_SERVE_PORT):
        return

    # Previous process may have died — clean up handle
    if _OPENCODE_SERVE_PROC is not None:
        _OPENCODE_SERVE_PROC.poll()
        if _OPENCODE_SERVE_PROC.returncode is not None:
            _OPENCODE_SERVE_PROC = None

    if _OPENCODE_SERVE_PROC is not None:
        return

    log.info("Starting opencode serve on port %d", _OPENCODE_SERVE_PORT)
    _OPENCODE_SERVE_PROC = subprocess.Popen(
        ["opencode", "serve", "--port", str(_OPENCODE_SERVE_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for the server to become ready (up to 15 seconds)
    for _ in range(30):
        if _is_port_open(_OPENCODE_SERVE_PORT):
            log.info("opencode serve is ready")
            return
        import time
        time.sleep(0.5)

    log.warning("opencode serve did not become ready in time")


def _parse_message_parts(response: dict) -> list[dict]:
    """Extract normalized content blocks from a send_message response."""
    content_blocks: list[dict] = []

    # The response may contain the assistant message directly or nested
    # under a key like "message", "content", or "parts".
    parts = None
    if isinstance(response, dict):
        parts = (
            response.get("parts")
            or response.get("content")
            or response.get("message", {}).get("parts")
            or response.get("message", {}).get("content")
        )

    # If the response itself has a top-level text, treat the whole thing
    # as a single text response.
    if parts is None:
        text = ""
        if isinstance(response, dict):
            for key in ("text", "output", "result", "response", "content"):
                val = response.get(key)
                if isinstance(val, str) and val.strip():
                    text = val.strip()
                    break
        if text:
            content_blocks.append({"type": "text", "text": text})
        return content_blocks

    if not isinstance(parts, list):
        parts = [parts]

    for part in parts:
        if not isinstance(part, dict):
            if isinstance(part, str) and part.strip():
                content_blocks.append({"type": "text", "text": part})
            continue

        part_type = part.get("type", "")

        if part_type == "text":
            text = part.get("text", "")
            if text:
                content_blocks.append({"type": "text", "text": text})

        elif part_type == "reasoning":
            text = part.get("text", "")
            if text:
                content_blocks.append({
                    "type": "thinking",
                    "thinking": text,
                })

        elif part_type == "tool":
            tool_name = part.get("tool", part.get("name", "tool"))
            call_id = _part_call_id(part)
            state = part.get("state", {})
            status = state.get("status", "")

            if status in {"completed", "error"}:
                # Emit both the tool_use and tool_result
                if call_id:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": call_id,
                        "name": tool_name,
                        "input": state.get("input", {}),
                    })
                raw = (
                    state.get("output")
                    if status == "completed"
                    else state.get("error", "")
                )
                result_content = (
                    raw if isinstance(raw, str) else json.dumps(raw)
                )
                content_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": result_content,
                    "is_error": status == "error",
                    "name": tool_name,
                    "input": state.get("input", {}),
                })
            else:
                # Pending / running
                if call_id:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": call_id,
                        "name": tool_name,
                        "input": state.get("input", {}),
                    })

        elif part_type == "tool_use":
            call_id = _part_call_id(part)
            content_blocks.append({
                "type": "tool_use",
                "id": call_id or "",
                "name": part.get("name", part.get("tool", "tool")),
                "input": part.get("input", {}),
            })

        elif part_type == "tool_result":
            call_id = (
                part.get("tool_use_id")
                or _part_call_id(part)
            )
            content_blocks.append({
                "type": "tool_result",
                "tool_use_id": call_id or "",
                "content": part.get("content", ""),
                "is_error": part.get("is_error", False),
            })

    return content_blocks


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
    """Run OpenCode via the opencode_sdk, yielding normalized events.

    Since the SDK is synchronous (REST-based), we run blocking calls in a
    thread executor to avoid blocking the async event loop.
    """
    from opencode_sdk import OpencodeClient

    loop = asyncio.get_running_loop()

    # 1. Ensure the opencode serve process is running
    try:
        await loop.run_in_executor(None, _ensure_opencode_serve)
    except Exception as exc:
        log.error("Failed to start opencode serve: %s", exc)
        yield {"type": "error", "message": f"Failed to start opencode serve: {exc}"}
        return

    # 2. Create SDK client
    base_url = f"http://127.0.0.1:{_OPENCODE_SERVE_PORT}"
    try:
        client = OpencodeClient(base_url=base_url)
    except Exception as exc:
        log.error("Failed to create OpencodeClient: %s", exc)
        yield {"type": "error", "message": f"Failed to create OpencodeClient: {exc}"}
        return

    # 3. Create or reuse session
    session_id = None
    if continue_session and session_state:
        session_id = session_state.get("opencode_session_id")

    try:
        if session_id:
            # Reuse existing session
            log.info("Reusing OpenCode session %s", session_id)
        else:
            # Create a new session
            session = await loop.run_in_executor(
                None,
                lambda: client.create_session(title="CTF Challenge"),
            )
            session_id = session.get("id") or session.get("session_id", "")
            log.info("Created OpenCode session %s", session_id)
    except Exception as exc:
        log.error("Failed to create OpenCode session: %s", exc)
        yield {
            "type": "error",
            "message": f"Failed to create OpenCode session: {exc}",
        }
        return

    if not session_id:
        yield {
            "type": "error",
            "message": "OpenCode session creation returned no session ID",
        }
        return

    # Store session ID for future continuation
    if session_state is not None:
        session_state["opencode_session_id"] = session_id

    # 4. Send message (blocking call in executor)
    try:
        response = await loop.run_in_executor(
            None,
            lambda: client.send_message(session_id, prompt),
        )
    except Exception as exc:
        log.error("OpenCode send_message failed: %s", exc)
        yield {
            "type": "error",
            "message": f"OpenCode send_message failed: {exc}",
        }
        return

    if not isinstance(response, dict):
        # Treat non-dict response as plain text
        if response is not None:
            yield {
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": str(response)}],
                },
            }
        return

    # 5. Check for errors in response
    error = response.get("error")
    if error:
        msg = (
            _extract_error_message(error)
            if isinstance(error, dict)
            else str(error)
        )
        yield {"type": "error", "message": msg or "OpenCode error"}
        return

    # 6. Parse response into normalized events
    content_blocks = _parse_message_parts(response)

    # Separate tool_use/tool_result blocks from text/thinking blocks
    # to emit them as properly typed events
    assistant_content: list[dict] = []
    tool_result_content: list[dict] = []

    for block in content_blocks:
        if block["type"] == "tool_result":
            # First, flush any accumulated assistant content
            if assistant_content:
                yield {
                    "type": "assistant",
                    "message": {"content": assistant_content},
                }
                assistant_content = []
            tool_result_content.append(block)
        elif block["type"] == "tool_use":
            # tool_use goes as assistant content
            assistant_content.append(block)
            # Flush tool_use immediately so it appears before its result
            yield {
                "type": "assistant",
                "message": {"content": assistant_content},
            }
            assistant_content = []
        else:
            # text or thinking blocks
            assistant_content.append(block)

    # Flush remaining assistant content
    if assistant_content:
        yield {
            "type": "assistant",
            "message": {"content": assistant_content},
        }

    # Emit tool results as user messages (matching the convention)
    for block in tool_result_content:
        yield {
            "type": "user",
            "message": {"content": [block]},
        }

    # 7. Process outgoing broadcasts from notify_teammates tool
    if challenge_id and run_id:
        from .broadcast import broadcast_to_teammates, get_pending_broadcast
        # Read the shared queue file (written by TS tool)
        # Use atomic rename to claim the file and prevent race conditions
        shared_dir = Path(cwd) / "_shared"
        queue_file = shared_dir / ".notify_queue"
        claimed_file = shared_dir / f".notify_queue.claimed.{run_id}"
        async def _process_queue_file(src: Path) -> None:
            """Read broadcasts from a queue file and forward them."""
            if not src.exists():
                return
            # Claim by renaming to a unique temp name
            tmp = shared_dir / f".notify_processing.{run_id}"
            try:
                src.rename(tmp)
            except FileNotFoundError:
                return  # Another run claimed it
            try:
                for line in tmp.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("|", 1)
                    msg = parts[1] if len(parts) > 1 else parts[0]
                    await broadcast_to_teammates(
                        challenge_id, run_id, msg
                    )
                tmp.unlink(missing_ok=True)
            except Exception as exc:
                log.warning("Failed to process notify queue: %s", exc)
                # Leave the file for next pass — don't delete unread data

        # Process any stranded claimed file first, then the fresh queue
        await _process_queue_file(claimed_file)
        await _process_queue_file(queue_file)

        # 8. Check for incoming broadcasts and process follow-up turns
        while True:
            pending = await get_pending_broadcast(challenge_id, run_id)
            if not pending:
                break
            yield {
                "type": "system",
                "subtype": "teammate_broadcast",
                "message": f"[Teammate breakthrough]: {pending}",
            }
            try:
                followup_text = (
                    f"[Teammate breakthrough]:\n{pending}\n\n"
                    "Incorporate this if relevant. Continue working."
                )
                followup_resp = await loop.run_in_executor(
                    None,
                    lambda: client.send_message(session_id, followup_text),
                )
                # Parse and yield the follow-up response
                if followup_resp is not None and not isinstance(followup_resp, dict):
                    yield {
                        "type": "assistant",
                        "message": {"content": [{"type": "text", "text": str(followup_resp)}]},
                    }
                elif isinstance(followup_resp, dict):
                    fu_error = followup_resp.get("error")
                    if fu_error:
                        err_msg = (
                            _extract_error_message(fu_error)
                            if isinstance(fu_error, dict)
                            else str(fu_error)
                        )
                        yield {"type": "error", "message": err_msg or "OpenCode follow-up error"}
                        break
                    fu_blocks = _parse_message_parts(followup_resp)
                    fu_assistant = [b for b in fu_blocks if b["type"] not in ("tool_result",)]
                    fu_results = [b for b in fu_blocks if b["type"] == "tool_result"]
                    if fu_assistant:
                        yield {"type": "assistant", "message": {"content": fu_assistant}}
                    for b in fu_results:
                        yield {"type": "user", "message": {"content": [b]}}
                # Re-process outgoing queue after follow-up
                await _process_queue_file(queue_file)
            except Exception as exc:
                log.warning("Failed to send broadcast to OpenCode: %s", exc)
                break


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
    run_agent=_run_agent_sdk,
)
