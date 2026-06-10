"""Claude provider — uses claude-agent-sdk for agent execution."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from .base import AgentProvider

log = logging.getLogger("ctf-solver.claude")

CLAUDE_STATS_FILE = Path.home() / ".claude" / "stats-cache.json"
CLAUDE_SETTINGS_FILE = Path.home() / ".claude" / "settings.json"
CLAUDE_CREDENTIALS_FILE = Path.home() / ".claude" / ".credentials.json"
CLAUDE_USAGE_API = "https://api.anthropic.com/api/oauth/usage"

# Claude CLI `system` message subtypes that are internal status noise. These
# carry no useful human-readable text, so the parser would otherwise fall back
# to rendering the bare subtype string as a yellow status pill in the UI.
# Add new offenders here as they surface.
_DROP_SYSTEM_SUBTYPES = {
    "thinking_tokens",
}


def _session_wrapper_path(real_cli: str) -> str:
    """Return an executable wrapper that starts Claude in a new session."""
    digest = hashlib.sha256(real_cli.encode()).hexdigest()[:16]
    path = Path(tempfile.gettempdir()) / f"ctf-agent-claude-{digest}.py"
    content = (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import sys\n"
        f"REAL_CLI = {real_cli!r}\n"
        "os.setsid()\n"
        "os.execv(REAL_CLI, [REAL_CLI, *sys.argv[1:]])\n"
    )
    try:
        if not path.exists() or path.read_text() != content:
            path.write_text(content)
            path.chmod(0o700)
    except OSError:
        return real_cli
    return str(path)


# ---------------------------------------------------------------------------
# SDK-based agent runner
# ---------------------------------------------------------------------------

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
    """Run Claude via the agent SDK, yielding normalized events."""
    from claude_agent_sdk import (
        ClaudeSDKClient,
        ClaudeAgentOptions,
        AssistantMessage,
        UserMessage,
        SystemMessage,
        ResultMessage,
        StreamEvent,
        RateLimitEvent,
        TaskStartedMessage,
        TaskNotificationMessage,
        TaskProgressMessage,
        TextBlock,
        ThinkingBlock,
        ToolUseBlock,
        ToolResultBlock,
        ServerToolUseBlock,
        ServerToolResultBlock,
        create_sdk_mcp_server,
        tool,
    )
    from .broadcast import broadcast_to_teammates, get_pending_broadcast

    resume_session_id = None
    if continue_session and session_state:
        resume_session_id = session_state.get("claude_session_id")

    # Create notify_teammates MCP tool
    mcp_servers = {}
    if challenge_id and run_id:
        @tool(
            "notify_teammates",
            "Broadcast a validated breakthrough to all teammates. "
            "Only call this for confirmed, significant findings.",
            {"type": "object", "properties": {"message": {"type": "string", "description": "The breakthrough finding"}}, "required": ["message"]},
        )
        async def notify_teammates(params):
            msg = params.get("message", "")
            count = await broadcast_to_teammates(challenge_id, run_id, msg)
            return {"content": [{"type": "text", "text": f"Broadcast sent to {count} teammate(s)"}]}

        mcp_servers["ctf-collab"] = create_sdk_mcp_server(
            "ctf-collab", tools=[notify_teammates]
        )

    # Advisor tools: app.py passes a dict of name -> {description, schema, fn}.
    # Each is exposed as an MCP tool dispatched in-process (same pattern as
    # notify_teammates), giving the advisor read access to solver transcripts
    # and a relay to the broadcast bus.
    advisor_tools = kwargs.get("_advisor_tools") or {}
    if advisor_tools:
        adv_mcp_tools = []
        for tname, spec in advisor_tools.items():
            fn = spec["fn"]

            def _make(fn):
                async def _handler(params):
                    text = await fn(params or {})
                    return {"content": [{"type": "text", "text": str(text)}]}
                return _handler

            adv_mcp_tools.append(tool(
                tname, spec.get("description", ""),
                spec.get("schema", {"type": "object", "properties": {}}),
            )(_make(fn)))
        if adv_mcp_tools:
            mcp_servers["advisor"] = create_sdk_mcp_server(
                "advisor", tools=adv_mcp_tools)

    import shutil
    system_claude = shutil.which("claude")
    cli_path = _session_wrapper_path(system_claude) if system_claude else None

    _stderr_lines: list[str] = []

    def _stderr_handler(line: str) -> None:
        stripped = line.rstrip()
        log.warning("Claude CLI stderr: %s", stripped)
        _stderr_lines.append(stripped)

    claude_env = {"IS_SANDBOX": "1"}
    for key in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        value = os.environ.get(key, "")
        if value:
            claude_env[key] = value
    for key, value in (kwargs.get("_env") or {}).items():
        if key in {"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"} and value:
            claude_env[key] = str(value)

    options = ClaudeAgentOptions(
        permission_mode="bypassPermissions",
        cwd=str(cwd),
        model=model or None,
        effort=effort or None,
        resume=resume_session_id if resume_session_id else None,
        mcp_servers=mcp_servers if mcp_servers else {},
        cli_path=cli_path,
        stderr=_stderr_handler,
        env=claude_env,
    )

    def _normalize_msg(msg) -> dict | None:
        """Convert an SDK message to our normalized event dict."""
        if isinstance(msg, AssistantMessage):
            content = []
            for block in msg.content:
                if isinstance(block, ThinkingBlock):
                    content.append({"type": "thinking", "thinking": block.thinking})
                elif isinstance(block, TextBlock):
                    content.append({"type": "text", "text": block.text})
                elif isinstance(block, ToolUseBlock):
                    content.append({
                        "type": "tool_use", "id": block.id,
                        "name": block.name, "input": block.input,
                    })
                elif isinstance(block, ToolResultBlock):
                    content.append({
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "tool_use_id", "") or getattr(block, "id", ""),
                        "content": str(getattr(block, "content", "")),
                        "is_error": getattr(block, "is_error", False),
                    })
                elif isinstance(block, ServerToolUseBlock):
                    content.append({
                        "type": "tool_use", "id": block.id,
                        "name": block.name, "input": block.input,
                        "server": True,
                    })
                elif isinstance(block, ServerToolResultBlock):
                    content.append({
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "tool_use_id", ""),
                        "content": str(getattr(block, "content", "")),
                        "server": True,
                    })
            if msg.error:
                content.append({
                    "type": "text",
                    "text": f"[API Error: {msg.error}]",
                })
            if not content:
                return None
            event = {"type": "assistant", "message": {"content": content}}
            if msg.usage:
                event["message"]["usage"] = msg.usage
            if msg.parent_tool_use_id:
                event["parent_tool_use_id"] = msg.parent_tool_use_id
            if msg.session_id and session_state is not None:
                session_state["claude_session_id"] = msg.session_id
            return event

        elif isinstance(msg, UserMessage):
            # UserMessage.content is normally a list of blocks. The CLI also
            # echoes back user turns we sent with plain-string content (the
            # initial prompt and broadcast injections) as a raw str. Those
            # are already rendered in the UI by app.py (the "user_prompt" and
            # "teammate_broadcast" events), so drop the echo here. Guard
            # explicitly — iterating a str would yield characters, not blocks.
            if isinstance(msg.content, str):
                return None
            content = []
            for block in msg.content:
                if isinstance(block, ToolResultBlock):
                    content.append({
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "tool_use_id", "") or getattr(block, "id", ""),
                        "content": str(getattr(block, "content", "")),
                        "is_error": getattr(block, "is_error", False),
                    })
                elif isinstance(block, TextBlock):
                    content.append({"type": "text", "text": block.text})
            if content:
                return {"type": "user", "message": {"content": content}}

        elif isinstance(msg, TaskStartedMessage):
            desc = getattr(msg, "description", "") or ""
            task_type = getattr(msg, "task_type", "") or ""
            label = desc or task_type or "background task"
            return {"type": "system", "message": f"Started {label}"}

        elif isinstance(msg, TaskNotificationMessage):
            status = getattr(msg, "status", "")
            summary = getattr(msg, "summary", "")
            return {"type": "system", "message": f"Task {status}: {summary}" if summary else f"Task {status}"}

        elif isinstance(msg, TaskProgressMessage):
            return None

        elif isinstance(msg, SystemMessage):
            subtype = getattr(msg, "subtype", "")
            data = getattr(msg, "data", {}) or {}
            if session_state is not None and data.get("session_id"):
                session_state["claude_session_id"] = data["session_id"]
            if subtype == "init":
                return None
            # Skip internal status subtypes that would otherwise render as
            # yellow status pills in the UI (see _DROP_SYSTEM_SUBTYPES).
            if subtype in _DROP_SYSTEM_SUBTYPES:
                log.debug("Dropping blacklisted Claude system subtype: %s", subtype)
                return None
            text = data.get("message", "") or subtype
            if text:
                return {"type": "system", "message": text}

        elif isinstance(msg, ResultMessage):
            event: dict = {"type": "result", "subtype": msg.subtype}
            if msg.is_error:
                event["is_error"] = True
            if msg.errors:
                event["errors"] = msg.errors
            if msg.api_error_status:
                event["api_error_status"] = msg.api_error_status
            if msg.result:
                event["result"] = msg.result
            if msg.total_cost_usd:
                event["total_cost_usd"] = msg.total_cost_usd
            if msg.usage:
                event["usage"] = msg.usage
            if msg.num_turns:
                event["num_turns"] = msg.num_turns
            if msg.duration_ms:
                event["duration_ms"] = msg.duration_ms
            if msg.duration_api_ms:
                event["duration_api_ms"] = msg.duration_api_ms
            if msg.model_usage:
                event["model_usage"] = msg.model_usage
            if msg.session_id and session_state is not None:
                session_state["claude_session_id"] = msg.session_id
            return event

        elif isinstance(msg, RateLimitEvent):
            info = msg.rate_limit_info
            if not info:
                return None
            status = getattr(info, "status", "")
            resets_at = getattr(info, "resets_at", None)
            rate_type = getattr(info, "rate_limit_type", "")
            utilization = getattr(info, "utilization", None)
            event = {
                "type": "rate_limit_event",
                "rate_limit_info": {
                    "status": status,
                    "utilization": utilization,
                    "resets_at": resets_at,
                    "rate_limit_type": rate_type,
                },
            }
            if status == "rejected":
                import time as _time
                wait_msg = ""
                if resets_at:
                    wait_secs = max(0, resets_at - _time.time())
                    wait_msg = f" (resets in {int(wait_secs)}s)"
                event["_also_system"] = {
                    "type": "system",
                    "message": f"Rate limited{wait_msg} — waiting for capacity",
                }
            return event

        elif isinstance(msg, StreamEvent):
            event_data = msg.event or {}
            event_type = event_data.get("type", "")
            if event_type == "system" and event_data.get("subtype") == "init":
                if session_state is not None and event_data.get("session_id"):
                    session_state["claude_session_id"] = event_data["session_id"]
                return None
            return event_data

        return None

    # Queue for broadcast messages to inject via streaming input.
    # Messages yielded by the generator are queued by the SDK and
    # delivered after Claude finishes its current tool call — no
    # interruption, no lost work.
    _broadcast_queue: asyncio.Queue[str] = asyncio.Queue()
    _broadcast_ui_events: asyncio.Queue[dict] = asyncio.Queue()
    _poll_task: asyncio.Task | None = None

    async def _poll_broadcasts():
        while True:
            await asyncio.sleep(5)
            try:
                pending = await get_pending_broadcast(challenge_id, run_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
            if not pending:
                continue
            log.info("Queuing broadcast for Claude streaming input")
            _broadcast_ui_events.put_nowait({
                "type": "system",
                "subtype": "teammate_broadcast",
                "message": f"[Teammate breakthrough]: {pending}",
            })
            await _broadcast_queue.put(pending)

    async def _message_stream():
        """Async generator that yields the initial prompt and any broadcasts."""
        yield {
            "type": "user",
            "message": {"role": "user", "content": prompt},
        }
        while True:
            pending = await _broadcast_queue.get()
            yield {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": (
                        f"[Teammate breakthrough received]:\n{pending}\n\n"
                        "Incorporate this into your approach if relevant. "
                        "Continue working on the challenge."
                    ),
                },
            }

    client = ClaudeSDKClient(options)
    try:
        # Store ref so caller can kill process if needed
        _run = kwargs.get("_run")
        if _run is not None:
            _run["_sdk_client"] = client

        if challenge_id and run_id:
            _poll_task = asyncio.create_task(_poll_broadcasts())

        # connect() with async generator spawns stream_input as a
        # background task — messages are delivered between tool calls.
        await client.connect(_message_stream())
        if _run is not None:
            transport = getattr(client, "_transport", None)
            proc = getattr(transport, "_process", None) if transport else None
            pid = getattr(proc, "pid", None)
            if pid:
                _run["_agent_root_pid"] = pid
                try:
                    _run["_agent_pgid"] = os.getpgid(pid)
                except OSError:
                    _run["_agent_pgid"] = None

        async for msg in client.receive_messages():
                # Drain broadcast UI events
                while not _broadcast_ui_events.empty():
                    yield _broadcast_ui_events.get_nowait()

                event = _normalize_msg(msg)
                if event:
                    also = event.pop("_also_system", None)
                    yield event
                    if also:
                        yield also

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error("Claude SDK error: %s", exc, exc_info=True)
        err_msg = str(exc)
        if _stderr_lines:
            err_msg += "\nstderr:\n" + "\n".join(_stderr_lines[-20:])
        yield {"type": "error", "message": err_msg}
    finally:
        if _poll_task and not _poll_task.done():
            _poll_task.cancel()
        try:
            await asyncio.wait_for(client.disconnect(), timeout=10)
        except (Exception, asyncio.CancelledError, asyncio.TimeoutError):
            pass


# ---------------------------------------------------------------------------
# CLI fallback (build_command for legacy/subprocess path)
# ---------------------------------------------------------------------------

def _build_command(
    challenge: dict, prompt: str, is_continue: bool
) -> list[str]:
    cmd = [
        "claude",
        "-p",
        "--dangerously-skip-permissions",
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    if challenge.get("model"):
        cmd.extend(["--model", challenge["model"]])
    if challenge.get("effort"):
        cmd.extend(["--effort", challenge["effort"]])
    if is_continue:
        cmd.append("--continue")
    cmd.append(prompt)
    return cmd


def _normalize_saved_events(events: list[dict]) -> list[dict]:
    return events


def _normalize_live_event(event: dict, challenge: dict) -> dict | None:
    return event


# ---------------------------------------------------------------------------
# Auth / usage
# ---------------------------------------------------------------------------

def _get_auth() -> dict | None:
    try:
        result = subprocess.run(
            ["claude", "auth", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        json.JSONDecodeError,
    ):
        pass
    return None


def _get_stats() -> dict | None:
    if CLAUDE_STATS_FILE.exists():
        try:
            return json.loads(CLAUDE_STATS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _get_oauth_token() -> str | None:
    if not CLAUDE_CREDENTIALS_FILE.exists():
        return None
    try:
        creds = json.loads(CLAUDE_CREDENTIALS_FILE.read_text())
        return creds.get("claudeAiOauth", {}).get("accessToken")
    except (json.JSONDecodeError, OSError):
        return None


def _fetch_usage_api() -> dict | None:
    import requests

    token = _get_oauth_token()
    if not token:
        return None
    try:
        resp = requests.get(
            CLAUDE_USAGE_API,
            headers={
                "Authorization": f"Bearer {token}",
                "anthropic-beta": "oauth-2025-04-20",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        log.debug("Failed to fetch Claude usage API", exc_info=True)
    return None


def _format_reset_time(iso_str: str | None) -> str:
    if not iso_str:
        return ""
    try:
        from datetime import datetime, timezone
        reset = datetime.fromisoformat(iso_str)
        now = datetime.now(timezone.utc)
        delta = reset - now
        secs = int(delta.total_seconds())
        if secs <= 0:
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
    except Exception:
        return ""


def _get_usage_data() -> dict | None:
    auth = _get_auth()
    if not auth or not auth.get("loggedIn"):
        return None

    data = {
        "auth_rows": [
            {"label": "Account", "value": auth.get("email", "")},
            {
                "label": "Plan",
                "value": auth.get("subscriptionType", ""),
            },
            {"label": "Org", "value": auth.get("orgName", "")},
        ],
        "stat_rows": [],
        "daily_activity": [],
        "daily_activity_title": "Daily Activity (Claude)",
    }

    usage_api = _fetch_usage_api()
    if usage_api:
        five = usage_api.get("five_hour") or {}
        seven = usage_api.get("seven_day") or {}
        if "utilization" in five:
            reset = _format_reset_time(five.get("resets_at"))
            label = "5h usage"
            if reset:
                label += f" (resets in {reset})"
            data["stat_rows"].append({
                "label": label,
                "value": f"{five['utilization']:.0f}%",
                "bar": five["utilization"],
            })
        if "utilization" in seven:
            reset = _format_reset_time(seven.get("resets_at"))
            label = "Weekly usage"
            if reset:
                label += f" (resets in {reset})"
            data["stat_rows"].append({
                "label": label,
                "value": f"{seven['utilization']:.0f}%",
                "bar": seven["utilization"],
            })

        for key, display in (
            ("seven_day_opus", "Opus weekly"),
            ("seven_day_sonnet", "Sonnet weekly"),
        ):
            bucket = usage_api.get(key)
            if bucket and "utilization" in bucket:
                reset = _format_reset_time(bucket.get("resets_at"))
                label = display
                if reset:
                    label += f" (resets in {reset})"
                data["stat_rows"].append({
                    "label": label,
                    "value": f"{bucket['utilization']:.0f}%",
                    "bar": bucket["utilization"],
                })

        extra = usage_api.get("extra_usage") or {}
        if extra.get("is_enabled"):
            used = extra.get("used_credits", 0)
            limit = extra.get("monthly_limit", 0)
            currency = extra.get("currency", "USD")
            pct = extra.get("utilization", 0)
            data["stat_rows"].append({
                "label": "Extra usage credits",
                "value": f"{currency} {used:,.0f} / {limit:,.0f}",
                "bar": pct,
            })

    stats = _get_stats()
    if stats:
        total_sessions = stats.get("totalSessions", 0)
        total_messages = stats.get("totalMessages", 0)
        if total_sessions:
            data["stat_rows"].append({
                "label": "Sessions",
                "value": str(total_sessions),
            })
        if total_messages:
            data["stat_rows"].append({
                "label": "Messages",
                "value": f"{total_messages:,}",
            })
        for model, tok_usage in stats.get("modelUsage", {}).items():
            input_tokens = tok_usage.get("inputTokens", 0)
            input_tokens += tok_usage.get("cacheReadInputTokens", 0)
            input_tokens += tok_usage.get("cacheCreationInputTokens", 0)
            output_tokens = tok_usage.get("outputTokens", 0)
            total_tokens = input_tokens + output_tokens
            data["stat_rows"].append({
                "label": model,
                "value": (
                    f"{total_tokens / 1000:.0f}k tokens "
                    f"({input_tokens / 1000:.0f}k in / "
                    f"{output_tokens / 1000:.0f}k out)"
                ),
            })
        data["daily_activity"] = stats.get("dailyActivity", [])
    return data


# ---------------------------------------------------------------------------
# Provider definition
# ---------------------------------------------------------------------------

provider = AgentProvider(
    name="claude",
    label="Claude",
    models=(
        ("", "Provider default"),
        ("claude-fable-5", "Fable 5"),
        ("claude-opus-4-8", "Opus 4.8"),
        ("claude-opus-4-7", "Opus 4.7"),
        ("claude-sonnet-4-6", "Sonnet 4.6"),
        ("claude-opus-4-6", "Opus 4.6"),
        ("claude-opus-4-6[1m]", "Opus 4.6 (1M)"),
        ("claude-opus-4-5-20251101", "Opus 4.5"),
        ("claude-haiku-4-5-20251001", "Haiku 4.5"),
        ("claude-sonnet-4-5-20250929", "Sonnet 4.5"),
    ),
    default_model="claude-opus-4-6",
    auth_connect_command="claude auth login",
    badge_mode="model",
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
        ("max", "Max"),
    ),
    default_effort="high",
)
