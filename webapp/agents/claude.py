"""Claude provider — uses claude-agent-sdk for agent execution."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

from .base import AgentProvider

log = logging.getLogger("ctf-solver.claude")

CLAUDE_STATS_FILE = Path.home() / ".claude" / "stats-cache.json"
CLAUDE_SETTINGS_FILE = Path.home() / ".claude" / "settings.json"


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
        TextBlock,
        ThinkingBlock,
        ToolUseBlock,
        ToolResultBlock,
        create_sdk_mcp_server,
        tool,
    )
    from .broadcast import broadcast_to_teammates, get_pending_broadcast

    session_id = None
    if continue_session and session_state:
        session_id = session_state.get("claude_session_id")

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
            return {"status": f"Broadcast sent to {count} teammate(s)"}

        mcp_servers["ctf-collab"] = create_sdk_mcp_server(
            "ctf-collab", tools=[notify_teammates]
        )

    import shutil
    system_claude = shutil.which("claude")

    def _stderr_handler(line: str) -> None:
        log.warning("Claude CLI stderr: %s", line.rstrip())

    options = ClaudeAgentOptions(
        permission_mode="bypassPermissions",
        cwd=str(cwd),
        model=model or None,
        effort=effort or None,
        continue_conversation=continue_session and session_id is not None,
        session_id=session_id,
        mcp_servers=mcp_servers if mcp_servers else {},
        cli_path=system_claude,
        stderr=_stderr_handler,
    )

    client = ClaudeSDKClient(options)

    # Queue for broadcast events that the background poller discovered
    # and injected via client.query(). We yield these in the main loop
    # so the webapp can display them.
    broadcast_events: asyncio.Queue[dict] = asyncio.Queue()
    poll_task: asyncio.Task | None = None

    async def _poll_broadcasts() -> None:
        """Poll for teammate broadcasts and inject them mid-session."""
        while True:
            await asyncio.sleep(5)
            try:
                pending = await get_pending_broadcast(
                    challenge_id, run_id
                )
            except Exception:
                continue
            if not pending:
                continue
            log.info("Injecting teammate broadcast into Claude session")
            broadcast_events.put_nowait({
                "type": "system",
                "subtype": "teammate_broadcast",
                "message": f"[Teammate breakthrough]: {pending}",
            })
            try:
                await client.query(
                    f"[Teammate breakthrough received]:\n{pending}\n\n"
                    "Incorporate this into your approach if relevant. "
                    "Continue working on the challenge."
                )
            except Exception as exc:
                log.warning("Failed to inject broadcast: %s", exc)

    try:
        await client.connect(prompt)

        if challenge_id and run_id:
            poll_task = asyncio.create_task(_poll_broadcasts())

        async for msg in client.receive_messages():
            # Drain any pending broadcast events first
            while not broadcast_events.empty():
                yield broadcast_events.get_nowait()

            if isinstance(msg, AssistantMessage):
                content = []
                for block in msg.content:
                    if isinstance(block, ThinkingBlock):
                        content.append({
                            "type": "thinking",
                            "thinking": block.thinking,
                        })
                    elif isinstance(block, TextBlock):
                        content.append({
                            "type": "text",
                            "text": block.text,
                        })
                    elif isinstance(block, ToolUseBlock):
                        content.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })
                    elif isinstance(block, ToolResultBlock):
                        content.append({
                            "type": "tool_result",
                            "tool_use_id": block.tool_use_id
                            if hasattr(block, "tool_use_id")
                            else block.id
                            if hasattr(block, "id")
                            else "",
                            "content": str(block.content)
                            if hasattr(block, "content")
                            else "",
                            "is_error": getattr(block, "is_error", False),
                        })

                if not content:
                    continue

                event = {
                    "type": "assistant",
                    "message": {"content": content},
                }
                if msg.usage:
                    event["message"]["usage"] = msg.usage
                if msg.parent_tool_use_id:
                    event["parent_tool_use_id"] = msg.parent_tool_use_id
                if msg.session_id and session_state is not None:
                    session_state["claude_session_id"] = msg.session_id
                yield event

            elif isinstance(msg, UserMessage):
                content = []
                for block in msg.content:
                    if isinstance(block, ToolResultBlock):
                        content.append({
                            "type": "tool_result",
                            "tool_use_id": getattr(block, "tool_use_id", "")
                            or getattr(block, "id", ""),
                            "content": str(
                                getattr(block, "content", "")
                            ),
                            "is_error": getattr(
                                block, "is_error", False
                            ),
                        })
                    elif isinstance(block, TextBlock):
                        content.append({
                            "type": "text",
                            "text": block.text,
                        })
                if content:
                    yield {
                        "type": "user",
                        "message": {"content": content},
                    }

            elif isinstance(msg, SystemMessage):
                text = ""
                if hasattr(msg, "content"):
                    if isinstance(msg.content, str):
                        text = msg.content
                    elif isinstance(msg.content, list):
                        text = " ".join(
                            str(getattr(b, "text", b))
                            for b in msg.content
                        )
                if text:
                    yield {"type": "system", "message": text}

            elif isinstance(msg, ResultMessage):
                event = {"type": "result"}
                if msg.result:
                    event["result"] = msg.result
                if msg.total_cost_usd:
                    event["total_cost_usd"] = msg.total_cost_usd
                if msg.session_id and session_state is not None:
                    session_state["claude_session_id"] = msg.session_id
                yield event

            elif isinstance(msg, RateLimitEvent):
                info = msg.rate_limit_info
                yield {
                    "type": "rate_limit_event",
                    "rate_limit_info": {
                        "status": getattr(info, "status", ""),
                        "utilization": getattr(
                            info, "utilization", 0
                        ),
                    }
                    if info
                    else {},
                }

            elif isinstance(msg, StreamEvent):
                # Pass through raw stream events for init etc.
                event_data = msg.event or {}
                event_type = event_data.get("type", "")
                if event_type == "system" and event_data.get(
                    "subtype"
                ) == "init":
                    if session_state is not None and event_data.get(
                        "session_id"
                    ):
                        session_state["claude_session_id"] = (
                            event_data["session_id"]
                        )
                    continue
                yield event_data

    except Exception as exc:
        log.error("Claude SDK error: %s", exc)
        yield {"type": "error", "message": str(exc)}
    finally:
        if poll_task and not poll_task.done():
            poll_task.cancel()
        try:
            await client.disconnect()
        except Exception:
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
        for model, usage in stats.get("modelUsage", {}).items():
            input_tokens = usage.get("inputTokens", 0)
            input_tokens += usage.get("cacheReadInputTokens", 0)
            input_tokens += usage.get("cacheCreationInputTokens", 0)
            output_tokens = usage.get("outputTokens", 0)
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
        ("opus", "Opus"),
        ("sonnet", "Sonnet"),
        ("haiku", "Haiku"),
    ),
    default_model="opus",
    auth_connect_command="claude auth login",
    autonomous_default=False,
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
        ("max", "Max"),
    ),
    default_effort="medium",
)
