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
CLAUDE_CREDENTIALS_FILE = Path.home() / ".claude" / ".credentials.json"
CLAUDE_USAGE_API = "https://api.anthropic.com/api/oauth/usage"


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
            return {"status": f"Broadcast sent to {count} teammate(s)"}

        mcp_servers["ctf-collab"] = create_sdk_mcp_server(
            "ctf-collab", tools=[notify_teammates]
        )

    import shutil
    system_claude = shutil.which("claude")

    _stderr_lines: list[str] = []

    def _stderr_handler(line: str) -> None:
        stripped = line.rstrip()
        log.warning("Claude CLI stderr: %s", stripped)
        _stderr_lines.append(stripped)

    options = ClaudeAgentOptions(
        permission_mode="bypassPermissions",
        cwd=str(cwd),
        model=model or None,
        effort=effort or None,
        resume=resume_session_id,
        mcp_servers=mcp_servers if mcp_servers else {},
        cli_path=system_claude,
        stderr=_stderr_handler,
        env={"IS_SANDBOX": "1"},
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
        log.error("Claude SDK error: %s", exc, exc_info=True)
        err_msg = str(exc)
        if _stderr_lines:
            err_msg += "\nstderr:\n" + "\n".join(_stderr_lines[-20:])
        yield {"type": "error", "message": err_msg}
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
        ("claude-opus-4-7", "Opus 4.7"),
        ("claude-sonnet-4-6", "Sonnet 4.6"),
        ("claude-opus-4-6", "Opus 4.6"),
        ("claude-opus-4-5-20251101", "Opus 4.5"),
        ("claude-haiku-4-5-20251001", "Haiku 4.5"),
        ("claude-sonnet-4-5-20250929", "Sonnet 4.5"),
    ),
    default_model="claude-opus-4-7",
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
    default_effort="high",
)
