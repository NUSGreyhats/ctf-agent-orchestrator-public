from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import sys
import time

if sys.platform != "win32":
    import pty
    import select
from pathlib import Path

from .base import AgentProvider

CLAUDE_STATS_FILE = Path.home() / ".claude" / "stats-cache.json"
CLAUDE_SETTINGS_FILE = Path.home() / ".claude" / "settings.json"
CLAUDE_CLI_CACHE_TTL_SECONDS = 300
CLAUDE_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CLAUDE_MODEL_TOKEN_RE = re.compile(
    r"\b(claude-[a-z0-9.-]+|opus|sonnet|haiku)\b",
    re.IGNORECASE,
)
_cli_model_cache: tuple[float, tuple[tuple[str, str], ...]] | None = None


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


def _discover_models() -> tuple[tuple[str, str], ...]:
    models: list[tuple[str, str]] = [("", "Provider default")]
    seen = {""}

    if sys.platform != "win32":
        for value, label in _discover_models_from_cli():
            if value and value not in seen:
                seen.add(value)
                models.append((value, label))

    if CLAUDE_SETTINGS_FILE.exists():
        try:
            settings = json.loads(CLAUDE_SETTINGS_FILE.read_text())
            value = settings.get("model")
            if isinstance(value, str) and value and value not in seen:
                seen.add(value)
                models.append((value, value))
        except (json.JSONDecodeError, OSError):
            pass

    stats = _get_stats()
    if stats:
        for value in sorted(stats.get("modelUsage", {})):
            if value and value not in seen:
                seen.add(value)
                models.append((value, value))

    return tuple(models)


def _normalize_model_label(label: str) -> str:
    value = CLAUDE_ANSI_RE.sub("", label).strip().lower()
    value = re.sub(r"\s+", "", value)
    return value


def _parse_models_from_cli_output(text: str) -> tuple[tuple[str, str], ...]:
    text = CLAUDE_ANSI_RE.sub("", text).replace("\r", "\n")
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in CLAUDE_MODEL_TOKEN_RE.finditer(text):
        token = _normalize_model_label(match.group(1))
        if token in seen:
            continue
        seen.add(token)
        rows.append((token, token))
    return tuple(rows)


def _discover_models_from_cli() -> tuple[tuple[str, str], ...]:
    global _cli_model_cache
    now = time.monotonic()
    if _cli_model_cache and _cli_model_cache[0] > now:
        return _cli_model_cache[1]

    # Claude's interactive slash command is `/model` (not `/models`).
    if not shutil.which("claude"):
        _cli_model_cache = (now + CLAUDE_CLI_CACHE_TTL_SECONDS, ())
        return ()

    models: tuple[tuple[str, str], ...] = ()
    master_fd: int | None = None
    slave_fd: int | None = None
    proc: subprocess.Popen[bytes] | None = None
    chunks: list[str] = []

    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            ["claude"],
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
            now = time.monotonic()
            while actions and now >= actions[0][0]:
                if master_fd is None:
                    break
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

            if proc.poll() is not None and not ready:
                break

        if chunks:
            models = _parse_models_from_cli_output("".join(chunks))
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

    _cli_model_cache = (time.monotonic() + CLAUDE_CLI_CACHE_TTL_SECONDS, models)
    return models


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
    effort_levels=(
        ("", "Provider default"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("max", "Max"),
    ),
    default_effort="medium",
)
