#!/usr/bin/env python3
"""CTF Challenge Solver Web App.

Runs coding-agent integrations to solve CTF challenges, streaming
normalized output to authenticated users via WebSocket.

Supports 2 solving modes:
- single: One run.
- parallel: Multiple runs (one per agent). Auto-stop on solve.
"""

import asyncio
import base64
import copy
import difflib
import hashlib
import io
import ipaddress
import json
import logging
import math
import os
import re
import zipfile

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("ctf-solver")
import mimetypes
import pty
import secrets
import signal
import subprocess
import shutil
import tempfile
import uuid
import time as _time
from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlparse

try:
    from .discord_bot import (
        get_bot, make_thread_name, make_challenge_embed,
        make_solve_embed, make_stop_embed, DiscordBot, DiscordGateway,
        make_category_name, make_challenge_channel_name, _truncate,
    )
except ImportError:
    from discord_bot import (
        get_bot, make_thread_name, make_challenge_embed,
        make_solve_embed, make_stop_embed, DiscordBot, DiscordGateway,
        make_category_name, make_challenge_channel_name, _truncate,
    )

try:
    from .agents import (
        DEFAULT_AGENT,
        PARALLEL_AGENT_VALUE,
        PROVIDERS,
        VALID_AGENTS,
        get_provider,
    )
except ImportError:
    from agents import (  # type: ignore
        DEFAULT_AGENT,
        PARALLEL_AGENT_VALUE,
        PROVIDERS,
        VALID_AGENTS,
        get_provider,
    )
try:
    from .plugins import get_plugins, get_plugin
    from .plugins.base import RemoteFile, RemoteFileTooLarge, format_bytes
except ImportError:
    from plugins import get_plugins, get_plugin  # type: ignore
    from plugins.base import RemoteFile, RemoteFileTooLarge, format_bytes  # type: ignore

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, Response
from starlette.routing import Route, WebSocketRoute, Mount
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect

APP_PASSWORD = os.environ["APP_PASSWORD"]
SESSION_SECRET = os.environ["SESSION_SECRET"]
if len(SESSION_SECRET) < 32:
    raise ValueError(
        "SESSION_SECRET must be at least 32 characters. "
        "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
    )
TLS_ENABLED = bool(os.environ.get("TLS_CERTFILE"))
ALLOWED_ORIGINS = {
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
}
APP_ROOT_DIR = Path(os.environ.get("APP_ROOT_DIR", "/root/ctf-agent-wrapper"))
CHALLENGES_DIR = APP_ROOT_DIR / "challenges"
CHALLENGES_DIR.mkdir(parents=True, exist_ok=True)
STATE_ROOT_DIR = APP_ROOT_DIR / "state"
STATE_ROOT_DIR.mkdir(parents=True, exist_ok=True)

# Rate limiting for login
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_login_attempts: dict[str, list[float]] = defaultdict(list)

HISTORY_TOOL_OUTPUT_PREVIEW_CHARS = int(os.environ.get(
    "HISTORY_TOOL_OUTPUT_PREVIEW_CHARS", "12000"
))
RUN_EVENT_MEMORY_TAIL = max(0, int(os.environ.get(
    "RUN_EVENT_MEMORY_TAIL", "200"
)))
WS_SEND_TIMEOUT_SECONDS = float(os.environ.get("WS_SEND_TIMEOUT_SECONDS", "2"))

challenges: dict[str, dict] = {}
_instance_locks: dict[str, asyncio.Lock] = {}

CONNECTIONS_FILE = STATE_ROOT_DIR / "connections.json"
DEFAULT_MAX_PLATFORM_IMPORT_SIZE_GB = 2.0
BYTES_PER_GIB = 1024 ** 3
DEFAULT_DISCORD_CHALLENGE_LAYOUT = "threads"
VALID_DISCORD_CHALLENGE_LAYOUTS = {"threads", "channels"}
DISCORD_COMPONENT_PREFIX = "ctf"
DISCORD_BUTTON_ACTIONS = {
    "status",
    "stats",
    "tail",
    "flags",
    "submit",
    "solved",
    "stop",
    "resume",
}
DISCORD_FLAG_REVIEW_ACTIONS = {
    "flag_submit",
    "flag_reject",
    "flag_correct",
    "flag_broadcast",
}
AUTH_SESSION_TTL_SECONDS = 10 * 60
AUTH_STATUS_TIMEOUT_SECONDS = 8
AUTH_COMMANDS = {
    "claude": {
        "default": ("claude", "auth", "login"),
    },
    "codex": {
        "default": ("codex", "login", "--device-auth"),
    },
}
AUTH_STATUS_COMMANDS = {
    "claude": ("claude", "auth", "status", "--json"),
    "codex": ("codex", "login", "status"),
}
_agent_auth_sessions: dict[str, dict] = {}


def load_connections() -> list[dict]:
    if CONNECTIONS_FILE.exists():
        try:
            data = json.loads(CONNECTIONS_FILE.read_text())
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def save_connections(connections: list[dict]) -> None:
    CONNECTIONS_FILE.write_text(json.dumps(connections, indent=2))


def plugin_connection_identity(config: dict) -> str:
    identity = str_field(config.get("username", ""))
    if identity:
        return identity
    for key in ("token", "team_token"):
        value = str_field(config.get(key, ""))
        if value:
            return value[:8] + "..."
    return ""


def plugin_connection_id(plugin_name: str, source_url: str, config: dict) -> str:
    return f"{plugin_name}:{source_url}:{plugin_connection_identity(config)}"


def source_urls_match(left: str, right: str) -> bool:
    return str_field(left).rstrip("/") == str_field(right).rstrip("/")


def save_plugin_connection(
    plugin_name: str,
    plugin,
    config: dict,
    source_url: str,
) -> str:
    """Persist plugin credentials and return the stable connection id."""
    connections = load_connections()
    identity = plugin_connection_identity(config)
    conn_id = plugin_connection_id(plugin_name, source_url, config)
    label_suffix = f" ({identity})" if identity and "..." not in identity else ""
    existing = next(
        (c for c in connections if c.get("id") == conn_id),
        None,
    )
    if existing:
        existing["config"] = config
        existing["last_sync"] = utc_now_iso()
    else:
        connections.append({
            "id": conn_id,
            "plugin": plugin_name,
            "label": f"{plugin.label} — {source_url}{label_suffix}",
            "config": config,
            "last_sync": utc_now_iso(),
        })
    save_connections(connections)
    return conn_id


def load_agent_env_auth() -> dict:
    """Load persisted provider environment credentials."""
    if AGENT_ENV_AUTH_FILE.exists():
        try:
            data = json.loads(AGENT_ENV_AUTH_FILE.read_text())
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_agent_env_auth(data: dict) -> None:
    """Persist provider environment credentials with owner-only perms."""
    AGENT_ENV_AUTH_FILE.write_text(json.dumps(data, indent=2))
    try:
        AGENT_ENV_AUTH_FILE.chmod(0o600)
    except OSError:
        pass


def _stored_agent_env_auth(agent: str) -> dict:
    data = load_agent_env_auth()
    entry = data.get(agent)
    return entry if isinstance(entry, dict) else {}


def agent_runtime_env(agent: str) -> dict[str, str]:
    """Return persisted/process env vars needed by a provider at runtime."""
    env: dict[str, str] = {}
    if agent != "claude":
        return env
    stored = _stored_agent_env_auth(agent)
    for key in CLAUDE_ENV_AUTH_KEYS:
        value = str_field(stored.get(key, "")).strip()
        if not value:
            value = os.environ.get(key, "").strip()
        if value:
            env[key] = value
    return env


def public_agent_env_auth(agent: str) -> dict:
    """Return non-secret env credential metadata for the UI/status API."""
    if agent != "claude":
        return {"supported": False, "configured": False}
    stored = _stored_agent_env_auth(agent)
    runtime = agent_runtime_env(agent)
    stored_token = bool(str_field(stored.get("ANTHROPIC_AUTH_TOKEN", "")).strip())
    process_token = bool(os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip())
    stored_value = any(
        str_field(stored.get(key, "")).strip()
        for key in CLAUDE_ENV_AUTH_KEYS
    )
    source = "stored" if stored_token else "process" if process_token else ""
    return {
        "supported": True,
        "configured": bool(runtime.get("ANTHROPIC_AUTH_TOKEN")),
        "base_url": runtime.get("ANTHROPIC_BASE_URL", ""),
        "token_set": bool(runtime.get("ANTHROPIC_AUTH_TOKEN")),
        "saved": stored_value,
        "source": source,
    }


def utc_now_iso() -> str:
    """Return an explicit UTC timestamp for browser-safe JSON metadata."""
    return datetime.now(timezone.utc).isoformat()


def _imported_remote_ids(plugin_name: str, source_url: str = "") -> set[str]:
    """Return set of remote_ids already imported from a plugin+source."""
    ids = set()
    for c in challenges.values():
        if c.get("_plugin") != plugin_name:
            continue
        if source_url and c.get("_source_url", "") != source_url:
            continue
        if c.get("_remote_id"):
            ids.add(c["_remote_id"])
    return ids


def _resolve_plugin_config(challenge: dict) -> tuple:
    """Resolve plugin instance and config for a challenge.

    Returns (plugin, config) or (None, {}) if not available.
    """
    plugin_name = challenge.get("_plugin")
    remote_id = challenge.get("_remote_id")
    if not plugin_name or not remote_id:
        return None, {}

    plugin = get_plugin(plugin_name)
    if not plugin:
        return None, {}

    conn_id = challenge.get("_connection_id", "")
    source_url = challenge.get("_source_url", "")
    for conn in load_connections():
        if conn_id and conn.get("id") == conn_id:
            return plugin, conn["config"]
        if conn.get("plugin") == plugin_name and source_url:
            try:
                conn_src = plugin.source_url(conn.get("config", {}))
            except Exception:
                continue
            if source_urls_match(conn_src, source_url):
                return plugin, conn["config"]

    return None, {}


VALID_MODES = {"single", "parallel"}

_FLAG_PATTERNS = [
    re.compile(r"picoCTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"HTB\{[^}]+\}", re.IGNORECASE),
]
CTFGREP_DEFAULT_TERMS = ("flag{", "ctf{", "picoCTF{", "HTB{")
CTFGREP_MAX_TERMS = 6
CTFGREP_CANDIDATE_INNER_MAX = 100
CTFGREP_TIMEOUT_SECONDS = 60
CTFGREP_AUTO_SUBMIT_WAIT_SECONDS = 10


def normalize_flag_format(value: str) -> str:
    """Normalize a user-provided flag format placeholder."""
    return str(value or "").strip()


def _unique_strings(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        item = str(value or "").strip()
        if not item:
            continue
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def challenge_flag_formats(challenge: dict) -> list[str]:
    """Return all configured flag formats for a challenge."""
    formats = [challenge.get("flag_format", "")]
    extra = challenge.get("extra_flag_formats", [])
    if isinstance(extra, list):
        formats.extend(str(item) for item in extra)
    return _unique_strings(formats)


def add_challenge_flag_format(challenge: dict, flag_format: str) -> tuple[bool, str]:
    """Add a flag format to a challenge, preserving the legacy primary field."""
    normalized = normalize_flag_format(flag_format)
    if not normalized:
        raise ValueError("flag format required")
    existing = {item.casefold() for item in challenge_flag_formats(challenge)}
    if normalized.casefold() in existing:
        return False, normalized
    if not str(challenge.get("flag_format", "")).strip():
        challenge["flag_format"] = normalized
    else:
        extra = challenge.setdefault("extra_flag_formats", [])
        if not isinstance(extra, list):
            extra = []
            challenge["extra_flag_formats"] = extra
        extra.append(normalized)
    return True, normalized


def _flag_format_prefix(flag_format: str) -> str:
    text = normalize_flag_format(flag_format)
    return text.split("{", 1)[0].strip() if "{" in text else text


def flag_lookup_key(flag: str) -> str:
    """Return a case-insensitive key for comparing flag strings."""
    return str(flag).casefold()


def detected_flag_key(detected: dict, flag: str) -> str:
    """Return the existing detected flag key matching flag, ignoring case."""
    wanted = flag_lookup_key(flag)
    for existing in detected:
        if flag_lookup_key(existing) == wanted:
            return existing
    return flag


def set_detected_flag_status(challenge: dict, flag: str, status: str) -> str:
    """Set detected flag status using case-insensitive flag identity."""
    detected = challenge.setdefault("detected_flags", {})
    key = detected_flag_key(detected, flag)
    detected[key] = status
    ensure_detected_flag_meta(challenge, key)
    return key


def _empty_detected_flag_meta() -> dict:
    return {
        "sources": [],
        "submissions": [],
    }


def ensure_detected_flag_meta(challenge: dict, flag: str) -> dict:
    """Return sidecar metadata for a detected flag, preserving old maps."""
    meta_map = challenge.setdefault("detected_flag_meta", {})
    key = detected_flag_key(meta_map, flag)
    if key != flag and key in meta_map:
        meta_map[flag] = meta_map.pop(key)
    meta = meta_map.setdefault(flag, _empty_detected_flag_meta())
    if not isinstance(meta.get("sources"), list):
        meta["sources"] = []
    if not isinstance(meta.get("submissions"), list):
        meta["submissions"] = []
    return meta


def detected_flag_meta(challenge: dict, flag: str) -> dict:
    key = detected_flag_key(challenge.setdefault("detected_flags", {}), flag)
    return ensure_detected_flag_meta(challenge, key)


def _event_source_timestamp(event: dict | None) -> str:
    if not isinstance(event, dict):
        return utc_now_iso()
    for key in ("timestamp", "created_at", "time"):
        value = event.get(key)
        if value:
            return str(value)
    return utc_now_iso()


def record_detected_flag_source(
    challenge: dict,
    flag: str,
    *,
    run_id: str = "",
    agent: str = "",
    event: dict | None = None,
    event_index: int | None = None,
    source_type: str = "detected",
) -> tuple[str, bool]:
    """Attach source traceability to a flag candidate."""
    stored_flag = detected_flag_key(challenge.setdefault("detected_flags", {}), flag)
    meta = ensure_detected_flag_meta(challenge, stored_flag)
    if "created_at" not in meta:
        meta["created_at"] = utc_now_iso()
    meta["updated_at"] = utc_now_iso()

    event_type = event.get("type", "") if isinstance(event, dict) else ""
    source = {
        "type": source_type,
        "run_id": run_id,
        "agent": agent,
        "event_index": event_index if isinstance(event_index, int) else None,
        "event_type": event_type,
        "timestamp": _event_source_timestamp(event),
    }
    for existing in meta["sources"]:
        if (
            existing.get("type") == source["type"]
            and existing.get("run_id") == source["run_id"]
            and existing.get("event_index") == source["event_index"]
        ):
            return stored_flag, False
    meta["sources"].append(source)
    return stored_flag, True


def record_flag_submission(
    challenge: dict,
    flag: str,
    *,
    submitted_flag: str = "",
    run_id: str = "",
    flag_id: str | int | None = None,
    question: int | None = None,
    correct: bool = False,
    message: str = "",
    auto: bool = False,
    manual_mark: bool = False,
) -> str:
    """Attach submission history and target slot metadata to a flag."""
    stored_flag = detected_flag_key(challenge.setdefault("detected_flags", {}), flag)
    meta = ensure_detected_flag_meta(challenge, stored_flag)
    if "created_at" not in meta:
        meta["created_at"] = utc_now_iso()
    now = utc_now_iso()
    if flag_id not in (None, ""):
        meta["flag_id"] = flag_id
    if question:
        meta["question"] = question
    meta["last_submitted_at"] = now
    meta["last_message"] = message
    meta["last_correct"] = bool(correct)
    meta["updated_at"] = now
    meta["submissions"].append({
        "at": now,
        "run_id": run_id,
        "flag_id": flag_id,
        "question": question,
        "submitted_flag": submitted_flag or flag,
        "correct": bool(correct),
        "message": message,
        "auto": bool(auto),
        "manual_mark": bool(manual_mark),
    })
    return stored_flag


def normalize_flag_for_submission(flag: str, flag_format: str | list[str] = "") -> str:
    """Match the configured flag prefix casing before remote submission."""
    if not flag_format or "{" not in flag:
        return flag
    formats = flag_format if isinstance(flag_format, list) else [flag_format]
    flag_prefix, rest = flag.split("{", 1)
    for item in formats:
        if "{" not in item:
            continue
        format_prefix = item.split("{", 1)[0]
        if len(format_prefix) < 2:
            continue
        if flag_lookup_key(flag_prefix) == flag_lookup_key(format_prefix):
            return f"{format_prefix}{{{rest}"
    return flag


def flag_patterns(flag_formats: list[str] | None = None) -> list[re.Pattern]:
    """Return default flag regexes plus regexes derived from configured formats."""
    patterns = list(_FLAG_PATTERNS)
    seen_prefixes = set()
    for flag_format in flag_formats or []:
        prefix = _flag_format_prefix(flag_format)
        if len(prefix) >= 2:
            key = prefix.casefold()
            if key in seen_prefixes:
                continue
            seen_prefixes.add(key)
            patterns.append(
                re.compile(
                    re.escape(prefix) + r"\{[^}]+\}",
                    re.IGNORECASE,
                )
            )
    return patterns


def detect_flags(text: str, flag_formats: list[str] | None = None) -> list[str]:
    """Return all unique flags found in text."""
    if not text:
        return []
    patterns = flag_patterns(flag_formats)
    placeholders = {item.casefold() for item in flag_formats or [] if item}
    found: list[str] = []
    seen = set()
    for pat in patterns:
        for m in pat.finditer(text):
            candidate = m.group(0)
            key = flag_lookup_key(candidate)
            if key in placeholders or key in seen:
                continue
            seen.add(key)
            found.append(candidate)
    return found


def detect_flag(text: str, flag_format: str = "") -> str | None:
    """Return the first flag found in text, or None."""
    flags = detect_flags(text, [flag_format] if flag_format else [])
    return flags[0] if flags else None

METADATA_FILE = "challenge.json"
OUTPUT_FILE = "output.jsonl"
SETTINGS_FILE = CHALLENGES_DIR / "settings.json"
AGENT_ENV_AUTH_FILE = STATE_ROOT_DIR / "agent-env-auth.json"
CLAUDE_ENV_AUTH_KEYS = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN")
REPO_SKILLS_DIR = APP_ROOT_DIR / "skills"
ALL_SKILLS_DIR = APP_ROOT_DIR / "all-skills"
PROJECT_SKILL_DIRS = (
    Path(".claude") / "skills",
    Path(".codex") / "skills",
)
SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
MAX_SKILL_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_SKILL_UPLOAD_FILES = 300
VALID_HOOKS = {"rtk"}
_PREVIEW_TTL = 3600
_bulk_previews: dict[str, dict] = {}
_platform_import_progress: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Challenge status derivation
# ---------------------------------------------------------------------------

def derive_challenge_status(challenge: dict) -> str:
    """Derive challenge-level status from run statuses."""
    statuses = {r["status"] for r in challenge["runs"].values()}
    if not statuses:
        return "pending"
    if "solved" in statuses:
        return "solved"
    if "solving" in statuses:
        return "solving"
    if "pending" in statuses:
        return "pending"
    if statuses <= {"failed"}:
        return "failed"
    if "completed" in statuses and not (statuses - {"completed", "failed"}):
        return "completed"
    return "failed"


# ---------------------------------------------------------------------------
# Run helpers
# ---------------------------------------------------------------------------

def bind_run_process_group(run: dict, pid: int | None) -> None:
    if not pid:
        return
    run["_agent_root_pid"] = int(pid)
    try:
        run["_agent_pgid"] = os.getpgid(int(pid))
    except ProcessLookupError:
        run["_agent_pgid"] = None
    except OSError as exc:
        log.debug("Could not read process group for pid %s: %s", pid, exc)
        run["_agent_pgid"] = None


def _valid_run_pgid(run: dict) -> int | None:
    pgid = run.get("_agent_pgid")
    if not isinstance(pgid, int) or pgid <= 1:
        return None
    try:
        if pgid == os.getpgrp():
            return None
    except OSError:
        return None
    return pgid


def _process_group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


async def _terminate_run_process_group(run: dict, timeout: float = 5.0) -> bool:
    pgid = _valid_run_pgid(run)
    if not pgid:
        return False
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError as exc:
        log.warning("Failed to terminate process group %s: %s", pgid, exc)
        return False

    deadline = _time.monotonic() + timeout
    proc = run.get("process")
    while _time.monotonic() < deadline:
        if proc and getattr(proc, "returncode", None) is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=0.2)
                return True
            except asyncio.TimeoutError:
                pass
        elif not _process_group_alive(pgid):
            return True
        await asyncio.sleep(0.1)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        log.warning("Failed to kill process group %s: %s", pgid, exc)
        return False
    return True


async def stop_run(run: dict, reason: str = "user_stop") -> None:
    """Stop a run — handles CLI (process), SDK (task), and remote swarm runs."""
    proc = run.get("process")
    task = run.get("task")
    swarm_proc = run.get("_swarm_proc")
    has_active = (
        (proc and proc.returncode is None)
        or (task and not task.done())
        or (swarm_proc is not None and swarm_proc.returncode is None)
    )

    if not has_active:
        return

    # Set BEFORE terminating so the finalizer sees it during unwind
    run["_stop_reason"] = reason

    # Remote swarm run: ask the worker to wind down over the SSH control channel.
    if swarm_proc is not None and swarm_proc.returncode is None:
        try:
            from .swarm_exec import stop_remote_run
        except ImportError:
            from swarm_exec import stop_remote_run
        await stop_remote_run(run, reason)

    group_stopped = await _terminate_run_process_group(run)
    if not group_stopped and proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=5)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass


async def apply_solved_status(
    challenge_id: str,
    challenge: dict,
    flag: str = "",
    run_id: str = "",
    stop_reason: str = "solved",
) -> tuple[str | None, dict | None]:
    """Mark a challenge solved, stop active runs, and broadcast status.

    This is shared by the web UI, platform submit endpoints, and Discord
    commands so all solve paths persist and notify consistently.
    """
    runs = challenge.get("runs", {})
    if not runs:
        return None, None

    target_run_id = run_id if run_id in runs else ""
    if not target_run_id:
        for status in ("solving", "completed", "failed", "pending", "solved"):
            target_run_id = next(
                (rid for rid, run in runs.items() if run.get("status") == status),
                "",
            )
            if target_run_id:
                break
    if not target_run_id:
        target_run_id = next(iter(runs), "")
    if not target_run_id:
        return None, None

    target_run = runs[target_run_id]
    if flag:
        set_detected_flag_status(challenge, flag, "correct")

    target_run["status"] = "solved"
    target_run["error"] = None
    await stop_run(target_run, stop_reason)
    finish_run_timer(target_run)

    changed_run_ids = {target_run_id}
    if challenge.get("mode") == "parallel":
        for other_id, other_run in runs.items():
            if other_id == target_run_id:
                continue
            if other_run.get("status") not in ("solving", "pending"):
                continue
            other_run["status"] = "failed"
            other_run["error"] = None
            stop_event = {
                "type": "system",
                "message": (
                    f"Stopped: {target_run.get('agent', '?')} solved "
                    "the challenge."
                ),
            }
            await _append_run_event(challenge_id, other_id, other_run, stop_event)
            await stop_run(other_run, "sibling_solved")
            finish_run_timer(other_run)
            changed_run_ids.add(other_id)

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)

    for changed_id in changed_run_ids:
        changed_run = runs[changed_id]
        await broadcast(challenge_id, changed_id, {
            "type": "run_status",
            "run_id": changed_id,
            "status": changed_run["status"],
            "error": changed_run.get("error"),
            "duration_ms": effective_run_duration_ms(changed_run),
        })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    return target_run_id, target_run


def make_run(
    run_id: str,
    agent: str,
    model: str,
    effort: str,
    status: str = "pending",
) -> dict:
    """Create a new run dict with all required fields."""
    return {
        "id": run_id,
        "agent": agent,
        "model": model,
        "effort": effort,
        "status": status,
        "process": None,
        "task": None,
        "output_lines": [],
        "_event_count": 0,
        "ws_clients": set(),
        "error": None,
        "solve_start": None,
        "duration_ms": None,
        "_codex_thread_id": None,
        "_saw_provider_message": False,
        "_last_stream_error": None,
        "_last_stderr_lines": [],
        "_last_unknown_events": [],
        "_agent_root_pid": None,
        "_agent_pgid": None,
        "_submit_token": secrets.token_urlsafe(24),
        "goal": None,
    }


def normalize_run_goal(goal: object, provider: str = "") -> dict | None:
    if not isinstance(goal, dict):
        return None

    def text_field(name: str, camel_name: str | None = None) -> str:
        value = goal.get(name)
        if value is None and camel_name:
            value = goal.get(camel_name)
        return value.strip() if isinstance(value, str) else ""

    def int_field(name: str, camel_name: str | None = None) -> int | None:
        value = goal.get(name)
        if value is None and camel_name:
            value = goal.get(camel_name)
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return int(value)
        return None

    normalized = {
        "provider": text_field("provider") or provider,
        "thread_id": text_field("thread_id", "threadId"),
        "objective": text_field("objective"),
        "status": text_field("status"),
        "token_budget": int_field("token_budget", "tokenBudget"),
        "tokens_used": int_field("tokens_used", "tokensUsed"),
        "time_used_seconds": int_field("time_used_seconds", "timeUsedSeconds"),
        "created_at": int_field("created_at", "createdAt"),
        "updated_at": int_field("updated_at", "updatedAt"),
    }
    normalized = {
        key: value for key, value in normalized.items()
        if value not in ("", None)
    }
    if not normalized.get("objective") and not normalized.get("status"):
        return None
    return normalized


def run_codex_thread_id(run: dict) -> str:
    session_state = run.get("_session_state") or {}
    thread_id = session_state.get("codex_thread_id")
    if isinstance(thread_id, str) and thread_id:
        return thread_id
    thread_id = run.get("_codex_thread_id")
    return thread_id if isinstance(thread_id, str) else ""


def run_goal_editable(run: dict) -> bool:
    return run.get("agent") == "codex" and bool(run_codex_thread_id(run))


def apply_run_goal_event(run: dict, event: dict) -> bool:
    if event.get("type") != "run_goal":
        return False
    provider = str(event.get("provider") or run.get("agent") or "")
    run["goal"] = normalize_run_goal(event.get("goal"), provider)
    return True


def effective_run_duration_ms(run: dict) -> int:
    """Return cumulative active runtime, including the current active segment."""
    base = int(run.get("duration_ms") or 0)
    solve_start = run.get("solve_start")
    if solve_start is not None:
        try:
            base += int(max(0, _time.monotonic() - float(solve_start)) * 1000)
        except (TypeError, ValueError):
            pass
    return base


def run_elapsed_seconds(run: dict) -> float:
    return round(effective_run_duration_ms(run) / 1000, 1)


def start_run_timer(run: dict, reset: bool = False) -> None:
    if reset:
        run["duration_ms"] = 0
    run["solve_start"] = _time.monotonic()


def finish_run_timer(run: dict) -> None:
    if run.get("solve_start") is not None:
        run["duration_ms"] = effective_run_duration_ms(run)
        run["solve_start"] = None
    elif run.get("duration_ms") is None:
        run["duration_ms"] = 0


def assign_notes_labels(runs: dict[str, dict]) -> None:
    """Assign unique notes_label for WORKING_NOTES filenames in parallel mode."""
    counts: dict[str, int] = {}
    for r in runs.values():
        counts[r["agent"]] = counts.get(r["agent"], 0) + 1
    indices: dict[str, int] = {}
    for r in runs.values():
        if r.get("notes_label"):
            continue
        a = r["agent"]
        if counts[a] > 1:
            idx = indices.get(a, 0) + 1
            indices[a] = idx
            r["notes_label"] = f"{a}-{idx}"
        else:
            r["notes_label"] = a


def run_notes_filename(challenge: dict, run: dict) -> str:
    if challenge.get("mode") == "parallel":
        return f"WORKING_NOTES_{run.get('notes_label', run['agent'])}.md"
    return "WORKING_NOTES.md"


def public_run_summary(
    challenge: dict,
    run: dict,
    settings: dict | None = None,
) -> dict:
    summary = {
        "id": run["id"],
        "agent": run["agent"],
        "model": run["model"],
        "effort": run.get("effort", ""),
        "status": run["status"],
        "error": run.get("error"),
        "duration_ms": effective_run_duration_ms(run),
        "enabled_skills": run_enabled_skills(challenge, run, settings),
        "skill_override": run_has_skill_override(run),
        "goal": normalize_run_goal(run.get("goal"), str(run.get("agent") or "")),
        "goal_editable": run_goal_editable(run),
    }
    if run.get("custom_prompt"):
        summary["custom_prompt"] = run["custom_prompt"]
        summary["custom_prompt_mode"] = run.get("custom_prompt_mode", "append")
    return summary


def public_run_list_summary(run: dict) -> dict:
    """Small run shape for dashboard cards."""
    return {
        "id": run["id"],
        "agent": run["agent"],
        "model": run["model"],
        "effort": run.get("effort", ""),
        "status": run["status"],
        "duration_ms": effective_run_duration_ms(run),
    }


def working_notes_template(label: str) -> str:
    return (
        f"# Working Notes — {label}\n"
        "## Challenge Understanding\n"
        "## Hypotheses\n"
        "[ ] untested  [x] failed  [>] active\n"
        "## Key Findings\n"
        "## Tools & Techniques Tried\n"
        "## Dead Ends\n"
        "## Next Steps\n"
    )


def get_run_cwd(challenge_id: str, run: dict) -> Path:
    """Return the working directory for a run.

    New challenges use clean per-run workspaces for all modes. Legacy
    single-run challenges may not have _runs/{run_id}; keep those working
    by falling back to the challenge root.
    """
    challenge = challenges[challenge_id]
    run_dir = CHALLENGES_DIR / challenge_id / "_runs" / run["id"]
    if run_dir.exists() or challenge["mode"] == "parallel":
        return run_dir
    return CHALLENGES_DIR / challenge_id


def seed_working_notes(challenge_id: str, run: dict) -> Path:
    """Create this run's expected working notes file if it is missing."""
    challenge = challenges[challenge_id]
    notes_path = get_run_cwd(challenge_id, run) / run_notes_filename(challenge, run)
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    if not notes_path.exists():
        notes_path.write_text(
            working_notes_template(run.get("notes_label", run["agent"]))
        )
    return notes_path


def setup_parallel_shared_dir(challenge_id: str) -> Path:
    """Create the shared directory for parallel challenges."""
    shared_dir = CHALLENGES_DIR / challenge_id / "_shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    return shared_dir


def _symlink_challenge_files(files_dir: Path, challenge_files_dir: Path) -> None:
    """Populate challenge_files/ with symlinks to files under _files/.

    The provider cwd stays clean while agents can still browse challenge
    files through a dedicated data directory.
    """
    challenge_files_dir.mkdir(parents=True, exist_ok=True)
    if not files_dir.exists():
        return

    for item in files_dir.rglob("*"):
        rel = item.relative_to(files_dir)
        dest = challenge_files_dir / rel
        if item.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        if not item.is_file():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() or dest.is_symlink():
            continue
        dest.symlink_to(item)


def setup_run_dir(challenge_id: str, run_id: str) -> Path:
    """Create a clean provider working directory for a run."""
    challenge_dir = CHALLENGES_DIR / challenge_id
    files_dir = challenge_dir / "_files"
    shared_dir = challenge_dir / "_shared"
    run_dir = challenge_dir / "_runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    _symlink_challenge_files(files_dir, run_dir / "challenge_files")

    shared_link = run_dir / "_shared"
    if shared_dir.exists() and not shared_link.exists():
        shared_link.symlink_to(shared_dir)

    return run_dir


def setup_parallel_run_dir(challenge_id: str, run_id: str) -> Path:
    """Compatibility wrapper for existing parallel-mode call sites."""
    return setup_run_dir(challenge_id, run_id)


def ensure_run_submit_token(run: dict) -> str:
    token = run.get("_submit_token")
    if not token:
        token = secrets.token_urlsafe(24)
        run["_submit_token"] = token
    return token


def write_submit_answer_helper(challenge_id: str, run_id: str) -> None:
    """Write a local helper agents can use to submit arbitrary answers."""
    challenge = challenges.get(challenge_id)
    if not challenge or not challenge.get("_plugin") or not challenge.get("_remote_id"):
        return
    run = challenge.get("runs", {}).get(run_id)
    if not run:
        return
    token = ensure_run_submit_token(run)
    run_dir = get_run_cwd(challenge_id, run)
    scheme = "https" if TLS_ENABLED else "http"
    helper = run_dir / "submit_answer.py"
    helper.write_text(f'''#!/usr/bin/env python3
"""Submit candidate answers for this platform challenge.

Examples:
  ./submit_answer.py --answer 'HTB{{...}}'
  ./submit_answer.py --question 1 --answer 'candidate answer'
  ./submit_answer.py --flag-id 12345 --answer 'candidate answer'
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

URL = {json.dumps(f"{scheme}://127.0.0.1:443/api/agent/submit-answer")}
CHALLENGE_ID = {json.dumps(challenge_id)}
RUN_ID = {json.dumps(run_id)}
TOKEN = {json.dumps(token)}

parser = argparse.ArgumentParser(description="Submit a candidate answer")
parser.add_argument("--question", type=int, help="1-based question number")
parser.add_argument("--flag-id", help="platform flag/question id")
parser.add_argument("--answer", required=True, help="candidate answer/flag")
args = parser.parse_args()

payload = {{
    "challenge_id": CHALLENGE_ID,
    "run_id": RUN_ID,
    "token": TOKEN,
    "answer": args.answer,
}}
if args.question is not None:
    payload["question"] = args.question
if args.flag_id:
    payload["flag_id"] = args.flag_id

req = urllib.request.Request(
    URL,
    data=json.dumps(payload).encode(),
    headers={{"Content-Type": "application/json"}},
    method="POST",
)
ctx = ssl._create_unverified_context() if URL.startswith("https://") else None
try:
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        data = json.loads(resp.read().decode())
except urllib.error.HTTPError as exc:
    try:
        data = json.loads(exc.read().decode())
    except Exception:
        data = {{"error": str(exc)}}
    print(json.dumps(data, indent=2))
    sys.exit(1)

print(json.dumps(data, indent=2))
sys.exit(0)
''')
    helper.chmod(0o700)


def setup_parallel_cross_notes(challenge_id: str, runs: dict | None = None) -> None:
    """Symlink each agent's WORKING_NOTES into other agents' run dirs.

    Also seeds each agent's own notes file so symlinks never dangle.
    """
    if runs is None:
        challenge = challenges.get(challenge_id)
        if not challenge:
            return
        runs = challenge["runs"]
    runs_dir = CHALLENGES_DIR / challenge_id / "_runs"
    run_items = list(runs.items())

    # Seed each agent's own notes file so cross-symlinks resolve
    for rid, run in run_items:
        run_dir = runs_dir / rid
        if not run_dir.exists():
            continue
        label = run.get("notes_label", run["agent"])
        own_notes = run_dir / f"WORKING_NOTES_{label}.md"
        if not own_notes.exists():
            legacy_notes = run_dir / "WORKING_NOTES.md"
            if legacy_notes.exists():
                own_notes.write_text(legacy_notes.read_text(errors="replace"))
            else:
                own_notes.write_text(working_notes_template(label))

    # Cross-link: symlink each teammate's notes into this run dir
    for rid, run in run_items:
        run_dir = runs_dir / rid
        if not run_dir.exists():
            continue
        for other_rid, other_run in run_items:
            if other_rid == rid:
                continue
            notes_name = f"WORKING_NOTES_{other_run.get('notes_label', other_run['agent'])}.md"
            other_notes = runs_dir / other_rid / notes_name
            link = run_dir / notes_name
            if not link.exists():
                link.symlink_to(other_notes)


# ---------------------------------------------------------------------------
# Bulk preview cleanup
# ---------------------------------------------------------------------------

def _cleanup_old_previews() -> None:
    now = _time.monotonic()
    expired = [
        t for t, p in _bulk_previews.items()
        if now - p["created_at"] > _PREVIEW_TTL
    ]
    for token in expired:
        base_dir = _bulk_previews.pop(token)["base_dir"]
        shutil.rmtree(base_dir, ignore_errors=True)


_PARALLEL_RESERVED = {"_shared", "_runs", "_files", ".last_seen_breakthroughs"}


def normalize_uploaded_path(raw_path: str, parallel: bool = False) -> str | None:
    """Normalize an uploaded relative path and reject unsafe values."""
    if not raw_path:
        return None

    raw_path = raw_path.replace("\\", "/")
    parts = []
    for part in raw_path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            return None
        parts.append(part)

    if not parts:
        return None
    if parts[0] == STATE_ROOT_DIR.name:
        return None
    # Block reserved names only in parallel mode
    if parallel:
        if parts[0] in _PARALLEL_RESERVED or parts[0].startswith("WORKING_NOTES_"):
            return None
    return "/".join(parts)


# ---------------------------------------------------------------------------
# Provider state helpers
# ---------------------------------------------------------------------------

def provider_state_for_metadata(run: dict) -> dict:
    """Extract provider-specific state from a run dict."""
    state = {}
    if run.get("_codex_thread_id"):
        state["codex_thread_id"] = run["_codex_thread_id"]
    return state


# ---------------------------------------------------------------------------
# State directories and persistence
# ---------------------------------------------------------------------------

def challenge_state_dir(challenge_id: str) -> Path:
    return STATE_ROOT_DIR / challenge_id


def metadata_path(challenge_id: str) -> Path:
    new_path = challenge_state_dir(challenge_id) / METADATA_FILE
    legacy_candidates = [
        CHALLENGES_DIR / challenge_id / METADATA_FILE,
        CHALLENGES_DIR / challenge_id / ".ctf-solver" / METADATA_FILE,
    ]
    for legacy_path in legacy_candidates:
        if legacy_path.exists() and not new_path.exists():
            return legacy_path
    if new_path.exists():
        return new_path
    return legacy_candidates[0]


def ensure_state_dir(challenge_id: str) -> Path:
    path = challenge_state_dir(challenge_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def migrate_legacy_state(challenge_id: str) -> None:
    state_dir = ensure_state_dir(challenge_id)
    legacy_dirs = [
        CHALLENGES_DIR / challenge_id,
        CHALLENGES_DIR / challenge_id / ".ctf-solver",
    ]
    for name in (METADATA_FILE, OUTPUT_FILE):
        new = state_dir / name
        for legacy_dir in legacy_dirs:
            legacy = legacy_dir / name
            if not legacy.exists():
                continue
            if new.exists():
                legacy.unlink()
            else:
                legacy.replace(new)
            break
    hidden_dir = CHALLENGES_DIR / challenge_id / ".ctf-solver"
    if hidden_dir.exists():
        shutil.rmtree(hidden_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Output log persistence — per-run
# ---------------------------------------------------------------------------

def _run_output_path(challenge_id: str, run_id: str) -> Path:
    """Return the path for a run's output log."""
    return ensure_state_dir(challenge_id) / f"{run_id}.jsonl"


def _legacy_output_log_path(challenge_id: str) -> Path:
    """Legacy output log path (pre-runs)."""
    new_path = challenge_state_dir(challenge_id) / OUTPUT_FILE
    legacy_candidates = [
        CHALLENGES_DIR / challenge_id / OUTPUT_FILE,
        CHALLENGES_DIR / challenge_id / ".ctf-solver" / OUTPUT_FILE,
    ]
    for legacy_path in legacy_candidates:
        if legacy_path.exists() and not new_path.exists():
            return legacy_path
    if new_path.exists():
        return new_path
    return legacy_candidates[0]


def append_output_event(challenge_id: str, run_id: str, event: dict) -> None:
    """Append a single event to the run's output log on disk."""
    if challenge_id not in challenges:
        return
    if challenges[challenge_id].get("_deleted"):
        return
    out_path = _run_output_path(challenge_id, run_id)
    with out_path.open("a") as f:
        json.dump(event, f)
        f.write("\n")


def clear_output_log(challenge_id: str, run_id: str) -> None:
    """Clear the output log file for a fresh run."""
    out_path = _run_output_path(challenge_id, run_id)
    if out_path.exists():
        out_path.unlink()


def iter_output_log_indexed(challenge_id: str, run_id: str):
    """Yield (event_index, event) pairs from a run JSONL log.

    The event index is the non-empty JSONL line index. Invalid lines are skipped
    as events but still advance the index, keeping full-output refs stable.
    """
    out_path = _run_output_path(challenge_id, run_id)
    if not out_path.exists():
        return
    with out_path.open() as f:
        event_index = 0
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event_index += 1
                continue
            yield event_index, event
            event_index += 1


def iter_output_log_events(challenge_id: str, run_id: str):
    """Yield saved output events from disk for a specific run."""
    for _idx, event in iter_output_log_indexed(challenge_id, run_id):
        yield event


def count_output_log_events(challenge_id: str, run_id: str) -> int:
    """Count non-empty JSONL records without materializing the transcript."""
    out_path = _run_output_path(challenge_id, run_id)
    if not out_path.exists():
        return 0
    count = 0
    with out_path.open() as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def load_output_log_slice(
    challenge_id: str,
    run_id: str,
    start: int,
    end: int,
) -> list[tuple[int, dict]]:
    """Load saved events in [start, end) without reading the whole log."""
    if end <= start:
        return []
    selected = []
    for event_index, event in iter_output_log_indexed(challenge_id, run_id):
        if event_index < start:
            continue
        if event_index >= end:
            break
        selected.append((event_index, event))
    return selected


def _tail_nonempty_jsonl_lines(path: Path, limit: int) -> list[str]:
    """Read the last non-empty JSONL lines without scanning from the start."""
    if limit <= 0 or not path.exists():
        return []
    lines: deque[bytes] = deque(maxlen=limit)
    chunk_size = 64 * 1024
    remainder = b""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        while pos > 0 and len(lines) < limit:
            read_size = min(chunk_size, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size) + remainder
            parts = chunk.splitlines()
            if pos > 0:
                remainder = parts[0] if parts else b""
                parts = parts[1:]
            else:
                remainder = b""
            for raw in reversed(parts):
                if raw.strip():
                    lines.appendleft(raw)
                    if len(lines) >= limit:
                        break
        if pos == 0 and remainder.strip() and len(lines) < limit:
            lines.appendleft(remainder)
    return [line.decode("utf-8", errors="replace") for line in lines]


def load_output_log_tail_slice(
    challenge_id: str,
    run_id: str,
    total: int,
    limit: int,
) -> list[tuple[int, dict]]:
    """Load the latest saved events without reading the whole log."""
    out_path = _run_output_path(challenge_id, run_id)
    raw_lines = _tail_nonempty_jsonl_lines(out_path, limit)
    start = max(0, total - len(raw_lines))
    selected = []
    for offset, line in enumerate(raw_lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        selected.append((start + offset, event))
    return selected


def load_output_log_event(
    challenge_id: str,
    run_id: str,
    event_index: int,
) -> dict | None:
    """Load one saved event by event index."""
    if event_index < 0:
        return None
    for idx, event in iter_output_log_indexed(challenge_id, run_id):
        if idx == event_index:
            return event
        if idx > event_index:
            break
    return None


def tail_output_log_events(
    challenge_id: str,
    run_id: str,
    limit: int,
    *,
    skip_types: set[str] | None = None,
) -> list[tuple[int, dict]]:
    """Return the last `limit` events, optionally skipping event types."""
    if limit <= 0:
        return []
    tail = deque(maxlen=limit)
    for event_index, event in iter_output_log_indexed(challenge_id, run_id):
        if skip_types and event.get("type") in skip_types:
            continue
        tail.append((event_index, event))
    return list(tail)


def load_output_log(challenge_id: str, run_id: str) -> list[dict]:
    """Load saved output events from disk for a specific run."""
    events = [
        event for _idx, event in iter_output_log_indexed(challenge_id, run_id)
    ]
    return events


def run_event_count(challenge_id: str, run_id: str, run: dict) -> int:
    """Return the total persisted event count for a run."""
    count = run.get("_event_count")
    if isinstance(count, int) and count >= 0:
        return count
    count = count_output_log_events(challenge_id, run_id)
    run["_event_count"] = count
    return count


def _remember_run_event_tail(
    challenge_id: str,
    run_id: str,
    run: dict,
    event: dict,
    event_index: int,
) -> None:
    """Keep a compact bounded event tail for live UI state only."""
    if RUN_EVENT_MEMORY_TAIL <= 0:
        run["output_lines"] = []
        return
    tail = run.setdefault("output_lines", [])
    tail.append(compact_history_event(challenge_id, run_id, event, event_index))
    overflow = len(tail) - RUN_EVENT_MEMORY_TAIL
    if overflow > 0:
        del tail[:overflow]


def record_run_event(
    challenge_id: str,
    run_id: str,
    run: dict,
    event: dict,
) -> int:
    """Persist a full event and retain only a compact bounded in-memory tail."""
    event_index = run_event_count(challenge_id, run_id, run)
    append_output_event(challenge_id, run_id, event)
    run["_event_count"] = event_index + 1
    _remember_run_event_tail(challenge_id, run_id, run, event, event_index)
    return event_index


def run_event_lock(run: dict) -> asyncio.Lock:
    lock = run.get("_event_lock")
    if not isinstance(lock, asyncio.Lock):
        lock = asyncio.Lock()
        run["_event_lock"] = lock
    return lock


def reset_run_events(challenge_id: str, run_id: str, run: dict) -> None:
    """Clear persisted and in-memory transcript state for a fresh run."""
    run["output_lines"] = []
    run["_event_count"] = 0
    clear_output_log(challenge_id, run_id)


def _parse_positive_int(value, default: int, minimum: int = 0, maximum: int = 1000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _event_search_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "\n".join(_event_search_text(item) for item in value)
    if isinstance(value, dict):
        skip_keys = {
            "usage",
            "model_usage",
            "rate_limit_info",
            "uuid",
            "session_id",
        }
        return "\n".join(
            _event_search_text(item)
            for key, item in value.items()
            if key not in skip_keys
        )
    return str(value)


def _search_preview(text: str, query: str, limit: int = 180) -> str:
    normalized = " ".join(str(text or "").split())
    if len(normalized) <= limit:
        return normalized
    idx = normalized.casefold().find(query.casefold())
    if idx < 0:
        return normalized[: limit - 1] + "..."
    start = max(0, idx - limit // 3)
    end = min(len(normalized), start + limit)
    if end - start < limit:
        start = max(0, end - limit)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(normalized) else ""
    return prefix + normalized[start:end] + suffix


def _load_legacy_output_log(challenge_id: str) -> list[dict]:
    """Load legacy output log (pre-runs format)."""
    out_path = _legacy_output_log_path(challenge_id)
    if not out_path.exists():
        return []
    events = []
    with out_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _normalize_output_lines(
    events: list[dict], agent: str
) -> list[dict]:
    return get_provider(agent).normalize_saved_events(events)


def _stats_number(data: dict | None, *keys: str) -> float:
    if not isinstance(data, dict):
        return 0
    for key in keys:
        value = data.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return float(value)
    return 0


def _usage_stats(raw: dict | None) -> dict:
    input_details = {}
    if isinstance(raw, dict):
        input_details = (
            raw.get("input_token_details")
            or raw.get("inputTokenDetails")
            or {}
        )
    if not isinstance(input_details, dict):
        input_details = {}
    return {
        "inputTokens": int(_stats_number(
            raw, "input_tokens", "inputTokens",
            "prompt_tokens", "promptTokens",
        )),
        "outputTokens": int(_stats_number(
            raw, "output_tokens", "outputTokens",
            "completion_tokens", "completionTokens",
        )),
        "cacheReadTokens": int(_stats_number(
            raw, "cache_read_input_tokens", "cacheReadInputTokens",
            "cached_input_tokens", "cachedInputTokens",
        ) or _stats_number(input_details, "cached_tokens", "cachedTokens")),
        "cacheCreationTokens": int(_stats_number(
            raw, "cache_creation_input_tokens", "cacheCreationInputTokens",
        )),
    }


def _usage_delta(current: dict, previous: dict | None) -> dict:
    delta = {}
    previous = previous or {}
    for key, value in current.items():
        prev_value = previous.get(key, 0)
        if value <= 0:
            delta[key] = 0
        elif value >= prev_value:
            delta[key] = value - prev_value
        else:
            delta[key] = value
    return delta


def _positive_delta(current: float, previous: float | None) -> float:
    if current <= 0:
        return 0
    if previous is None:
        return current
    return current - previous if current >= previous else current


def _add_usage_stats(stats: dict, usage: dict) -> None:
    stats["inputTokens"] += usage.get("inputTokens", 0)
    stats["outputTokens"] += usage.get("outputTokens", 0)
    stats["cacheReadTokens"] += usage.get("cacheReadTokens", 0)
    stats["cacheCreationTokens"] += usage.get("cacheCreationTokens", 0)


def _empty_stats() -> dict:
    return {
        "inputTokens": 0,
        "outputTokens": 0,
        "cacheReadTokens": 0,
        "cacheCreationTokens": 0,
        "toolCalls": 0,
        "turns": 0,
        "costUsd": 0.0,
        "durationMs": 0,
        "durationApiMs": 0,
        "modelUsage": {},
    }


def _model_usage_stats(raw: dict | None) -> dict:
    if not isinstance(raw, dict):
        return {}
    normalized = {}
    for model, usage in raw.items():
        if not isinstance(usage, dict):
            continue
        normalized[model] = {
            "inputTokens": int(_stats_number(
                usage, "inputTokens", "input_tokens",
            )),
            "outputTokens": int(_stats_number(
                usage, "outputTokens", "output_tokens",
            )),
            "cacheReadInputTokens": int(_stats_number(
                usage, "cacheReadInputTokens", "cache_read_input_tokens",
                "cachedInputTokens", "cached_input_tokens",
            )),
            "cacheCreationInputTokens": int(_stats_number(
                usage, "cacheCreationInputTokens",
                "cache_creation_input_tokens",
            )),
            "costUSD": _stats_number(usage, "costUSD", "cost_usd"),
            "webSearchRequests": int(_stats_number(
                usage, "webSearchRequests", "web_search_requests",
            )),
        }
    return normalized


def _add_model_usage_delta(
    stats: dict, current: dict, previous: dict[str, dict]
) -> None:
    if not current:
        return
    model_stats = stats.setdefault("modelUsage", {})
    for model, usage in current.items():
        prev = previous.get(model)
        target = model_stats.setdefault(model, {
            "inputTokens": 0,
            "outputTokens": 0,
            "cacheReadInputTokens": 0,
            "cacheCreationInputTokens": 0,
            "costUSD": 0.0,
            "webSearchRequests": 0,
        })
        for key, value in usage.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            prev_value = prev.get(key, 0) if isinstance(prev, dict) else 0
            if value <= 0:
                delta = 0
            elif value >= prev_value:
                delta = value - prev_value
            else:
                delta = value
            target[key] = target.get(key, 0) + delta
        previous[model] = usage


def _event_tool_call_count(event: dict) -> int:
    if event.get("type") != "assistant":
        return 0
    message = event.get("message")
    if not isinstance(message, dict):
        return 0
    content = message.get("content")
    if not isinstance(content, list):
        return 0
    return sum(
        1 for block in content
        if isinstance(block, dict) and block.get("type") == "tool_use"
    )


def _codex_thread_usage_for_run(run: dict) -> dict | None:
    if run.get("agent") != "codex":
        return None
    session_state = run.get("_session_state") or {}
    thread_id = (
        session_state.get("codex_thread_id")
        or run.get("_codex_thread_id")
        or (run.get("provider_state") or {}).get("codex_thread_id")
    )
    if not thread_id:
        return None
    try:
        from .agents.codex import get_thread_token_usage
    except ImportError:
        from agents.codex import get_thread_token_usage  # type: ignore
    return get_thread_token_usage(thread_id)


def _aggregate_run_stats(run: dict, events: Iterable[dict]) -> dict:
    stats = _empty_stats()
    assistant_usage = _empty_stats()
    result_seen = False
    codex_seen = False
    last_result_usage = None
    last_codex_usage = None
    last_result_cost = None
    last_result_turns = None
    last_api_duration = None
    last_model_usage: dict[str, dict] = {}

    for event in events:
        if not isinstance(event, dict):
            continue
        stats["toolCalls"] += _event_tool_call_count(event)
        etype = event.get("type")

        if etype == "assistant":
            message = event.get("message")
            usage = (
                message.get("usage")
                if isinstance(message, dict)
                else None
            )
            if usage:
                _add_usage_stats(assistant_usage, _usage_stats(usage))
            continue

        if etype == "result":
            result_seen = True
            usage = _usage_stats(event.get("usage"))
            _add_usage_stats(stats, _usage_delta(usage, last_result_usage))
            last_result_usage = usage

            cost = _stats_number(event, "total_cost_usd", "costUsd")
            if cost:
                stats["costUsd"] += _positive_delta(cost, last_result_cost)
                last_result_cost = cost

            turns = _stats_number(event, "num_turns", "turns")
            if turns:
                stats["turns"] += int(_positive_delta(
                    turns, last_result_turns
                ))
                last_result_turns = turns

            api_duration = _stats_number(event, "duration_api_ms")
            if api_duration:
                stats["durationApiMs"] += int(_positive_delta(
                    api_duration, last_api_duration
                ))
                last_api_duration = api_duration

            _add_model_usage_delta(
                stats,
                _model_usage_stats(event.get("model_usage")),
                last_model_usage,
            )
            continue

        if etype == "codex_usage":
            codex_seen = True
            usage = _usage_stats(event.get("usage"))
            _add_usage_stats(stats, _usage_delta(usage, last_codex_usage))
            last_codex_usage = usage

    if not result_seen and not codex_seen:
        thread_usage = _codex_thread_usage_for_run(run)
        if thread_usage:
            codex_seen = True
            _add_usage_stats(stats, _usage_stats(thread_usage))

    if not result_seen and not codex_seen:
        _add_usage_stats(stats, assistant_usage)

    stats["durationMs"] = effective_run_duration_ms(run)
    stats["costUsd"] = round(stats["costUsd"], 8)
    stats["modelUsage"] = {
        model: usage
        for model, usage in stats.get("modelUsage", {}).items()
        if any(value for value in usage.values())
    }
    return stats


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def _path_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (FileNotFoundError, ValueError):
        return False


def _read_skill_frontmatter(skill_file: Path) -> dict[str, str]:
    try:
        lines = skill_file.read_text(errors="replace").splitlines()
    except OSError:
        return {}
    if not lines or lines[0].strip() != "---":
        return {}

    data: dict[str, str] = {}
    active_key = ""
    folded: list[str] = []

    def flush_folded() -> None:
        nonlocal active_key, folded
        if active_key and folded:
            data[active_key] = " ".join(part.strip() for part in folded).strip()
        active_key = ""
        folded = []

    for line in lines[1:]:
        if line.strip() == "---":
            flush_folded()
            break
        if not line.startswith(" ") and ":" in line:
            flush_folded()
            key, raw_value = line.split(":", 1)
            key = key.strip()
            value = raw_value.strip()
            if value in {">", "|"}:
                active_key = key
                folded = []
            else:
                data[key] = value.strip().strip('"').strip("'")
            continue
        if active_key and line.startswith(" "):
            folded.append(line)
    return data


def _skill_entry_from_file(skill_file: Path, root: Path) -> dict | None:
    frontmatter = _read_skill_frontmatter(skill_file)
    name = (frontmatter.get("name") or skill_file.parent.name).strip()
    if not SKILL_NAME_RE.match(name):
        log.warning("Ignoring invalid skill name %r from %s", name, skill_file)
        return None

    description = frontmatter.get("description", "").strip()
    try:
        rel_path = skill_file.parent.relative_to(APP_ROOT_DIR).as_posix()
    except ValueError:
        rel_path = skill_file.parent.name
    source = "catalog" if _path_under(skill_file, ALL_SKILLS_DIR) else "repo"
    return {
        "name": name,
        "description": description,
        "source": source,
        "path": rel_path,
        "_path": str(skill_file.parent),
        "_root": str(root),
    }


_skill_catalog_cache: list[dict] | None = None
_skill_catalog_by_name_cache: dict[str, dict] | None = None


def invalidate_skill_catalog_cache() -> None:
    global _skill_catalog_cache, _skill_catalog_by_name_cache
    _skill_catalog_cache = None
    _skill_catalog_by_name_cache = None


def discover_skill_catalog() -> list[dict]:
    """Return available skills, preferring the runtime all-skills catalog."""
    global _skill_catalog_cache
    if _skill_catalog_cache is not None:
        return _skill_catalog_cache

    entries: dict[str, dict] = {}
    for root in (REPO_SKILLS_DIR, ALL_SKILLS_DIR):
        if not root.exists():
            continue
        for skill_file in sorted(root.rglob("SKILL.md")):
            entry = _skill_entry_from_file(skill_file, root)
            if entry:
                entries[entry["name"]] = entry
    _skill_catalog_cache = sorted(
        entries.values(),
        key=lambda item: item["name"].lower(),
    )
    return _skill_catalog_cache


def skill_catalog_by_name() -> dict[str, dict]:
    global _skill_catalog_by_name_cache
    if _skill_catalog_by_name_cache is None:
        _skill_catalog_by_name_cache = {
            entry["name"]: entry for entry in discover_skill_catalog()
        }
    return _skill_catalog_by_name_cache


# Skills enabled by default for new challenges (when the operator has not
# customized the set in Settings). Tool/forensics skills that should always be
# available; methodology/category/tool-specific skills like the ROP and crypto
# skills are left off so they load on demand via their triggers.
DEFAULT_ENABLED_SKILLS = [
    "kernel-gef-debugging",
    "analyze-with-ida-domain-api",
    "apk-analysis",
    "volatility3-memdump",
    "file-repair-and-stego",
    "tsk-disk-recovery",
    "pcap-extraction",
]


def default_enabled_skill_names() -> list[str]:
    available = {entry["name"] for entry in discover_skill_catalog()}
    return [name for name in DEFAULT_ENABLED_SKILLS if name in available]


def _coerce_skill_list(value: object) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = []
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed]
            return []
        return [part.strip() for part in raw.split(",")]
    if isinstance(value, list):
        return [str(item).strip() for item in value]
    return []


def normalize_enabled_skills(
    value: object,
    *,
    default: list[str] | None = None,
) -> list[str]:
    catalog = skill_catalog_by_name()
    requested = _coerce_skill_list(value)
    if requested is None:
        requested = default if default is not None else default_enabled_skill_names()

    normalized: list[str] = []
    seen: set[str] = set()
    for name in requested:
        if name in catalog and name not in seen:
            normalized.append(name)
            seen.add(name)
    return normalized


def normalize_enabled_hooks(value: object) -> list[str]:
    requested = _coerce_skill_list(value) or []
    normalized: list[str] = []
    seen: set[str] = set()
    for name in requested:
        if name in VALID_HOOKS and name not in seen:
            normalized.append(name)
            seen.add(name)
    return normalized


def enabled_hooks(settings: dict | None = None) -> set[str]:
    settings = settings or load_settings()
    return set(normalize_enabled_hooks(settings.get("enabled_hooks")))


def public_skill_catalog(settings: dict | None = None) -> dict:
    settings = settings or load_settings()
    skills = []
    for entry in discover_skill_catalog():
        public = {
            key: value
            for key, value in entry.items()
            if not key.startswith("_")
        }
        skills.append(public)
    return {
        "skills": skills,
        "default_enabled_skills": normalize_enabled_skills(
            settings.get("enabled_skills"),
            default=default_enabled_skill_names(),
        ),
    }


def _safe_skill_archive_path(raw_path: str) -> PurePosixPath | None:
    normalized = raw_path.replace("\\", "/").strip("/")
    if not normalized:
        return None
    path = PurePosixPath(normalized)
    if path.is_absolute():
        return None
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    file_type = (info.external_attr >> 16) & 0o170000
    return file_type == 0o120000


def _uploaded_skill_name(skill_file: Path, fallback_name: str) -> str | None:
    frontmatter = _read_skill_frontmatter(skill_file)
    name = (frontmatter.get("name") or fallback_name).strip()
    return name if SKILL_NAME_RE.match(name) else None


def _public_skill_entry(entry: dict) -> dict:
    return {
        key: value
        for key, value in entry.items()
        if not key.startswith("_")
    }


def _install_uploaded_skill_dir(
    skill_dir: Path,
    fallback_name: str,
) -> tuple[dict | None, str | None]:
    skill_file = skill_dir / "SKILL.md"
    if not skill_file.is_file():
        return None, "Uploaded skill must contain SKILL.md"

    skill_name = _uploaded_skill_name(skill_file, fallback_name)
    if not skill_name:
        return None, (
            "Uploaded skill has an invalid name. Use letters, numbers, "
            "dots, underscores, or hyphens."
        )

    ALL_SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    dest = ALL_SKILLS_DIR / skill_name
    tmp_dest = ALL_SKILLS_DIR / f".{skill_name}.{uuid.uuid4().hex}.tmp"
    try:
        shutil.copytree(skill_dir, tmp_dest, symlinks=False)
        if dest.is_symlink():
            dest.unlink()
        elif dest.exists():
            shutil.rmtree(dest)
        tmp_dest.rename(dest)
    except OSError as exc:
        shutil.rmtree(tmp_dest, ignore_errors=True)
        return None, f"Failed to install skill: {exc}"

    entry = _skill_entry_from_file(dest / "SKILL.md", ALL_SKILLS_DIR)
    if not entry:
        return None, "Installed skill could not be loaded"
    return entry, None


def _extract_uploaded_skill_zip(
    archive_bytes: bytes,
    extract_dir: Path,
    fallback_name: str,
) -> tuple[Path | None, str, str | None]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile:
        return None, fallback_name, "Invalid zip file"

    files: dict[str, bytes] = {}
    total_size = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        if _zipinfo_is_symlink(info):
            return (
                None,
                fallback_name,
                f"Zip contains unsupported symlink: {info.filename}",
            )
        safe_path = _safe_skill_archive_path(info.filename)
        if not safe_path:
            return None, fallback_name, f"Zip contains unsafe path: {info.filename}"
        if safe_path.parts[0] == "__MACOSX" or safe_path.name == ".DS_Store":
            continue
        total_size += info.file_size
        if total_size > MAX_SKILL_UPLOAD_BYTES:
            return None, fallback_name, "Skill upload is too large"
        if len(files) >= MAX_SKILL_UPLOAD_FILES:
            return None, fallback_name, "Skill upload contains too many files"
        files[safe_path.as_posix()] = zf.read(info)

    skill_paths = [
        PurePosixPath(path)
        for path in files
        if PurePosixPath(path).name == "SKILL.md"
    ]
    if not skill_paths:
        return None, fallback_name, "Zip must contain a SKILL.md file"
    if len(skill_paths) > 1:
        return (
            None,
            fallback_name,
            "Upload one skill at a time; zip contains multiple SKILL.md files",
        )

    skill_root = skill_paths[0].parent
    prefix = "" if skill_root.as_posix() == "." else f"{skill_root.as_posix()}/"
    skill_fallback = (
        fallback_name if skill_root.as_posix() == "." else skill_root.name
    )
    for path, data in files.items():
        if prefix and not path.startswith(prefix):
            continue
        rel = path[len(prefix):] if prefix else path
        if not rel:
            continue
        dest = extract_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return extract_dir, skill_fallback, None


def challenge_enabled_skills(
    challenge: dict,
    settings: dict | None = None,
) -> list[str]:
    settings = settings or load_settings()
    return normalize_enabled_skills(
        challenge.get("enabled_skills"),
        default=normalize_enabled_skills(settings.get("enabled_skills")),
    )


def run_has_skill_override(run: dict) -> bool:
    return run.get("enabled_skills") is not None


def run_enabled_skills(
    challenge: dict,
    run: dict,
    settings: dict | None = None,
) -> list[str]:
    if run_has_skill_override(run):
        return normalize_enabled_skills(run.get("enabled_skills"), default=[])
    return challenge_enabled_skills(challenge, settings)


def sync_run_skill_links(challenge: dict, run: dict) -> None:
    """Materialize selected project skills into this run's provider dirs."""
    run_dir = get_run_cwd(challenge["id"], run)
    selected = run_enabled_skills(challenge, run)
    catalog = skill_catalog_by_name()

    for rel_dir in PROJECT_SKILL_DIRS:
        skills_dir = run_dir / rel_dir
        skills_dir.mkdir(parents=True, exist_ok=True)

        for child in list(skills_dir.iterdir()):
            if child.is_symlink():
                child.unlink()

        for name in selected:
            entry = catalog.get(name)
            if not entry:
                continue
            source = Path(entry["_path"])
            if not source.exists():
                continue
            dest = skills_dir / name
            if dest.exists() or dest.is_symlink():
                continue
            dest.symlink_to(source)


def sync_challenge_skill_links(challenge: dict) -> None:
    for run in challenge.get("runs", {}).values():
        sync_run_skill_links(challenge, run)


def load_settings() -> dict:
    """Load global settings from disk."""
    defaults = {
        "default_agent": DEFAULT_AGENT,
        "default_flag_format": "",
        "theme": "dark",
        "auto_submit_flags": False,
        "chat_view_mode": "split",
        "enabled_agents": [],
        "agent_models": {},
        "agent_efforts": {},
        "enabled_skills": None,
        "enabled_hooks": [],
        "max_platform_import_size_gb": DEFAULT_MAX_PLATFORM_IMPORT_SIZE_GB,
        "discord_enabled": False,
        "discord_bot_token": "",
        "discord_channel_id": "",
        "discord_guild_id": "",
        "discord_challenge_layout": DEFAULT_DISCORD_CHALLENGE_LAYOUT,
        "swarm": {},
    }
    if SETTINGS_FILE.exists():
        try:
            loaded = json.loads(SETTINGS_FILE.read_text())
            if isinstance(loaded, dict):
                for k, v in loaded.items():
                    if k in defaults:
                        defaults[k] = v
        except (json.JSONDecodeError, OSError):
            pass
    defaults["max_platform_import_size_gb"] = normalize_platform_import_size_gb(
        defaults.get("max_platform_import_size_gb")
    )
    defaults["discord_challenge_layout"] = normalize_discord_challenge_layout(
        defaults.get("discord_challenge_layout")
    )
    defaults["enabled_skills"] = normalize_enabled_skills(
        defaults.get("enabled_skills"),
        default=default_enabled_skill_names(),
    )
    defaults["enabled_hooks"] = normalize_enabled_hooks(
        defaults.get("enabled_hooks")
    )
    return defaults


def normalize_platform_import_size_gb(value) -> float:
    """Return a sane per-challenge platform import cap in GiB."""
    try:
        gb = float(value)
    except (TypeError, ValueError):
        gb = DEFAULT_MAX_PLATFORM_IMPORT_SIZE_GB
    if not math.isfinite(gb) or gb <= 0:
        gb = DEFAULT_MAX_PLATFORM_IMPORT_SIZE_GB
    return round(gb, 3)


def platform_import_limit_bytes(settings: dict | None = None) -> int:
    settings = settings or load_settings()
    gb = normalize_platform_import_size_gb(
        settings.get("max_platform_import_size_gb")
    )
    return int(gb * BYTES_PER_GIB)


def normalize_discord_challenge_layout(value) -> str:
    layout = str(value or DEFAULT_DISCORD_CHALLENGE_LAYOUT).strip().lower()
    if layout not in VALID_DISCORD_CHALLENGE_LAYOUTS:
        return DEFAULT_DISCORD_CHALLENGE_LAYOUT
    return layout


def _discord_destination_id(challenge: dict) -> str:
    return str(
        challenge.get("_discord_channel_id")
        or challenge.get("_discord_thread_id")
        or ""
    )


def _discord_destination_kind(challenge: dict) -> str:
    if challenge.get("_discord_channel_id"):
        return "channel"
    if challenge.get("_discord_thread_id"):
        return "thread"
    return ""


def _discord_component_id(challenge_id: str, action: str) -> str:
    return f"{DISCORD_COMPONENT_PREFIX}:{challenge_id}:{action}"


def _discord_flag_token(flag: str) -> str:
    digest = hashlib.sha256(flag_lookup_key(flag).encode()).digest()
    return base64.urlsafe_b64encode(digest[:9]).decode().rstrip("=")


def _discord_flag_component_id(challenge_id: str, action: str, flag: str) -> str:
    return f"{DISCORD_COMPONENT_PREFIX}:{challenge_id}:{action}:{_discord_flag_token(flag)}"


def _discord_button(challenge: dict, action: str, label: str, style: int = 2) -> dict:
    return {
        "type": 2,
        "style": style,
        "label": label,
        "custom_id": _discord_component_id(challenge.get("id", ""), action),
    }


def discord_challenge_components(challenge: dict) -> list[dict]:
    return [
        {
            "type": 1,
            "components": [
                _discord_button(challenge, "status", "Status", 1),
                _discord_button(challenge, "stats", "Stats"),
                _discord_button(challenge, "tail", "Tail"),
                _discord_button(challenge, "flags", "Flags"),
            ],
        },
        {
            "type": 1,
            "components": [
                _discord_button(challenge, "submit", "Submit Flag", 1),
                _discord_button(challenge, "solved", "Mark Solved", 3),
                _discord_button(challenge, "stop", "Stop", 4),
                _discord_button(challenge, "resume", "Resume"),
            ],
        },
    ]


def _discord_flag_modal_components(
    field_id: str,
    label: str,
    required: bool,
    placeholder: str = "",
) -> list[dict]:
    field = {
        "type": 4,
        "custom_id": field_id,
        "label": label[:45],
        "style": 1,
        "required": required,
    }
    if placeholder:
        field["placeholder"] = placeholder[:100]
    return [{"type": 1, "components": [field]}]


def discord_flag_review_components(challenge: dict, flag: str) -> list[dict]:
    challenge_id = challenge.get("id", "")
    return [{
        "type": 1,
        "components": [
            {
                "type": 2,
                "style": 1,
                "label": "Submit",
                "custom_id": _discord_flag_component_id(
                    challenge_id, "flag_submit", flag
                ),
            },
            {
                "type": 2,
                "style": 4,
                "label": "Reject",
                "custom_id": _discord_flag_component_id(
                    challenge_id, "flag_reject", flag
                ),
            },
            {
                "type": 2,
                "style": 3,
                "label": "Mark Correct",
                "custom_id": _discord_flag_component_id(
                    challenge_id, "flag_correct", flag
                ),
            },
            {
                "type": 2,
                "style": 2,
                "label": "Broadcast",
                "custom_id": _discord_flag_component_id(
                    challenge_id, "flag_broadcast", flag
                ),
            },
        ],
    }]


async def discord_create_thread_destination(challenge: dict, bot: DiscordBot) -> None:
    thread_name = make_thread_name(challenge)
    embed = make_challenge_embed(challenge)
    # Reuse existing thread if one matches
    existing_id = await bot.find_thread_by_name(thread_name)
    if existing_id:
        challenge["_discord_thread_id"] = existing_id
        challenge["_discord_challenge_layout"] = "threads"
        save_metadata(challenge)
        await bot.send_message(
            existing_id,
            embed=embed,
            components=discord_challenge_components(challenge),
        )
        log.info("Discord thread reused: %s -> %s", thread_name, existing_id)
        return
    thread_id = await bot.create_thread(thread_name)
    if thread_id:
        challenge["_discord_thread_id"] = thread_id
        challenge["_discord_challenge_layout"] = "threads"
        save_metadata(challenge)
        await bot.send_message(
            thread_id,
            embed=embed,
            components=discord_challenge_components(challenge),
        )
        log.info("Discord thread created: %s -> %s", thread_name, thread_id)


async def discord_create_channel_destination(challenge: dict, bot: DiscordBot) -> None:
    guild_id = await bot.default_guild_id()
    if not guild_id:
        log.error("Discord channel mode requires a guild text channel")
        return

    category_name = make_category_name(challenge)
    category_id = str(challenge.get("_discord_category_id", ""))
    if not category_id:
        category_id = await bot.find_category_by_name(category_name, guild_id) or ""
    if not category_id:
        category_id = await bot.create_category(category_name, guild_id) or ""
    if not category_id:
        return

    channel_name = make_challenge_channel_name(challenge)
    channel_id = str(challenge.get("_discord_channel_id", ""))
    if not channel_id:
        channel_id = await bot.find_text_channel_by_name(
            channel_name,
            category_id,
            guild_id,
        ) or ""
    embed = make_challenge_embed(challenge)
    if channel_id:
        challenge["_discord_category_id"] = category_id
        challenge["_discord_channel_id"] = channel_id
        challenge["_discord_challenge_layout"] = "channels"
        save_metadata(challenge)
        await bot.send_message(
            channel_id,
            embed=embed,
            components=discord_challenge_components(challenge),
        )
        log.info(
            "Discord channel reused: %s/%s -> %s",
            category_name,
            channel_name,
            channel_id,
        )
        return

    topic = f"CTF Solver challenge {challenge.get('id', '')}".strip()
    channel_id = await bot.create_text_channel(
        channel_name,
        parent_id=category_id,
        guild_id=guild_id,
        topic=topic,
    )
    if channel_id:
        challenge["_discord_category_id"] = category_id
        challenge["_discord_channel_id"] = channel_id
        challenge["_discord_challenge_layout"] = "channels"
        save_metadata(challenge)
        await bot.send_message(
            channel_id,
            embed=embed,
            components=discord_challenge_components(challenge),
        )
        log.info(
            "Discord channel created: %s/%s -> %s",
            category_name,
            channel_name,
            channel_id,
        )


async def discord_ensure_destination(challenge: dict) -> None:
    settings = load_settings()
    bot = get_bot(settings)
    if not bot:
        return
    layout = normalize_discord_challenge_layout(
        settings.get("discord_challenge_layout")
    )
    if layout == "channels":
        await discord_create_channel_destination(challenge, bot)
    else:
        await discord_create_thread_destination(challenge, bot)


async def discord_mark_solved(challenge: dict, flag: str = "", agent: str = "") -> None:
    bot = get_bot(load_settings())
    if not bot:
        return
    category = challenge.get("category", "")
    name = challenge.get("name", "Unknown")
    if category:
        new_name = f"[solved][{category}] {name}"
    else:
        new_name = f"[solved] {name}"
    destination_id = _discord_destination_id(challenge)
    if destination_id:
        if _discord_destination_kind(challenge) == "channel":
            await bot.rename_channel(
                destination_id,
                make_challenge_channel_name(challenge, solved=True),
            )
        else:
            await bot.rename_thread(destination_id, new_name)
    # Post to main channel
    parts = [f"\U0001f6a9 **{name}** solved!"]
    if agent:
        parts.append(f"by `{agent}`")
    if flag:
        parts.append(f"— `{flag}`")
    await bot.send_channel_message(" ".join(parts))


async def discord_notify(
    challenge: dict,
    content: str = "",
    embed: dict | None = None,
    components: list[dict] | None = None,
) -> None:
    destination_id = _discord_destination_id(challenge)
    if not destination_id:
        return
    bot = get_bot(load_settings())
    if not bot:
        return
    await bot.send_message(destination_id, content, embed, components)


def _discord_fenced_text(text: str, available_chars: int) -> str:
    overhead = len("```text\n\n```")
    body_limit = max(0, available_chars - overhead)
    body = str(text or "").replace("```", "'''")
    if len(body) > body_limit:
        body = body[: max(0, body_limit - 4)].rstrip() + "\n..."
    return f"```text\n{body}\n```"


def _discord_resume_prompt_message(run: dict, prompt: str) -> str:
    model_info = run.get("model", "") or "provider default"
    if run.get("effort"):
        model_info += f", {run['effort']}"
    header = f"**{run.get('agent', 'agent')}** ({model_info}) resume prompt:\n"
    return header + _discord_fenced_text(prompt, 2000 - len(header))


def save_settings(settings: dict) -> None:
    """Persist global settings to disk."""
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))
    try:
        os.chmod(SETTINGS_FILE, 0o600)
    except OSError:
        pass


def settings_for_client(settings: dict) -> dict:
    """Return settings safe to send to the browser (GCP key redacted)."""
    out = dict(settings)
    swarm = dict(out.get("swarm") or {})
    sa = swarm.pop("service_account", None)
    swarm["service_account_configured"] = bool(sa)
    out["swarm"] = swarm
    return out


# ---------------------------------------------------------------------------
# Metadata persistence
# ---------------------------------------------------------------------------

def _serialize_runs(challenge: dict) -> dict:
    """Serialize runs for metadata (strip non-serializable fields)."""
    serialized = {}
    for run_id, run in challenge["runs"].items():
        run_meta = {
            "id": run["id"],
            "agent": run["agent"],
            "model": run["model"],
            "effort": run.get("effort", ""),
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": effective_run_duration_ms(run),
            "solve_start": None,
            "notes_label": run.get("notes_label", ""),
            "provider_state": provider_state_for_metadata(run),
            "_session_state": run.get("_session_state", {}),
            "_submit_token": run.get("_submit_token", ""),
            "event_count": run_event_count(challenge["id"], run_id, run),
            "goal": normalize_run_goal(run.get("goal"), str(run.get("agent") or "")),
        }
        if run_has_skill_override(run):
            run_meta["enabled_skills"] = run_enabled_skills(challenge, run)
        if run.get("custom_prompt"):
            run_meta["custom_prompt"] = run["custom_prompt"]
            run_meta["custom_prompt_mode"] = run.get(
                "custom_prompt_mode", "append"
            )
        serialized[run_id] = run_meta
    return serialized


def save_metadata(challenge: dict) -> None:
    """Persist challenge metadata to disk."""
    if challenge.get("_deleted"):
        return
    meta = {
        "id": challenge["id"],
        "name": challenge["name"],
        "description": challenge["description"],
        "category": challenge.get("category", ""),
        "flag_format": challenge["flag_format"],
        "extra_flag_formats": challenge.get("extra_flag_formats", []),
        "mode": challenge["mode"],
        "status": challenge["status"],
        "created_at": challenge["created_at"],
        "files": challenge["files"],
        "enabled_skills": challenge_enabled_skills(challenge),
        "error": challenge.get("error"),
        "runs": _serialize_runs(challenge),
        "_plugin": challenge.get("_plugin", ""),
        "_remote_id": challenge.get("_remote_id", ""),
        "_points": challenge.get("_points", 0),
        "_solves": challenge.get("_solves", 0),
        "_tags": challenge.get("_tags", []),
        "_flag_questions": challenge.get("_flag_questions", []),
        "_instance_info": challenge.get("_instance_info"),
        "_swarm_instance": challenge.get("_swarm_instance", ""),
        "_source_url": challenge.get("_source_url", ""),
        "_connection_id": challenge.get("_connection_id", ""),
        "_discord_thread_id": challenge.get("_discord_thread_id", ""),
        "_discord_channel_id": challenge.get("_discord_channel_id", ""),
        "_discord_category_id": challenge.get("_discord_category_id", ""),
        "_discord_challenge_layout": challenge.get("_discord_challenge_layout", ""),
        "detected_flags": challenge.get("detected_flags", {}),
        "detected_flag_meta": challenge.get("detected_flag_meta", {}),
    }
    meta_path = ensure_state_dir(challenge["id"]) / METADATA_FILE
    meta_path.write_text(json.dumps(meta, indent=2))


# ---------------------------------------------------------------------------
# Agent/model resolution helpers
# ---------------------------------------------------------------------------

def parse_agents_field(agents_str: str) -> list[dict]:
    """Parse agents field from frontend.

    Accepts either:
    - A plain agent name: "claude"
    - Comma-separated names: "claude,codex"
    - JSON array of {agent, model} objects: '[{"agent":"claude","model":"opus"}]'

    Returns list of {"agent": str, "model": str} dicts.
    """
    if not agents_str:
        return []
    agents_str = agents_str.strip()
    if agents_str.startswith("["):
        try:
            parsed = json.loads(agents_str)
            if isinstance(parsed, list):
                return [
                    {
                        "agent": str_field(entry.get("agent", "")) if isinstance(entry, dict) else str_field(entry),
                        "model": str_field(entry.get("model", "")) if isinstance(entry, dict) else "",
                        "effort": str_field(entry.get("effort", "")) if isinstance(entry, dict) else "",
                    }
                    for entry in parsed
                ]
        except json.JSONDecodeError:
            pass
    return [{"agent": a.strip(), "model": "", "effort": ""} for a in agents_str.split(",") if a.strip()]


def resolved_default_model(agent: str) -> str:
    return get_provider(agent).resolved_default_model()


def resolved_default_effort(agent: str) -> str:
    provider = get_provider(agent)
    values = [value for value, _ in provider.effort_levels if value]
    default = provider.default_effort
    if values and default not in values:
        default = values[0]
    return default if default in values else ""


def normalize_effort_for_agent(agent: str, effort: str) -> str:
    provider = get_provider(agent)
    allowed = {value for value, _ in provider.effort_levels if value}
    if not allowed:
        return ""
    if effort in allowed:
        return effort
    return resolved_default_effort(agent)


# ---------------------------------------------------------------------------
# Load challenges from disk
# ---------------------------------------------------------------------------

def load_challenges_from_disk() -> None:
    """Scan CHALLENGES_DIR for existing challenges on startup."""
    for d in sorted(CHALLENGES_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        challenge_id = d.name
        if challenge_id in challenges:
            continue
        migrate_legacy_state(challenge_id)
        meta_path = metadata_path(challenge_id)
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except (json.JSONDecodeError, OSError):
                meta = {}
        else:
            meta = {}

        mode = meta.get("mode", "single")
        if mode not in VALID_MODES:
            mode = "single"

        # Restore runs from saved metadata, or migrate old format
        saved_runs = meta.get("runs", {})
        runs: dict[str, dict] = {}

        if saved_runs:
            # New format: restore runs
            for run_id, run_meta in saved_runs.items():
                run_agent = run_meta.get("agent", DEFAULT_AGENT)
                if run_agent not in VALID_AGENTS:
                    run_agent = DEFAULT_AGENT
                saved_run_status = run_meta.get("status", "unknown")
                run_status = saved_run_status
                if run_status == "solving":
                    run_status = "failed"
                provider_state = run_meta.get("provider_state", {})
                run = make_run(
                    run_id=run_id,
                    agent=run_agent,
                    model=run_meta.get(
                        "model",
                        resolved_default_model(run_agent),
                    ),
                    effort=run_meta.get(
                        "effort",
                        resolved_default_effort(run_agent),
                    ),
                    status=run_status,
                )
                run["error"] = run_meta.get("error")
                run["duration_ms"] = run_meta.get("duration_ms")
                run["goal"] = normalize_run_goal(
                    run_meta.get("goal"),
                    str(run.get("agent") or ""),
                )
                if run_meta.get("notes_label"):
                    run["notes_label"] = run_meta["notes_label"]
                if "enabled_skills" in run_meta:
                    run["enabled_skills"] = normalize_enabled_skills(
                        run_meta.get("enabled_skills"),
                        default=[],
                    )
                custom_prompt = str(
                    run_meta.get("custom_prompt") or ""
                ).strip()
                if custom_prompt:
                    run["custom_prompt"] = custom_prompt
                    run["custom_prompt_mode"] = str(
                        run_meta.get("custom_prompt_mode") or "append"
                    )
                run["_codex_thread_id"] = provider_state.get(
                    "codex_thread_id"
                )
                session_state = run_meta.get("_session_state", {})
                # Backfill from legacy provider_state
                if not session_state:
                    if run.get("_codex_thread_id"):
                        session_state["codex_thread_id"] = run["_codex_thread_id"]
                run["_session_state"] = session_state
                run["_submit_token"] = run_meta.get("_submit_token", "")
                saved_event_count = run_meta.get("event_count")
                if (
                    saved_run_status != "solving"
                    and isinstance(saved_event_count, int)
                    and saved_event_count >= 0
                ):
                    run["_event_count"] = saved_event_count
                else:
                    run["_event_count"] = count_output_log_events(
                        challenge_id, run_id
                    )
                run["output_lines"] = []
                runs[run_id] = run
        else:
            # Legacy format: migrate to single run
            old_agent = meta.get("agent", DEFAULT_AGENT)
            if old_agent not in VALID_AGENTS:
                old_agent = DEFAULT_AGENT
            old_status = meta.get("status", "unknown")
            if old_status == "solving":
                old_status = "failed"
            provider_state = meta.get("provider_state", {})
            run_id = uuid.uuid4().hex[:8]
            run = make_run(
                run_id=run_id,
                agent=old_agent,
                model=meta.get(
                    "model",
                    resolved_default_model(old_agent),
                ),
                effort=meta.get(
                    "effort",
                    resolved_default_effort(old_agent),
                ),
                status=old_status,
            )
            run["error"] = meta.get("error")
            run["duration_ms"] = meta.get("duration_ms")
            run["_codex_thread_id"] = provider_state.get(
                "codex_thread_id"
            )
            session_state_legacy = meta.get("_session_state", {})
            if not session_state_legacy:
                if run.get("_codex_thread_id"):
                    session_state_legacy["codex_thread_id"] = run["_codex_thread_id"]
            run["_session_state"] = session_state_legacy
            # Try legacy output log
            legacy_events = _load_legacy_output_log(challenge_id)
            # Migrate legacy output to run-specific file
            if legacy_events:
                out_path = _run_output_path(challenge_id, run_id)
                if not out_path.exists():
                    with out_path.open("w") as f:
                        for evt in legacy_events:
                            json.dump(evt, f)
                            f.write("\n")
            run["_event_count"] = count_output_log_events(challenge_id, run_id)
            run["output_lines"] = []
            runs[run_id] = run

        # No tasks survive a restart — reset stale "solving" runs
        for run in runs.values():
            if run["status"] == "solving":
                run["status"] = "failed"
                run["error"] = "Server restarted while solving"

        if (d / "_files").exists():
            if mode == "parallel":
                setup_parallel_shared_dir(challenge_id)
            for run_id in runs:
                setup_run_dir(challenge_id, run_id)
            if mode == "parallel":
                assign_notes_labels(runs)
                setup_parallel_cross_notes(challenge_id, runs)

        challenge = {
            "id": challenge_id,
            "name": meta.get("name", f"Challenge {challenge_id}"),
            "description": meta.get("description", ""),
            "flag_format": meta.get("flag_format", ""),
            "extra_flag_formats": meta.get("extra_flag_formats", []),
            "enabled_skills": normalize_enabled_skills(
                meta.get("enabled_skills"),
                default=normalize_enabled_skills(
                    load_settings().get("enabled_skills")
                ),
            ),
            "mode": mode,
            "status": "pending",
            "created_at": meta.get(
                "created_at", datetime.now().isoformat()
            ),
            "files": meta.get("files", []),
            "error": meta.get("error"),
            "runs": runs,
            "category": meta.get("category", ""),
            "_plugin": meta.get("_plugin", ""),
            "_remote_id": meta.get("_remote_id", ""),
            "_points": meta.get("_points", 0),
            "_solves": meta.get("_solves", 0),
            "_tags": meta.get("_tags", []),
            "_flag_questions": meta.get("_flag_questions", []),
            "_instance_info": meta.get("_instance_info"),
            "_swarm_instance": meta.get("_swarm_instance", ""),
            "_source_url": meta.get("_source_url", ""),
            "_connection_id": meta.get("_connection_id", ""),
            "_discord_thread_id": meta.get("_discord_thread_id", ""),
            "_discord_channel_id": meta.get("_discord_channel_id", ""),
            "_discord_category_id": meta.get("_discord_category_id", ""),
            "_discord_challenge_layout": meta.get("_discord_challenge_layout", ""),
            "detected_flags": meta.get("detected_flags", {}),
            "detected_flag_meta": meta.get("detected_flag_meta", {}),
        }
        challenge["status"] = derive_challenge_status(challenge)
        challenges[challenge_id] = challenge
        sync_challenge_skill_links(challenge)


load_challenges_from_disk()


# Register Discord breakthrough hook
async def _discord_breakthrough_hook(challenge_id: str, source_run_id: str, message: str):
    challenge = challenges.get(challenge_id)
    if not challenge:
        return
    run = challenge["runs"].get(source_run_id, {})
    agent = run.get("agent", "?")
    await discord_notify(challenge, f"**{agent}** breakthrough: {message}")

try:
    from .agents.broadcast import set_discord_hook
except ImportError:
    from agents.broadcast import set_discord_hook
set_discord_hook(_discord_breakthrough_hook)


# ---------------------------------------------------------------------------
# Auth and CSRF
# ---------------------------------------------------------------------------

def _check_basic_auth(auth_header: str) -> bool:
    """Validate HTTP Basic Auth credentials (any username, password = APP_PASSWORD)."""
    if not auth_header.startswith("Basic "):
        return False
    try:
        import base64
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        _, _, password = decoded.partition(":")
        return secrets.compare_digest(password, APP_PASSWORD)
    except Exception:
        return False


def require_auth(request: Request) -> Response | None:
    if request.session.get("authenticated"):
        return None

    client_ip = request.client.host if request.client else "unknown"
    if err := _check_rate_limit(client_ip):
        return err

    auth = request.headers.get("authorization", "")
    if _check_basic_auth(auth):
        _login_attempts.pop(client_ip, None)
        request.session["authenticated"] = True
        return None
    if auth:
        _login_attempts[client_ip].append(_time.monotonic())
    return Response(
        content="Unauthorized",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="CTF Solver"'},
    )


def require_csrf(request: Request) -> JSONResponse | None:
    """Reject state-changing requests missing a valid CSRF token."""
    token = request.headers.get("x-csrf-token", "")
    session_token = request.session.get("csrf_token", "")
    if not token or not session_token:
        return JSONResponse(
            {"error": "missing csrf token"}, status_code=403
        )
    if not secrets.compare_digest(token, session_token):
        return JSONResponse(
            {"error": "invalid csrf token"}, status_code=403
        )
    return None


async def read_json_object(request: Request) -> tuple[dict, JSONResponse | None]:
    """Read a JSON request body and require a top-level object."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return {}, JSONResponse({"error": "invalid JSON body"}, status_code=400)
    except Exception:
        return {}, JSONResponse({"error": "invalid request body"}, status_code=400)
    if not isinstance(body, dict):
        return {}, JSONResponse({"error": "expected JSON object"}, status_code=400)
    return body, None


def str_field(value: object, default: str = "") -> str:
    """Normalize optional JSON/form scalar values to strings."""
    if value is None:
        return default
    return str(value)


def _check_rate_limit(client_ip: str) -> JSONResponse | None:
    """Block login if too many recent failures from this IP."""
    now = _time.monotonic()
    attempts = _login_attempts[client_ip]
    # Prune old attempts outside the window
    _login_attempts[client_ip] = [
        t for t in attempts if now - t < LOGIN_WINDOW_SECONDS
    ]
    if len(_login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        return JSONResponse(
            {"error": "too many login attempts, try again later"},
            status_code=429,
        )
    return None


def websocket_origin_allowed(websocket: WebSocket) -> bool:
    """Allow browser WebSockets only from same-origin or configured origins."""
    origin = websocket.headers.get("origin", "")
    if not origin:
        return False
    if origin in ALLOWED_ORIGINS:
        return True

    host = websocket.headers.get("host", "")
    if not host:
        return False
    parsed = urlparse(origin)
    expected_scheme = "https" if TLS_ENABLED else "http"
    return parsed.scheme == expected_scheme and parsed.netloc == host


# ---------------------------------------------------------------------------
# Basic routes
# ---------------------------------------------------------------------------

async def index(request: Request) -> Response:
    # Support ?token=PASSWORD for easy bookmarkable login
    token = request.query_params.get("token", "")
    if token and secrets.compare_digest(token, APP_PASSWORD):
        request.session["authenticated"] = True
        from starlette.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=302)
    if err := require_auth(request):
        return err
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(
        html_path.read_text(),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


async def login(request: Request) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    if err := _check_rate_limit(client_ip):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    password = str_field(body.get("password", ""))
    if secrets.compare_digest(password, APP_PASSWORD):
        _login_attempts.pop(client_ip, None)
        csrf_token = secrets.token_hex(32)
        request.session["authenticated"] = True
        request.session["csrf_token"] = csrf_token
        return JSONResponse({"ok": True, "csrf_token": csrf_token})

    _login_attempts[client_ip].append(_time.monotonic())
    return JSONResponse({"error": "invalid password"}, status_code=403)


async def logout(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    request.session.clear()
    return JSONResponse({"ok": True})


async def csrf_token(request: Request) -> JSONResponse:
    """Return the CSRF token for the current session."""
    if err := require_auth(request):
        return err
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        request.session["csrf_token"] = token
    return JSONResponse({"csrf_token": token})


# ---------------------------------------------------------------------------
# Broadcast helpers
# ---------------------------------------------------------------------------

async def _send_ws_json(websocket: WebSocket, data: dict) -> bool:
    try:
        if WS_SEND_TIMEOUT_SECONDS > 0:
            await asyncio.wait_for(
                websocket.send_json(data),
                timeout=WS_SEND_TIMEOUT_SECONDS,
            )
        else:
            await websocket.send_json(data)
        return True
    except Exception:
        return False


async def _broadcast_to_ws_set(clients: set, data: dict) -> None:
    targets = list(clients)
    if not targets:
        return
    results = await asyncio.gather(
        *(_send_ws_json(ws, data) for ws in targets),
        return_exceptions=True,
    )
    for ws, ok in zip(targets, results):
        if ok is not True:
            clients.discard(ws)


async def broadcast(challenge_id: str, run_id: str, data: dict):
    """Send data to a specific run's WebSocket clients."""
    challenge = challenges.get(challenge_id)
    if not challenge:
        return
    run = challenge["runs"].get(run_id)
    if not run:
        return
    await _broadcast_to_ws_set(run["ws_clients"], data)


async def broadcast_challenge(challenge_id: str, data: dict):
    """Send data to ALL runs' WebSocket clients AND global clients."""
    challenge = challenges.get(challenge_id)
    if not challenge:
        return
    for run in challenge["runs"].values():
        await _broadcast_to_ws_set(run["ws_clients"], data)
    enriched = {**data, "challenge_id": challenge_id}
    await broadcast_global(enriched)


_global_ws_clients: set = set()


async def broadcast_global(data: dict):
    """Send data to all globally-connected WebSocket clients."""
    await _broadcast_to_ws_set(_global_ws_clients, data)


# ---------------------------------------------------------------------------
# Challenge listing
# ---------------------------------------------------------------------------

def public_challenge_summary(
    challenge: dict,
    settings: dict | None = None,
) -> dict:
    settings = settings or load_settings()
    runs_summary = [
        public_run_summary(challenge, run, settings)
        for run in challenge.get("runs", {}).values()
    ]
    return {
        "id": challenge["id"],
        "name": challenge["name"],
        "description": challenge["description"],
        "category": challenge.get("category", ""),
        "flag_format": challenge["flag_format"],
        "flag_formats": challenge_flag_formats(challenge),
        "extra_flag_formats": challenge.get("extra_flag_formats", []),
        "mode": challenge["mode"],
        "status": challenge["status"],
        "error": challenge.get("error"),
        "created_at": challenge["created_at"],
        "files": challenge["files"],
        "enabled_skills": challenge_enabled_skills(challenge, settings),
        "points": challenge.get("_points", 0),
        "solves": challenge.get("_solves", 0),
        "flag_questions": challenge.get("_flag_questions", []),
        "runs": runs_summary,
        "detected_flags": challenge.get("detected_flags", {}),
        "detected_flag_meta": challenge.get("detected_flag_meta", {}),
    }


def public_challenge_list_summary(challenge: dict) -> dict:
    """Small challenge shape for dashboard cards."""
    files = challenge.get("files", [])
    return {
        "id": challenge["id"],
        "name": challenge["name"],
        "category": challenge.get("category", ""),
        "mode": challenge["mode"],
        "status": challenge["status"],
        "error": challenge.get("error"),
        "created_at": challenge["created_at"],
        "file_count": len(files) if isinstance(files, list) else 0,
        "points": challenge.get("_points", 0),
        "solves": challenge.get("_solves", 0),
        "runs": [
            public_run_list_summary(run)
            for run in challenge.get("runs", {}).values()
        ],
    }


async def list_challenges(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    detail = str(request.query_params.get("detail", "")).lower()
    if detail in {"1", "true", "yes", "full"}:
        settings = load_settings()
        result = [
            public_challenge_summary(c, settings) for c in challenges.values()
        ]
    else:
        result = [public_challenge_list_summary(c) for c in challenges.values()]
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return JSONResponse(result)


async def get_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(public_challenge_summary(challenge))


def _event_tool_result_blocks(event: dict) -> list[dict]:
    message = event.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if not isinstance(content, list):
        return []
    return [
        block for block in content
        if isinstance(block, dict) and block.get("type") == "tool_result"
    ]


def _tool_output_text(event: dict, block: dict) -> str:
    output = ""
    result = event.get("tool_use_result")
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text")
                    if text:
                        parts.append(str(text))
            output = "\n".join(parts)
        if not output:
            stdout = result.get("stdout")
            stderr = result.get("stderr")
            if stdout:
                output = str(stdout)
            if stderr:
                output += ("\n" if output else "") + str(stderr)
            matches = result.get("matches")
            if not output and isinstance(matches, list):
                output = ", ".join(str(item) for item in matches)

    if not output:
        content = block.get("content")
        if isinstance(content, str):
            output = content
        elif isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    value = (
                        item.get("text")
                        or item.get("tool_name")
                        or json.dumps(item)
                    )
                else:
                    value = str(item)
                parts.append(str(value))
            output = "\n".join(parts)
    return output


def _find_tool_result_block(event: dict, tool_use_id: str = "") -> dict | None:
    blocks = _event_tool_result_blocks(event)
    if not blocks:
        return None
    if tool_use_id:
        for block in blocks:
            if str(block.get("tool_use_id") or "") == tool_use_id:
                return block
        return None
    return blocks[0]


def _apply_tool_output_preview(event: dict, block: dict, preview: str, ref: dict) -> None:
    result = event.get("tool_use_result")
    if isinstance(result, dict):
        result["content"] = [{"type": "text", "text": preview}]
        for key in ("stdout", "stderr", "matches"):
            result.pop(key, None)
        result["full_output_ref"] = ref

    content = block.get("content")
    if isinstance(content, str):
        block["content"] = preview
    elif isinstance(content, list):
        block["content"] = [{"type": "text", "text": preview}]
    block["full_output_ref"] = ref


def compact_history_event(
    challenge_id: str,
    run_id: str,
    event: dict,
    event_index: int,
) -> dict:
    compact = copy.deepcopy(event)
    if HISTORY_TOOL_OUTPUT_PREVIEW_CHARS <= 0:
        return compact

    original_blocks = _event_tool_result_blocks(event)
    compact_blocks = _event_tool_result_blocks(compact)
    for original_block, compact_block in zip(original_blocks, compact_blocks):
        output = _tool_output_text(event, original_block)
        if len(output) <= HISTORY_TOOL_OUTPUT_PREVIEW_CHARS:
            continue
        tool_use_id = str(original_block.get("tool_use_id") or "")
        query = f"?tool_use_id={quote(tool_use_id, safe='')}" if tool_use_id else ""
        ref = {
            "truncated": True,
            "chars": len(output),
            "preview_chars": HISTORY_TOOL_OUTPUT_PREVIEW_CHARS,
            "event_index": event_index,
            "tool_use_id": tool_use_id,
            "url": (
                f"/api/challenges/{quote(challenge_id, safe='')}"
                f"/runs/{quote(run_id, safe='')}"
                f"/events/{event_index}/tool-output{query}"
            ),
        }
        _apply_tool_output_preview(
            compact,
            compact_block,
            output[:HISTORY_TOOL_OUTPUT_PREVIEW_CHARS],
            ref,
        )
    return compact


async def list_run_events(request: Request) -> JSONResponse:
    """Return a paginated slice of saved run events.

    Slices are addressed by event index. `before` is an exclusive end index;
    omitting it returns the latest chunk.
    """
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    run_id = request.path_params["run_id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    run = challenge["runs"].get(run_id)
    if not run:
        return JSONResponse({"error": "run not found"}, status_code=404)

    limit = _parse_positive_int(
        request.query_params.get("limit"),
        default=200,
        minimum=1,
        maximum=500,
    )
    total = run_event_count(challenge_id, run_id, run)
    before = _parse_positive_int(
        request.query_params.get("before"),
        default=total,
        minimum=0,
        maximum=total,
    )
    start = max(0, before - limit)
    if before == total:
        selected_pairs = load_output_log_tail_slice(
            challenge_id, run_id, total, limit
        )
        if selected_pairs:
            start = selected_pairs[0][0]
    else:
        selected_pairs = load_output_log_slice(
            challenge_id, run_id, start, before
        )
    selected = [
        compact_history_event(challenge_id, run_id, event, event_index)
        for event_index, event in selected_pairs
    ]
    return JSONResponse({
        "events": selected,
        "start": start,
        "end": before,
        "total": total,
        "next_before": start if start > 0 else None,
        "has_more": start > 0,
    })


async def get_run_event_tool_output(request: Request) -> Response:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    run_id = request.path_params["run_id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    run = challenge["runs"].get(run_id)
    if not run:
        return JSONResponse({"error": "run not found"}, status_code=404)

    try:
        event_index = int(request.path_params["event_index"])
    except (TypeError, ValueError):
        return JSONResponse({"error": "invalid event index"}, status_code=400)

    total = run_event_count(challenge_id, run_id, run)
    if event_index < 0 or event_index >= total:
        return JSONResponse({"error": "event not found"}, status_code=404)

    event = load_output_log_event(challenge_id, run_id, event_index)
    if event is None:
        return JSONResponse({"error": "event not found"}, status_code=404)
    if not isinstance(event, dict):
        return JSONResponse({"error": "event has no tool output"}, status_code=404)
    tool_use_id = str(request.query_params.get("tool_use_id") or "")
    block = _find_tool_result_block(event, tool_use_id)
    if not block:
        return JSONResponse({"error": "tool output not found"}, status_code=404)

    output = _tool_output_text(event, block)
    return Response(
        output,
        media_type="text/plain; charset=utf-8",
        headers={"X-Output-Chars": str(len(output))},
    )


async def get_challenge_stats(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    runs = {}
    totals = _empty_stats()
    for run_id, run in challenge.get("runs", {}).items():
        events = iter_output_log_events(challenge_id, run_id)
        stats = _aggregate_run_stats(run, events)
        runs[run_id] = stats
        totals["inputTokens"] += stats["inputTokens"]
        totals["outputTokens"] += stats["outputTokens"]
        totals["cacheReadTokens"] += stats["cacheReadTokens"]
        totals["cacheCreationTokens"] += stats["cacheCreationTokens"]
        totals["toolCalls"] += stats["toolCalls"]
        totals["turns"] += stats["turns"]
        totals["costUsd"] += stats["costUsd"]
        totals["durationMs"] += stats["durationMs"]
        totals["durationApiMs"] += stats["durationApiMs"]

    totals["costUsd"] = round(totals["costUsd"], 8)
    return JSONResponse({
        "runs": runs,
        "total": totals,
    })


async def search_challenge_transcript(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    query = str_field(request.query_params.get("q", "")).strip()
    if not query:
        return JSONResponse({
            "query": "",
            "matches": [],
            "truncated": False,
        })
    limit = _parse_positive_int(
        request.query_params.get("limit"),
        default=100,
        minimum=1,
        maximum=500,
    )
    run_filter = str_field(request.query_params.get("run_id", "")).strip()
    query_key = query.casefold()
    matches = []
    truncated = False

    for run_id, run in challenge.get("runs", {}).items():
        if run_filter and run_id != run_filter:
            continue
        for idx, event in iter_output_log_indexed(challenge_id, run_id):
            text = _event_search_text(event)
            if query_key not in text.casefold():
                continue
            matches.append({
                "run_id": run_id,
                "run_label": run.get("agent", "?"),
                "event_index": idx,
                "event_type": event.get("type", ""),
                "preview": _search_preview(text, query),
            })
            if len(matches) >= limit:
                truncated = True
                break
        if truncated:
            break

    return JSONResponse({
        "query": query,
        "matches": matches,
        "truncated": truncated,
    })


# ---------------------------------------------------------------------------
# Create challenge
# ---------------------------------------------------------------------------

async def create_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    form = await request.form()
    name = form.get("name", "").strip()
    description = form.get("description", "").strip()
    flag_format = form.get("flag_format", "").strip()
    mode = form.get("mode", "single").strip()
    agents_str = form.get("agents", "").strip()
    model = form.get("model", "").strip()
    effort = form.get("effort", "").strip()
    enabled_skills = normalize_enabled_skills(
        form.get("enabled_skills"),
        default=normalize_enabled_skills(load_settings().get("enabled_skills")),
    )

    if mode not in VALID_MODES:
        return JSONResponse(
            {"error": f"invalid mode: {mode}"}, status_code=400
        )

    # Determine agent list with per-agent models
    agent_entries = parse_agents_field(agents_str)
    if not agent_entries:
        single_agent = form.get("agent", "").strip() or DEFAULT_AGENT
        agent_entries = [{"agent": single_agent, "model": model}]

    # Validate agents
    for entry in agent_entries:
        if entry["agent"] not in VALID_AGENTS:
            return JSONResponse(
                {"error": f"invalid agent: {entry['agent']}"},
                status_code=400,
            )

    # For single mode, only use first agent
    if mode == "single":
        agent_entries = agent_entries[:1]
    else:
        # Deduplicate identical agent+model+effort combos in parallel mode
        seen: set[tuple] = set()
        deduped = []
        for entry in agent_entries:
            key = (entry["agent"], entry.get("model", ""), entry.get("effort", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        agent_entries = deduped

    # Read uploaded files into memory
    file_data: dict[str, bytes] = {}
    for _, field in form.multi_items():
        if hasattr(field, "filename") and field.filename:
            safe_path = normalize_uploaded_path(
                field.filename, parallel=(mode == "parallel")
            )
            if not safe_path:
                if mode == "parallel":
                    return JSONResponse(
                        {"error": f"filename '{field.filename}' conflicts "
                         "with reserved parallel workspace names"},
                        status_code=400,
                    )
                continue
            if safe_path in file_data:
                return JSONResponse(
                    {"error": f"duplicate file path: {safe_path}"},
                    status_code=400,
                )
            file_data[safe_path] = await field.read()

    challenge_id = uuid.uuid4().hex[:12]
    display_name = name or f"Challenge {challenge_id}"
    challenge_dir = CHALLENGES_DIR / challenge_id
    challenge_dir.mkdir(parents=True)

    is_parallel = mode == "parallel"

    if is_parallel:
        setup_parallel_shared_dir(challenge_id)

    # Store all untrusted challenge files away from the provider cwd.
    files_dir = challenge_dir / "_files"
    files_dir.mkdir(parents=True, exist_ok=True)
    for rel_path, fdata in file_data.items():
        dest = files_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(fdata)

    # Create runs
    runs: dict[str, dict] = {}
    for entry in agent_entries:
        agent_name = entry["agent"]
        run_id = uuid.uuid4().hex[:8]
        run_model = entry.get("model") or model or resolved_default_model(agent_name)
        run_effort = normalize_effort_for_agent(agent_name, entry.get("effort") or effort)
        run = make_run(
            run_id=run_id,
            agent=agent_name,
            model=run_model,
            effort=run_effort,
            status="solving",
        )
        runs[run_id] = run
        setup_run_dir(challenge_id, run_id)

    # Set up cross-agent note visibility for parallel mode
    if is_parallel:
        assign_notes_labels(runs)
        setup_parallel_cross_notes(challenge_id, runs)

    challenge = {
        "id": challenge_id,
        "name": display_name,
        "description": description,
        "category": "",
        "flag_format": flag_format,
        "extra_flag_formats": [],
        "mode": mode,
        "status": "solving",
        "created_at": datetime.now().isoformat(),
        "files": sorted(file_data.keys()),
        "enabled_skills": enabled_skills,
        "error": None,
        "runs": runs,
    }
    challenges[challenge_id] = challenge
    # Optionally pin the challenge to a swarm worker (run target).
    requested_target = form.get("swarm_instance", "").strip()
    if requested_target:
        assigned = assign_swarm_to_challenge(challenge, requested_target)
        if not assigned and requested_target not in ("", "local"):
            log.warning(
                "[%s] swarm target '%s' unavailable; running locally",
                challenge_id[:8], requested_target,
            )
    sync_challenge_skill_links(challenge)
    save_metadata(challenge)
    asyncio.create_task(discord_ensure_destination(challenge))

    # Start all runs
    def _task_done_cb(t: asyncio.Task, rid: str = "") -> None:
        exc = t.exception() if not t.cancelled() else None
        if exc:
            log.error("[%s/%s] TASK EXCEPTION: %s", challenge_id[:8], rid[:8], exc, exc_info=exc)

    for run_id, run in runs.items():
        run.pop("_stop_reason", None)
        log.info("[%s/%s] Creating asyncio task for agent=%s", challenge_id[:8], run_id[:8], run["agent"])
        task = asyncio.create_task(
            run_agent_task(challenge_id, run_id)
        )
        task.add_done_callback(lambda t, rid=run_id: _task_done_cb(t, rid))
        run["task"] = task

    return JSONResponse(
        {"id": challenge_id, "status": "solving"},
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Bulk preview (preserved exactly)
# ---------------------------------------------------------------------------

async def bulk_preview(request: Request) -> JSONResponse:
    """Preview uploaded bulk archive and return editable challenge rows."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    import io
    import zipfile

    form = await request.form()
    archive_field = form.get("zipfile")
    if not archive_field or not hasattr(archive_field, "read"):
        return JSONResponse(
            {"error": "No archive uploaded"}, status_code=400
        )

    archive_bytes = await archive_field.read()
    original_name = (
        getattr(archive_field, "filename", None) or ""
    ).lower()
    is_7z = original_name.endswith(".7z")

    _cleanup_old_previews()
    token = uuid.uuid4().hex[:16]
    base_dir = Path(tempfile.mkdtemp(prefix=f"ctf-bulk-{token}-"))

    archive_files: dict[str, bytes] = {}
    try:
        if is_7z:
            tmp_archive = base_dir / "_archive.7z"
            tmp_archive.write_bytes(archive_bytes)
            extract_dir = base_dir / "_extract"
            extract_dir.mkdir()
            result = subprocess.run(
                ["7z", "x", f"-o{extract_dir}", "-y", str(tmp_archive)],
                capture_output=True,
                text=True,
            )
            tmp_archive.unlink(missing_ok=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr or result.stdout)
            extract_root = extract_dir.resolve()
            for p in extract_dir.rglob("*"):
                rel_name = p.relative_to(extract_dir).as_posix()
                if p.is_symlink():
                    raise RuntimeError(
                        f"Archive contains unsupported symlink entry: {rel_name}"
                    )
                if not p.is_file():
                    continue
                try:
                    p.resolve(strict=True).relative_to(extract_root)
                except (FileNotFoundError, ValueError):
                    raise RuntimeError(
                        f"Archive entry escapes extraction directory: {rel_name}"
                    )
                archive_files[rel_name] = p.read_bytes()
        else:
            try:
                zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
            except zipfile.BadZipFile:
                shutil.rmtree(base_dir, ignore_errors=True)
                return JSONResponse(
                    {"error": "Invalid zip file"}, status_code=400
                )
            archive_files = {
                name: zf.read(name)
                for name in zf.namelist()
                if not name.endswith("/")
            }
        sanitized_files: dict[str, bytes] = {}
        for path, raw in archive_files.items():
            safe_path = normalize_uploaded_path(path)
            if not safe_path:
                continue
            sanitized_files[safe_path] = raw
        archive_files = sanitized_files
    except Exception as exc:
        shutil.rmtree(base_dir, ignore_errors=True)
        return JSONResponse(
            {"error": f"Failed to read archive: {exc}"},
            status_code=400,
        )

    # Group entries by top-level folder.
    folders: dict[str, list[str]] = {}
    for path in archive_files:
        if path.startswith("__MACOSX") or path.startswith("."):
            continue
        parts = path.split("/", 1)
        if len(parts) < 2 or not parts[1]:
            continue
        folder, filename = parts[0], parts[1]
        if filename.endswith("/"):
            continue
        folders.setdefault(folder, []).append(path)

    if not folders:
        shutil.rmtree(base_dir, ignore_errors=True)
        return JSONResponse(
            {"error": "Archive contains no challenge folders"},
            status_code=400,
        )

    description_files = {"description.txt", "prompt.txt"}
    preview_folders: dict[str, dict] = {}
    challenges_preview = []
    for folder_name, entries in sorted(folders.items()):
        folder_dir = base_dir / folder_name
        folder_dir.mkdir(parents=True, exist_ok=True)
        description = ""
        file_names: list[str] = []
        for entry in entries:
            filename = entry.split("/", 1)[1]
            raw = archive_files[entry]
            if filename.lower() in description_files:
                description = raw.decode(
                    "utf-8", errors="replace"
                ).strip()
                continue
            dest = folder_dir / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            file_names.append(filename)
        preview_folders[folder_name] = {
            "dir": str(folder_dir),
            "files": file_names,
        }
        challenges_preview.append({
            "folder_name": folder_name,
            "name": folder_name,
            "description": description,
            "files": file_names,
        })

    _bulk_previews[token] = {
        "base_dir": base_dir,
        "created_at": _time.monotonic(),
        "folders": preview_folders,
    }
    return JSONResponse({
        "preview_token": token,
        "challenges": challenges_preview,
    })


# ---------------------------------------------------------------------------
# Bulk upload — with mode support
# ---------------------------------------------------------------------------

async def bulk_upload(request: Request) -> JSONResponse:
    """Create challenges from a previously previewed bulk archive."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    token = str_field(body.get("preview_token", ""))
    if not token or token not in _bulk_previews:
        return JSONResponse(
            {"error": "Invalid or expired preview token"},
            status_code=400,
        )

    preview = _bulk_previews.pop(token)
    base_dir = preview["base_dir"]
    preview_folders = preview["folders"]

    try:
        global_flag_format = str_field(body.get("flag_format", "")).strip()
        mode = str_field(body.get("mode", "single")).strip()
        if mode not in VALID_MODES:
            mode = "single"

        # Determine agents with per-agent models
        agents_str = body.get("agents", "")
        if isinstance(agents_str, list):
            agents_str = json.dumps(agents_str)
        agents_str = str(agents_str).strip()
        agent_entries = parse_agents_field(agents_str)
        if not agent_entries:
            single_agent = str_field(body.get("agent", "")).strip() or DEFAULT_AGENT
            agent_entries = [{"agent": single_agent, "model": ""}]

        # Validate agents
        agent_entries = [
            e for e in agent_entries if e["agent"] in VALID_AGENTS
        ]
        if not agent_entries:
            agent_entries = [{"agent": DEFAULT_AGENT, "model": ""}]

        if mode == "single":
            agent_entries = agent_entries[:1]
        else:
            seen_a: set[tuple] = set()
            agent_entries = [e for e in agent_entries if not ((e["agent"], e.get("model", ""), e.get("effort", "")) in seen_a or seen_a.add((e["agent"], e.get("model", ""), e.get("effort", ""))))]

        model = str_field(body.get("model", "")).strip()
        effort = str_field(body.get("effort", "")).strip()
        paused = bool(body.get("paused", False))
        default_enabled_skills = normalize_enabled_skills(
            body.get("enabled_skills"),
            default=normalize_enabled_skills(load_settings().get("enabled_skills")),
        )
        challenges_cfg = body.get("challenges", [])
        if not isinstance(challenges_cfg, list):
            return JSONResponse({"error": "challenges must be a list"}, status_code=400)

        is_parallel = mode == "parallel"
        created = []

        for cfg in challenges_cfg:
            if not isinstance(cfg, dict):
                continue
            if not cfg.get("enabled", True):
                continue
            folder_name = str_field(cfg.get("folder_name", ""))
            folder_info = preview_folders.get(folder_name)
            if not folder_info:
                continue
            folder_dir = Path(folder_info["dir"])
            file_names = folder_info["files"]

            ch_name = str_field(cfg.get("name", "")).strip() or folder_name
            ch_description = str_field(cfg.get("description", "")).strip()
            ch_flag_format = (
                str_field(cfg.get("flag_format", "")).strip()
                or global_flag_format
            )
            ch_enabled_skills = (
                normalize_enabled_skills(
                    cfg.get("enabled_skills"),
                    default=default_enabled_skills,
                )
                if "enabled_skills" in cfg
                else default_enabled_skills
            )

            challenge_id = uuid.uuid4().hex[:12]
            challenge_dir = CHALLENGES_DIR / challenge_id
            challenge_dir.mkdir(parents=True)

            if is_parallel:
                setup_parallel_shared_dir(challenge_id)
                # Filter reserved names that survived preview
                filtered = [
                    f for f in file_names
                    if f.split("/")[0] not in _PARALLEL_RESERVED
                    and not f.split("/")[0].startswith("WORKING_NOTES_")
                ]
                dropped = set(file_names) - set(filtered)
                if dropped:
                    log.warning(
                        "Bulk upload: dropped reserved names for "
                        "challenge %s: %s", ch_name, dropped
                    )
                file_names = filtered

            files_dest = challenge_dir / "_files"
            files_dest.mkdir(parents=True, exist_ok=True)

            for fname in file_names:
                src = folder_dir / fname
                if src.exists():
                    dest = files_dest / fname
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dest)

            challenge_status = "pending" if paused else "solving"

            runs: dict[str, dict] = {}
            for entry in agent_entries:
                agent_name = entry["agent"]
                run_id = uuid.uuid4().hex[:8]
                run_model = entry.get("model") or model or resolved_default_model(agent_name)
                run_effort = normalize_effort_for_agent(agent_name, entry.get("effort") or effort)
                run = make_run(
                    run_id=run_id,
                    agent=agent_name,
                    model=run_model,
                    effort=run_effort,
                    status=challenge_status,
                )
                runs[run_id] = run
                setup_run_dir(challenge_id, run_id)

            if is_parallel:
                assign_notes_labels(runs)
                setup_parallel_cross_notes(challenge_id, runs)

            challenge = {
                "id": challenge_id,
                "name": ch_name,
                "description": ch_description,
                "flag_format": ch_flag_format,
                "extra_flag_formats": [],
                "mode": mode,
                "status": challenge_status,
                "created_at": datetime.now().isoformat(),
                "files": file_names,
                "enabled_skills": ch_enabled_skills,
                "error": None,
                "runs": runs,
            }
            challenges[challenge_id] = challenge
            sync_challenge_skill_links(challenge)
            save_metadata(challenge)

            if challenge_status == "solving":
                for run_id, run in runs.items():
                    run.pop("_stop_reason", None)
                    run["task"] = asyncio.create_task(
                        run_agent_task(challenge_id, run_id)
                    )

            created.append({
                "id": challenge_id,
                "name": ch_name,
                "status": challenge_status,
            })

        return JSONResponse({"created": created}, status_code=201)
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Solve / Stop / Steer / Unsolve / Delete
# ---------------------------------------------------------------------------

async def solve_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    if challenge["status"] == "solving":
        return JSONResponse({"error": "already solving"}, status_code=409)

    target_run_id = request.query_params.get("run_id")
    resume = request.query_params.get("resume") == "1"

    def _start_run(run_id: str, run: dict):
        if resume:
            # Keep output history and session state for true resume
            resume_event = {
                "type": "system",
                "message": "Resuming agent session...",
            }
            record_run_event(challenge_id, run_id, run, resume_event)
        else:
            # Full retry — clear everything
            reset_run_events(challenge_id, run_id, run)
            run["_session_state"] = {}
            run["duration_ms"] = 0
            run["solve_start"] = None
        run["status"] = "solving"
        run.pop("_stop_reason", None)
        run["task"] = asyncio.create_task(
            run_agent_task(
                challenge_id, run_id,
                continue_msg=(
                    "Continue working on this CTF challenge. "
                    "Read your WORKING_NOTES file to recall "
                    "what was already tried."
                ) if resume else None,
            )
        )

    if target_run_id:
        run = challenge["runs"].get(target_run_id)
        if not run:
            return JSONResponse(
                {"error": "run not found"}, status_code=404
            )
        _start_run(target_run_id, run)
    else:
        for run_id, run in challenge["runs"].items():
            _start_run(run_id, run)

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    return JSONResponse({"status": challenge["status"]})


async def stop_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    target_run_id = request.query_params.get("run_id")

    if target_run_id:
        runs_to_stop = {target_run_id: challenge["runs"].get(target_run_id)}
        if not runs_to_stop[target_run_id]:
            return JSONResponse(
                {"error": "run not found"}, status_code=404
            )
    else:
        runs_to_stop = dict(challenge["runs"])

    changed_run_ids = []
    for run_id, run in runs_to_stop.items():
        if not run:
            continue
        if run["status"] not in ("solving", "pending"):
            continue
        run["status"] = "failed"
        run["error"] = None
        stop_event = {
            "type": "system",
            "message": "Agent stopped by user.",
        }
        await _append_run_event(challenge_id, run_id, run, stop_event)
        await stop_run(run, "user_stop")
        finish_run_timer(run)
        changed_run_ids.append(run_id)

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    for run_id in changed_run_ids:
        run = challenge["runs"][run_id]
        await broadcast(challenge_id, run_id, {
            "type": "run_status",
            "run_id": run_id,
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": effective_run_duration_ms(run),
        })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    return JSONResponse({
        "status": challenge["status"],
        "run_ids": changed_run_ids,
    })


async def get_challenge_prompt_template(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    enabled_skills = normalize_enabled_skills(
        body.get("enabled_skills"),
        default=challenge_enabled_skills(challenge),
    )
    prompt = build_add_run_prompt_template(challenge, enabled_skills)
    return JSONResponse({
        "prompt": prompt,
        "placeholders": [
            "{{WORKING_NOTES_PATH}}",
            "{{TEAMMATE_CONTEXT}}",
            "{{REMOTE_INSTANCE_CONNECTION_INFO}}",
        ],
    })


async def add_challenge_runs(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    if challenge.get("status") == "solved":
        return JSONResponse(
            {"error": "challenge is solved; un-solve it before adding agents"},
            status_code=409,
        )

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err

    agents_value = body.get("agents", "")
    agents_str = (
        json.dumps(agents_value)
        if isinstance(agents_value, list)
        else str_field(agents_value).strip()
    )
    agent_entries = parse_agents_field(agents_str)
    if not agent_entries:
        single_agent = str_field(body.get("agent", "")).strip() or DEFAULT_AGENT
        agent_entries = [{
            "agent": single_agent,
            "model": str_field(body.get("model", "")),
            "effort": str_field(body.get("effort", "")),
        }]

    valid_entries = []
    seen: set[tuple[str, str, str]] = set()
    for entry in agent_entries:
        agent_name = entry.get("agent", "")
        if agent_name not in VALID_AGENTS:
            return JSONResponse(
                {"error": f"invalid agent: {agent_name}"},
                status_code=400,
            )
        key = (
            agent_name,
            entry.get("model", ""),
            entry.get("effort", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        valid_entries.append(entry)

    if not valid_entries:
        return JSONResponse({"error": "agent required"}, status_code=400)

    custom_prompt = str_field(body.get("prompt", "")).strip()
    custom_prompt_mode = str_field(body.get("prompt_mode", "")).strip()
    if custom_prompt_mode not in {"full", "append"}:
        custom_prompt_mode = "append"
    has_skill_override = "enabled_skills" in body
    enabled_skills = normalize_enabled_skills(
        body.get("enabled_skills"),
        default=[],
    ) if has_skill_override else []

    new_total = len(challenge.get("runs", {})) + len(valid_entries)
    if new_total > 1:
        challenge["mode"] = "parallel"
        setup_parallel_shared_dir(challenge_id)
        for existing_run in challenge["runs"].values():
            setup_run_dir(challenge_id, existing_run["id"])

    added_run_ids = []
    for entry in valid_entries:
        agent_name = entry["agent"]
        run_id = uuid.uuid4().hex[:8]
        run_model = (
            entry.get("model")
            or str_field(body.get("model", ""))
            or resolved_default_model(agent_name)
        )
        run_effort = normalize_effort_for_agent(
            agent_name,
            entry.get("effort") or str_field(body.get("effort", "")),
        )
        run = make_run(
            run_id=run_id,
            agent=agent_name,
            model=run_model,
            effort=run_effort,
            status="solving",
        )
        if custom_prompt:
            run["custom_prompt"] = custom_prompt
            run["custom_prompt_mode"] = custom_prompt_mode
        if has_skill_override:
            run["enabled_skills"] = enabled_skills
        challenge["runs"][run_id] = run
        setup_run_dir(challenge_id, run_id)
        added_run_ids.append(run_id)

    if challenge.get("mode") == "parallel":
        assign_notes_labels(challenge["runs"])
        setup_parallel_cross_notes(challenge_id, challenge["runs"])

    for run_id in added_run_ids:
        sync_run_skill_links(challenge, challenge["runs"][run_id])

    challenge["status"] = derive_challenge_status(challenge)
    challenge["error"] = None
    save_metadata(challenge)

    def _task_done_cb(t: asyncio.Task, rid: str = "") -> None:
        exc = t.exception() if not t.cancelled() else None
        if exc:
            log.error(
                "[%s/%s] TASK EXCEPTION: %s",
                challenge_id[:8], rid[:8], exc, exc_info=exc,
            )

    added_runs = []
    for run_id in added_run_ids:
        run = challenge["runs"][run_id]
        task = asyncio.create_task(run_agent_task(challenge_id, run_id))
        task.add_done_callback(lambda t, rid=run_id: _task_done_cb(t, rid))
        run["task"] = task
        summary = public_run_summary(challenge, run)
        added_runs.append(summary)
        await broadcast_challenge(challenge_id, {
            "type": "run_added",
            "challenge_id": challenge_id,
            "run": summary,
        })

    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    return JSONResponse({
        "status": challenge["status"],
        "mode": challenge["mode"],
        "runs": added_runs,
    }, status_code=201)


async def broadcast_to_agents(request: Request) -> JSONResponse:
    """Broadcast a user message to all active runs as a breakthrough."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    message = str_field(body.get("message", "")).strip()
    if not message:
        return JSONResponse({"error": "message required"}, status_code=400)

    try:
        from .agents.broadcast import broadcast_to_teammates, _queues
    except ImportError:
        from agents.broadcast import broadcast_to_teammates, _queues

    # Broadcast to all runs (not from any specific run)
    queues = _queues.get(challenge_id, {})
    count = 0
    for run_id, queue in queues.items():
        await queue.put(f"[User]: {message}")
        count += 1

    # Also notify via Discord
    await discord_notify(challenge, f"**User** breakthrough: {message}")

    return JSONResponse({"ok": True, "sent_to": count})


async def _steer_run_with_message(
    challenge_id: str,
    target_run_id: str,
    run: dict,
    message: str,
    *,
    display_message: str | None = None,
    stop_reason: str = "steer",
) -> None:
    """Stop a run immediately and resume it with a continuation message."""
    await stop_run(run, stop_reason)
    finish_run_timer(run)

    steer_event = {
        "type": "user_steer",
        "message": display_message or message,
    }
    await _append_run_event(challenge_id, target_run_id, run, steer_event)

    run["status"] = "solving"
    run["error"] = None
    run.pop("_stop_reason", None)
    run["task"] = asyncio.create_task(
        run_agent_task(
            challenge_id, target_run_id, continue_msg=message
        )
    )


def _format_skill_mentions(skill_names: list[str]) -> str:
    mentions = [f"${name}" for name in skill_names if name]
    if len(mentions) <= 1:
        return "".join(mentions)
    return f"{', '.join(mentions[:-1])} and {mentions[-1]}"


def _skill_resume_message(
    run: dict,
    challenge_id: str = "",
    run_id: str = "",
    codex_skill_mentions: list[str] | None = None,
) -> str | None:
    has_history = bool(run.get("output_lines"))
    if not has_history and challenge_id and run_id:
        has_history = run_event_count(challenge_id, run_id, run) > 0
    if run.get("status") == "pending" and not has_history:
        return None
    message = "Continue solving the challenge."
    mention_text = _format_skill_mentions(codex_skill_mentions or [])
    if mention_text:
        message += f" You may use {mention_text} if you see fit."
    return message


async def _start_run_after_skill_change(
    challenge_id: str,
    run_id: str,
    run: dict,
    continue_msg: str | None,
    codex_skill_mentions: list[str] | None = None,
) -> None:
    run["status"] = "solving"
    run["error"] = None
    run.pop("_stop_reason", None)
    run["task"] = asyncio.create_task(
        run_agent_task(
            challenge_id,
            run_id,
            continue_msg=continue_msg,
            codex_skill_mentions=codex_skill_mentions,
        )
    )


async def steer_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    message = str_field(body.get("message", "")).strip()
    if not message:
        return JSONResponse(
            {"error": "message required"}, status_code=400
        )

    target_run_id = str_field(body.get("run_id", ""))

    if target_run_id:
        run = challenge["runs"].get(target_run_id)
        if not run:
            return JSONResponse(
                {"error": "run not found"}, status_code=404
            )
    else:
        # Find the first solving run
        run = None
        target_run_id = None
        for rid, r in challenge["runs"].items():
            if r["status"] == "solving":
                run = r
                target_run_id = rid
                break
        if not run:
            # Fall back to first run
            target_run_id = next(iter(challenge["runs"]), None)
            if target_run_id:
                run = challenge["runs"][target_run_id]
        if not run or not target_run_id:
            return JSONResponse(
                {"error": "no run to steer"}, status_code=404
            )

    await _steer_run_with_message(
        challenge_id,
        target_run_id,
        run,
        message,
    )

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    return JSONResponse({"status": challenge["status"]})


async def unsolve_challenge(request: Request) -> JSONResponse:
    """Set solved run(s) back to failed so user can retry."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    changed_run_ids = []
    for run_id, run in challenge["runs"].items():
        if run["status"] == "solved":
            run["status"] = "failed"
            changed_run_ids.append(run_id)

    if not changed_run_ids:
        return JSONResponse(
            {"error": "no solved runs to unsolve"}, status_code=409
        )

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    for rid in changed_run_ids:
        await broadcast(challenge_id, rid, {
            "type": "run_status",
            "run_id": rid,
            "status": "failed",
            "duration_ms": effective_run_duration_ms(challenge["runs"][rid]),
        })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    return JSONResponse({"status": challenge["status"]})


async def mark_solved(request: Request) -> JSONResponse:
    """Mark a specific run (or the challenge) as solved.

    Only call this when a flag is confirmed correct — either via
    auto-submit to the platform or by the user confirming manually.
    """
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    run_id = str_field(body.get("run_id", ""))
    solved_flag = str_field(body.get("flag", "")).strip()
    has_questions = bool(challenge.get("_flag_questions"))

    if has_questions:
        try:
            question_value = body.get("question")
            question = int(question_value) if question_value not in (None, "") else None
            resolved_question, resolved_flag_id, question_idx = resolve_flag_question(
                challenge, question, body.get("flag_id")
            )
            if resolved_question is None and resolved_flag_id is None:
                raise ValueError(
                    "question or flag_id is required for multi-answer challenges"
                )
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        if solved_flag:
            stored_flag = set_detected_flag_status(challenge, solved_flag, "correct")
            record_flag_submission(
                challenge,
                stored_flag,
                submitted_flag=solved_flag,
                run_id=run_id,
                flag_id=resolved_flag_id,
                question=question_idx,
                correct=True,
                message="Marked correct manually",
                manual_mark=True,
            )
        else:
            stored_flag = ""
        if resolved_question is not None:
            resolved_question["solved"] = True
        all_questions_solved = all(
            q.get("solved") for q in challenge.get("_flag_questions", [])
        )
        if not all_questions_solved:
            save_metadata(challenge)
            if stored_flag:
                await broadcast_global({
                    "type": "flag_result",
                    "challenge_id": challenge_id,
                    "flag": stored_flag,
                    "correct": True,
                    "message": "Marked correct manually",
                    "meta": detected_flag_meta(challenge, stored_flag),
                    "flag_questions": challenge.get("_flag_questions", []),
                    "all_questions_solved": False,
                    "status": challenge.get("status", ""),
                })
            return JSONResponse({
                "status": challenge["status"],
                "run_id": run_id,
                "flag": stored_flag,
                "flag_id": resolved_flag_id,
                "question": question_idx,
                "flag_questions": challenge.get("_flag_questions", []),
                "all_questions_solved": False,
                "meta": detected_flag_meta(challenge, stored_flag) if stored_flag else {},
            })

    solved_run_id, solved_run = await apply_solved_status(
        challenge_id,
        challenge,
        flag=solved_flag,
        run_id=run_id,
        stop_reason="manual_solved",
    )
    if not solved_run:
        return JSONResponse(
            {"error": "no eligible run to mark as solved"},
            status_code=409,
        )

    agent = solved_run.get("agent", "")
    await discord_notify(
        challenge,
        embed=make_solve_embed(challenge, solved_flag or "???", agent),
    )
    await discord_mark_solved(challenge, solved_flag or "", agent)
    return JSONResponse({
        "status": challenge["status"],
        "run_id": solved_run_id,
        "flag": solved_flag,
        "flag_questions": challenge.get("_flag_questions", []),
        "all_questions_solved": True if has_questions else False,
        "meta": detected_flag_meta(challenge, solved_flag) if solved_flag else {},
    })


async def delete_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    # Mark deleted so finalizers become no-ops
    challenge["_deleted"] = True

    # Stop all runs
    for run in challenge["runs"].values():
        await stop_run(run, "deleted")

    # Free any swarm worker pinned to this challenge.
    release_swarm_from_challenge(challenge)

    challenge_dir = CHALLENGES_DIR / challenge_id
    if challenge_dir.exists():
        shutil.rmtree(challenge_dir)
    shutil.rmtree(challenge_state_dir(challenge_id), ignore_errors=True)

    del challenges[challenge_id]
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# File viewer
# ---------------------------------------------------------------------------

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico"}
TEXT_EXTS = {
    ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".log", ".sh", ".bash", ".zsh",
    ".py", ".js", ".ts", ".c", ".cpp", ".h", ".hpp", ".rs", ".go",
    ".java", ".rb", ".pl", ".lua", ".sql", ".html", ".css", ".php",
    ".r", ".m", ".asm", ".s", ".diff", ".patch",
}
MAX_TEXT_SIZE = 512 * 1024
MAX_HEX_SIZE = 64 * 1024
MAX_DISCORD_FILE_READ = 64 * 1024
PROJECT_SKILL_ROOTS = {".claude", ".codex"}


def safe_user_path(raw: str) -> str | None:
    """Return a safe relative POSIX path, or None if unsafe."""
    p = PurePosixPath(str(raw).replace("\\", "/"))
    if p.is_absolute():
        return None
    if any(part in ("", ".", "..") for part in p.parts):
        return None
    if not p.parts:
        return None
    return p.as_posix()


def safe_user_dir(raw: str) -> str | None:
    """Return a safe relative POSIX directory path, allowing root."""
    value = str(raw or "").replace("\\", "/")
    if value.startswith("/"):
        return None
    value = value.strip("/")
    if not value or value == ".":
        return ""
    p = PurePosixPath(value)
    if p.is_absolute():
        return None
    if any(part in ("", ".", "..") for part in p.parts):
        return None
    return p.as_posix()


def is_project_skill_relpath(raw: str) -> bool:
    parts = PurePosixPath(str(raw or "").replace("\\", "/")).parts
    return bool(parts and parts[0] in PROJECT_SKILL_ROOTS)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_allowed_path(
    base: Path, raw: str, allowed_roots: list[Path]
) -> Path | None:
    """Resolve a user-supplied path under one of the allowed roots."""
    safe = safe_user_path(raw)
    if not safe:
        return None
    target = (base / safe).resolve()
    for root in allowed_roots:
        try:
            target.relative_to(root.resolve())
            return target
        except ValueError:
            continue
    return None


def resolve_allowed_dir(
    base: Path, raw: str, allowed_roots: list[Path]
) -> tuple[Path | None, str | None]:
    """Resolve a user-supplied directory under one of the allowed roots."""
    safe = safe_user_dir(raw)
    if safe is None:
        return None, None
    target = (base / safe).resolve() if safe else base.resolve()
    for root in allowed_roots:
        try:
            target.relative_to(root.resolve())
            return target, safe
        except ValueError:
            continue
    return None, None


def classify_file(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in IMAGE_EXTS:
        return "image"
    if ext in TEXT_EXTS:
        return "text"
    try:
        chunk = path.read_bytes()[:8192]
        chunk.decode("utf-8")
        return "text"
    except (UnicodeDecodeError, OSError):
        return "binary"


def _resolve_file_dir(challenge_id: str, run_id: str | None) -> Path | None:
    """Resolve the directory for file listing based on mode and run_id."""
    challenge = challenges.get(challenge_id)
    if not challenge:
        return None
    challenge_dir = CHALLENGES_DIR / challenge_id
    if run_id and run_id in challenge["runs"]:
        run_dir = challenge_dir / "_runs" / run_id
        if run_dir.exists():
            return run_dir
        # Legacy single-run challenges predate _runs/{run_id}.
        if challenge.get("mode") == "single":
            return challenge_dir

    # New challenges store untrusted files under _files/ for all modes.
    # Without a run_id, show raw challenge files instead of exposing _runs/.
    files_dir = challenge_dir / "_files"
    if files_dir.is_dir():
        return files_dir

    return challenge_dir


def _allowed_file_roots(challenge_id: str, base_dir: Path) -> list[Path]:
    """Roots that file viewing may follow from a resolved base directory."""
    challenge_dir = CHALLENGES_DIR / challenge_id
    roots = [base_dir]
    runs_dir = challenge_dir / "_runs"
    try:
        is_run_dir = _is_relative_to(base_dir.resolve(), runs_dir.resolve())
    except FileNotFoundError:
        is_run_dir = False
    if is_run_dir:
        roots.extend([challenge_dir / "_files", challenge_dir / "_shared"])
    return [root for root in roots if root.exists()]


def _swarm_file_ip(challenge_id: str, run_id: str | None) -> str:
    """If a run's workspace lives on a swarm worker, return that worker's IP."""
    if not run_id:
        return ""
    challenge = challenges.get(challenge_id)
    if not challenge or run_id not in challenge.get("runs", {}):
        return ""
    return _resolve_swarm_ip(challenge)


def _classify_name(name: str) -> str:
    ext = os.path.splitext(name)[1].lower()
    if ext in IMAGE_EXTS:
        return "image"
    if ext in TEXT_EXTS:
        return "text"
    return "binary"


def _render_file_payload(name: str, data: bytes, total: int) -> dict:
    """Build a get_file JSON payload from raw bytes (used by the remote path)."""
    ext = os.path.splitext(name)[1].lower()
    if ext in IMAGE_EXTS:
        mime = mimetypes.guess_type(name)[0] or "image/png"
        return {"type": "image", "mime": mime,
                "data": base64.b64encode(data).decode("ascii"),
                "name": name, "size": total}
    is_text = ext in TEXT_EXTS
    if not is_text:
        try:
            data[:8192].decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            is_text = False
    if is_text:
        content = data[:MAX_TEXT_SIZE].decode("utf-8", errors="replace")
        if total > MAX_TEXT_SIZE:
            content += f"\n\n... (truncated, {total} bytes total)"
        return {"type": "text", "content": content, "name": name,
                "ext": ext, "size": total}
    chunk = data[:MAX_HEX_SIZE]
    lines = []
    for off in range(0, len(chunk), 16):
        c = chunk[off:off + 16]
        hexp = " ".join(f"{b:02x}" for b in c)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        lines.append(f"{off:08x}  {hexp:<48s}  |{asc}|")
    if total > MAX_HEX_SIZE:
        lines.append(f"... ({total} bytes total, showing first {MAX_HEX_SIZE})")
    return {"type": "binary", "hexdump": "\n".join(lines),
            "name": name, "size": total}


async def list_files(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)

    run_id = request.query_params.get("run_id")

    # Remote run: browse the worker's workspace over SSH.
    swarm_ip = _swarm_file_ip(challenge_id, run_id)
    if swarm_ip and request.query_params.get("browse") == "1":
        requested_dir = request.query_params.get("dir", "")
        safe_dir = safe_user_dir(requested_dir)
        if safe_dir is None:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            from .swarm_exec import ssh_browse
        except ImportError:
            from swarm_exec import ssh_browse
        result = await ssh_browse(swarm_ip, challenge_id, run_id, safe_dir)
        if result.get("error") == "forbidden":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if result.get("error"):
            return JSONResponse({"error": "not found"}, status_code=404)
        entries = []
        for e in result.get("entries", []):
            rel = (
                (PurePosixPath(safe_dir) / e["name"]).as_posix()
                if safe_dir else e["name"]
            )
            item = {"kind": e["kind"], "name": e["name"], "path": rel}
            if e["kind"] == "file":
                item["size"] = e.get("size", 0)
                item["type"] = _classify_name(e["name"])
            entries.append(item)
        parent = ""
        if safe_dir:
            parent_path = PurePosixPath(safe_dir).parent.as_posix()
            parent = "" if parent_path == "." else parent_path
        return JSONResponse({"path": safe_dir, "parent": parent, "entries": entries})

    challenge_dir = _resolve_file_dir(challenge_id, run_id)
    if not challenge_dir or not challenge_dir.exists():
        return JSONResponse({"error": "not found"}, status_code=404)

    allowed_roots = [
        root.resolve() for root in _allowed_file_roots(challenge_id, challenge_dir)
    ]

    if request.query_params.get("browse") == "1":
        requested_dir = request.query_params.get("dir", "")
        current_dir, safe_dir = resolve_allowed_dir(
            challenge_dir, requested_dir, allowed_roots
        )
        if safe_dir is None:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if is_project_skill_relpath(safe_dir):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if not current_dir or not current_dir.is_dir():
            return JSONResponse({"error": "not found"}, status_code=404)

        entries = []
        try:
            children = sorted(
                current_dir.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.casefold()),
            )
        except OSError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        for child in children:
            try:
                resolved = child.resolve()
            except OSError:
                continue
            if not any(_is_relative_to(resolved, root) for root in allowed_roots):
                continue

            rel = (
                (PurePosixPath(safe_dir) / child.name).as_posix()
                if safe_dir else child.name
            )
            if is_project_skill_relpath(rel):
                continue
            try:
                if child.is_dir():
                    entries.append({
                        "kind": "directory",
                        "name": child.name,
                        "path": rel,
                    })
                elif child.is_file():
                    entries.append({
                        "kind": "file",
                        "name": child.name,
                        "path": rel,
                        "size": child.stat().st_size,
                        "type": classify_file(child),
                    })
            except OSError:
                continue

        parent = ""
        if safe_dir:
            parent_path = PurePosixPath(safe_dir).parent.as_posix()
            parent = "" if parent_path == "." else parent_path
        return JSONResponse({
            "path": safe_dir,
            "parent": parent,
            "entries": entries,
        })

    files = []
    for p in sorted(challenge_dir.rglob("*")):
        if not p.is_file():
            continue
        resolved = p.resolve()
        if not any(_is_relative_to(resolved, root) for root in allowed_roots):
            continue
        rel = str(p.relative_to(challenge_dir))
        if is_project_skill_relpath(rel):
            continue
        files.append({
            "path": rel,
            "size": p.stat().st_size,
            "type": classify_file(p),
        })
    return JSONResponse(files)


async def get_file(request: Request) -> Response:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)
    file_path = request.path_params["path"]
    if is_project_skill_relpath(file_path):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    run_id = request.query_params.get("run_id")

    swarm_ip = _swarm_file_ip(challenge_id, run_id)
    if swarm_ip:
        safe_rel = safe_user_path(file_path)
        if safe_rel is None:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            from .swarm_exec import ssh_read
        except ImportError:
            from swarm_exec import ssh_read
        result = await ssh_read(
            swarm_ip, challenge_id, run_id, safe_rel, MAX_TEXT_SIZE + MAX_HEX_SIZE)
        if result.get("error") == "forbidden":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if result.get("error"):
            return JSONResponse({"error": "not found"}, status_code=404)
        data = base64.b64decode(result.get("data", ""))
        return JSONResponse(_render_file_payload(
            PurePosixPath(file_path).name, data, int(result.get("total", len(data)))))

    challenge_dir = _resolve_file_dir(challenge_id, run_id)
    if not challenge_dir:
        return JSONResponse({"error": "not found"}, status_code=404)

    full_path = resolve_allowed_path(
        challenge_dir,
        file_path,
        _allowed_file_roots(challenge_id, challenge_dir),
    )
    if not full_path:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if not full_path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)

    file_type = classify_file(full_path)
    ext = full_path.suffix.lower()

    if file_type == "image":
        mime = mimetypes.guess_type(str(full_path))[0] or "image/png"
        data = full_path.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return JSONResponse({
            "type": "image",
            "mime": mime,
            "data": b64,
            "name": full_path.name,
            "size": len(data),
        })

    if file_type == "text":
        size = full_path.stat().st_size
        if size > MAX_TEXT_SIZE:
            content = full_path.read_bytes()[:MAX_TEXT_SIZE].decode(
                "utf-8", errors="replace"
            )
            content += f"\n\n... (truncated, {size} bytes total)"
        else:
            content = full_path.read_text(errors="replace")
        return JSONResponse({
            "type": "text",
            "content": content,
            "name": full_path.name,
            "ext": ext,
            "size": size,
        })

    # Binary: return hexdump
    data = full_path.read_bytes()[:MAX_HEX_SIZE]
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{offset:08x}  {hex_part:<48s}  |{ascii_part}|")
    total = full_path.stat().st_size
    if total > MAX_HEX_SIZE:
        lines.append(f"... ({total} bytes total, showing first {MAX_HEX_SIZE})")
    return JSONResponse({
        "type": "binary",
        "hexdump": "\n".join(lines),
        "name": full_path.name,
        "size": total,
    })


async def download_file(request: Request) -> Response:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)
    file_path = request.path_params["path"]
    if is_project_skill_relpath(file_path):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    run_id = request.query_params.get("run_id")

    swarm_ip = _swarm_file_ip(challenge_id, run_id)
    if swarm_ip:
        safe_rel = safe_user_path(file_path)
        if safe_rel is None:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            from .swarm_exec import ssh_read
        except ImportError:
            from swarm_exec import ssh_read
        # Cap downloads to a sane size over SSH.
        result = await ssh_read(
            swarm_ip, challenge_id, run_id, safe_rel, 64 * 1024 * 1024)
        if result.get("error") == "forbidden":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if result.get("error"):
            return JSONResponse({"error": "not found"}, status_code=404)
        name = PurePosixPath(file_path).name
        data = base64.b64decode(result.get("data", ""))
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        return Response(content=data, media_type=mime, headers={
            "Content-Disposition": f'attachment; filename="{name}"'})

    challenge_dir = _resolve_file_dir(challenge_id, run_id)
    if not challenge_dir:
        return JSONResponse({"error": "not found"}, status_code=404)

    full_path = resolve_allowed_path(
        challenge_dir,
        file_path,
        _allowed_file_roots(challenge_id, challenge_dir),
    )
    if not full_path:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if not full_path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)

    mime = (
        mimetypes.guess_type(str(full_path))[0]
        or "application/octet-stream"
    )
    data = full_path.read_bytes()
    return Response(
        content=data,
        media_type=mime,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{full_path.name}"'
            ),
        },
    )

_VIEWER_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#212121;--bg-card:#292929;--bg-panel:#303030;--bg-input:#383838;--bg-hover:#3c3c3c;
  --border:#424242;--border-light:#515151;
  --text:#eeffff;--text-muted:#b0bec5;--text-dim:#616161;
  --accent:#89ddff;--accent-dim:rgba(137,221,255,0.12);
  --green:#c3e88d;--green-dim:rgba(195,232,141,0.12);
  --yellow:#ffcb6b;--yellow-dim:rgba(255,203,107,0.12);
  --red:#f07178;--red-dim:rgba(240,113,120,0.12);
  --orange:#f78c6c;--orange-dim:rgba(247,140,108,0.12);
  --purple:#c792ea;--purple-dim:rgba(199,146,234,0.12);
  --mono:"JetBrains Mono","Fira Code","SF Mono","Cascadia Code",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);display:flex;height:100vh;overflow:hidden}
a{color:var(--accent)}

/* Sidebar */
.sidebar{width:280px;min-width:280px;background:var(--bg-panel);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.sidebar h2{padding:14px 16px;font-size:13px;border-bottom:1px solid var(--border);color:var(--text)}
.sidebar .meta{padding:12px 16px;font-size:0.75rem;color:var(--text-muted);border-bottom:1px solid var(--border);line-height:1.7}
.sidebar .meta b{color:var(--text)}
.sidebar .meta code{font-family:var(--mono);font-size:0.72em;background:rgba(0,0,0,0.3);padding:0.1em 0.35em;border-radius:4px;color:var(--red)}
.file-list{flex:1;overflow-y:auto;padding:8px}
.file-list .file{padding:6px 12px;font-size:0.72rem;font-family:var(--mono);cursor:pointer;border-radius:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text-muted)}
.file-list .file:hover{background:var(--bg-hover);color:var(--text)}
.file-list .file.active{background:var(--accent-dim);color:var(--accent)}

/* Main area */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.tab-bar{display:flex;background:var(--bg-panel);border-bottom:1px solid var(--border)}
.tab-bar button{padding:8px 16px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:0.78rem;border-bottom:2px solid transparent;font-family:var(--sans)}
.tab-bar button.active{color:var(--text);border-bottom-color:var(--accent)}
.tab-bar button:hover{color:var(--text)}
.content{flex:1;overflow-y:auto;padding:0.5rem 0.75rem}

/* Run selector */
.run-select{display:flex;gap:8px;padding:8px 12px;background:var(--bg-panel);border-bottom:1px solid var(--border)}
.run-select button{padding:4px 12px;background:var(--bg-card);border:1px solid var(--border);color:var(--text-muted);border-radius:4px;cursor:pointer;font-size:0.72rem;font-family:var(--sans)}
.run-select button.active{background:var(--accent-dim);border-color:var(--accent);color:var(--accent)}

/* Chat bubbles */
.chat-bubble{max-width:80%;margin-bottom:0.5rem;padding:0.55rem 0.75rem;border-radius:12px;font-size:0.82rem;line-height:1.6;word-break:break-word;clear:both}
.chat-assistant{float:left;background:var(--bg-card);border:1px solid var(--border);border-bottom-left-radius:4px}
.chat-user{float:right;background:var(--accent-dim);border:1px solid var(--accent);border-bottom-right-radius:4px;color:var(--accent)}
.chat-label{font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;margin-bottom:0.2rem;opacity:0.6}
.chat-body{white-space:pre-wrap}
.chat-body p{margin:0}.chat-body p+p{margin-top:0.4em}
.chat-body strong{color:var(--text);font-weight:700}
.chat-body em{font-style:italic;opacity:0.9}
.msg-ts{font-size:0.6rem;color:var(--text-dim);font-family:var(--mono);opacity:0.7;float:right;margin-left:8px}

/* Thinking */
.chat-thinking-bubble{background:var(--purple-dim);border-color:rgba(199,146,234,0.25)}
.step-thinking{padding:0;color:var(--purple);font-size:0.75rem;font-style:italic}
.step-thinking summary{cursor:pointer;outline:none;list-style:none;padding:0.4rem 0.5rem;display:flex;align-items:center;gap:0.35rem}
.step-thinking summary::-webkit-details-marker{display:none}
.step-thinking summary::before{content:"\25B6";font-size:0.55rem;transition:transform 0.15s;display:inline-block;font-style:normal}
.step-thinking[open] summary::before{content:"\25BC"}
.thinking-label{font-weight:600;font-style:normal}
.thinking-preview{opacity:0.7;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.thinking-body{padding:0.4rem 0.5rem;padding-top:0;white-space:pre-wrap;word-break:break-word;line-height:1.5;max-height:400px;overflow-y:auto;border-top:1px solid rgba(199,146,234,0.15)}

/* Tool groups */
.chat-tool-group{clear:both;width:90%;margin:0.35rem auto;border:1px solid var(--border);border-radius:8px;background:var(--bg-card);overflow:hidden}
.chat-tool-collapsed{display:none}
.chat-tool-collapsed.chat-tool-expanded{display:block}
.chat-tool-expand{display:block;width:100%;text-align:center;padding:0.25rem;font-size:0.7rem;color:var(--text-muted);border:none;border-top:1px solid var(--border);border-bottom:1px solid var(--border);border-radius:0;background:none;cursor:pointer}
.chat-tool-expand:hover{background:var(--bg-hover)}

/* Individual tool */
.step-tool{border-bottom:1px solid var(--border)}
.step-tool:last-child{border-bottom:none}
.tool-bar{display:flex;align-items:center;gap:0.4rem;padding:0.35rem 0.65rem;cursor:pointer;user-select:none;font-size:0.75rem;transition:background 0.1s}
.tool-bar:hover{background:var(--bg-hover)}
.tool-icon{width:20px;height:20px;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:0.6rem;font-weight:800;flex-shrink:0;font-family:var(--mono)}
.tool-icon-bash{background:var(--green);color:#212121}
.tool-icon-read{background:var(--accent);color:#212121}
.tool-icon-write{background:var(--orange);color:#212121}
.tool-icon-edit{background:var(--yellow);color:#212121}
.tool-icon-other{background:var(--text-dim);color:var(--text)}
.tool-name{font-weight:700;color:var(--text);font-family:var(--mono);font-size:0.7rem}
.tool-desc{color:var(--text-muted);font-size:0.7rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)}
.tool-status{font-size:0.6rem;font-weight:700;padding:0.1rem 0.35rem;border-radius:4px;text-transform:uppercase;letter-spacing:0.03em}
.tool-status-done{color:var(--green);background:var(--green-dim)}
.tool-status-error{color:var(--red);background:var(--red-dim)}
.tool-detail{display:none}
.tool-detail.open{display:block}
.tool-input-section,.tool-output-section{padding:0.35rem 0.65rem;font-family:var(--mono);font-size:0.7rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;max-height:250px;overflow-y:auto}
.tool-input-section{background:rgba(0,0,0,0.15);border-top:1px solid var(--border);color:var(--text-muted)}
.tool-output-section{background:rgba(0,0,0,0.25);border-top:1px solid var(--border);color:var(--text-muted)}
.tool-output-error{color:var(--red)}

/* System / error / result messages */
.system-msg{clear:both;text-align:center;padding:0.25rem 0.75rem;color:var(--yellow);font-style:italic;font-size:0.7rem;background:var(--yellow-dim);border-radius:12px;margin:0.25rem auto;max-width:fit-content}
.error-msg{clear:both;padding:0.3rem 0.65rem;color:var(--red);font-size:0.75rem;font-family:var(--mono);white-space:pre-wrap}
.result-block{clear:both;margin:0.5rem 0;border:1px solid var(--green);border-radius:8px;background:var(--green-dim);padding:0.6rem 0.75rem}
.result-label{font-size:0.65rem;font-weight:700;text-transform:uppercase;color:var(--green);margin-bottom:0.25rem;letter-spacing:0.04em}
.result-text{font-size:0.82rem;line-height:1.6;white-space:pre-wrap;word-break:break-word}

/* Markdown */
.md-h1{font-size:1rem;font-weight:700;margin:0.5em 0 0.25em;color:var(--text);border-bottom:1px solid var(--border);padding-bottom:0.2em}
.md-h2{font-size:0.9rem;font-weight:700;margin:0.4em 0 0.2em;color:var(--text)}
.md-h3{font-size:0.85rem;font-weight:700;margin:0.3em 0 0.15em;color:var(--text)}
.md-code{font-family:var(--mono);font-size:0.78em;background:rgba(0,0,0,0.3);padding:0.1em 0.35em;border-radius:4px;color:var(--red)}
.md-codeblock{background:rgba(0,0,0,0.35);border:1px solid var(--border);border-radius:6px;padding:0.5rem 0.65rem;margin:0.3em 0;font-family:var(--mono);font-size:0.75rem;line-height:1.5;overflow-x:auto;white-space:pre;color:var(--text)}
.md-codeblock code{background:none;padding:0;color:inherit}
.md-list{list-style:disc;padding-left:1.2em;margin:0.2em 0}
.md-list li{margin:0.15em 0}

/* Status badge */
.status-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.65rem;font-weight:600}
.status-badge.solved{background:var(--green-dim);color:var(--green)}
.status-badge.failed{background:var(--red-dim);color:var(--red)}
.status-badge.solving{background:var(--accent-dim);color:var(--accent)}
.status-badge.pending{background:var(--border);color:var(--text-muted)}

/* File viewer */
.file-viewer{padding:16px}
.file-viewer h3{font-size:0.85rem;color:var(--text)}
.file-viewer pre{font-family:var(--mono);font-size:0.75rem;white-space:pre-wrap;word-break:break-word;line-height:1.5;background:rgba(0,0,0,0.35);padding:12px;border-radius:6px;border:1px solid var(--border);color:var(--text)}
.file-viewer img{max-width:100%;border-radius:6px}
.file-viewer .binary-note{color:var(--text-muted);font-style:italic;font-size:0.78rem}

.clearfix::after{content:'';display:block;clear:both}
</style>
</head>
<body>
<div class="sidebar">
  <h2>{{TITLE_SHORT}}</h2>
  <div class="meta">
    <b>Status:</b> <span class="status-badge {{STATUS}}">{{STATUS}}</span><br>
    <b>Mode:</b> {{MODE}}<br>
    <b>Created:</b> {{CREATED}}<br>
    <b>Flag format:</b> <code>{{FLAG_FORMAT}}</code><br>
    {{DETECTED_FLAGS}}
  </div>
  <div class="file-list" id="file-list"></div>
</div>
<div class="main">
  <div class="tab-bar">
    <button class="active" onclick="showTab('stream')">Stream</button>
    <button onclick="showTab('files')">Files</button>
  </div>
  <div id="tab-stream" class="content"></div>
  <div id="tab-files" class="content" style="display:none"></div>
</div>
<script>
const DATA = {{DATA_JSON}};
const challenge = DATA.challenge;
const streams = DATA.streams;
const files = DATA.files;

function showTab(name) {
  document.getElementById('tab-stream').style.display = name === 'stream' ? '' : 'none';
  document.getElementById('tab-files').style.display = name === 'files' ? '' : 'none';
  document.querySelectorAll('.tab-bar button').forEach((b, i) => {
    b.classList.toggle('active', (i === 0 && name === 'stream') || (i === 1 && name === 'files'));
  });
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function renderMarkdown(text) {
  let h = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  h = h.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre class="md-codeblock"><code>$2</code></pre>');
  h = h.replace(/`([^`\n]+)`/g, '<code class="md-code">$1</code>');
  h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');
  h = h.replace(/^### (.+)$/gm, '<div class="md-h3">$1</div>');
  h = h.replace(/^## (.+)$/gm, '<div class="md-h2">$1</div>');
  h = h.replace(/^# (.+)$/gm, '<div class="md-h1">$1</div>');
  h = h.replace(/^[*-] (.+)$/gm, '<li>$1</li>');
  h = h.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
  h = h.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul class="md-list">$1</ul>');
  h = h.replace(/\n\n/g, '</p><p>');
  h = '<p>' + h + '</p>';
  h = h.replace(/<p><\/p>/g, '');
  h = h.replace(/<p>(<(?:pre|ul|div)[^>]*>)/g, '$1');
  h = h.replace(/(<\/(?:pre|ul|div)>)<\/p>/g, '$1');
  return h;
}

function truncate(s, n) { return !s ? '' : s.length > n ? s.slice(0, n) + '...' : s; }
function shortPath(p) { if (!p) return ''; const parts = p.split('/'); return parts.length <= 3 ? p : '.../' + parts.slice(-2).join('/'); }

function fmtElapsed(seconds) {
  if (seconds == null) return '';
  const s = Math.floor(seconds);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60), rem = s % 60;
  if (m < 60) return m + 'm' + (rem ? ' ' + rem + 's' : '');
  return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
}

function iconClass(n) {
  const m = {Bash:'tool-icon-bash',Read:'tool-icon-read',Write:'tool-icon-write',Edit:'tool-icon-edit'};
  return m[n] || 'tool-icon-other';
}
function iconLetter(n) {
  const m = {Bash:'$',Read:'R',Write:'W',Edit:'E',Grep:'?',Glob:'*',Agent:'A',Skill:'S'};
  return m[n] || n.charAt(0);
}
function toolSummaryText(name, input) {
  if (!input) return '';
  switch (name) {
    case 'Bash': return input.description || truncate(input.command || '', 60);
    case 'Read': return shortPath(input.file_path || '');
    case 'Write': return shortPath(input.file_path || '');
    case 'Edit': return shortPath(input.file_path || '');
    case 'Agent': return input.description || truncate(input.prompt || '', 60);
    case 'Skill': return input.skill || input.skill_name || '';
    default: return truncate(JSON.stringify(input), 60);
  }
}
function toolInputDisplay(name, input) {
  if (!input) return '';
  switch (name) {
    case 'Bash': return input.command || '';
    case 'Read': return input.file_path || '';
    case 'Write': return (input.file_path || '') + '\n---\n' + truncate(input.content || '', 2000);
    case 'Edit': return (input.file_path || '') + '\n- ' + (input.old_string || '') + '\n+ ' + (input.new_string || '');
    case 'Agent': return (input.description || '') + '\n' + (input.prompt || '');
    default: return JSON.stringify(input, null, 2);
  }
}

function renderStreams() {
  const container = document.getElementById('tab-stream');
  const runIds = Object.keys(streams);
  if (runIds.length > 1) {
    const sel = document.createElement('div');
    sel.className = 'run-select';
    runIds.forEach((rid, i) => {
      const run = challenge.runs[rid];
      const btn = document.createElement('button');
      btn.textContent = run ? run.agent + ' (' + run.model + ')' : rid;
      btn.className = i === 0 ? 'active' : '';
      btn.onclick = () => {
        sel.querySelectorAll('button').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        showRun(rid);
      };
      sel.appendChild(btn);
    });
    container.appendChild(sel);
  }
  const feed = document.createElement('div');
  feed.id = 'stream-feed';
  container.appendChild(feed);
  if (runIds.length > 0) showRun(runIds[0]);
}

function showRun(runId) {
  const feed = document.getElementById('stream-feed');
  feed.innerHTML = '';
  const events = streams[runId] || [];
  const pendingTools = new Map();
  let toolEls = [];

  function flushTools() {
    if (!toolEls.length) return;
    const group = document.createElement('div');
    group.className = 'chat-tool-group';
    if (toolEls.length > 2) {
      group.appendChild(toolEls[0]);
      const collapsed = document.createElement('div');
      collapsed.className = 'chat-tool-collapsed';
      const expandBtn = document.createElement('button');
      expandBtn.className = 'chat-tool-expand';
      expandBtn.textContent = (toolEls.length - 2) + ' more tool call' + (toolEls.length - 2 !== 1 ? 's' : '');
      expandBtn.onclick = () => { collapsed.classList.add('chat-tool-expanded'); expandBtn.style.display = 'none'; };
      for (let j = 1; j < toolEls.length - 1; j++) collapsed.appendChild(toolEls[j]);
      group.appendChild(expandBtn);
      group.appendChild(collapsed);
      group.appendChild(toolEls[toolEls.length - 1]);
    } else {
      toolEls.forEach(el => group.appendChild(el));
    }
    feed.appendChild(group);
    toolEls = [];
  }

  function buildToolUse(block) {
    const wrapper = document.createElement('div');
    wrapper.className = 'step-tool';
    const bar = document.createElement('div');
    bar.className = 'tool-bar';
    const icon = document.createElement('span');
    icon.className = 'tool-icon ' + iconClass(block.name);
    icon.textContent = iconLetter(block.name);
    const nameEl = document.createElement('span');
    nameEl.className = 'tool-name';
    nameEl.textContent = block.name;
    const desc = document.createElement('span');
    desc.className = 'tool-desc';
    desc.textContent = toolSummaryText(block.name, block.input);
    const status = document.createElement('span');
    status.className = 'tool-status tool-status-done';
    status.textContent = 'done';
    bar.append(icon, nameEl, desc, status);
    const detail = document.createElement('div');
    detail.className = 'tool-detail';
    const inputText = toolInputDisplay(block.name, block.input);
    if (inputText) {
      const sec = document.createElement('div');
      sec.className = 'tool-input-section';
      sec.textContent = inputText;
      detail.appendChild(sec);
    }
    const outSec = document.createElement('div');
    outSec.className = 'tool-output-section';
    outSec.textContent = '(no output yet)';
    detail.appendChild(outSec);
    bar.onclick = () => detail.classList.toggle('open');
    wrapper.append(bar, detail);
    wrapper._statusEl = status;
    wrapper._outputEl = outSec;
    return wrapper;
  }

  for (const ev of events) {
    // System messages
    if (ev.type === 'system') {
      if (ev.subtype === 'init') continue;
      flushTools();
      if (ev.message) {
        const div = document.createElement('div');
        div.className = 'system-msg';
        div.textContent = ev.message;
        if (ev.ts != null) { const ts = document.createElement('span'); ts.className = 'msg-ts'; ts.textContent = fmtElapsed(ev.ts); div.appendChild(ts); }
        feed.appendChild(div);
      }
      continue;
    }

    // Error
    if (ev.type === 'error') {
      flushTools();
      const div = document.createElement('div');
      div.className = 'error-msg';
      div.textContent = ev.message || ev.error || JSON.stringify(ev);
      feed.appendChild(div);
      continue;
    }

    // User prompt / steer
    if (ev.type === 'user_prompt' || ev.type === 'user_steer') {
      flushTools();
      const bubble = document.createElement('div');
      bubble.className = 'chat-bubble chat-user';
      if (ev.ts != null) { const ts = document.createElement('span'); ts.className = 'msg-ts'; ts.textContent = fmtElapsed(ev.ts); bubble.appendChild(ts); }
      const label = document.createElement('div');
      label.className = 'chat-label';
      label.textContent = ev.type === 'user_steer' ? 'You' : 'Prompt';
      const body = document.createElement('div');
      body.className = 'chat-body';
      body.textContent = ev.message || '';
      bubble.append(label, body);
      feed.appendChild(bubble);
      continue;
    }

    // Rate limit
    if (ev.type === 'rate_limit_event') continue;

    // Result
    if (ev.type === 'result') {
      flushTools();
      if (ev.result) {
        const block = document.createElement('div');
        block.className = 'result-block';
        block.innerHTML = '<div class="result-label">Result</div><div class="result-text">' + renderMarkdown(ev.result) + '</div>';
        feed.appendChild(block);
      }
      continue;
    }

    // Assistant message
    if (ev.type === 'assistant' && ev.message && ev.message.content) {
      for (const block of ev.message.content) {
        if (block.type === 'thinking' && block.thinking) {
          flushTools();
          const bubble = document.createElement('div');
          bubble.className = 'chat-bubble chat-assistant chat-thinking-bubble';
          const details = document.createElement('details');
          details.className = 'step-thinking';
          const summary = document.createElement('summary');
          const lbl = document.createElement('span');
          lbl.className = 'thinking-label';
          lbl.textContent = 'Thinking';
          const preview = document.createElement('span');
          preview.className = 'thinking-preview';
          preview.textContent = ' ' + truncate(block.thinking, 120);
          if (ev.ts != null) { const ts = document.createElement('span'); ts.className = 'msg-ts'; ts.textContent = fmtElapsed(ev.ts); summary.append(lbl, preview, ts); }
          else summary.append(lbl, preview);
          details.appendChild(summary);
          const body = document.createElement('div');
          body.className = 'thinking-body';
          body.textContent = block.thinking;
          details.appendChild(body);
          bubble.appendChild(details);
          feed.appendChild(bubble);
        }
        else if (block.type === 'text' && block.text) {
          flushTools();
          const bubble = document.createElement('div');
          bubble.className = 'chat-bubble chat-assistant';
          if (ev.ts != null) { const ts = document.createElement('span'); ts.className = 'msg-ts'; ts.textContent = fmtElapsed(ev.ts); bubble.appendChild(ts); }
          const div = document.createElement('div');
          div.className = 'chat-body';
          div.innerHTML = renderMarkdown(block.text);
          bubble.appendChild(div);
          feed.appendChild(bubble);
        }
        else if (block.type === 'tool_use') {
          const toolEl = buildToolUse(block);
          toolEls.push(toolEl);
          pendingTools.set(block.id, toolEl);
        }
      }
      continue;
    }

    // User (tool results)
    if (ev.type === 'user' && ev.message && ev.message.content) {
      for (const block of ev.message.content) {
        if (block.type !== 'tool_result') continue;
        let toolEl = pendingTools.get(block.tool_use_id);
        if (!toolEl) continue;
        let output = '';
        if (ev.tool_use_result && ev.tool_use_result.content) {
          output = ev.tool_use_result.content.map(c => c.text || '').filter(Boolean).join('\n');
        }
        if (!output && ev.tool_use_result) {
          const r = ev.tool_use_result;
          if (r.stdout) output = r.stdout;
          if (r.stderr) output += (output ? '\n' : '') + r.stderr;
        }
        if (!output && typeof block.content === 'string') output = block.content;
        if (!output && Array.isArray(block.content))
          output = block.content.map(c => c.text || JSON.stringify(c)).join('\n');
        const isError = block.is_error === true;
        toolEl._statusEl.className = 'tool-status ' + (isError ? 'tool-status-error' : 'tool-status-done');
        toolEl._statusEl.textContent = isError ? 'error' : 'done';
        toolEl._outputEl.textContent = output || '(no output)';
        if (isError) toolEl._outputEl.classList.add('tool-output-error');
        pendingTools.delete(block.tool_use_id);
      }
      continue;
    }
  }
  flushTools();
}

function renderFileList() {
  const list = document.getElementById('file-list');
  list.innerHTML = '';
  if (!files || Object.keys(files).length === 0) {
    list.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:0.72rem">No challenge files</div>';
    return;
  }
  Object.keys(files).sort().forEach(name => {
    const div = document.createElement('div');
    div.className = 'file';
    div.textContent = name;
    div.title = name;
    div.onclick = () => {
      list.querySelectorAll('.file').forEach(f => f.classList.remove('active'));
      div.classList.add('active');
      showFile(name);
    };
    list.appendChild(div);
  });
}

function showFile(name) {
  showTab('files');
  const container = document.getElementById('tab-files');
  container.innerHTML = '';
  const entry = files[name];
  const wrapper = document.createElement('div');
  wrapper.className = 'file-viewer';
  const heading = document.createElement('h3');
  heading.textContent = name;
  heading.style.marginBottom = '12px';
  wrapper.appendChild(heading);
  if (entry.encoding === 'base64') {
    if (entry.mime && entry.mime.startsWith('image/')) {
      const img = document.createElement('img');
      img.src = 'data:' + entry.mime + ';base64,' + entry.data;
      wrapper.appendChild(img);
    } else {
      const note = document.createElement('div');
      note.className = 'binary-note';
      note.textContent = 'Binary file (' + (entry.size || '?') + ' bytes). Download from the zip to inspect.';
      wrapper.appendChild(note);
    }
  } else {
    const pre = document.createElement('pre');
    pre.textContent = entry.data;
    wrapper.appendChild(pre);
  }
  container.appendChild(wrapper);
}

renderStreams();
renderFileList();
</script>
</body>
</html>"""


def _export_challenge_to_zip(
    zf: zipfile.ZipFile,
    challenge: dict,
    prefix: str,
    *,
    include_streams: bool = True,
    include_files: bool = True,
) -> None:
    """Write a single challenge's data + viewer into an open ZipFile."""
    from html import escape as _esc

    challenge_id = challenge["id"]
    meta = {
        "id": challenge_id,
        "name": challenge["name"],
        "description": challenge["description"],
        "category": challenge.get("category", ""),
        "flag_format": challenge["flag_format"],
        "flag_formats": challenge_flag_formats(challenge),
        "mode": challenge["mode"],
        "status": challenge["status"],
        "created_at": challenge["created_at"],
        "enabled_skills": challenge_enabled_skills(challenge),
        "detected_flags": challenge.get("detected_flags", {}),
        "detected_flag_meta": challenge.get("detected_flag_meta", {}),
        "flag_questions": challenge.get("_flag_questions", []),
        "export": {
            "streams": include_streams,
            "files": include_files,
        },
        "runs": {},
    }
    for run_id, run in challenge["runs"].items():
        meta["runs"][run_id] = {
            "id": run["id"],
            "agent": run["agent"],
            "model": run["model"],
            "effort": run.get("effort", ""),
            "status": run["status"],
            "duration_ms": effective_run_duration_ms(run),
            "notes_label": run.get("notes_label", ""),
            "enabled_skills": run_enabled_skills(challenge, run),
            "skill_override": run_has_skill_override(run),
            "custom_prompt": run.get("custom_prompt", ""),
            "custom_prompt_mode": run.get("custom_prompt_mode", "append"),
        }

    zf.writestr(f"{prefix}/challenge.json", json.dumps(meta, indent=2))

    stream_data: dict[str, list[dict]] = {}
    if include_streams:
        for run_id in challenge["runs"]:
            events = load_output_log(challenge_id, run_id)
            stream_data[run_id] = events
            jsonl = "\n".join(json.dumps(ev) for ev in events)
            zf.writestr(f"{prefix}/streams/{run_id}.jsonl", jsonl)

    file_entries: dict[str, dict] = {}
    if include_files:
        files_dir = CHALLENGES_DIR / challenge_id / "_files"
        if files_dir.is_dir():
            for p in sorted(files_dir.rglob("*")):
                if not p.is_file():
                    continue
                rel = str(p.relative_to(files_dir))
                data = p.read_bytes()
                zf.writestr(f"{prefix}/files/{rel}", data)
                ftype = classify_file(p)
                if ftype == "image":
                    mime = mimetypes.guess_type(str(p))[0] or "image/png"
                    file_entries[rel] = {
                        "encoding": "base64",
                        "mime": mime,
                        "data": base64.b64encode(data).decode("ascii"),
                        "size": len(data),
                    }
                elif ftype == "text":
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        text = data.decode("utf-8", errors="replace")
                    file_entries[rel] = {
                        "encoding": "utf-8",
                        "data": text,
                        "size": len(data),
                    }
                else:
                    file_entries[rel] = {
                        "encoding": "base64",
                        "mime": "application/octet-stream",
                        "data": base64.b64encode(data[:64 * 1024]).decode("ascii"),
                        "size": len(data),
                    }

        for run_id in challenge["runs"]:
            run_dir = CHALLENGES_DIR / challenge_id / "_runs" / run_id
            if not run_dir.is_dir():
                continue
            for p in sorted(run_dir.rglob("*")):
                if not p.is_file():
                    continue
                if p.is_symlink():
                    continue
                rel = str(p.relative_to(run_dir))
                if rel.startswith("challenge_files"):
                    continue
                data = p.read_bytes()
                zf.writestr(f"{prefix}/run_files/{run_id}/{rel}", data)
                ftype = classify_file(p)
                viewer_key = f"[{run_id}] {rel}"
                if ftype == "text":
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        text = data.decode("utf-8", errors="replace")
                    file_entries[viewer_key] = {
                        "encoding": "utf-8",
                        "data": text,
                        "size": len(data),
                    }

    detected = challenge.get("detected_flags", {})
    detected_html = ""
    if detected:
        parts = []
        for flag, st in detected.items():
            parts.append(f"<code>{_esc(flag)}</code> ({_esc(str(st))})")
        detected_html = "<b>Flags:</b> " + ", ".join(parts)

    viewer_data = {
        "challenge": meta,
        "streams": stream_data,
        "files": file_entries,
    }
    data_json = json.dumps(viewer_data).replace("</", "<\\/")

    html = _VIEWER_HTML
    html = html.replace("{{TITLE}}", _esc(meta["name"]))
    title_short = meta["name"][:50] + ("..." if len(meta["name"]) > 50 else "")
    html = html.replace("{{TITLE_SHORT}}", _esc(title_short))
    html = html.replace("{{STATUS}}", _esc(meta["status"]))
    html = html.replace("{{MODE}}", _esc(meta["mode"]))
    html = html.replace("{{CREATED}}", _esc(meta["created_at"][:19]))
    html = html.replace("{{FLAG_FORMAT}}", _esc(meta["flag_format"] or "—"))
    html = html.replace("{{DETECTED_FLAGS}}", detected_html)
    html = html.replace("{{DATA_JSON}}", data_json)

    zf.writestr(f"{prefix}/viewer.html", html)


def _safe_challenge_prefix(challenge: dict) -> str:
    name = re.sub(r"[^a-zA-Z0-9_\- ]", "", challenge["name"])[:80].strip()
    return (name or challenge["id"]).replace(" ", "_")


def _format_export_duration(ms: int) -> str:
    if not ms:
        return ""
    total_sec = int(ms // 1000)
    minutes = total_sec // 60
    seconds = total_sec % 60
    if minutes >= 60:
        hours = minutes // 60
        return f"{hours}h {minutes % 60}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _bulk_export_index_html(
    entries: list[tuple[str, dict]],
    *,
    include_streams: bool,
    include_files: bool,
) -> str:
    """Build a self-contained landing page for a multi-challenge export."""
    from html import escape as _esc

    grouped: dict[str, list[tuple[str, dict]]] = {}
    for prefix, challenge in entries:
        category = challenge.get("category", "") or "Uncategorized"
        grouped.setdefault(category, []).append((prefix, challenge))

    total = len(entries)
    solved = sum(1 for _, c in entries if c.get("status") == "solved")
    generated_at = utc_now_iso()[:19].replace("T", " ")
    export_bits = []
    if include_streams:
        export_bits.append("streams")
    if include_files:
        export_bits.append("files")
    if not export_bits:
        export_bits.append("metadata only")

    category_html = []
    for category in sorted(grouped):
        cards = []
        for prefix, challenge in sorted(
            grouped[category], key=lambda item: item[1].get("name", "").casefold()
        ):
            runs = challenge.get("runs", {})
            run_count = len(runs)
            total_duration = sum(
                effective_run_duration_ms(run)
                for run in runs.values()
            )
            duration = _format_export_duration(total_duration)
            mode = str(challenge.get("mode", "single")).replace("_", " ")
            points = challenge.get("_points", 0)
            solves = challenge.get("_solves", 0)
            file_count = len(challenge.get("files", []))
            status = str(challenge.get("status", "pending"))
            run_info = (
                f"{run_count} run{'s' if run_count != 1 else ''}"
                if run_count
                else "no runs"
            )
            info = " | ".join(
                item for item in [
                    f"{points} pts" if points else "",
                    f"{solves} solve{'s' if solves != 1 else ''}",
                    mode,
                    run_info,
                    f"{file_count} file{'s' if file_count != 1 else ''}",
                    duration,
                ] if item
            )
            cards.append(f"""
        <a class="challenge-card status-{_esc(status)}" href="{_esc(prefix)}/viewer.html">
          <span class="badge badge-{_esc(status)}">{_esc(status)}</span>
          <span class="card-name">{_esc(challenge.get("name", "?"))}</span>
          <span class="card-info">{_esc(info)}</span>
        </a>""")
        category_html.append(f"""
    <section class="category">
      <h2>{_esc(category)}</h2>
      <div class="grid">
        {''.join(cards)}
      </div>
    </section>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTF Export</title>
<style>
*{{box-sizing:border-box}}
:root{{
  --bg:#212121;--bg-card:#292929;--bg-hover:#3c3c3c;--border:#424242;
  --text:#eeffff;--muted:#b0bec5;--dim:#78909c;--accent:#89ddff;
  --green:#c3e88d;--yellow:#ffcb6b;--red:#f07178;--blue:#82aaff;
  --green-dim:rgba(195,232,141,.12);--yellow-dim:rgba(255,203,107,.12);
  --red-dim:rgba(240,113,120,.12);--blue-dim:rgba(130,170,255,.12);
  --mono:"SF Mono","Cascadia Code",monospace;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
}}
body{{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans)}}
header{{padding:1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;gap:.75rem;align-items:flex-end;flex-wrap:wrap}}
h1{{font-size:1.1rem;margin:0;font-weight:700}}
.summary{{color:var(--muted);font-size:.78rem;font-family:var(--mono)}}
main{{padding:1rem;display:flex;flex-direction:column;gap:1rem}}
.category h2{{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:.3rem;margin:.2rem 0 .55rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:.55rem}}
.challenge-card{{position:relative;display:flex;flex-direction:column;gap:.4rem;min-height:5.1rem;text-decoration:none;color:inherit;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:.65rem .75rem;transition:.15s}}
.challenge-card:hover{{background:var(--bg-hover);border-color:var(--accent);transform:translateY(-1px)}}
.challenge-card.status-solving{{border-left:3px solid var(--yellow)}}
.challenge-card.status-solved{{border-left:3px solid var(--green);background:var(--green-dim);border-color:var(--green)}}
.challenge-card.status-failed{{border-left:3px solid var(--red)}}
.challenge-card.status-completed{{border-left:3px solid var(--blue)}}
.challenge-card.status-pending{{border-left:3px solid var(--dim)}}
.badge{{position:absolute;top:.45rem;right:.45rem;padding:.14rem .45rem;border-radius:6px;font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.05em}}
.badge-solving{{background:var(--yellow-dim);color:var(--yellow)}}
.badge-solved{{background:var(--green-dim);color:var(--green)}}
.badge-failed{{background:var(--red-dim);color:var(--red)}}
.badge-completed{{background:var(--blue-dim);color:var(--blue)}}
.badge-pending{{background:#383838;color:var(--muted)}}
.card-name{{font-size:.84rem;font-weight:700;padding-right:4.2rem;line-height:1.3}}
.card-info{{font:.68rem var(--mono);color:var(--muted);line-height:1.45}}
.hint{{font-size:.72rem;color:var(--dim)}}
</style>
</head>
<body>
<header>
  <div>
    <h1>CTF Export</h1>
    <div class="summary">{solved}/{total} solved &middot; {_esc(", ".join(export_bits))} &middot; generated {_esc(generated_at)} UTC</div>
  </div>
  <div class="hint">Open any card to view its transcript and exported files.</div>
</header>
<main>
  {''.join(category_html)}
</main>
</body>
</html>"""


def _truthy_export_option(value, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


def _export_options_from_query(request: Request) -> tuple[bool, bool]:
    include_streams = _truthy_export_option(
        request.query_params.get("streams"), True
    )
    include_files = _truthy_export_option(
        request.query_params.get("files"), True
    )
    return include_streams, include_files


def _export_options_from_body(body: dict) -> tuple[bool, bool]:
    include_streams = _truthy_export_option(body.get("streams"), True)
    include_files = _truthy_export_option(body.get("files"), True)
    return include_streams, include_files


async def export_challenge(request: Request) -> Response:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    buf = io.BytesIO()
    prefix = _safe_challenge_prefix(challenge)
    include_streams, include_files = _export_options_from_query(request)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _export_challenge_to_zip(
            zf,
            challenge,
            prefix,
            include_streams=include_streams,
            include_files=include_files,
        )

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{prefix}.zip"'},
    )


async def export_challenges_bulk(request: Request) -> Response:
    if err := require_auth(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    ids = body.get("ids", [])
    if not isinstance(ids, list) or not ids:
        return JSONResponse({"error": "ids required"}, status_code=400)
    include_streams, include_files = _export_options_from_body(body)

    found = []
    for cid in ids:
        c = challenges.get(str(cid))
        if c:
            found.append(c)
    if not found:
        return JSONResponse({"error": "no matching challenges"}, status_code=404)

    buf = io.BytesIO()
    seen_prefixes: dict[str, int] = {}
    exported_entries: list[tuple[str, dict]] = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for c in found:
            prefix = _safe_challenge_prefix(c)
            count = seen_prefixes.get(prefix, 0)
            seen_prefixes[prefix] = count + 1
            if count:
                prefix = f"{prefix}_{count}"
            _export_challenge_to_zip(
                zf,
                c,
                prefix,
                include_streams=include_streams,
                include_files=include_files,
            )
            exported_entries.append((prefix, c))
        zf.writestr(
            "index.html",
            _bulk_export_index_html(
                exported_entries,
                include_streams=include_streams,
                include_files=include_files,
            ),
        )

    filename = f"ctf_export_{len(found)}_challenges.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Build prompt
# ---------------------------------------------------------------------------

def _instance_field_parts(instance_info: dict, include_type: bool = True) -> list[str]:
    fields = []
    if instance_info.get("url"):
        fields.append(f"URL: {instance_info['url']}")
    if instance_info.get("connection"):
        fields.append(f"Connection: {instance_info['connection']}")
    if instance_info.get("host"):
        fields.append(f"Host: {instance_info['host']}")
    if instance_info.get("port"):
        fields.append(f"Port: {instance_info['port']}")
    if instance_info.get("expires_at"):
        fields.append(f"Expires at: {instance_info['expires_at']}")
    if include_type and instance_info.get("type"):
        fields.append(f"Type: {instance_info['type']}")
    return fields


def _instance_prompt_lines(instance_info: dict) -> list[str]:
    remotes = instance_info.get("remotes")
    if isinstance(remotes, list) and remotes:
        lines = []
        for idx, remote in enumerate(remotes, 1):
            if not isinstance(remote, dict):
                continue
            fields = _instance_field_parts(remote)
            if fields:
                lines.append(f"Remote {idx}: {', '.join(fields)}")
        if lines:
            return lines
    return _instance_field_parts(instance_info)


def _teammate_context(challenge: dict, run: dict) -> str:
    teammates = []
    for rid, r in challenge["runs"].items():
        if rid != run["id"]:
            teammates.append(r.get("notes_label", r["agent"]))
    if not teammates:
        return ""
    parts = [
        f"You are working in a team with: {', '.join(teammates)}.",
        "Work independently first — try your own approaches before "
        "looking at what others are doing.",
        "",
        "Teammates' notes are available at:",
    ]
    for teammate in teammates:
        parts.append(f"  - WORKING_NOTES_{teammate}.md")
    parts.extend([
        "",
        "Only read teammates' notes if you have exhausted your "
        "own ideas or are completely stuck.",
        "",
        "Call `notify_teammates` when you confirm any of these:",
        "- The vulnerability class or challenge category "
        '(e.g., "this is a heap UAF", "RSA with small e")',
        "- A key, secret, password, or credential you extracted",
        "- A decoded or decrypted intermediate value",
        "- The correct tool or technique to use "
        '(e.g., "Fermat factorization works here")',
        "- The flag",
        "",
        "Do NOT notify for unverified hypotheses or guesses — "
        "only confirmed findings. "
        "Notify early and often. Do not wait until you have "
        "the flag.",
        "",
        "You may receive '[Teammate breakthrough]' messages "
        "between turns. Read them and incorporate useful "
        "findings into your approach.",
    ])
    return "\n".join(parts)


def _remote_instance_context(instance_info: dict | None) -> str:
    if not instance_info:
        return ""
    lines = ["Remote instance connection info:"]
    for line in _instance_prompt_lines(instance_info):
        lines.append(f"  {line}")
    return "\n".join(lines)


def _enabled_hook_prompt_lines(settings: dict | None = None) -> list[str]:
    hooks = enabled_hooks(settings)
    lines: list[str] = []
    if "rtk" in hooks:
        lines.append(
            "RTK is available: use `rtk <command>` only for noisy summaries; "
            "use raw commands for exact bytes, offsets, payloads, hashes, and "
            "exit status."
        )
    return lines


def _append_enabled_hook_prompt_context(prompt: str) -> str:
    lines = _enabled_hook_prompt_lines()
    if not lines:
        return prompt
    return f"{prompt.rstrip()}\n\n" + "\n".join(lines)


def _render_run_prompt_template(
    template: str,
    challenge: dict,
    run: dict,
    instance_info: dict | None,
) -> str:
    notes_path = get_run_cwd(challenge["id"], run) / run_notes_filename(challenge, run)
    replacements = {
        "{{WORKING_NOTES_PATH}}": str(notes_path),
        "{{TEAMMATE_CONTEXT}}": _teammate_context(challenge, run),
        "{{REMOTE_INSTANCE_CONNECTION_INFO}}": _remote_instance_context(instance_info),
    }
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return "\n".join(line.rstrip() for line in rendered.splitlines()).strip()


def _build_standard_prompt(
    challenge: dict,
    run: dict,
    instance_info: dict | None = None,
    *,
    enabled_skills: list[str] | None = None,
    notes_path: str | None = None,
    team_placeholder: bool = False,
    remote_placeholder: bool = False,
    has_challenge_files: bool | None = None,
) -> str:
    """Build the default CTF solving prompt without run-specific overrides."""
    is_parallel = challenge["mode"] == "parallel"

    notes_file = run_notes_filename(challenge, run)
    run_cwd = None
    if notes_path is None or has_challenge_files is None:
        try:
            run_cwd = get_run_cwd(challenge["id"], run)
        except Exception:
            run_cwd = None
    notes_path = notes_path or (
        str(run_cwd / notes_file) if run_cwd else notes_file
    )
    enabled_skill_set = set(
        enabled_skills if enabled_skills is not None else run_enabled_skills(challenge, run)
    )

    parts = [
        "You are solving a CTF challenge.",
    ]
    if "ctf-methodology" in enabled_skill_set:
        parts.append("Follow ctf-methodology and solve the CTF challenge")
    parts.extend(_enabled_hook_prompt_lines())

    parts.extend([
        "",
        f"Maintain this exact working notes file: `{notes_path}`",
        "Update this file as you work. If you lose context, re-read it first.",
    ])

    # Parallel mode: team awareness
    teammate_context = (
        "{{TEAMMATE_CONTEXT}}" if team_placeholder else (
            _teammate_context(challenge, run) if is_parallel else ""
        )
    )
    if teammate_context:
        parts.extend(["", teammate_context])

    parts.extend([
        "",
        f"Challenge: {challenge['name']}",
    ])
    if challenge["description"]:
        parts.append(f"Description: {challenge['description']}")
    flag_questions = challenge.get("_flag_questions") or []
    if flag_questions:
        parts.extend([
            "This is a multi-answer platform challenge. There may not be a fixed flag format.",
            "Answer each question exactly as asked, and submit candidates with `./submit_answer.py`.",
            "Questions:",
        ])
        for idx, q in enumerate(flag_questions, 1):
            solved = " [already solved]" if q.get("solved") else ""
            flag_id = q.get("flag_id")
            flag_label = f" [flag_id {flag_id}]" if flag_id not in (None, "") else ""
            parts.append(f"  {idx}.{flag_label} {q.get('question', '')}{solved}")
        parts.extend([
            "Submission examples:",
            "  ./submit_answer.py --question 1 --answer 'candidate answer'",
            "  ./submit_answer.py --flag-id <id> --answer 'candidate answer'",
            "If an answer is incorrect, keep investigating and try another candidate.",
        ])
    else:
        formats = challenge_flag_formats(challenge)
        if formats:
            label = "Flag format" if len(formats) == 1 else "Flag formats"
            parts.append(f"{label}: {', '.join(formats)}")
        else:
            parts.append(
                "No flag format specified. Look for common "
                "formats like flag{{...}}, FLAG{{...}}, "
                "CTF{{...}}, or ask."
            )
    remote_context = (
        "{{REMOTE_INSTANCE_CONNECTION_INFO}}"
        if remote_placeholder
        else _remote_instance_context(instance_info)
    )
    if remote_context:
        parts.extend(["", remote_context])

    has_declared_files = bool(challenge.get("files"))
    if has_challenge_files is None:
        has_challenge_files = bool(
            has_declared_files
            and run_cwd
            and (run_cwd / "challenge_files").exists()
        )

    if has_challenge_files:
        parts.extend([
            "",
            "The challenge files are in ./challenge_files/ (some may be symlinks).",
            "Do not inspect parent directories, repository root files, .git metadata, "
            "or unrelated system paths.",
        ])
    elif not has_declared_files:
        parts.extend([
            "",
            "This challenge has no attached files. Solve from the description, "
            "category, provided flag format, and any remote instance connection "
            "information above.",
            "Do not stop merely because ./challenge_files/ is empty or absent.",
            "Do not inspect parent directories, repository root files, .git metadata, "
            "or unrelated system paths.",
            "Keep command output bounded: avoid unbounded recursive listings, and use "
            "targeted commands with limits (for example, head/tail).",
        ])
    else:
        parts.extend([
            "",
            "The challenge files are in the current directory (some may be symlinks).",
            "Use `ls -la` to list files, not `find . -type f` which misses symlinks.",
            "Do not inspect parent directories, repository root files, .git metadata, "
            "or unrelated system paths.",
            "If the current directory has no challenge files, report that clearly and stop. "
            "Do not search elsewhere for surrogate targets.",
            "Keep command output bounded: avoid unbounded recursive listings, and use "
            "targeted commands with limits (for example, head/tail).",
        ])
    return "\n".join(parts)


def build_add_run_prompt_template(
    challenge: dict,
    enabled_skills: list[str],
) -> str:
    template_run = make_run(
        run_id="{{RUN_ID}}",
        agent="{{AGENT}}",
        model="{{MODEL}}",
        effort="{{EFFORT}}",
        status="pending",
    )
    template_challenge = {**challenge, "mode": "parallel"}
    return _build_standard_prompt(
        template_challenge,
        template_run,
        enabled_skills=enabled_skills,
        notes_path="{{WORKING_NOTES_PATH}}",
        team_placeholder=True,
        remote_placeholder=True,
        has_challenge_files=bool(challenge.get("files")),
    )


def build_prompt(challenge: dict, run: dict, instance_info: dict | None = None) -> str:
    """Build the CTF solving prompt."""
    custom_prompt = str(run.get("custom_prompt") or "").strip()
    if custom_prompt and run.get("custom_prompt_mode") == "full":
        return _render_run_prompt_template(
            custom_prompt,
            challenge,
            run,
            instance_info,
        )

    prompt = _build_standard_prompt(challenge, run, instance_info)
    if custom_prompt:
        prompt += "\n\nRun-specific instructions:\n" + custom_prompt
    return prompt


# ---------------------------------------------------------------------------
# Run agent
# ---------------------------------------------------------------------------

def _event_flag_texts(event: dict) -> list[str]:
    """Extract agent-visible text to scan for flags."""
    etype = event.get("type", "")
    if etype == "assistant":
        msg = event.get("message", {})
        texts = []
        for block in msg.get("content", []):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and block.get("text"):
                texts.append(str(block.get("text")))
        return texts
    if etype == "system" and event.get("subtype") == "teammate_broadcast":
        message = event.get("message")
        if message:
            return [str(message)]
    return []


def infer_auto_submit_flag_id(challenge: dict) -> str | int | None:
    """Infer a multi-answer flag_id only when there is no ambiguity."""
    questions = challenge.get("_flag_questions") or []
    if not questions:
        return None
    unsolved = [q for q in questions if not q.get("solved")]
    if len(unsolved) != 1:
        return None
    return unsolved[0].get("flag_id")


def _handle_detected_flag(
    challenge_id: str,
    run_id: str,
    challenge: dict,
    flag: str,
    *,
    event: dict | None = None,
    event_index: int | None = None,
    source_type: str = "detected",
    auto_submit_tasks: list[asyncio.Task] | None = None,
) -> bool:
    """Persist, broadcast, and optionally auto-submit a detected flag."""
    run = challenge["runs"].get(run_id)
    if not run:
        return False

    detected = challenge.setdefault("detected_flags", {})
    detected_key = detected_flag_key(detected, flag)
    current_status = detected.get(detected_key)
    is_new = detected_key not in detected
    if is_new:
        detected_key = set_detected_flag_status(challenge, flag, "pending")
    _, source_added = record_detected_flag_source(
        challenge,
        detected_key,
        run_id=run_id,
        agent=run.get("agent", ""),
        event=event,
        event_index=event_index,
        source_type=source_type,
    )
    if is_new or source_added:
        save_metadata(challenge)

    if is_new:
        flag_event = {
            "type": "flag_found",
            "flag": detected_key,
            "meta": detected_flag_meta(challenge, detected_key),
            "run_id": run_id,
            "agent": run["agent"],
            "challenge_id": challenge_id,
            "challenge_name": challenge.get("name", ""),
        }

        async def _notify():
            await broadcast(challenge_id, run_id, flag_event)
            await broadcast_global(flag_event)
            await discord_notify(
                challenge,
                f"**{run.get('agent', '?')}** found possible flag: `{detected_key}`",
                components=discord_flag_review_components(challenge, detected_key),
            )
        asyncio.create_task(_notify())

    settings = load_settings()
    if not settings.get("auto_submit_flags"):
        return is_new
    if current_status in {"correct", "wrong"}:
        return is_new

    seen = run.setdefault("_flags_submitted", set())
    seen_key = flag_lookup_key(detected_key)
    if seen_key in seen:
        return is_new
    seen.add(seen_key)

    plugin_name = challenge.get("_plugin")
    remote_id = challenge.get("_remote_id")
    if not plugin_name or not remote_id:
        return is_new

    plugin = get_plugin(plugin_name)
    if not plugin:
        return is_new

    config = resolve_challenge_plugin_config(challenge)
    if not config:
        return is_new

    auto_flag_id = None
    if challenge.get("_flag_questions"):
        auto_flag_id = infer_auto_submit_flag_id(challenge)
        if auto_flag_id in (None, ""):
            return is_new
    auto_question_idx = None
    if auto_flag_id not in (None, ""):
        _, _, auto_question_idx = resolve_flag_question(
            challenge, None, auto_flag_id
        )

    async def _submit():
        submit_flag = normalize_flag_for_submission(
            detected_key, challenge_flag_formats(challenge)
        )
        question_idx = auto_question_idx
        try:
            result = await plugin.submit_flag(
                config, remote_id, submit_flag, flag_id=auto_flag_id
            )
            submit_event = {
                "type": "system",
                "subtype": "flag_submit",
                "message": (
                    f"Auto-submitted flag: {submit_flag}\n"
                    f"Result: {'Correct!' if result.correct else result.message}"
                ),
            }
            await _append_run_event(challenge_id, run_id, run, submit_event)

            if result.correct:
                if auto_flag_id not in (None, ""):
                    for idx, item in enumerate(challenge.get("_flag_questions", []), 1):
                        if str(item.get("flag_id")) == str(auto_flag_id):
                            item["solved"] = True
                            question_idx = idx
                            break
                all_questions_solved = bool(challenge.get("_flag_questions")) and all(
                    q.get("solved") for q in challenge.get("_flag_questions", [])
                )
            else:
                all_questions_solved = False

            stored_flag = set_detected_flag_status(
                challenge, submit_flag, "correct" if result.correct else "wrong"
            )
            record_flag_submission(
                challenge,
                stored_flag,
                submitted_flag=submit_flag,
                run_id=run_id,
                flag_id=auto_flag_id,
                question=question_idx,
                correct=result.correct,
                message=result.message,
                auto=True,
            )
            save_metadata(challenge)

            await broadcast_global({
                "type": "flag_result",
                "challenge_id": challenge_id,
                "flag": stored_flag,
                "correct": result.correct,
                "message": result.message if not result.correct else "",
                "meta": detected_flag_meta(challenge, stored_flag),
                "flag_questions": challenge.get("_flag_questions", []),
                "all_questions_solved": all_questions_solved,
                "status": challenge.get("status", ""),
            })

            if result.correct:
                if challenge.get("_flag_questions") and not all_questions_solved:
                    save_metadata(challenge)
                    return
                _, solved_run = await apply_solved_status(
                    challenge_id,
                    challenge,
                    flag=submit_flag,
                    run_id=run_id,
                    stop_reason="auto_submit_solved",
                )
                solved_agent = (
                    solved_run.get("agent", "")
                    if solved_run
                    else run.get("agent", "")
                )
                await discord_notify(
                    challenge,
                    embed=make_solve_embed(challenge, submit_flag, solved_agent),
                )
                await discord_mark_solved(challenge, submit_flag, solved_agent)
            else:
                # Allow resubmission if the same candidate reappears later
                seen.discard(seen_key)
                wrong_event = {
                    "type": "system",
                    "message": (
                        f"Flag '{submit_flag}' was incorrect: {result.message}. "
                        "Keep trying."
                    ),
                }
                await _append_run_event(challenge_id, run_id, run, wrong_event)
        except Exception:
            seen.discard(seen_key)

    task = asyncio.create_task(_submit())
    if auto_submit_tasks is not None:
        auto_submit_tasks.append(task)
    return is_new


def _try_detect_and_submit_flag(
    challenge_id: str,
    run_id: str,
    event: dict,
    challenge: dict,
    event_index: int | None = None,
) -> None:
    """Detect flags in agent output. Broadcast to frontend and auto-submit if enabled."""
    for text in _event_flag_texts(event):
        for flag in detect_flags(text, challenge_flag_formats(challenge)):
            source_type = (
                "teammate_broadcast"
                if event.get("type") == "system"
                and event.get("subtype") == "teammate_broadcast"
                else "detected"
            )
            _handle_detected_flag(
                challenge_id,
                run_id,
                challenge,
                flag,
                event=event,
                event_index=event_index,
                source_type=source_type,
            )


def _path_has_entries(path: Path) -> bool:
    try:
        next(path.iterdir())
        return True
    except (StopIteration, OSError):
        return False


def _ctfgrep_preflight_target(challenge_id: str, run_cwd: Path) -> Path | None:
    files_dir = CHALLENGES_DIR / challenge_id / "_files"
    if files_dir.is_dir() and _path_has_entries(files_dir):
        return files_dir

    challenge_files_dir = run_cwd / "challenge_files"
    if challenge_files_dir.is_dir() and _path_has_entries(challenge_files_dir):
        return challenge_files_dir

    return None


def _ctfgrep_search_terms(challenge: dict) -> list[str]:
    configured_terms = []
    for flag_format in challenge_flag_formats(challenge):
        text = normalize_flag_format(flag_format)
        if "{" not in text:
            continue
        prefix = text.split("{", 1)[0].strip()
        if len(prefix) >= 2:
            configured_terms.append(f"{prefix}{{")
    terms = configured_terms or list(CTFGREP_DEFAULT_TERMS)
    return _unique_strings(terms)[:CTFGREP_MAX_TERMS]


def _ctfgrep_candidate_flags(challenge: dict, text: str) -> list[str]:
    candidates = []
    for flag in detect_flags(text, challenge_flag_formats(challenge)):
        if "{" not in flag or not flag.endswith("}"):
            continue
        inner = flag.split("{", 1)[1][:-1]
        if len(inner) <= CTFGREP_CANDIDATE_INNER_MAX:
            candidates.append(flag)
    return _unique_strings(candidates)


async def _run_ctfgrep_preflight(
    challenge_id: str,
    run_id: str,
    challenge: dict,
    run: dict,
    run_cwd: Path,
) -> bool:
    """Silently add bounded ctfgrep hits to detected flag candidates."""
    target_dir = _ctfgrep_preflight_target(challenge_id, run_cwd)
    if target_dir is None:
        return False

    ctfgrep = shutil.which("ctfgrep")
    if not ctfgrep:
        log.info(
            "[%s/%s] ctfgrep preflight skipped: ctfgrep was not found",
            challenge_id[:8], run_id[:8],
        )
        return False

    terms = _ctfgrep_search_terms(challenge)
    raw_outputs = []

    for term in terms:
        cmd = [ctfgrep, "-i", "-m", "4", "-t", "4", str(target_dir), term]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(run_cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=CTFGREP_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = await proc.communicate()
                log.info(
                    "[%s/%s] ctfgrep preflight timed out after %ss for %r",
                    challenge_id[:8], run_id[:8],
                    CTFGREP_TIMEOUT_SECONDS, term,
                )
        except Exception as exc:
            log.warning(
                "[%s/%s] ctfgrep preflight failed for %r: %s",
                challenge_id[:8], run_id[:8], term, exc,
            )
            continue

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")
        combined = "\n".join(
            part for part in (stdout_text.strip(), stderr_text.strip()) if part
        )
        raw_outputs.append(combined)
        if proc.returncode not in (0, None):
            log.info(
                "[%s/%s] ctfgrep preflight exited with code %s for %r",
                challenge_id[:8], run_id[:8], proc.returncode, term,
            )

    raw_text = "\n".join(raw_outputs)
    candidate_flags = _ctfgrep_candidate_flags(challenge, raw_text)

    auto_submit_tasks: list[asyncio.Task] = []
    for flag in candidate_flags:
        _handle_detected_flag(
            challenge_id,
            run_id,
            challenge,
            flag,
            source_type="ctfgrep_preflight",
            auto_submit_tasks=auto_submit_tasks,
        )

    if auto_submit_tasks:
        await asyncio.wait(
            auto_submit_tasks,
            timeout=CTFGREP_AUTO_SUBMIT_WAIT_SECONDS,
        )
    return bool(candidate_flags)


async def _run_agent_sdk_path(
    challenge_id: str,
    run_id: str,
    challenge: dict,
    run: dict,
    provider,
    prompt: str,
    is_continue: bool,
    codex_skill_mentions: list[str] | None = None,
) -> None:
    """Run an agent using the provider's SDK (no subprocess)."""
    run_cwd = get_run_cwd(challenge_id, run)
    session_state = run.setdefault("_session_state", {})

    log.info(
        "[%s/%s] Starting %s via SDK (continue=%s, cwd=%s)",
        challenge_id[:8], run_id[:8], run["agent"],
        is_continue, run_cwd,
    )

    saw_message = False
    last_error = None

    # Register for broadcast messages (parallel mode)
    is_parallel = challenge.get("mode") == "parallel"
    if is_parallel:
        try:
            from webapp.agents.broadcast import register_run, unregister_run
        except ImportError:
            from agents.broadcast import register_run, unregister_run
        register_run(challenge_id, run_id)

    log.info(
        "[%s/%s] About to call provider.run_agent (agent=%s, model=%s, effort=%s, cwd=%s, continue=%s)",
        challenge_id[:8], run_id[:8], run["agent"], run.get("model", ""),
        run.get("effort", ""), run_cwd, is_continue,
    )
    swarm_ip = _resolve_swarm_ip(challenge)
    if swarm_ip:
        try:
            from .swarm_exec import remote_run_agent
        except ImportError:
            from swarm_exec import remote_run_agent
        log.info(
            "[%s/%s] Dispatching to swarm worker %s (%s)",
            challenge_id[:8], run_id[:8], challenge.get("_swarm_instance"), swarm_ip,
        )
        event_source = remote_run_agent(
            challenge, run, prompt, is_continue, swarm_ip,
            env=agent_runtime_env(run["agent"]),
            codex_skill_mentions=codex_skill_mentions or [],
        )
    else:
        event_source = provider.run_agent(
            prompt=prompt,
            model=run.get("model", ""),
            effort=run.get("effort", ""),
            cwd=str(run_cwd),
            continue_session=is_continue,
            session_state=session_state,
            challenge_id=challenge_id if is_parallel else "",
            run_id=run_id if is_parallel else "",
            _codex_skill_mentions=codex_skill_mentions or [],
            _env=agent_runtime_env(run["agent"]),
            _run=run,
        )
    try:
        async for event in event_source:
            # Check if we've been stopped externally
            stop_reason = run.get("_stop_reason")
            if stop_reason:
                log.info(
                    "[%s/%s] SDK run stopped: %s",
                    challenge_id[:8], run_id[:8], stop_reason,
                )
                break

            if not event or not isinstance(event, dict):
                continue

            etype = event.get("type", "")

            if etype in ("assistant", "user", "result"):
                if not saw_message and session_state.get("claude_session_id"):
                    save_metadata(challenge)
                saw_message = True
            if etype == "error":
                last_error = event.get("message", "")

            if "ts" not in event and run.get("solve_start"):
                event["ts"] = run_elapsed_seconds(run)

            if etype == "run_goal":
                event["provider"] = str(event.get("provider") or provider.name or "")
                event["goal"] = normalize_run_goal(
                    event.get("goal"),
                    event["provider"],
                )
                apply_run_goal_event(run, event)
                save_metadata(challenge)

            event_index = await _append_run_event(
                challenge_id, run_id, run, event
            )

            # Auto-submit flag detection
            if (
                etype == "assistant"
                or (
                    etype == "system"
                    and event.get("subtype") == "teammate_broadcast"
                )
            ):
                _try_detect_and_submit_flag(
                    challenge_id, run_id, event, challenge, event_index
                )
            if etype == "result" and provider.name == "claude":
                await _mark_run_completed_from_result(
                    challenge_id, run_id, challenge, run, event
                )
                break

    except asyncio.CancelledError:
        log.info("[%s/%s] SDK task cancelled", challenge_id[:8], run_id[:8])
    except Exception as exc:
        log.error(
            "[%s/%s] SDK exception: %s",
            challenge_id[:8], run_id[:8], exc,
        )
        last_error = str(exc)
        err_event = {"type": "error", "message": str(exc)}
        await _append_run_event(challenge_id, run_id, run, err_event)
    finally:
        # Kill the Claude process if still alive (async with handles
        # normal disconnect, but cancellation may skip __aexit__)
        sdk_client = run.pop("_sdk_client", None)
        if sdk_client:
            try:
                transport = getattr(sdk_client, '_transport', None)
                proc = getattr(transport, '_process', None) if transport else None
                if proc and proc.returncode is None:
                    proc.kill()
                    log.info("[%s/%s] Claude process killed (pid=%s)", challenge_id[:8], run_id[:8], proc.pid)
            except (Exception, asyncio.CancelledError):
                pass
        # Unregister from broadcast bus
        if is_parallel:
            unregister_run(challenge_id, run_id)

    # --- Finalization ---
    try:
        stop_reason = run.pop("_stop_reason", None)

        log.info(
            "[%s/%s] SDK finalization: stop_reason=%s, saw_msg=%s, status=%s",
            challenge_id[:8], run_id[:8], stop_reason, saw_message,
            run["status"],
        )

        if stop_reason:
            if run["status"] not in ("completed", "failed", "solved"):
                run["status"] = "failed"
        elif run["status"] == "solved":
            # Auto-submit marked it solved — stop siblings in parallel mode
            if challenge.get("mode") == "parallel":
                for other_id, other_run in challenge["runs"].items():
                    if other_id == run_id:
                        continue
                    if other_run["status"] in ("solving", "pending"):
                        await stop_run(other_run, "sibling_solved")
                        finish_run_timer(other_run)
                        other_run["status"] = "failed"
        elif saw_message and not last_error:
            run["status"] = "completed"
            run["error"] = None
        else:
            run["status"] = "failed"
            run["error"] = last_error or "Agent produced no output"
            if last_error:
                err_event = {"type": "error", "message": last_error}
                await _append_run_event(challenge_id, run_id, run, err_event)

        finish_run_timer(run)

        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)

        # Discord: agent stopped notification
        last_msg = ""
        for evt in reversed(run.get("output_lines", [])):
            if evt.get("type") == "assistant":
                for block in evt.get("message", {}).get("content", []):
                    if block.get("type") == "text" and block.get("text"):
                        last_msg = block["text"]
                        break
                if last_msg:
                    break
        asyncio.create_task(discord_notify(challenge, embed=make_stop_embed(challenge, run, last_msg)))

    except Exception as exc:
        log.error(
            "[%s/%s] Finalization error: %s",
            challenge_id[:8], run_id[:8], exc, exc_info=True,
        )
        if run["status"] == "solving":
            run["status"] = "failed"
            run["error"] = f"Finalization error: {exc}"
        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)
        err_event = {"type": "error", "message": f"Finalization error: {exc}"}
        await _append_run_event(challenge_id, run_id, run, err_event)
    finally:
        if run["status"] == "solving":
            run["status"] = "failed"
            challenge["status"] = derive_challenge_status(challenge)
            save_metadata(challenge)

    try:
        await broadcast(challenge_id, run_id, {
            "type": "run_status",
            "run_id": run_id,
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": effective_run_duration_ms(run),
        })
        await broadcast_challenge(challenge_id, {
            "type": "challenge_status",
            "status": challenge["status"],
        })
    except Exception as exc:
        log.error("[%s/%s] Broadcast error: %s", challenge_id[:8], run_id[:8], exc)


def _challenge_needs_remote_instance(challenge: dict) -> bool:
    tags = [str(t).lower() for t in challenge.get("_tags", [])]
    if any(
        t == "docker" or t.startswith("docker:") or t in {"machine", "scenario"}
        for t in tags
    ):
        return True
    return str(challenge.get("category", "")).lower() == "fullpwn"


def _instance_ready_message(instance_info: dict) -> str:
    ready_msg = "Instance ready"
    conn_parts = _instance_connection_parts(instance_info)
    if conn_parts:
        ready_msg += f": {'; '.join(conn_parts)}"
    return ready_msg


def _instance_connection_parts(instance_info: dict) -> list[str]:
    remotes = instance_info.get("remotes")
    if isinstance(remotes, list) and remotes:
        conn_parts = []
        for idx, remote in enumerate(remotes, 1):
            if not isinstance(remote, dict):
                continue
            fields = _instance_field_parts(remote, include_type=False)
            if fields:
                conn_parts.append(f"Remote {idx}: {', '.join(fields)}")
        if conn_parts:
            return conn_parts
    return _instance_field_parts(instance_info, include_type=False)


async def _append_run_event(
    challenge_id: str, run_id: str, run: dict, event: dict
) -> int:
    if "ts" not in event and run.get("solve_start"):
        event["ts"] = run_elapsed_seconds(run)
    async with run_event_lock(run):
        event_index = run_event_count(challenge_id, run_id, run)
        await asyncio.to_thread(append_output_event, challenge_id, run_id, event)
        run["_event_count"] = event_index + 1
        _remember_run_event_tail(challenge_id, run_id, run, event, event_index)
    await broadcast(
        challenge_id,
        run_id,
        compact_history_event(challenge_id, run_id, event, event_index),
    )
    return event_index


async def _mark_run_completed_from_result(
    challenge_id: str, run_id: str, challenge: dict, run: dict,
    event: dict | None = None,
) -> None:
    """Finalize a run when a provider emits its final result.

    Marks the run failed (not completed) when the result carries an error,
    so an errored agent run isn't reported as a clean finish.
    """
    if run.get("_stop_reason") or run.get("status") != "solving":
        return
    event = event or {}
    if event.get("is_error"):
        errors = event.get("errors")
        if errors:
            message = "; ".join(str(e) for e in errors)
        else:
            message = event.get("result") or (
                f"Agent ended with error: {event.get('subtype') or 'unknown'}"
            )
        api_status = event.get("api_error_status")
        if api_status:
            message = f"{message} (HTTP {api_status})"
        run["status"] = "failed"
        run["error"] = message
    else:
        run["status"] = "completed"
        run["error"] = None
    finish_run_timer(run)
    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    await broadcast(challenge_id, run_id, {
        "type": "run_status",
        "run_id": run_id,
        "status": run["status"],
        "error": run.get("error"),
        "duration_ms": effective_run_duration_ms(run),
    })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })


async def _fail_run_before_agent(
    challenge_id: str, run_id: str, challenge: dict, run: dict, message: str
) -> None:
    await _append_run_event(
        challenge_id,
        run_id,
        run,
        {"type": "error", "message": message},
    )
    run["status"] = "failed"
    run["error"] = message
    finish_run_timer(run)
    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    await broadcast(challenge_id, run_id, {
        "type": "run_status",
        "run_id": run_id,
        "status": run["status"],
        "error": run.get("error"),
        "duration_ms": effective_run_duration_ms(run),
    })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })


async def _ensure_remote_instance_online(
    challenge_id: str, run_id: str, challenge: dict, run: dict
) -> tuple[bool, dict | None]:
    instance_info = challenge.get("_instance_info")
    if not _challenge_needs_remote_instance(challenge):
        return True, None
    checked_at = float(challenge.get("_instance_info_checked_at") or 0)
    if instance_info and _time.monotonic() - checked_at < 60:
        return True, instance_info
    failed_at = float(challenge.get("_instance_start_failed_at") or 0)
    if failed_at and _time.monotonic() - failed_at < 60:
        message = (
            challenge.get("_instance_start_error")
            or "Remote instance did not become ready; agent was not started."
        )
        await _fail_run_before_agent(challenge_id, run_id, challenge, run, message)
        return False, None

    remote_id = challenge.get("_remote_id")
    plugin, config = _resolve_plugin_config(challenge)
    if not remote_id or not plugin:
        if instance_info:
            return True, instance_info
        await _fail_run_before_agent(
            challenge_id,
            run_id,
            challenge,
            run,
            "Remote instance is required, but the platform connection is missing.",
        )
        return False, None

    await _append_run_event(
        challenge_id,
        run_id,
        run,
        {"type": "system", "message": "Starting remote instance..."},
    )

    lock = _instance_locks.setdefault(challenge_id, asyncio.Lock())
    start_error = ""
    async with lock:
        instance_info = challenge.get("_instance_info")
        checked_at = float(challenge.get("_instance_info_checked_at") or 0)
        if instance_info and _time.monotonic() - checked_at < 60:
            pass
        else:
            failed_at = float(challenge.get("_instance_start_failed_at") or 0)
            if failed_at and _time.monotonic() - failed_at < 60:
                start_error = (
                    challenge.get("_instance_start_error")
                    or "Remote instance did not become ready; agent was not started."
                )
            else:
                challenge.pop("_instance_info", None)
                try:
                    instance_info = await plugin.start_instance(config, remote_id)
                except Exception as exc:
                    start_error = str(exc) or exc.__class__.__name__
                    log.error("Failed to start instance for %s: %s", remote_id, exc)
                if instance_info:
                    challenge["_instance_info"] = instance_info
                    challenge["_instance_info_checked_at"] = _time.monotonic()
                    challenge.pop("_instance_start_failed_at", None)
                    challenge.pop("_instance_start_error", None)
                    save_metadata(challenge)
                else:
                    failure_message = (
                        f"Remote instance did not become ready: {start_error}"
                        if start_error
                        else "Remote instance did not become ready; agent was not started."
                    )
                    challenge["_instance_start_failed_at"] = _time.monotonic()
                    challenge["_instance_start_error"] = failure_message
                    save_metadata(challenge)

    instance_info = challenge.get("_instance_info")
    if instance_info:
        await _append_run_event(
            challenge_id,
            run_id,
            run,
            {"type": "system", "message": _instance_ready_message(instance_info)},
        )
        return True, instance_info

    message = (
        challenge.get("_instance_start_error")
        or (
            f"Remote instance did not become ready: {start_error}"
            if start_error
            else "Remote instance did not become ready; agent was not started."
        )
    )
    await _fail_run_before_agent(challenge_id, run_id, challenge, run, message)
    return False, None


async def run_agent_task(
    challenge_id: str,
    run_id: str,
    continue_msg: str | None = None,
    codex_skill_mentions: list[str] | None = None,
):
    """Run an agent for a specific run of a challenge."""
    challenge = challenges[challenge_id]
    run = challenge["runs"][run_id]
    run_cwd = get_run_cwd(challenge_id, run)
    sync_run_skill_links(challenge, run)
    seed_working_notes(challenge_id, run)
    write_submit_answer_helper(challenge_id, run_id)
    start_run_timer(run)

    if not continue_msg:
        await _run_ctfgrep_preflight(challenge_id, run_id, challenge, run, run_cwd)
        if run.get("status") == "solved" or challenge.get("status") == "solved":
            return

    provider = get_provider(run["agent"])

    # Start remote instance if needed. Agents must not begin work until a
    # required docker container or machine/scenario is online.
    ok_to_start, instance_info = await _ensure_remote_instance_online(
        challenge_id, run_id, challenge, run
    )
    if not ok_to_start:
        return

    if continue_msg:
        prompt = _append_enabled_hook_prompt_context(continue_msg)
        if instance_info:
            conn_parts = _instance_connection_parts(instance_info)
            if conn_parts:
                prompt += f"\n\nRemote instance: {', '.join(conn_parts)}"
    else:
        prompt = build_prompt(challenge, run, instance_info)

    session_state_for_prompt = run.get("_session_state", {})
    has_session = bool(
        session_state_for_prompt.get("claude_session_id")
        or session_state_for_prompt.get("codex_thread_id")
    )

    if continue_msg and has_session:
        sys_event = {
            "type": "system",
            "message": f"Resuming {provider.label} session...",
        }
    elif continue_msg:
        sys_event = {
            "type": "system",
            "message": f"Continuing {provider.label} (new session)...",
        }
    else:
        sys_event = {
            "type": "system",
            "message": f"{provider.label} agent starting...",
        }
    await _append_run_event(challenge_id, run_id, run, sys_event)
    model_info = run.get('model', '')
    if run.get('effort'):
        model_info += f", {run['effort']}"
    await discord_notify(challenge, f"**{run['agent']}** ({model_info}) — {sys_event['message']}")

    prompt_event = {"type": "user_prompt", "message": prompt}
    if run.get("solve_start"):
        prompt_event["ts"] = run_elapsed_seconds(run)
    await _append_run_event(challenge_id, run_id, run, prompt_event)
    if continue_msg:
        await discord_notify(
            challenge,
            _discord_resume_prompt_message(run, prompt),
        )

    # --- SDK path: use provider's run_agent if available ---
    if provider.supports_sdk:
        log.info("[%s/%s] Entering SDK path for %s", challenge_id[:8], run_id[:8], run["agent"])
        try:
            await _run_agent_sdk_path(
                challenge_id, run_id, challenge, run, provider,
                prompt, bool(continue_msg),
                codex_skill_mentions=codex_skill_mentions,
            )
        except Exception as exc:
            log.error("[%s/%s] SDK path CRASHED: %s", challenge_id[:8], run_id[:8], exc, exc_info=True)
            if run["status"] == "solving":
                run["status"] = "failed"
                run["error"] = str(exc)
            finish_run_timer(run)
            challenge["status"] = derive_challenge_status(challenge)
            save_metadata(challenge)
            err_event = {"type": "error", "message": f"SDK error: {exc}"}
            await _append_run_event(challenge_id, run_id, run, err_event)
            await broadcast(challenge_id, run_id, {
                "type": "run_status", "run_id": run_id,
                "status": run["status"], "error": run.get("error"),
                "duration_ms": effective_run_duration_ms(run),
            })
            await broadcast_challenge(challenge_id, {
                "type": "challenge_status",
                "status": challenge["status"],
            })
        log.info("[%s/%s] SDK path completed for %s", challenge_id[:8], run_id[:8], run["agent"])
        return

    # --- CLI fallback path ---
    env = os.environ.copy()
    env["IS_SANDBOX"] = "1"
    env.update(agent_runtime_env(run["agent"]))

    # Build command using run data instead of challenge data
    # We pass a dict that looks like the old challenge format for provider compatibility
    compat_dict = {
        "id": challenge["id"],
        "name": challenge["name"],
        "description": challenge["description"],
        "flag_format": challenge["flag_format"],
        "agent": run["agent"],
        "model": run["model"],
        "effort": run.get("effort", ""),
        "_codex_thread_id": run.get("_codex_thread_id"),
    }
    cmd = provider.build_command(compat_dict, prompt, bool(continue_msg))

    log.info(
        "[%s/%s] Starting %s: %s (continue=%s, cwd=%s)",
        challenge_id[:8], run_id[:8], run["agent"],
        " ".join(cmd[:6]) + ("..." if len(cmd) > 6 else ""),
        bool(continue_msg), run_cwd,
    )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(run_cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        start_new_session=True,
        limit=2 ** 24,  # 16 MB — default 64 KB is too small for large JSON events
    )
    run["process"] = proc
    bind_run_process_group(run, proc.pid)
    run["_saw_provider_message"] = False
    run["_last_stream_error"] = None
    run["_last_stderr_lines"] = []
    run["_last_unknown_events"] = []

    try:
        async def stream_events(
            stream: asyncio.StreamReader | None, stream_name: str
        ) -> None:
            if stream is None:
                return

            async for raw_line in stream:
                line = raw_line.decode(
                    "utf-8", errors="replace"
                ).strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    event = {
                        "type": "raw",
                        "text": line,
                        "stream": stream_name,
                    }

                provider_state_before = provider_state_for_metadata(run)
                event = provider.normalize_live_event(event, run)
                if (
                    provider_state_for_metadata(run)
                    != provider_state_before
                ):
                    save_metadata(challenge)
                if event is None:
                    continue

                if event.get("type") in {"assistant", "user", "result"}:
                    run["_saw_provider_message"] = True
                elif (
                    event.get("type") == "raw"
                    and event.get("stream") == "stdout"
                ):
                    run["_saw_provider_message"] = True

                if event.get("type") == "error":
                    run["_last_stream_error"] = event.get(
                        "message"
                    )
                elif (
                    event.get("type") == "raw"
                    and event.get("stream") == "stderr"
                    and event.get("text")
                ):
                    stderr_lines = run.setdefault(
                        "_last_stderr_lines", []
                    )
                    stderr_lines.append(event["text"])
                    if len(stderr_lines) > 20:
                        del stderr_lines[:-20]
                elif event.get("type") not in {
                    "assistant",
                    "user",
                    "result",
                    "system",
                    "status",
                    "rate_limit_event",
                    "codex_usage",
                    "user_steer",
                    "raw",
                }:
                    unknown_events = run.setdefault(
                        "_last_unknown_events", []
                    )
                    try:
                        preview = json.dumps(event, default=str)
                    except TypeError:
                        preview = str(event)
                    unknown_events.append(preview[:2000])
                    if len(unknown_events) > 5:
                        del unknown_events[:-5]

                event_index = await _append_run_event(
                    challenge_id, run_id, run, event
                )

                # Auto-submit flag detection
                if (
                    event.get("type") == "assistant"
                    or (
                        event.get("type") == "system"
                        and event.get("subtype") == "teammate_broadcast"
                    )
                ):
                    _try_detect_and_submit_flag(
                        challenge_id, run_id, event, challenge, event_index
                    )

        await asyncio.gather(
            stream_events(proc.stdout, "stdout"),
            stream_events(proc.stderr, "stderr"),
        )

        await proc.wait()

        log.info(
            "[%s/%s] Process exited: code=%s, saw_msg=%s, stop_reason=%s",
            challenge_id[:8], run_id[:8], proc.returncode,
            run.get("_saw_provider_message", False),
            run.get("_stop_reason", "none"),
        )

        stream_error = run.get("_last_stream_error")
        saw_provider_message = run.get(
            "_saw_provider_message", False
        )
        stderr_tail = "\n".join(
            run.get("_last_stderr_lines", [])
        ).strip()
        unknown_tail = "\n".join(
            run.get("_last_unknown_events", [])
        ).strip()

        # Check if external code already set the final status
        # (steer, mark_solved, sibling stop, auto-submit).
        # If _stop_reason is set, the run was intentionally terminated
        # and its status is already correct — skip normal finalization.
        stop_reason = run.pop("_stop_reason", None)

        log.info(
            "[%s/%s] Finalizing: stop_reason=%s, current_status=%s",
            challenge_id[:8], run_id[:8], stop_reason, run["status"],
        )

        if stop_reason:
            # Status already set by the caller (steer, etc.)
            # Auto-stop siblings if this run was solved
            if run["status"] == "solved" and challenge["mode"] == "parallel":
                for other_id, other_run in challenge["runs"].items():
                    if other_id == run_id:
                        continue
                    if other_run["status"] in ("solving", "pending"):
                        await stop_run(other_run, "sibling_solved")
                        finish_run_timer(other_run)
                        other_run["status"] = "failed"
                        other_run["error"] = None
        elif run["status"] == "solved":
            # Auto-submit marked it solved during streaming
            if challenge["mode"] == "parallel":
                for other_id, other_run in challenge["runs"].items():
                    if other_id == run_id:
                        continue
                    if other_run["status"] in ("solving", "pending"):
                        await stop_run(other_run, "sibling_solved")
                        finish_run_timer(other_run)
                        other_run["status"] = "failed"
                        other_run["error"] = None
        elif proc.returncode == 0 and not stream_error and saw_provider_message:
            run["status"] = "completed"
            run["error"] = None
        else:
            run["status"] = "failed"
            if proc.returncode != 0:
                error_msg = (
                    f"Agent exited with code {proc.returncode}"
                )
                if stream_error:
                    error_msg += f"\n{stream_error}"
                elif stderr_tail:
                    error_msg += f"\n{stderr_tail}"
            elif stream_error:
                error_msg = stream_error
            elif stderr_tail:
                error_msg = stderr_tail
            else:
                error_msg = (
                    "Agent exited without producing a usable response."
                )
                if unknown_tail:
                    error_msg += (
                        "\nLast provider events:\n"
                        f"{unknown_tail}"
                    )
            run["error"] = error_msg
            err_event = {
                "type": "error",
                "message": error_msg,
                "exit_code": proc.returncode,
            }
            await _append_run_event(challenge_id, run_id, run, err_event)

    except Exception as exc:
        stop_reason = run.pop("_stop_reason", None)
        if not stop_reason:
            run["status"] = "failed"
            run["error"] = str(exc)
            err_event = {"type": "error", "message": str(exc)}
            await _append_run_event(challenge_id, run_id, run, err_event)
    finally:
        # Only clear process if it's still OUR process (not a replacement
        # started by a steer/handoff while we were unwinding)
        if run.get("process") is proc:
            run["process"] = None
        if run.get("solve_start") and run.get("process") is None:
            finish_run_timer(run)
        # Skip status updates if a new process has already taken over
        # (steer/handoff started a replacement while we were unwinding)
        if run.get("process") is not None and run.get("process") is not proc:
            return
        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)
        await broadcast(challenge_id, run_id, {
            "type": "run_status",
            "run_id": run_id,
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": effective_run_duration_ms(run),
        })
        await broadcast_challenge(challenge_id, {
            "type": "challenge_status",
            "status": challenge["status"],
        })


# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------

async def challenge_ws(websocket: WebSocket):
    if not websocket_origin_allowed(websocket):
        await websocket.close(code=4003)
        return
    if not websocket.session.get("authenticated"):
        auth = websocket.headers.get("authorization", "")
        if not _check_basic_auth(auth):
            await websocket.close(code=4001)
            return

    challenge_id = websocket.path_params["id"]
    run_id = websocket.path_params["run_id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        await websocket.close(code=4004)
        return
    run = challenge["runs"].get(run_id)
    if not run:
        await websocket.close(code=4004)
        return

    await websocket.accept()
    run["ws_clients"].add(websocket)

    history_total = run_event_count(challenge_id, run_id, run)
    history_param = str(websocket.query_params.get("history", "1")).lower()
    after_param = websocket.query_params.get("after")
    start_index = 0
    end_index = 0
    if after_param not in (None, ""):
        after_idx = _parse_positive_int(
            after_param,
            default=history_total,
            minimum=0,
            maximum=history_total,
        )
        start_index = after_idx
        end_index = history_total
    elif history_param not in {"0", "false", "no", "off"}:
        start_index = 0
        end_index = history_total

    # Send requested history/catch-up events before the current status.
    for offset, event in load_output_log_slice(
        challenge_id, run_id, start_index, end_index
    ):
        await websocket.send_json(
            compact_history_event(challenge_id, run_id, event, offset)
        )

    # Send current run status
    await websocket.send_json({
        "type": "run_status", "run_id": run_id,
        "status": run["status"],
        "duration_ms": effective_run_duration_ms(run),
    })

    # Send current challenge-level status
    await websocket.send_json({
        "type": "challenge_status",
        "status": challenge["status"],
    })

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        run["ws_clients"].discard(websocket)


async def global_events_ws(websocket: WebSocket):
    if not websocket_origin_allowed(websocket):
        await websocket.close(code=4003)
        return
    if not websocket.session.get("authenticated"):
        auth = websocket.headers.get("authorization", "")
        if not _check_basic_auth(auth):
            await websocket.close(code=4001)
            return
    await websocket.accept()
    _global_ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        _global_ws_clients.discard(websocket)


# ---------------------------------------------------------------------------
# Agent Auth Sessions
# ---------------------------------------------------------------------------

def _prune_agent_auth_sessions() -> None:
    now = _time.monotonic()
    expired = [
        session_id
        for session_id, session in _agent_auth_sessions.items()
        if now - float(session.get("created_at", 0)) > AUTH_SESSION_TTL_SECONDS
    ]
    for session_id in expired:
        session = _agent_auth_sessions.pop(session_id, None)
        proc = session.get("process") if isinstance(session, dict) else None
        if isinstance(proc, subprocess.Popen) and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass


def _agent_auth_command(agent: str, method: str = "default") -> tuple[str, ...] | None:
    commands = AUTH_COMMANDS.get(agent)
    if not commands:
        return None
    return commands.get(method) or commands.get("default")


def _agent_auth_status_command(agent: str) -> tuple[str, ...] | None:
    return AUTH_STATUS_COMMANDS.get(agent)


def _run_auth_status_command(agent: str) -> dict:
    command = _agent_auth_status_command(agent)
    login_command = _agent_auth_command(agent)
    env_auth = public_agent_env_auth(agent)
    result: dict = {
        "agent": agent,
        "available": False,
        "connected": False,
        "command": " ".join(login_command or ()),
        "env_auth": env_auth,
        "rows": [],
    }
    if not command:
        result["error"] = "Unsupported agent"
        return result
    if not shutil.which(command[0]):
        result["error"] = f"{command[0]} is not installed"
        return result

    result["available"] = True
    if agent == "claude" and env_auth.get("configured"):
        source = env_auth.get("source")
        source_label = "Process env vars" if source == "process" else "Saved env vars"
        rows = [
            {"label": "Method", "value": source_label},
            {"label": "Token", "value": "ANTHROPIC_AUTH_TOKEN configured"},
        ]
        if env_auth.get("base_url"):
            rows.append({
                "label": "Base URL",
                "value": str(env_auth["base_url"]),
            })
        result["connected"] = True
        result["rows"] = rows
        return result

    env = os.environ.copy()
    env.update(agent_runtime_env(agent))
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(APP_ROOT_DIR),
            text=True,
            capture_output=True,
            timeout=AUTH_STATUS_TIMEOUT_SECONDS,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        result["error"] = "Auth status timed out"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    text = stdout or stderr
    if agent == "claude":
        try:
            payload = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            payload = {}
        connected = bool(payload.get("loggedIn"))
        result["connected"] = connected
        rows = []
        if payload.get("email"):
            rows.append({"label": "Account", "value": str(payload["email"])})
        if payload.get("authMethod"):
            rows.append({"label": "Method", "value": str(payload["authMethod"])})
        if payload.get("subscriptionType"):
            rows.append({"label": "Plan", "value": str(payload["subscriptionType"])})
        if payload.get("orgName"):
            rows.append({"label": "Org", "value": str(payload["orgName"])})
        result["rows"] = rows
        if not connected and text:
            result["error"] = text[:300]
        return result

    if agent == "codex":
        text_l = text.casefold()
        connected = (
            completed.returncode == 0
            and "not logged in" not in text_l
            and ("logged in" in text_l or "authenticated" in text_l)
        )
        result["connected"] = connected
        rows = []
        if text:
            method = re.sub(r"^logged in using\s+", "", text, flags=re.IGNORECASE)
            rows.append({
                "label": "Method" if connected else "Status",
                "value": method[:160],
            })
        result["rows"] = rows
        if not connected and text:
            result["error"] = text[:300]
        return result

    result["error"] = text[:300] if text else "Unknown auth status"
    return result


async def agent_auth_status(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    async def _one(agent: str) -> tuple[str, dict]:
        return agent, await asyncio.to_thread(_run_auth_status_command, agent)

    pairs = await asyncio.gather(*(_one(agent) for agent in PROVIDERS))
    return JSONResponse({"agents": dict(pairs)})


async def start_agent_auth(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err

    agent = str_field(body.get("agent", "")).strip()
    method = str_field(body.get("method", "default")).strip() or "default"
    if agent not in PROVIDERS:
        return JSONResponse({"error": f"Unknown agent: {agent}"}, status_code=400)

    command = _agent_auth_command(agent, method)
    if not command:
        return JSONResponse(
            {"error": f"No auth command configured for {agent}"},
            status_code=400,
        )
    if not shutil.which(command[0]):
        return JSONResponse(
            {"error": f"{command[0]} is not installed"},
            status_code=400,
        )

    _prune_agent_auth_sessions()
    session_id = secrets.token_urlsafe(24)
    _agent_auth_sessions[session_id] = {
        "id": session_id,
        "agent": agent,
        "method": method,
        "command": list(command),
        "created_at": _time.monotonic(),
        "started": False,
    }
    return JSONResponse({
        "session_id": session_id,
        "agent": agent,
        "command": " ".join(command),
    })


async def set_agent_env_auth(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err

    agent = str_field(body.get("agent", "")).strip()
    if agent != "claude":
        return JSONResponse(
            {"error": "Environment auth is only supported for Claude"},
            status_code=400,
        )

    data = load_agent_env_auth()
    current = data.get(agent) if isinstance(data.get(agent), dict) else {}
    if body.get("clear"):
        data.pop(agent, None)
        save_agent_env_auth(data)
        return JSONResponse({
            "ok": True,
            "agent": agent,
            "status": _run_auth_status_command(agent),
        })

    base_url = str_field(body.get("base_url", "")).strip()
    auth_token = str_field(body.get("auth_token", "")).strip()
    existing_token = str_field(current.get("ANTHROPIC_AUTH_TOKEN", "")).strip()
    process_token = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()
    if not auth_token and not existing_token and not process_token:
        return JSONResponse(
            {"error": "ANTHROPIC_AUTH_TOKEN is required"},
            status_code=400,
        )

    entry = dict(current)
    if base_url:
        entry["ANTHROPIC_BASE_URL"] = base_url
    else:
        entry.pop("ANTHROPIC_BASE_URL", None)
    if auth_token:
        entry["ANTHROPIC_AUTH_TOKEN"] = auth_token

    if entry:
        data[agent] = entry
    else:
        data.pop(agent, None)
    save_agent_env_auth(data)
    return JSONResponse({
        "ok": True,
        "agent": agent,
        "status": _run_auth_status_command(agent),
    })


async def _pty_read_once(fd: int) -> bytes:
    loop = asyncio.get_running_loop()
    ready = loop.create_future()

    def _mark_ready() -> None:
        if not ready.done():
            ready.set_result(None)

    loop.add_reader(fd, _mark_ready)
    try:
        await ready
        return os.read(fd, 4096)
    finally:
        try:
            loop.remove_reader(fd)
        except Exception:
            pass


async def _agent_auth_output_loop(websocket: WebSocket, master_fd: int) -> None:
    while True:
        try:
            chunk = await _pty_read_once(master_fd)
        except OSError:
            break
        if not chunk:
            break
        await websocket.send_json({
            "type": "output",
            "data": chunk.decode("utf-8", errors="replace"),
        })


async def _agent_auth_input_loop(
    websocket: WebSocket,
    master_fd: int,
    proc: subprocess.Popen,
) -> str:
    while proc.poll() is None:
        try:
            raw = await websocket.receive_text()
        except WebSocketDisconnect:
            return "disconnect"
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        msg_type = str(message.get("type", ""))
        if msg_type == "cancel":
            return "cancel"
        if msg_type == "input":
            data = str(message.get("data", ""))
            if data:
                try:
                    os.write(master_fd, data.encode("utf-8", errors="replace"))
                except OSError:
                    return "closed"
    return "exited"


async def _terminate_auth_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        await asyncio.wait_for(asyncio.to_thread(proc.wait), timeout=5)
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        await asyncio.to_thread(proc.wait)


async def agent_auth_ws(websocket: WebSocket):
    if not websocket_origin_allowed(websocket):
        await websocket.close(code=4003)
        return
    if not websocket.session.get("authenticated"):
        auth = websocket.headers.get("authorization", "")
        if not _check_basic_auth(auth):
            await websocket.close(code=4001)
            return

    _prune_agent_auth_sessions()
    session_id = websocket.path_params["session_id"]
    session = _agent_auth_sessions.get(session_id)
    if not session:
        await websocket.close(code=4004)
        return
    if session.get("started"):
        await websocket.close(code=4009)
        return
    session["started"] = True

    await websocket.accept()
    command = [str(part) for part in session.get("command", [])]
    master_fd = -1
    proc: subprocess.Popen | None = None
    output_task: asyncio.Task | None = None
    input_task: asyncio.Task | None = None
    wait_task: asyncio.Task | None = None
    try:
        await websocket.send_json({
            "type": "start",
            "agent": session.get("agent", ""),
            "command": " ".join(command),
        })
        master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env.setdefault("TERM", "xterm-256color")
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(APP_ROOT_DIR),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
                env=env,
            )
        finally:
            os.close(slave_fd)
        session["process"] = proc

        output_task = asyncio.create_task(
            _agent_auth_output_loop(websocket, master_fd)
        )
        input_task = asyncio.create_task(
            _agent_auth_input_loop(websocket, master_fd, proc)
        )
        wait_task = asyncio.create_task(asyncio.to_thread(proc.wait))
        done, _pending = await asyncio.wait(
            {input_task, wait_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        reason = ""
        if input_task in done:
            reason = input_task.result()
            if reason in {"cancel", "disconnect", "closed"}:
                await _terminate_auth_process(proc)
        returncode = await wait_task
        if output_task and not output_task.done():
            try:
                await asyncio.wait_for(output_task, timeout=0.5)
            except asyncio.TimeoutError:
                output_task.cancel()
        if reason != "disconnect":
            await websocket.send_json({
                "type": "exit",
                "returncode": returncode,
                "cancelled": reason == "cancel",
            })
    except WebSocketDisconnect:
        if proc:
            await _terminate_auth_process(proc)
    except Exception as exc:
        log.error("Agent auth session failed: %s", exc, exc_info=True)
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        for task in (input_task, output_task):
            if task and not task.done():
                task.cancel()
        if master_fd >= 0:
            try:
                os.close(master_fd)
            except OSError:
                pass
        _agent_auth_sessions.pop(session_id, None)


# ---------------------------------------------------------------------------
# Settings / Agents / Usage
# ---------------------------------------------------------------------------

async def get_settings(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse(settings_for_client(load_settings()))


async def get_skills(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse(public_skill_catalog())


async def upload_skill(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    form = await request.form()
    upload = form.get("skill")
    if not upload or not hasattr(upload, "read"):
        return JSONResponse({"error": "No skill uploaded"}, status_code=400)

    filename = Path(getattr(upload, "filename", "") or "").name
    if not filename:
        return JSONResponse(
            {"error": "Skill upload must have a filename"},
            status_code=400,
        )

    raw = await upload.read()
    if not raw:
        return JSONResponse({"error": "Skill upload is empty"}, status_code=400)
    if len(raw) > MAX_SKILL_UPLOAD_BYTES:
        return JSONResponse(
            {"error": "Skill upload is too large"},
            status_code=400,
        )

    with tempfile.TemporaryDirectory(prefix="skill-upload-") as tmp:
        tmp_dir = Path(tmp)
        source_dir = tmp_dir / "skill"
        source_dir.mkdir()
        lower_name = filename.lower()
        fallback_name = Path(filename).stem

        if lower_name.endswith(".zip"):
            source_dir, fallback_name, extract_error = _extract_uploaded_skill_zip(
                raw, source_dir, fallback_name
            )
            if extract_error:
                return JSONResponse({"error": extract_error}, status_code=400)
        else:
            if (
                lower_name not in {"skill.md", "skill"}
                and not lower_name.endswith(".md")
            ):
                return JSONResponse(
                    {"error": "Upload a .zip skill bundle or a SKILL.md file"},
                    status_code=400,
                )
            (source_dir / "SKILL.md").write_bytes(raw)

        entry, install_error = _install_uploaded_skill_dir(source_dir, fallback_name)
        if install_error:
            return JSONResponse({"error": install_error}, status_code=400)

    invalidate_skill_catalog_cache()
    return JSONResponse({
        "ok": True,
        "skill": _public_skill_entry(entry),
        "catalog": public_skill_catalog(),
    })


async def discord_test(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    token = str_field(body.get("token", "")).strip()
    channel_id = str_field(body.get("channel_id", "")).strip()
    if not token or not channel_id:
        return JSONResponse({"error": "Token and channel ID are required"})
    try:
        from discord_bot import DiscordBot
    except ImportError:
        from .discord_bot import DiscordBot
    bot = DiscordBot(token, channel_id)
    try:
        result = await bot.send_channel_message("CTF Solver connected!")
        if result:
            return JSONResponse({"ok": True})
        return JSONResponse({"error": "Failed to send test message"})
    except Exception as exc:
        return JSONResponse({"error": str(exc)})
    finally:
        await bot.close()


async def discord_channels(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    token = str_field(body.get("token", "")).strip()
    if not token:
        return JSONResponse({"error": "Token required"}, status_code=400)
    try:
        from discord_bot import DiscordBot
    except ImportError:
        from .discord_bot import DiscordBot
    bot = DiscordBot(token, "")
    try:
        channels = await bot.list_guild_channels()
        return JSONResponse({"channels": channels})
    except Exception as exc:
        return JSONResponse({"error": str(exc)})
    finally:
        await bot.close()


# ---------------------------------------------------------------------------
# Swarm (remote GCP execution) — management endpoints
# ---------------------------------------------------------------------------

# Names of swarm operations currently running, to prevent overlap.
_swarm_busy: set[str] = set()


def _swarm_module():
    try:
        from . import swarm as swarm_mod
    except ImportError:
        import swarm as swarm_mod
    return swarm_mod


def _swarm_gcp_error():
    try:
        from .gcp import GCPError
    except ImportError:
        from gcp import GCPError
    return GCPError


def _swarm_log(kind: str):
    """Return an async log fn that broadcasts swarm progress over the global WS."""
    async def _log(message: str) -> None:
        await broadcast_global({
            "type": "swarm_event", "kind": kind, "level": "info",
            "message": message,
        })
    return _log


async def _swarm_broadcast(kind: str, message: str, level: str = "info", **extra):
    await broadcast_global({
        "type": "swarm_event", "kind": kind, "level": level,
        "message": message, **extra,
    })


def _swarm_config_view(settings: dict) -> dict:
    swarm_mod = _swarm_module()
    cfg = swarm_mod.swarm_config(settings)
    return {
        "service_account_configured": bool(cfg.get("service_account")),
        "project": cfg.get("project", ""),
        "zone": cfg.get("zone", ""),
        "default_machine_type": cfg.get("default_machine_type", "e2-standard-4"),
        "default_disk_size_gb": cfg.get("default_disk_size_gb", 100),
        "default_disk_type": cfg.get("default_disk_type", "pd-ssd"),
        "network": cfg.get("network", "default"),
        "subnetwork": cfg.get("subnetwork", "default"),
        "idle_stop_minutes": cfg.get("idle_stop_minutes", 30),
        "vpn_route": bool(cfg.get("vpn_route", False)),
        "use_adc": bool(cfg.get("use_adc", False)),
    }


def _wg_routed_networks() -> list[str]:
    """Internal CIDRs the reverse client routes (parsed from wg0.conf's peer)."""
    nets: list[str] = []
    if not WG_CONF.exists():
        return nets
    in_peer = False
    for line in WG_CONF.read_text().splitlines():
        s = line.strip()
        if s.startswith("[Peer]"):
            in_peer = True
            continue
        if in_peer and s.startswith("AllowedIPs"):
            for v in s.split("=", 1)[1].split(","):
                v = v.strip()
                if v and not v.startswith(VPN_SUBNET):
                    nets.append(v)
            break
    return nets


async def _swarm_enroll_vpn(name: str) -> None:
    """Enroll a worker as a wg0 peer so it routes internal CIDRs via the controller.

    Hub-and-spoke (SWARM.md, Solution 2). Best-effort; gated by the vpn_route
    toggle at the call site and a live wg0 here.
    """
    swarm_mod = _swarm_module()
    if not _wg_interface_up():
        await _swarm_broadcast("vpn", f"wg0 is down; skipped VPN for {name}", "error")
        return
    reg = swarm_mod.load_registry()
    inst = reg.get("instances", {}).get(name)
    if not inst or not inst.get("external_ip"):
        return
    ip_addr = inst["external_ip"]
    used = {i.get("vpn_ip") for i in reg["instances"].values() if i.get("vpn_ip")}
    used |= {VPN_SERVER_IP, VPN_CLIENT_IP}
    vpn_ip = next(
        (f"{VPN_SUBNET}.{o}" for o in range(3, 254)
         if f"{VPN_SUBNET}.{o}" not in used),
        "",
    )
    if not vpn_ip:
        await _swarm_broadcast("vpn", "no free VPN address", "error")
        return
    rc, out, _ = await swarm_mod.ssh_run(
        ip_addr,
        "priv=$(wg genkey); pub=$(printf '%s' \"$priv\" | wg pubkey); "
        "printf '%s\\n%s\\n' \"$priv\" \"$pub\"",
        check=False,
    )
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if rc != 0 or len(lines) < 2:
        await _swarm_broadcast("vpn", f"key generation failed on {name}", "error")
        return
    worker_priv, worker_pub = lines[0], lines[1]
    allowed = ", ".join([VPN_CIDR, *_wg_routed_networks()])
    worker_conf = (
        "[Interface]\n"
        f"Address = {vpn_ip}/24\n"
        f"PrivateKey = {worker_priv}\n"
        "\n[Peer]\n"
        f"PublicKey = {WG_SERVER_PUBLIC_KEY.read_text().strip()}\n"
        f"Endpoint = {_get_server_public_ip()}:51820\n"
        f"AllowedIPs = {allowed}\n"
        "PersistentKeepalive = 25\n"
    )
    # Record the peer first, then rebuild wg0.conf from the registry and apply
    # it live — this both persists the peer (survives wg-quick restarts) and
    # adds it to the running interface without bouncing the client (Fix B).
    inst["vpn_ip"] = vpn_ip
    inst["vpn_pubkey"] = worker_pub
    swarm_mod.save_registry(reg)
    try:
        _wg_persist_and_sync()
        await swarm_mod.ssh_write_file(ip_addr, "/etc/wireguard/wg0.conf", worker_conf)
        await swarm_mod.ssh_run(
            ip_addr,
            "wg-quick down wg0 2>/dev/null; wg-quick up wg0",
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        # Roll back the registry entry so the config stays consistent.
        inst.pop("vpn_ip", None)
        inst.pop("vpn_pubkey", None)
        swarm_mod.save_registry(reg)
        _wg_persist_and_sync()
        await _swarm_broadcast("vpn", f"VPN setup failed on {name}: {exc}", "error")
        return
    await _swarm_broadcast("vpn", f"{name} on VPN as {vpn_ip}", "success")


async def _swarm_remove_vpn(name: str) -> None:
    swarm_mod = _swarm_module()
    reg = swarm_mod.load_registry()
    inst = reg.get("instances", {}).get(name)
    if not inst:
        return
    inst.pop("vpn_ip", None)
    inst.pop("vpn_pubkey", None)
    swarm_mod.save_registry(reg)
    # Rebuild wg0.conf without this peer and apply live (syncconf drops the
    # removed peer while keeping the client + other workers connected).
    try:
        _wg_persist_and_sync()
    except Exception:  # noqa: BLE001
        pass


async def _swarm_idle_loop() -> None:
    """Periodically stop running workers that have been idle past the timeout."""
    swarm_mod = _swarm_module()
    while True:
        await asyncio.sleep(120)
        try:
            settings = load_settings()
            if not swarm_mod.is_configured(settings):
                continue
            timeout = int(swarm_mod.swarm_config(settings).get(
                "idle_stop_minutes", 30) or 0)
            if timeout <= 0:
                continue
            now = time.time()
            reg = swarm_mod.load_registry()
            to_stop = []
            for name, inst in reg.get("instances", {}).items():
                if inst.get("status") != "running":
                    continue
                if inst.get("challenge_id"):
                    inst["idle_since"] = int(now)  # busy → reset the clock
                    continue
                idle_since = inst.get("idle_since") or inst.get("created_at") or now
                if now - idle_since > timeout * 60:
                    to_stop.append(name)
            swarm_mod.save_registry(reg)
            for name in to_stop:
                try:
                    await swarm_mod.stop_worker(settings, name)
                    await _swarm_broadcast(
                        "idle", f"Auto-stopped idle worker {name}", "info",
                        refresh=True)
                except Exception as exc:  # noqa: BLE001
                    log.warning("swarm idle-stop %s failed: %s", name, exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("swarm idle loop error: %s", exc)


def _resolve_swarm_ip(challenge: dict) -> str:
    """Return the external IP of the running worker assigned to a challenge."""
    name = challenge.get("_swarm_instance")
    if not name:
        return ""
    swarm_mod = _swarm_module()
    inst = swarm_mod.load_registry().get("instances", {}).get(name)
    if not inst or inst.get("status") != "running":
        return ""
    return inst.get("external_ip", "") or ""


def assign_swarm_to_challenge(challenge: dict, requested: str) -> str:
    """Pin a challenge to a worker. requested = '' (local), 'auto', or a name.

    Returns the assigned instance name ('' if local / none available).
    """
    requested = (requested or "").strip()
    if not requested or requested == "local":
        challenge.pop("_swarm_instance", None)
        return ""
    swarm_mod = _swarm_module()
    reg = swarm_mod.load_registry()
    instances = reg.get("instances", {})
    name = ""
    if requested == "auto":
        # First running worker not already pinned to another challenge.
        for n, inst in instances.items():
            if inst.get("status") == "running" and not inst.get("challenge_id"):
                name = n
                break
    elif requested in instances:
        name = requested
    if not name:
        return ""
    challenge["_swarm_instance"] = name
    instances[name]["challenge_id"] = challenge.get("id")
    swarm_mod.save_registry(reg)
    return name


def release_swarm_from_challenge(challenge: dict) -> None:
    """Unpin a challenge's worker so it can be reused."""
    name = challenge.get("_swarm_instance")
    if not name:
        return
    swarm_mod = _swarm_module()
    reg = swarm_mod.load_registry()
    inst = reg.get("instances", {}).get(name)
    if inst and inst.get("challenge_id") == challenge.get("id"):
        inst["challenge_id"] = None
        inst["idle_since"] = int(time.time())
        swarm_mod.save_registry(reg)


async def swarm_status(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    settings = load_settings()
    swarm_mod = _swarm_module()
    reg = swarm_mod.load_registry()
    return JSONResponse({
        "configured": swarm_mod.is_configured(settings),
        "config": _swarm_config_view(settings),
        "image": reg.get("image", {}),
        "instances": list(reg.get("instances", {}).values()),
        "busy": sorted(_swarm_busy),
    })


async def swarm_save_config(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    settings = load_settings()
    swarm = dict(settings.get("swarm") or {})

    # Service account is only replaced when a non-empty value is sent.
    sa_raw = body.get("service_account")
    if isinstance(sa_raw, str) and sa_raw.strip():
        try:
            sa = json.loads(sa_raw)
        except json.JSONDecodeError:
            return JSONResponse(
                {"error": "Service account key is not valid JSON"}, status_code=400)
        if not isinstance(sa, dict) or "private_key" not in sa or (
            "client_email" not in sa
        ):
            return JSONResponse(
                {"error": "Service account JSON is missing required fields"},
                status_code=400)
        swarm["service_account"] = sa
        if not swarm.get("project") and sa.get("project_id"):
            swarm["project"] = sa["project_id"]
    elif isinstance(sa_raw, dict) and sa_raw:
        swarm["service_account"] = sa_raw

    if "project" in body:
        swarm["project"] = str_field(body["project"]).strip()
    if "zone" in body:
        swarm["zone"] = str_field(body["zone"]).strip()
    if "default_machine_type" in body:
        swarm["default_machine_type"] = str_field(body["default_machine_type"]).strip()
    if "default_disk_size_gb" in body:
        try:
            swarm["default_disk_size_gb"] = max(10, int(body["default_disk_size_gb"]))
        except (TypeError, ValueError):
            pass
    if "default_disk_type" in body:
        swarm["default_disk_type"] = str_field(body["default_disk_type"]).strip()
    if "network" in body:
        swarm["network"] = str_field(body["network"]).strip() or "default"
    if "subnetwork" in body:
        swarm["subnetwork"] = str_field(body["subnetwork"]).strip() or "default"
    if "idle_stop_minutes" in body:
        try:
            swarm["idle_stop_minutes"] = max(0, int(body["idle_stop_minutes"]))
        except (TypeError, ValueError):
            pass
    if "vpn_route" in body:
        swarm["vpn_route"] = bool(body["vpn_route"])
    if "use_adc" in body:
        swarm["use_adc"] = bool(body["use_adc"])

    settings["swarm"] = swarm
    save_settings(settings)
    return JSONResponse({"ok": True, "config": _swarm_config_view(settings)})


async def swarm_test(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    settings = load_settings()
    swarm_mod = _swarm_module()
    GCPError = _swarm_gcp_error()
    if not swarm_mod.is_configured(settings):
        return JSONResponse(
            {"error": "Set the service account and zone first"}, status_code=400)
    try:
        client = swarm_mod.make_client(settings)
        info = await client.test_connection()
        return JSONResponse({"ok": True, "info": info})
    except GCPError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"unexpected: {exc}"}, status_code=400)


async def swarm_build_image(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    settings = load_settings()
    swarm_mod = _swarm_module()
    if not swarm_mod.is_configured(settings):
        return JSONResponse({"error": "Configure GCP first"}, status_code=400)
    if "image" in _swarm_busy:
        return JSONResponse({"error": "Image build already running"}, status_code=409)
    cfg = swarm_mod.swarm_config(settings)

    async def _run() -> None:
        _swarm_busy.add("image")
        try:
            await swarm_mod.build_golden_image(
                settings, repo_root=APP_ROOT_DIR,
                machine_type=cfg.get("default_machine_type", "e2-standard-4"),
                disk_size_gb=int(cfg.get("default_disk_size_gb", 100)),
                disk_type=cfg.get("default_disk_type", "pd-ssd"),
                network=cfg.get("network", "default"),
                subnetwork=cfg.get("subnetwork", "default"),
                log=_swarm_log("image"),
            )
            await _swarm_broadcast("image", "Golden image build complete", "success")
        except Exception as exc:  # noqa: BLE001
            await _swarm_broadcast("image", f"Image build failed: {exc}", "error")
        finally:
            _swarm_busy.discard("image")

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "started": True})


async def swarm_create_instances(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    settings = load_settings()
    swarm_mod = _swarm_module()
    if not swarm_mod.is_configured(settings):
        return JSONResponse({"error": "Configure GCP first"}, status_code=400)
    cfg = swarm_mod.swarm_config(settings)
    try:
        count = max(1, min(20, int(body.get("count", 1))))
    except (TypeError, ValueError):
        count = 1
    machine_type = str_field(body.get("machine_type", "")) or cfg.get(
        "default_machine_type", "e2-standard-4")
    try:
        cpus = int(body.get("cpus", 0) or 0)
        mem_mb = int(body.get("mem_mb", 0) or 0)
    except (TypeError, ValueError):
        cpus, mem_mb = 0, 0
    try:
        disk_size_gb = int(body.get("disk_size_gb", 0) or cfg.get(
            "default_disk_size_gb", 100))
    except (TypeError, ValueError):
        disk_size_gb = int(cfg.get("default_disk_size_gb", 100))

    async def _run() -> None:
        _swarm_busy.add("create")
        try:
            for _ in range(count):
                name = f"ctf-swarm-{secrets.token_hex(3)}"
                await _swarm_broadcast("create", f"Creating {name}…")
                try:
                    await swarm_mod.create_worker(
                        settings, name, machine_type=machine_type, cpus=cpus,
                        mem_mb=mem_mb, disk_size_gb=disk_size_gb,
                        disk_type=cfg.get("default_disk_type", "pd-ssd"),
                        network=cfg.get("network", "default"),
                        subnetwork=cfg.get("subnetwork", "default"),
                    )
                    await _swarm_broadcast("create", f"{name} is up", "success")
                    if cfg.get("vpn_route"):
                        await _swarm_enroll_vpn(name)
                except Exception as exc:  # noqa: BLE001
                    await _swarm_broadcast(
                        "create", f"{name} failed: {exc}", "error")
        finally:
            _swarm_busy.discard("create")
            await _swarm_broadcast("create", "done", "info", refresh=True)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "started": True, "count": count})


async def swarm_instance_action(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    name = request.path_params["name"]
    action = request.path_params["action"]
    settings = load_settings()
    swarm_mod = _swarm_module()
    GCPError = _swarm_gcp_error()
    try:
        if action == "start":
            rec = await swarm_mod.start_worker(settings, name)
        elif action == "stop":
            rec = await swarm_mod.stop_worker(settings, name)
        elif action == "sync-credentials":
            reg = swarm_mod.load_registry()
            inst = reg.get("instances", {}).get(name, {})
            ip = inst.get("external_ip", "")
            if not ip:
                return JSONResponse(
                    {"error": "instance has no external IP (is it running?)"},
                    status_code=400)
            synced = await swarm_mod.sync_agent_credentials(ip)
            return JSONResponse({"ok": True, "synced": synced})
        else:
            return JSONResponse({"error": "unknown action"}, status_code=400)
        return JSONResponse({"ok": True, "instance": rec})
    except GCPError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


async def swarm_delete_instance(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    name = request.path_params["name"]
    settings = load_settings()
    swarm_mod = _swarm_module()
    GCPError = _swarm_gcp_error()
    try:
        await _swarm_remove_vpn(name)
        await swarm_mod.delete_worker(settings, name)
        return JSONResponse({"ok": True})
    except GCPError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


async def swarm_refresh(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    settings = load_settings()
    swarm_mod = _swarm_module()
    GCPError = _swarm_gcp_error()
    try:
        instances = await swarm_mod.refresh_workers(settings)
        return JSONResponse({"ok": True, "instances": instances})
    except GCPError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


def _static_provider_metadata(provider) -> dict:
    """Return provider metadata using static models only (no PTY discovery).

    This avoids the 3-8 second PTY subprocess that some provider discovery
    paths spawn. The static models list is always available and sufficient
    for the UI.
    """
    return {
        "name": provider.name,
        "label": provider.label,
        "models": [
            {"value": value, "label": label}
            for value, label in provider.models
        ] if provider.models else [
            {"value": "", "label": "Provider default"}
        ],
        "default_model": provider.default_model,
        "auth_connect_command": provider.auth_connect_command,
        "badge_mode": provider.badge_mode,
        "effort_levels": [
            {"value": value, "label": label}
            for value, label in provider.effort_levels
        ],
        "default_effort": provider.default_effort,
    }


async def list_agents(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse({
        "agents": [
            _static_provider_metadata(provider)
            for provider in PROVIDERS.values()
        ],
        "parallel_option": (
            {
                "value": PARALLEL_AGENT_VALUE,
                "label": "All (parallel)",
            }
            if len(PROVIDERS) > 1
            else None
        ),
    })


async def update_settings(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    settings = load_settings()
    discord_changed = any(
        key in body
        for key in (
            "discord_enabled",
            "discord_bot_token",
            "discord_channel_id",
            "discord_guild_id",
            "discord_challenge_layout",
        )
    )
    if "default_agent" in body:
        agent = str_field(body["default_agent"])
        if agent not in VALID_AGENTS:
            return JSONResponse(
                {"error": f"invalid agent: {agent}"},
                status_code=400,
            )
        settings["default_agent"] = agent
    if "default_flag_format" in body:
        settings["default_flag_format"] = str_field(
            body["default_flag_format"]
        )
    if "theme" in body:
        theme = str(body["theme"])
        if theme in ("dark", "light"):
            settings["theme"] = theme
    if "auto_submit_flags" in body:
        settings["auto_submit_flags"] = bool(body["auto_submit_flags"])
    if "chat_view_mode" in body:
        mode = str(body["chat_view_mode"])
        if mode in ("split", "tabbed"):
            settings["chat_view_mode"] = mode
    if "enabled_agents" in body:
        agents = body["enabled_agents"]
        if isinstance(agents, list):
            settings["enabled_agents"] = [
                str_field(a) for a in agents if str_field(a) in VALID_AGENTS
            ]
    if "agent_models" in body:
        models = body["agent_models"]
        if isinstance(models, dict):
            settings["agent_models"] = {
                str_field(k): str_field(v) for k, v in models.items()
                if str_field(k) in VALID_AGENTS
            }
    if "agent_efforts" in body:
        efforts = body["agent_efforts"]
        if isinstance(efforts, dict):
            settings["agent_efforts"] = {
                str_field(k): str_field(v) for k, v in efforts.items()
                if str_field(k) in VALID_AGENTS
            }
    if "enabled_skills" in body:
        settings["enabled_skills"] = normalize_enabled_skills(
            body.get("enabled_skills"),
            default=[],
        )
    if "enabled_hooks" in body:
        settings["enabled_hooks"] = normalize_enabled_hooks(
            body.get("enabled_hooks")
        )
    if "max_platform_import_size_gb" in body:
        settings["max_platform_import_size_gb"] = normalize_platform_import_size_gb(
            body.get("max_platform_import_size_gb")
        )
    if "discord_enabled" in body:
        settings["discord_enabled"] = bool(body["discord_enabled"])
    if "discord_bot_token" in body:
        settings["discord_bot_token"] = str(body["discord_bot_token"]).strip()
    if "discord_channel_id" in body:
        settings["discord_channel_id"] = str(body["discord_channel_id"]).strip()
    if "discord_guild_id" in body:
        settings["discord_guild_id"] = str(body["discord_guild_id"]).strip()
    if "discord_challenge_layout" in body:
        settings["discord_challenge_layout"] = normalize_discord_challenge_layout(
            body["discord_challenge_layout"]
        )
    save_settings(settings)
    if discord_changed:
        asyncio.create_task(_reconcile_discord_gateway())
    return JSONResponse(settings_for_client(settings))


def get_agent_challenge_stats() -> dict:
    """Aggregate per-agent stats from challenge/run metadata."""
    stats = {
        name: {
            "total": 0, "solved": 0, "failed": 0,
            "total_duration_ms": 0,
        }
        for name in VALID_AGENTS
    }
    for c in challenges.values():
        for run in c["runs"].values():
            agent = run.get("agent", DEFAULT_AGENT)
            bucket = stats.setdefault(agent, {
                "total": 0,
                "solved": 0,
                "failed": 0,
                "total_duration_ms": 0,
            })
            bucket["total"] += 1
            if run["status"] == "solved":
                bucket["solved"] += 1
            elif run["status"] == "failed":
                bucket["failed"] += 1
            duration_ms = effective_run_duration_ms(run)
            if duration_ms:
                bucket["total_duration_ms"] += duration_ms
    return stats


async def get_usage(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    async def _collect_provider_usage(name: str, provider) -> tuple[str, dict | None]:
        try:
            return name, await asyncio.to_thread(provider.get_usage_data)
        except Exception as exc:
            log.warning("Failed to collect %s usage data: %s", name, exc)
            return name, {
                "auth_rows": [{"label": "Error", "value": str(exc)}],
                "stat_rows": [],
                "daily_activity": [],
                "daily_activity_title": None,
            }

    usage_pairs = await asyncio.gather(*(
        _collect_provider_usage(name, provider)
        for name, provider in PROVIDERS.items()
    ))
    result = {
        "agents": dict(usage_pairs),
        "challenges": get_agent_challenge_stats(),
    }
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# Plugins (CTF platform integrations)
# ---------------------------------------------------------------------------


async def list_plugins(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    plugins = get_plugins()
    return JSONResponse([
        {
            "name": p.name,
            "label": p.label,
            "config_schema": [
                {
                    "name": f.name,
                    "label": f.label,
                    "type": f.field_type,
                    "required": f.required,
                    "placeholder": f.placeholder,
                    "default": f.default,
                }
                for f in p.config_schema()
            ],
        }
        for p in plugins.values()
    ])


async def plugin_test_connection(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    plugin_name = str_field(body.get("plugin", ""))
    config = body.get("config", {})
    if not isinstance(config, dict):
        return JSONResponse({"error": "config must be an object"}, status_code=400)

    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Unknown plugin: {plugin_name}"},
            status_code=404,
        )

    try:
        message = await plugin.test_connection(config)
        return JSONResponse({"ok": True, "message": message})
    except Exception as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )


async def plugin_fetch_challenges(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    plugin_name = str_field(body.get("plugin", ""))
    config = body.get("config", {})
    if not isinstance(config, dict):
        return JSONResponse({"error": "config must be an object"}, status_code=400)

    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Unknown plugin: {plugin_name}"},
            status_code=404,
        )

    try:
        remote_challenges = await plugin.fetch_challenges(config)
        return JSONResponse([
            {
                "remote_id": c.remote_id,
                "name": c.name,
                "description": c.description,
                "category": c.category,
                "points": c.points,
                "solves": c.solves,
                "files": [
                    {"name": f.name, "url": f.url}
                    for f in c.files
                ],
                "solved": c.solved,
                "tags": c.tags,
                "flag_questions": c.flag_questions,
            }
            for c in remote_challenges
        ])
    except Exception as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )


def _set_import_progress(progress_id: str, **fields) -> None:
    if not progress_id:
        return
    state = _platform_import_progress.setdefault(progress_id, {
        "id": progress_id,
        "status": "running",
        "started_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "events": [],
    })
    message = fields.get("message")
    if message and (not state.get("events") or state["events"][-1] != message):
        state.setdefault("events", []).append(str(message))
        del state["events"][:-20]
    state.update(fields)
    state["updated_at"] = utc_now_iso()


async def plugin_import_progress(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    progress_id = request.path_params["progress_id"]
    state = _platform_import_progress.get(progress_id)
    if not state:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(state)


async def plugin_import_challenges(request: Request) -> JSONResponse:
    """Download files and create challenges from a plugin fetch."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    plugin_name = str_field(body.get("plugin", ""))
    config = body.get("config", {})
    if not isinstance(config, dict):
        return JSONResponse({"error": "config must be an object"}, status_code=400)
    selected = body.get("challenges", [])
    if not isinstance(selected, list):
        return JSONResponse({"error": "challenges must be a list"}, status_code=400)
    mode = str_field(body.get("mode", "single")).strip()
    if mode not in VALID_MODES:
        mode = "single"
    agents_value = body.get("agents", "")
    if isinstance(agents_value, list):
        agents = json.dumps(agents_value)
    else:
        agents = str_field(agents_value).strip()
    model = str_field(body.get("model", ""))
    effort = str_field(body.get("effort", ""))
    flag_format = str_field(body.get("flag_format", "")).strip()
    paused = bool(body.get("paused", False))
    default_enabled_skills = normalize_enabled_skills(
        body.get("enabled_skills"),
        default=normalize_enabled_skills(load_settings().get("enabled_skills")),
    )
    progress_id = str_field(body.get("progress_id", "")).strip()
    enabled_selected = [
        item for item in selected
        if isinstance(item, dict) and item.get("enabled", True)
    ]
    total_enabled = len(enabled_selected)
    _set_import_progress(
        progress_id,
        status="running",
        phase="starting",
        total_challenges=total_enabled,
        completed_challenges=0,
        current_challenge="",
        current_file="",
        file_index=0,
        file_count=0,
        file_downloaded=0,
        file_total=None,
        overall_percent=0,
        message=f"Starting import for {total_enabled} challenge(s)",
    )

    plugin = get_plugin(plugin_name)
    if not plugin:
        _set_import_progress(
            progress_id,
            status="failed",
            phase="error",
            message=f"Unknown plugin: {plugin_name}",
        )
        return JSONResponse(
            {"error": f"Unknown plugin: {plugin_name}"},
            status_code=404,
        )

    # Save the connection before creating/running challenges. Instance-only
    # challenges can start immediately and need credentials during preflight.
    _source_url = plugin.source_url(config)
    _conn_id = save_plugin_connection(
        plugin_name,
        plugin,
        config,
        _source_url,
    )
    max_import_bytes = platform_import_limit_bytes()

    created = []
    processed_enabled = 0
    for ch_cfg in selected:
        if not isinstance(ch_cfg, dict):
            continue
        if not ch_cfg.get("enabled", True):
            continue

        processed_enabled += 1
        ch_name = str_field(ch_cfg.get("name", ""))
        ch_description = str_field(ch_cfg.get("description", ""))
        ch_remote_id = str_field(ch_cfg.get("remote_id", ""))
        ch_category = str_field(ch_cfg.get("category", ""))
        if ch_category:
            ch_description = f"Challenge Category: {ch_category}\n\n{ch_description}" if ch_description else f"Challenge Category: {ch_category}"
        ch_flag_format = str_field(ch_cfg.get("flag_format", "")) or flag_format
        ch_enabled_skills = (
            normalize_enabled_skills(
                ch_cfg.get("enabled_skills"),
                default=default_enabled_skills,
            )
            if "enabled_skills" in ch_cfg
            else default_enabled_skills
        )
        remote_files = ch_cfg.get("files", [])
        if not isinstance(remote_files, list):
            remote_files = []
        _set_import_progress(
            progress_id,
            phase="challenge",
            current_challenge=ch_name,
            challenge_index=processed_enabled,
            total_challenges=total_enabled,
            file_index=0,
            file_count=len(remote_files),
            file_downloaded=0,
            file_total=None,
            overall_percent=(
                int(((processed_enabled - 1) / max(1, total_enabled)) * 100)
            ),
            message=(
                f"Importing {ch_name} "
                f"({processed_enabled}/{total_enabled})"
            ),
        )

        # Download files (preserve paths, report failures). Enforce a
        # per-challenge aggregate cap to avoid unbounded platform imports.
        file_data: dict[str, bytes] = {}
        download_errors: list[str] = []
        downloaded_bytes = 0
        skip_reason = ""
        for file_idx, rf in enumerate(remote_files, 1):
            if not isinstance(rf, dict):
                download_errors.append("invalid file entry")
                continue
            raw_name = str_field(rf.get("name", ""))
            raw_url = str_field(rf.get("url", ""))
            if not raw_name or not raw_url:
                download_errors.append("file entry missing name or url")
                continue
            remaining_bytes = max_import_bytes - downloaded_bytes
            if remaining_bytes <= 0:
                skip_reason = (
                    f"Skipped: attached files exceed per-challenge platform "
                    f"import limit ({format_bytes(max_import_bytes)})"
                )
                file_data = {}
                break
            _set_import_progress(
                progress_id,
                phase="download",
                current_challenge=ch_name,
                current_file=raw_name,
                file_index=file_idx,
                file_count=len(remote_files),
                file_downloaded=0,
                file_total=None,
                overall_percent=(
                    int(((processed_enabled - 1) / max(1, total_enabled)) * 100)
                ),
                message=(
                    f"Downloading {raw_name} for {ch_name} "
                    f"({file_idx}/{len(remote_files)})"
                ),
            )

            async def _download_progress(
                downloaded: int,
                expected: int | None,
                *,
                _file_idx: int = file_idx,
                _raw_name: str = raw_name,
            ) -> None:
                file_fraction = 0.0
                if expected:
                    file_fraction = min(1.0, downloaded / max(1, expected))
                elif remote_files:
                    file_fraction = min(0.95, downloaded / max(1, remaining_bytes))
                challenge_fraction = (
                    ((_file_idx - 1) + file_fraction) / max(1, len(remote_files))
                )
                overall = (
                    ((processed_enabled - 1) + challenge_fraction)
                    / max(1, total_enabled)
                )
                _set_import_progress(
                    progress_id,
                    phase="download",
                    current_challenge=ch_name,
                    current_file=_raw_name,
                    file_index=_file_idx,
                    file_count=len(remote_files),
                    file_downloaded=downloaded,
                    file_total=expected,
                    overall_percent=int(max(0, min(100, overall * 100))),
                )

            try:
                data = await plugin.download_file(
                    config,
                    RemoteFile(name=raw_name, url=raw_url),
                    max_bytes=remaining_bytes,
                    progress_cb=_download_progress,
                )
                if downloaded_bytes + len(data) > max_import_bytes:
                    raise RemoteFileTooLarge(
                        f"downloaded {format_bytes(downloaded_bytes + len(data))}, "
                        f"limit {format_bytes(max_import_bytes)}"
                    )
                safe_name = normalize_uploaded_path(
                    raw_name, parallel=(mode == "parallel")
                )
                if not safe_name:
                    fallback = raw_name.split("/")[-1].split("?")[0]
                    safe_name = normalize_uploaded_path(
                        fallback, parallel=(mode == "parallel")
                    )
                    if not safe_name:
                        download_errors.append(f"{raw_name}: unsafe filename")
                        continue
                # Avoid collision: if path already used, suffix it
                if safe_name in file_data:
                    base, ext = (safe_name.rsplit(".", 1) + [""])[:2]
                    counter = 1
                    while True:
                        candidate = f"{base}_{counter}.{ext}" if ext else f"{base}_{counter}"
                        if candidate not in file_data:
                            safe_name = candidate
                            break
                        counter += 1
                    download_errors.append(
                        f"{raw_name}: renamed to {safe_name} (path collision)"
                    )
                file_data[safe_name] = data
                downloaded_bytes += len(data)
            except RemoteFileTooLarge as exc:
                skip_reason = (
                    f"Skipped: attached files exceed per-challenge platform "
                    f"import limit ({format_bytes(max_import_bytes)}): "
                    f"{raw_name}: {exc}"
                )
                file_data = {}
                break
            except Exception as exc:
                download_errors.append(
                    f"{raw_name}: {exc}"
                )

        if skip_reason:
            created.append({
                "id": "",
                "name": ch_name,
                "status": "skipped",
                "error": skip_reason,
            })
            _set_import_progress(
                progress_id,
                phase="skipped",
                current_challenge=ch_name,
                completed_challenges=processed_enabled,
                overall_percent=int(
                    (processed_enabled / max(1, total_enabled)) * 100
                ),
                message=f"Skipped {ch_name}: {skip_reason}",
            )
            continue

        if not file_data and download_errors:
            created.append({
                "id": "",
                "name": ch_name,
                "status": "error",
                "error": f"All downloads failed: {'; '.join(download_errors)}",
            })
            _set_import_progress(
                progress_id,
                phase="error",
                current_challenge=ch_name,
                completed_challenges=processed_enabled,
                overall_percent=int(
                    (processed_enabled / max(1, total_enabled)) * 100
                ),
                message=(
                    f"Failed to import {ch_name}: "
                    f"{'; '.join(download_errors)}"
                ),
            )
            continue

        partial_warning = ""
        if download_errors:
            partial_warning = (
                f"Warning: {len(download_errors)} file(s) failed to "
                f"download: {'; '.join(download_errors)}"
            )

        # Determine which agents to create runs for
        agent_entries = parse_agents_field(agents)
        # Filter to valid agents
        agent_entries = [
            e for e in agent_entries if e["agent"] in VALID_AGENTS
        ]
        if not agent_entries:
            agent_entries = [{"agent": DEFAULT_AGENT, "model": ""}]
        if mode == "single":
            agent_entries = agent_entries[:1]
        else:
            seen_a2: set[tuple] = set()
            agent_entries = [e for e in agent_entries if not ((e["agent"], e.get("model", ""), e.get("effort", "")) in seen_a2 or seen_a2.add((e["agent"], e.get("model", ""), e.get("effort", ""))))]

        challenge_id = uuid.uuid4().hex[:12]
        challenge_dir = CHALLENGES_DIR / challenge_id

        if mode == "parallel":
            setup_parallel_shared_dir(challenge_id)
        else:
            challenge_dir.mkdir(parents=True)

        files_dir = challenge_dir / "_files"
        files_dir.mkdir(parents=True, exist_ok=True)
        for fname, fdata in file_data.items():
            dest = files_dir / fname
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fdata)

        runs = {}
        challenge_status = "pending" if paused else "solving"
        for entry in agent_entries:
            agent_name = entry["agent"]
            run_id = uuid.uuid4().hex[:8]
            run_model = entry.get("model") or model or resolved_default_model(agent_name)
            run_effort = normalize_effort_for_agent(agent_name, entry.get("effort") or effort)
            runs[run_id] = make_run(
                run_id=run_id,
                agent=agent_name,
                model=run_model,
                effort=run_effort,
                status=challenge_status,
            )
            setup_run_dir(challenge_id, run_id)

        if mode == "parallel":
            assign_notes_labels(runs)
            setup_parallel_cross_notes(challenge_id, runs)

        challenge = {
            "id": challenge_id,
            "name": ch_name,
            "description": ch_description,
            "category": ch_category,
            "flag_format": ch_flag_format,
            "extra_flag_formats": [],
            "mode": mode,
            "status": challenge_status,
            "created_at": datetime.now().isoformat(),
            "files": sorted(file_data.keys()),
            "enabled_skills": ch_enabled_skills,
            "error": None,
            "runs": runs,
            "_plugin": plugin_name,
            "_remote_id": ch_remote_id,
            "_points": ch_cfg.get("points", 0),
            "_solves": ch_cfg.get("solves", 0),
            "_tags": ch_cfg.get("tags", []),
            "_flag_questions": ch_cfg.get("flag_questions", []),
            "_source_url": _source_url,
            "_connection_id": _conn_id,
        }
        challenges[challenge_id] = challenge
        sync_challenge_skill_links(challenge)
        save_metadata(challenge)
        asyncio.create_task(discord_ensure_destination(challenge))

        if challenge_status == "solving":
            for run_id, run in runs.items():
                run.pop("_stop_reason", None)
                run["task"] = asyncio.create_task(
                    run_agent_task(challenge_id, run_id)
                )

        entry = {
            "id": challenge_id,
            "name": ch_name,
            "status": challenge_status,
        }
        if partial_warning:
            entry["warning"] = partial_warning
        created.append(entry)
        _set_import_progress(
            progress_id,
            phase="created",
            current_challenge=ch_name,
            current_file="",
            file_index=len(remote_files),
            file_count=len(remote_files),
            file_downloaded=0,
            file_total=None,
            completed_challenges=processed_enabled,
            overall_percent=int(
                (processed_enabled / max(1, total_enabled)) * 100
            ),
            message=f"Created {ch_name}",
        )

    _set_import_progress(
        progress_id,
        status="done",
        phase="done",
        completed_challenges=processed_enabled,
        overall_percent=100 if total_enabled else 0,
        current_file="",
        file_downloaded=0,
        file_total=None,
        message=f"Import complete: {len(created)} item(s) processed",
    )
    return JSONResponse({"created": created}, status_code=201)


def resolve_challenge_plugin_config(challenge: dict) -> dict:
    """Resolve saved plugin credentials for an imported challenge."""
    _, config = _resolve_plugin_config(challenge)
    return config


def resolve_flag_question(
    challenge: dict, question: int | None, flag_id: str | int | None,
) -> tuple[dict | None, str | int | None, int | None]:
    """Resolve a 1-based question number or platform flag_id."""
    questions = challenge.get("_flag_questions") or []
    if flag_id not in (None, ""):
        flag_id_str = str(flag_id)
        for idx, item in enumerate(questions, 1):
            if str(item.get("flag_id")) == flag_id_str:
                return item, item.get("flag_id"), idx
        return None, flag_id, None
    if question is not None:
        idx = int(question)
        if idx < 1 or idx > len(questions):
            raise ValueError(f"question must be between 1 and {len(questions)}")
        item = questions[idx - 1]
        return item, item.get("flag_id"), idx
    return None, None, None


async def rescan_challenge_for_flags(
    challenge_id: str, challenge: dict, formats: list[str] | None = None
) -> list[dict]:
    """Scan saved run output for flags matching the configured formats."""
    search_formats = formats or challenge_flag_formats(challenge)
    found: dict[str, dict] = {}
    for run_id, run in challenge.get("runs", {}).items():
        for idx, event in iter_output_log_indexed(challenge_id, run_id):
            if not isinstance(event, dict):
                continue
            for text in _event_flag_texts(event):
                for flag in detect_flags(text, search_formats):
                    _handle_detected_flag(
                        challenge_id,
                        run_id,
                        challenge,
                        flag,
                        event=event,
                        event_index=idx,
                        source_type="scan",
                    )
                    stored = detected_flag_key(
                        challenge.setdefault("detected_flags", {}), flag
                    )
                    found[flag_lookup_key(stored)] = {
                        "flag": stored,
                        "status": challenge.get("detected_flags", {}).get(stored, "pending"),
                        "run_id": run_id,
                        "meta": detected_flag_meta(challenge, stored),
                    }
    return list(found.values())


async def add_flag_format(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    raw_format = str_field(body.get("format", "")).strip()
    if not raw_format:
        raw_format = str_field(body.get("flag_format", "")).strip()
    if not raw_format:
        return JSONResponse({"error": "flag format required"}, status_code=400)

    try:
        added, normalized = add_challenge_flag_format(challenge, raw_format)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    save_metadata(challenge)
    detected = await rescan_challenge_for_flags(
        challenge_id, challenge, challenge_flag_formats(challenge)
    )

    return JSONResponse({
        "added": added,
        "format": normalized,
        "flag_format": challenge.get("flag_format", ""),
        "flag_formats": challenge_flag_formats(challenge),
        "detected": detected,
        "auto_submit": bool(load_settings().get("auto_submit_flags")),
    })


async def add_manual_flag(request: Request) -> JSONResponse:
    """Persist a user-provided flag candidate without auto-detecting text."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    flag = str_field(body.get("flag", "")).strip()
    if not flag:
        return JSONResponse({"error": "flag required"}, status_code=400)

    detected = challenge.setdefault("detected_flags", {})
    stored_flag = detected_flag_key(detected, flag)
    added = stored_flag not in detected
    if added:
        stored_flag = set_detected_flag_status(challenge, flag, "pending")
    record_detected_flag_source(
        challenge,
        stored_flag,
        source_type="manual",
    )
    status = detected.get(stored_flag, "pending")
    save_metadata(challenge)

    return JSONResponse({
        "added": added,
        "flag": stored_flag,
        "status": status,
        "meta": detected_flag_meta(challenge, stored_flag),
    })


async def update_challenge_skills(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)

    return JSONResponse(
        {"error": "challenge skills are locked after creation"},
        status_code=405,
    )


async def _record_run_goal_event(
    challenge_id: str,
    run_id: str,
    challenge: dict,
    run: dict,
    event: dict,
) -> None:
    if "ts" not in event and run.get("solve_start"):
        event["ts"] = run_elapsed_seconds(run)
    apply_run_goal_event(run, event)
    await _append_run_event(challenge_id, run_id, run, event)
    save_metadata(challenge)


async def _mutate_run_goal(
    challenge_id: str,
    run_id: str,
    challenge: dict,
    run: dict,
    *,
    objective: str = "",
    clear: bool = False,
) -> dict:
    if run.get("agent") != "codex":
        raise ValueError("goals are only supported for Codex runs")
    thread_id = run_codex_thread_id(run)
    if not thread_id:
        raise RuntimeError("Codex thread is not ready yet")

    event: dict | None = None
    queue = run.get("_codex_goal_commands")
    if run.get("status") == "solving" and isinstance(queue, asyncio.Queue):
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        await queue.put({
            "action": "clear" if clear else "set",
            "objective": objective,
            "future": future,
        })
        event = await asyncio.wait_for(future, timeout=10.0)
        apply_run_goal_event(run, event)
        save_metadata(challenge)
        return public_run_summary(challenge, run)

    provider = get_provider(run.get("agent", ""))
    run_cwd = get_run_cwd(challenge_id, run)
    if clear:
        if not provider.clear_thread_goal:
            raise RuntimeError("provider does not support clearing goals")
        await provider.clear_thread_goal(thread_id, run_cwd)
        event = {
            "type": "run_goal",
            "provider": "codex",
            "goal": None,
            "message": "Goal cleared",
        }
    else:
        if not provider.set_thread_goal:
            raise RuntimeError("provider does not support editing goals")
        goal = await provider.set_thread_goal(thread_id, objective, run_cwd)
        event = {
            "type": "run_goal",
            "provider": "codex",
            "goal": normalize_run_goal(goal, "codex"),
            "message": "Goal updated",
        }

    await _record_run_goal_event(challenge_id, run_id, challenge, run, event)
    return public_run_summary(challenge, run)


async def update_run_goal(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    run_id = request.path_params["run_id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    run = challenge.get("runs", {}).get(run_id)
    if not run:
        return JSONResponse({"error": "run not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    objective = str_field(body.get("objective", "")).strip()
    if not objective:
        return JSONResponse({"error": "objective required"}, status_code=400)

    try:
        summary = await _mutate_run_goal(
            challenge_id,
            run_id,
            challenge,
            run,
            objective=objective,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except (asyncio.TimeoutError, RuntimeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=409)
    except Exception as exc:
        log.error("Failed to update run goal: %s", exc, exc_info=True)
        return JSONResponse({"error": str(exc)}, status_code=500)

    return JSONResponse({"run": summary})


async def clear_run_goal(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    run_id = request.path_params["run_id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    run = challenge.get("runs", {}).get(run_id)
    if not run:
        return JSONResponse({"error": "run not found"}, status_code=404)

    try:
        summary = await _mutate_run_goal(
            challenge_id,
            run_id,
            challenge,
            run,
            clear=True,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except (asyncio.TimeoutError, RuntimeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=409)
    except Exception as exc:
        log.error("Failed to clear run goal: %s", exc, exc_info=True)
        return JSONResponse({"error": str(exc)}, status_code=500)

    return JSONResponse({"run": summary})


async def update_run_skills(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    run_id = request.path_params["run_id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    if challenge.get("status") == "solved":
        return JSONResponse(
            {"error": "challenge is solved; run skills are locked"},
            status_code=409,
        )
    if run_id not in challenge.get("runs", {}):
        return JSONResponse({"error": "run not found"}, status_code=404)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err

    reset = bool(body.get("reset", False))
    apply_to_all = bool(body.get("apply_to_all", False))
    resume = body.get("resume", True) is not False
    enabled_skills = [] if reset else normalize_enabled_skills(
        body.get("enabled_skills"),
        default=[],
    )

    if apply_to_all:
        targets = [
            (rid, run)
            for rid, run in challenge.get("runs", {}).items()
            if run.get("status") != "solved"
        ]
    else:
        target_run = challenge["runs"][run_id]
        targets = (
            [(run_id, target_run)]
            if target_run.get("status") != "solved"
            else []
        )

    if not targets:
        return JSONResponse(
            {"error": "no non-solved runs to update"},
            status_code=409,
        )

    updated_runs = []
    for target_id, target_run in targets:
        old_effective_skills = run_enabled_skills(challenge, target_run)
        if resume:
            await stop_run(target_run, "skills_changed")
            finish_run_timer(target_run)

        if reset:
            target_run.pop("enabled_skills", None)
        else:
            target_run["enabled_skills"] = enabled_skills
        sync_run_skill_links(challenge, target_run)

        effective_skills = run_enabled_skills(challenge, target_run)
        codex_skill_mentions: list[str] = []
        if resume and target_run.get("agent") == "codex":
            previous = set(old_effective_skills)
            codex_skill_mentions = [
                name for name in effective_skills if name not in previous
            ]
        continue_msg = (
            _skill_resume_message(
                target_run,
                challenge_id,
                target_id,
                codex_skill_mentions=codex_skill_mentions,
            )
            if resume else None
        )
        skills_event = {
            "type": "run_skills",
            "run_id": target_id,
            "enabled_skills": effective_skills,
            "skill_override": run_has_skill_override(target_run),
            "message": (
                "Run skills reset to challenge defaults."
                if reset else "Run skills updated."
            ),
        }
        await _append_run_event(challenge_id, target_id, target_run, skills_event)

        if resume:
            await _start_run_after_skill_change(
                challenge_id,
                target_id,
                target_run,
                continue_msg,
                codex_skill_mentions=codex_skill_mentions,
            )
            status_event = {
                "type": "run_status",
                "run_id": target_id,
                "status": target_run["status"],
                "error": target_run.get("error"),
                "duration_ms": effective_run_duration_ms(target_run),
            }
            await broadcast(challenge_id, target_id, status_event)

        updated_runs.append(public_run_summary(challenge, target_run))

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    return JSONResponse({
        "status": challenge["status"],
        "runs": updated_runs,
        "enabled_skills": challenge_enabled_skills(challenge),
    })


async def plugin_submit_flag(request: Request) -> JSONResponse:
    """Submit a flag to the remote platform.

    Resolves connection config from the challenge's _connection_id,
    falling back to _source_url lookup if needed.
    """
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    challenge_id = str_field(body.get("challenge_id", ""))
    flag = str_field(body.get("flag", "")).strip()
    flag_id = body.get("flag_id")
    if not flag:
        return JSONResponse({"error": "flag required"}, status_code=400)

    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    plugin_name = challenge.get("_plugin")
    remote_id = challenge.get("_remote_id")
    if not plugin_name or not remote_id:
        return JSONResponse(
            {"error": "Challenge was not imported from a plugin"},
            status_code=400,
        )

    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Plugin {plugin_name} not found"},
            status_code=404,
        )

    config = resolve_challenge_plugin_config(challenge)

    if not config:
        return JSONResponse(
            {"error": "No saved connection found for this challenge. "
             "Re-import or sync to save credentials."},
            status_code=400,
        )

    try:
        question_num = body.get("question")
        resolved_question, resolved_flag_id, question_idx = resolve_flag_question(
            challenge,
            int(question_num) if question_num not in (None, "") else None,
            flag_id,
        )
        has_questions = bool(challenge.get("_flag_questions"))
        if has_questions and resolved_question is None and resolved_flag_id is None:
            raise ValueError(
                "question or flag_id is required for multi-answer challenges"
            )
        submit_flag = (
            flag
            if has_questions
            else normalize_flag_for_submission(
                flag, challenge_flag_formats(challenge)
            )
        )
        result = await plugin.submit_flag(
            config, remote_id, submit_flag, flag_id=resolved_flag_id,
        )

        stored_flag = set_detected_flag_status(
            challenge,
            submit_flag,
            "correct" if result.correct else "wrong",
        )

        if result.correct and resolved_question is not None:
            resolved_question["solved"] = True

        all_questions_solved = has_questions and all(
            q.get("solved") for q in challenge.get("_flag_questions", [])
        )

        record_flag_submission(
            challenge,
            stored_flag,
            submitted_flag=submit_flag,
            run_id=str_field(body.get("run_id", "")),
            flag_id=resolved_flag_id,
            question=question_idx,
            correct=result.correct,
            message=result.message,
            auto=False,
        )

        if result.correct and (not has_questions or all_questions_solved):
            _, solved_run = await apply_solved_status(
                challenge_id,
                challenge,
                flag=submit_flag,
                run_id=str_field(body.get("run_id", "")),
                stop_reason="manual_submit_solved",
            )
            solved_agent = solved_run.get("agent", "") if solved_run else ""
            await discord_notify(
                challenge,
                embed=make_solve_embed(challenge, submit_flag, solved_agent),
            )
            await discord_mark_solved(challenge, submit_flag, solved_agent)
        else:
            save_metadata(challenge)

        return JSONResponse({
            "correct": result.correct,
            "message": result.message,
            "flag": stored_flag,
            "submitted_flag": submit_flag,
            "status": challenge.get("status", ""),
            "flag_id": resolved_flag_id,
            "question": question_idx,
            "flag_questions": challenge.get("_flag_questions", []),
            "all_questions_solved": all_questions_solved,
            "meta": detected_flag_meta(challenge, stored_flag),
        })
    except Exception as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )


async def agent_submit_answer(request: Request) -> JSONResponse:
    """Local token-protected endpoint for run workspace submit_answer.py."""
    client_host = request.client.host if request.client else ""
    if client_host not in {"127.0.0.1", "::1"}:
        return JSONResponse({"error": "local submissions only"}, status_code=403)

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err

    challenge_id = str_field(body.get("challenge_id", ""))
    run_id = str_field(body.get("run_id", ""))
    token = str_field(body.get("token", ""))
    answer = str_field(body.get("answer", "")).strip()
    if not answer:
        return JSONResponse({"error": "answer required"}, status_code=400)

    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    run = challenge.get("runs", {}).get(run_id)
    if not run:
        return JSONResponse({"error": "run not found"}, status_code=404)
    expected_token = ensure_run_submit_token(run)
    if not token or not secrets.compare_digest(token, expected_token):
        return JSONResponse({"error": "invalid submission token"}, status_code=403)

    plugin_name = challenge.get("_plugin")
    remote_id = challenge.get("_remote_id")
    if not plugin_name or not remote_id:
        return JSONResponse(
            {"error": "Challenge was not imported from a plugin"},
            status_code=400,
        )
    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Plugin {plugin_name} not found"},
            status_code=404,
        )
    config = resolve_challenge_plugin_config(challenge)
    if not config:
        return JSONResponse(
            {"error": "No saved connection found for this challenge."},
            status_code=400,
        )

    try:
        question_value = body.get("question")
        question = int(question_value) if question_value not in (None, "") else None
        flag_id = body.get("flag_id")
        resolved_question, resolved_flag_id, question_idx = resolve_flag_question(
            challenge, question, flag_id,
        )
        has_questions = bool(challenge.get("_flag_questions"))
        if has_questions and resolved_question is None and resolved_flag_id is None:
            raise ValueError(
                "question or flag_id is required for multi-answer challenges"
            )
        submit_answer = (
            answer
            if has_questions
            else normalize_flag_for_submission(
                answer, challenge_flag_formats(challenge)
            )
        )
        result = await plugin.submit_flag(
            config, remote_id, submit_answer, flag_id=resolved_flag_id,
        )
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    detected_key = (
        f"{resolved_flag_id}:{submit_answer}" if resolved_flag_id else submit_answer
    )
    stored_flag = set_detected_flag_status(
        challenge,
        detected_key,
        "correct" if result.correct else "wrong",
    )
    record_flag_submission(
        challenge,
        stored_flag,
        submitted_flag=submit_answer,
        run_id=run_id,
        flag_id=resolved_flag_id,
        question=question_idx,
        correct=result.correct,
        message=result.message,
        auto=True,
    )

    if result.correct and resolved_question is not None:
        resolved_question["solved"] = True

    has_questions = bool(challenge.get("_flag_questions"))
    all_questions_solved = has_questions and all(
        q.get("solved") for q in challenge.get("_flag_questions", [])
    )

    status_word = "correct" if result.correct else "incorrect"
    target = f"question {question_idx}" if question_idx else "challenge"
    if resolved_flag_id:
        target += f" (flag_id {resolved_flag_id})"
    submit_event = {
        "type": "system",
        "message": f"Submitted answer for {target}: {status_word}. {result.message}",
        "timestamp": datetime.now().isoformat(),
    }
    await _append_run_event(challenge_id, run_id, run, submit_event)

    if result.correct and (not has_questions or all_questions_solved):
        _, solved_run = await apply_solved_status(
            challenge_id,
            challenge,
            flag=submit_answer,
            run_id=run_id,
            stop_reason="agent_submit_solved",
        )
        solved_agent = solved_run.get("agent", "") if solved_run else ""
        await discord_notify(
            challenge,
            embed=make_solve_embed(challenge, submit_answer, solved_agent),
        )
        await discord_mark_solved(challenge, submit_answer, solved_agent)
    else:
        save_metadata(challenge)

    return JSONResponse({
        "correct": result.correct,
        "message": result.message,
        "question": question_idx,
        "flag_id": resolved_flag_id,
        "flag": stored_flag,
        "submitted_flag": submit_answer,
        "all_questions_solved": all_questions_solved,
        "flag_questions": challenge.get("_flag_questions", []),
        "status": challenge.get("status", ""),
        "meta": detected_flag_meta(challenge, stored_flag),
    })


async def list_connections(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse(load_connections())


async def delete_connection(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    conn_id = str_field(body.get("id", ""))
    connections = load_connections()
    connections = [c for c in connections if c.get("id") != conn_id]
    save_connections(connections)
    return JSONResponse({"ok": True})


async def sync_connection(request: Request) -> JSONResponse:
    """Fetch new challenges from a saved connection."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    conn_id = str_field(body.get("id", ""))

    connections = load_connections()
    conn = next(
        (c for c in connections if c.get("id") == conn_id), None
    )
    if not conn:
        return JSONResponse(
            {"error": "Connection not found"}, status_code=404
        )

    plugin_name = conn.get("plugin", "")
    config = conn.get("config", {})
    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Plugin {plugin_name} not found"},
            status_code=404,
        )

    try:
        remote_challenges = await plugin.fetch_challenges(config)
    except Exception as exc:
        conn["last_error"] = str(exc)
        conn["last_error_at"] = utc_now_iso()
        save_connections(connections)
        return JSONResponse(
            {
                "error": str(exc),
                "connection": {
                    "id": conn["id"],
                    "plugin": conn["plugin"],
                    "label": conn["label"],
                },
                "last_error": conn["last_error"],
                "last_error_at": conn["last_error_at"],
            },
            status_code=400,
        )

    # Filter out already-imported challenges, while refreshing metadata for
    # existing imported entries (points/solves/questions can change).
    source_url = plugin.source_url(config)
    imported_ids = _imported_remote_ids(plugin_name, source_url)
    updated_existing = 0
    for rc in remote_challenges:
        rid = str(rc.remote_id)
        if rid not in imported_ids:
            continue
        for ch in challenges.values():
            if ch.get("_plugin") != plugin_name or ch.get("_remote_id") != rid:
                continue
            if source_url and ch.get("_source_url", "") != source_url:
                continue
            changed = False
            if rc.points and ch.get("_points") != rc.points:
                ch["_points"] = rc.points
                changed = True
            if rc.solves and ch.get("_solves") != rc.solves:
                ch["_solves"] = rc.solves
                changed = True
            if rc.flag_questions and ch.get("_flag_questions") != rc.flag_questions:
                ch["_flag_questions"] = rc.flag_questions
                changed = True
            if changed:
                save_metadata(ch)
                updated_existing += 1
            break

    unimported_challenges = [
        c for c in remote_challenges
        if str(c.remote_id) not in imported_ids
    ]
    new_challenges = [
        c for c in unimported_challenges
        if not c.solved
    ]
    skipped_solved = sum(
        1 for c in unimported_challenges
        if c.solved
    )

    # Update last_sync
    conn["last_sync"] = utc_now_iso()
    conn.pop("last_error", None)
    conn.pop("last_error_at", None)
    save_connections(connections)

    return JSONResponse({
        "connection": {
            "id": conn["id"],
            "plugin": conn["plugin"],
            "label": conn["label"],
        },
        "total": len(remote_challenges),
        "new": len(new_challenges),
        "skipped_solved": skipped_solved,
        "updated": updated_existing,
        "last_sync": conn["last_sync"],
        "challenges": [
            {
                "remote_id": c.remote_id,
                "name": c.name,
                "description": c.description,
                "category": c.category,
                "points": c.points,
                "solves": c.solves,
                "files": [
                    {"name": f.name, "url": f.url}
                    for f in c.files
                ],
                "solved": c.solved,
                "tags": c.tags,
                "flag_questions": c.flag_questions,
            }
            for c in unimported_challenges
        ],
    })


async def poll_connections(request: Request) -> JSONResponse:
    """Background poll: check all connections for new challenges and updated scores."""
    if err := require_auth(request):
        return err

    connections = load_connections()
    if not connections:
        return JSONResponse({"new_total": 0, "updates": []})

    new_total = 0
    updates = []
    errors = []
    last_sync = ""
    connections_changed = False

    for conn in connections:
        plugin_name = conn.get("plugin", "")
        config = conn.get("config", {})
        plugin = get_plugin(plugin_name)
        if not plugin:
            continue
        try:
            remote_challenges = await plugin.fetch_challenges(config)
        except Exception as exc:
            conn["last_error"] = str(exc)
            conn["last_error_at"] = utc_now_iso()
            connections_changed = True
            errors.append({
                "id": conn.get("id", ""),
                "label": conn.get("label", ""),
                "error": conn["last_error"],
                "at": conn["last_error_at"],
            })
            continue

        imported_ids = _imported_remote_ids(
            plugin_name, plugin.source_url(config)
        )
        new_count = sum(
            1 for c in remote_challenges
            if str(c.remote_id) not in imported_ids and not c.solved
        )
        new_total += new_count
        conn["last_sync"] = utc_now_iso()
        conn.pop("last_error", None)
        conn.pop("last_error_at", None)
        last_sync = conn["last_sync"]
        connections_changed = True

        for rc in remote_challenges:
            rid = str(rc.remote_id)
            if rid not in imported_ids:
                continue
            for ch in challenges.values():
                if ch.get("_plugin") == plugin_name and ch.get("_remote_id") == rid:
                    changed = False
                    if rc.points and ch.get("_points") != rc.points:
                        ch["_points"] = rc.points
                        changed = True
                    if rc.solves and ch.get("_solves") != rc.solves:
                        ch["_solves"] = rc.solves
                        changed = True
                    if rc.flag_questions and ch.get("_flag_questions") != rc.flag_questions:
                        ch["_flag_questions"] = rc.flag_questions
                        changed = True
                    if changed:
                        save_metadata(ch)
                        updates.append({
                            "id": ch["id"],
                            "name": ch["name"],
                            "points": rc.points,
                            "solves": rc.solves,
                        })
                    break

    if connections_changed:
        save_connections(connections)

    return JSONResponse({
        "new_total": new_total,
        "updates": updates,
        "last_sync": last_sync,
        "errors": errors,
    })


# ---------------------------------------------------------------------------
# VPN (WireGuard)
# ---------------------------------------------------------------------------

WG_DIR = Path("/etc/wireguard")
WG_CONF = WG_DIR / "wg0.conf"
WG_SERVER_PRIVATE_KEY = WG_DIR / "server_private.key"
WG_SERVER_PUBLIC_KEY = WG_DIR / "server_public.key"
WG_SETTINGS = WG_DIR / "wg0.settings.json"
WG_DNSMASQ_CONF = Path("/etc/dnsmasq.d/wg-ctf.conf")
VPN_SUBNET = "10.13.37"
VPN_CIDR = f"{VPN_SUBNET}.0/24"
VPN_CLIENT_IP = f"{VPN_SUBNET}.2"
VPN_SERVER_IP = f"{VPN_SUBNET}.1"


def _wg_installed() -> bool:
    return WG_SERVER_PRIVATE_KEY.exists() and WG_SERVER_PUBLIC_KEY.exists()


def _wg_interface_up() -> bool:
    try:
        result = subprocess.run(
            ["wg", "show", "wg0"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _wg_peer_info() -> dict | None:
    if not _wg_interface_up():
        return None
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return None
        parts = lines[1].split("\t")
        return {
            "public_key": parts[0] if len(parts) > 0 else "",
            "endpoint": parts[2] if len(parts) > 2 else "",
            "latest_handshake": parts[4] if len(parts) > 4 else "0",
            "transfer_rx": parts[5] if len(parts) > 5 else "0",
            "transfer_tx": parts[6] if len(parts) > 6 else "0",
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _validate_wg_public_key(public_key: str) -> bool:
    try:
        return len(base64.b64decode(public_key, validate=True)) == 32
    except Exception:
        return False


def _generate_wg_client_keypair() -> tuple[str, str]:
    private_result = subprocess.run(
        ["wg", "genkey"],
        capture_output=True, text=True, timeout=5,
    )
    if private_result.returncode != 0:
        raise RuntimeError(private_result.stderr.strip() or "wg genkey failed")

    private_key = private_result.stdout.strip()
    public_result = subprocess.run(
        ["wg", "pubkey"],
        input=f"{private_key}\n",
        capture_output=True, text=True, timeout=5,
    )
    if public_result.returncode != 0:
        raise RuntimeError(public_result.stderr.strip() or "wg pubkey failed")

    public_key = public_result.stdout.strip()
    if not _validate_wg_public_key(private_key):
        raise RuntimeError("generated invalid WireGuard private key")
    if not _validate_wg_public_key(public_key):
        raise RuntimeError("generated invalid WireGuard public key")
    return private_key, public_key


def _parse_vpn_networks(raw_networks: str) -> tuple[list[str], str | None]:
    """Parse client-side CIDRs the server should reverse-route through wg0."""
    raw_networks = raw_networks.strip()
    if not raw_networks:
        return [], None

    networks: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[\s,]+", raw_networks):
        token = token.strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return [], f"Invalid internal network CIDR: {token}"
        if network.version != 4:
            return [], f"IPv6 internal networks are not supported yet: {token}"
        if network.prefixlen == 0:
            return [], "0.0.0.0/0 is too broad for reverse VPN routing"
        normalized = str(network)
        if normalized not in seen:
            seen.add(normalized)
            networks.append(normalized)
    return networks, None


def _get_server_public_ip() -> str:
    """Best-effort detection of the server's public IP."""
    for cmd in (
        ["curl", "-s", "-4", "--max-time", "3", "ifconfig.me"],
        ["hostname", "-I"],
    ):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                ip = result.stdout.strip().split()[0]
                if ip and not ip.startswith("10.") and not ip.startswith("192.168."):
                    return ip
        except (FileNotFoundError, subprocess.TimeoutExpired, IndexError):
            continue
    return "YOUR_SERVER_IP"


def _swarm_vpn_peers() -> list[dict]:
    """Worker peers (pubkey + vpn_ip) enrolled on the VPN, from the swarm registry."""
    try:
        reg = _swarm_module().load_registry()
    except Exception:  # noqa: BLE001 - swarm optional
        return []
    peers = []
    for inst in reg.get("instances", {}).values():
        if inst.get("vpn_pubkey") and inst.get("vpn_ip"):
            peers.append({"pubkey": inst["vpn_pubkey"], "vpn_ip": inst["vpn_ip"]})
    return peers


def _build_wg_server_conf(
    client_public_key: str,
    client_networks: list[str],
    dns_forward: bool,
) -> str:
    server_private_key = WG_SERVER_PRIVATE_KEY.read_text().strip()
    allowed_ips = ", ".join([f"{VPN_CLIENT_IP}/32", *client_networks])
    egress_iface_cmd = "$(ip -4 route list default | awk '{print $5; exit}')"

    conf = f"""[Interface]
# dns_forward={"true" if dns_forward else "false"}
Address = {VPN_SERVER_IP}/24
ListenPort = 51820
PrivateKey = {server_private_key}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s {VPN_CIDR} -o {egress_iface_cmd} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s {VPN_CIDR} -o {egress_iface_cmd} -j MASQUERADE

[Peer]
PublicKey = {client_public_key}
AllowedIPs = {allowed_ips}
"""
    # Persist swarm worker peers so they survive wg-quick down/up (Fix B).
    for peer in _swarm_vpn_peers():
        conf += (
            f"\n[Peer]\n# swarm worker\n"
            f"PublicKey = {peer['pubkey']}\n"
            f"AllowedIPs = {peer['vpn_ip']}/32\n"
        )
    return conf


def _wg_parse_client_peer() -> tuple[str, list[str], bool] | None:
    """Extract the dial-in client's (pubkey, networks, dns_forward) from wg0.conf.

    The first [Peer] is the client; worker peers follow. Used to rebuild the
    config when swarm peers change without losing the client's settings.
    """
    if not WG_CONF.exists():
        return None
    pubkey, networks, dns_forward = "", [], True
    seen_peer = False
    in_client = False
    for line in WG_CONF.read_text().splitlines():
        s = line.strip()
        if s.startswith("# dns_forward="):
            dns_forward = s.split("=", 1)[1].strip().lower() == "true"
        elif s.startswith("[Peer]"):
            if seen_peer:
                break  # only the first peer is the client
            seen_peer = True
            in_client = True
        elif in_client and s.startswith("PublicKey"):
            pubkey = s.split("=", 1)[1].strip()
        elif in_client and s.startswith("AllowedIPs"):
            for v in s.split("=", 1)[1].split(","):
                v = v.strip()
                if v and v != f"{VPN_CLIENT_IP}/32":
                    networks.append(v)
    if not pubkey:
        return None
    return pubkey, networks, dns_forward


def _wg_persist_and_sync() -> None:
    """Rebuild wg0.conf (client + current swarm worker peers) and apply it live.

    Uses `wg syncconf` so the interface is not bounced — the dial-in client's
    handshake and existing worker peers survive while peers are added/removed.
    No-op if no client is configured.
    """
    parsed = _wg_parse_client_peer()
    if not parsed:
        return
    pubkey, networks, dns_forward = parsed
    WG_CONF.write_text(_build_wg_server_conf(pubkey, networks, dns_forward))
    os.chmod(str(WG_CONF), 0o600)
    if not _wg_interface_up():
        return
    try:
        stripped = subprocess.run(
            ["wg-quick", "strip", "wg0"], capture_output=True, text=True, timeout=10)
        if stripped.returncode != 0:
            return
        with tempfile.NamedTemporaryFile(
            "w", suffix=".conf", delete=False) as tf:
            tf.write(stripped.stdout)
            tmp = tf.name
        os.chmod(tmp, 0o600)
        subprocess.run(["wg", "syncconf", "wg0", tmp], capture_output=True, timeout=10)
        os.unlink(tmp)
    except (OSError, subprocess.SubprocessError):
        pass


def _build_wg_client_conf(
    client_private_key: str,
    client_networks: list[str],
    dns_forward: bool,
) -> str:
    server_public_key = WG_SERVER_PUBLIC_KEY.read_text().strip()
    server_ip = _get_server_public_ip()

    dns_line = f"DNS = {VPN_SERVER_IP}" if dns_forward else ""
    routed_networks = ""
    if client_networks:
        routed_networks = (
            "# Reverse-routed networks behind this client: "
            f"{', '.join(client_networks)}\n"
            "# Keep those CIDRs out of this peer's AllowedIPs; they must stay "
            "locally reachable from the client.\n"
        )
    client_setup = _build_wg_client_setup(client_networks)

    conf = f"""[Interface]
Address = {VPN_CLIENT_IP}/24
PrivateKey = {client_private_key}
{dns_line}
{client_setup}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_ip}:51820
{routed_networks}AllowedIPs = {VPN_CIDR}
PersistentKeepalive = 25
"""
    return conf


def _build_wg_client_setup(client_networks: list[str]) -> str:
    if not client_networks:
        return ""

    nat_up = "; ".join(
        f"iptables -t nat -A POSTROUTING -s {VPN_CIDR} -d {network} -j MASQUERADE"
        for network in client_networks
    )
    nat_down = "; ".join(
        f"iptables -t nat -D POSTROUTING -s {VPN_CIDR} -d {network} -j MASQUERADE"
        for network in client_networks
    )
    return (
        "# Linux clients only: reverse routing uses wg-quick, "
        "sysctl, and iptables.\n"
        "# These lines let this client route the internal CIDR(s).\n"
        "# They enable forwarding and NAT replies from the internal network "
        "back through the tunnel.\n"
        "PostUp = sysctl -w net.ipv4.ip_forward=1; "
        "iptables -A FORWARD -i %i -j ACCEPT; "
        "iptables -A FORWARD -o %i -j ACCEPT; "
        f"{nat_up}\n"
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT; "
        "iptables -D FORWARD -o %i -j ACCEPT; "
        f"{nat_down}\n"
    )


def _setup_dns_forwarder() -> None:
    """Configure dnsmasq to answer DNS queries on the WireGuard interface."""
    try:
        subprocess.run(
            ["apt-get", "install", "-y", "-qq", "dnsmasq"],
            capture_output=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return

    WG_DNSMASQ_CONF.write_text(
        f"interface=wg0\n"
        f"bind-interfaces\n"
        f"listen-address={VPN_SERVER_IP}\n"
        f"no-resolv\n"
        f"server=8.8.8.8\n"
        f"server=1.1.1.1\n"
    )
    subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)


def _teardown_dns_forwarder() -> None:
    if WG_DNSMASQ_CONF.exists():
        WG_DNSMASQ_CONF.unlink()
    subprocess.run(
        ["systemctl", "stop", "dnsmasq"], capture_output=True
    )


def _persist_wg_settings(dns_forward: bool) -> None:
    WG_SETTINGS.write_text(json.dumps({"dns_forward": dns_forward}))
    os.chmod(str(WG_SETTINGS), 0o600)


def _dns_forward_enabled() -> bool:
    if WG_SETTINGS.exists():
        try:
            settings = json.loads(WG_SETTINGS.read_text())
        except json.JSONDecodeError:
            settings = {}
        if "dns_forward" in settings:
            return bool(settings["dns_forward"])

    if WG_CONF.exists():
        for line in WG_CONF.read_text().splitlines():
            if line.startswith("# dns_forward="):
                return line.split("=", 1)[1].strip().lower() == "true"

    return WG_DNSMASQ_CONF.exists()


async def vpn_status(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    if not _wg_installed():
        return JSONResponse({
            "installed": False,
            "up": False,
            "peer": None,
            "server_public_key": None,
        })

    up = _wg_interface_up()
    peer = _wg_peer_info()
    return JSONResponse({
        "installed": True,
        "up": up,
        "peer": peer,
        "server_public_key": WG_SERVER_PUBLIC_KEY.read_text().strip(),
    })


async def vpn_configure(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    if not _wg_installed():
        return JSONResponse(
            {"error": "WireGuard not installed"}, status_code=400
        )

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    client_public_key = str_field(body.get("client_public_key", "")).strip()
    client_networks = str_field(body.get("client_networks", "")).strip()
    dns_forward = bool(body.get("dns_forward", True))
    client_private_key = ""

    if client_public_key:
        if not _validate_wg_public_key(client_public_key):
            return JSONResponse(
                {"error": "Invalid WireGuard public key format"},
                status_code=400,
            )
        client_private_key = "<YOUR_PRIVATE_KEY>"
    else:
        try:
            client_private_key, client_public_key = _generate_wg_client_keypair()
        except (FileNotFoundError, subprocess.TimeoutExpired, RuntimeError) as exc:
            return JSONResponse(
                {"error": f"Failed to generate client keypair: {exc}"},
                status_code=500,
            )

    if not client_public_key:
        return JSONResponse(
            {"error": "client_public_key required"}, status_code=400
        )

    client_networks, network_error = _parse_vpn_networks(client_networks)
    if network_error:
        return JSONResponse({"error": network_error}, status_code=400)

    # Bring down existing interface if up
    if _wg_interface_up():
        subprocess.run(["wg-quick", "down", "wg0"], capture_output=True)

    # Write server config
    server_conf = _build_wg_server_conf(
        client_public_key, client_networks, dns_forward
    )
    WG_CONF.write_text(server_conf)
    os.chmod(str(WG_CONF), 0o600)
    _persist_wg_settings(dns_forward)

    # Build client config
    client_conf = _build_wg_client_conf(
        client_private_key, client_networks, dns_forward
    )

    # Bring up interface
    result = subprocess.run(
        ["wg-quick", "up", "wg0"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return JSONResponse(
            {"error": f"Failed to start WireGuard: {result.stderr}"},
            status_code=500,
        )

    if dns_forward:
        _setup_dns_forwarder()
    else:
        _teardown_dns_forwarder()

    return JSONResponse({
        "ok": True,
        "client_config": client_conf,
        "client_setup": "",
        "client_networks": client_networks,
        "server_public_key": WG_SERVER_PUBLIC_KEY.read_text().strip(),
    })


async def vpn_toggle(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    if not _wg_installed():
        return JSONResponse(
            {"error": "WireGuard not installed"}, status_code=400
        )

    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    action = str_field(body.get("action", "")).strip()

    if action == "up":
        if not WG_CONF.exists():
            return JSONResponse(
                {"error": "VPN not configured yet"}, status_code=400
            )
        if not _wg_interface_up():
            result = subprocess.run(
                ["wg-quick", "up", "wg0"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                return JSONResponse(
                    {"error": f"Failed: {result.stderr}"},
                    status_code=500,
                )
        if _dns_forward_enabled():
            _setup_dns_forwarder()
        else:
            _teardown_dns_forwarder()
    elif action == "down":
        _persist_wg_settings(_dns_forward_enabled())
        if _wg_interface_up():
            subprocess.run(
                ["wg-quick", "down", "wg0"], capture_output=True
            )
        _teardown_dns_forwarder()
    else:
        return JSONResponse(
            {"error": "action must be 'up' or 'down'"},
            status_code=400,
        )

    return JSONResponse({"ok": True, "up": _wg_interface_up()})


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------

from contextlib import asynccontextmanager


def _discord_destination_to_challenge_id(destination_id: str) -> str | None:
    destination_id = str(destination_id or "")
    for ch_id, ch in challenges.items():
        if str(ch.get("_discord_thread_id", "")) == destination_id:
            return ch_id
        if str(ch.get("_discord_channel_id", "")) == destination_id:
            return ch_id
    return None


def _normalize_discord_destination_name(name: str) -> str:
    normalized = " ".join(str(name or "").strip().split())
    normalized = re.sub(r"^\[solved\]\s*", "", normalized, flags=re.IGNORECASE)
    return normalized.casefold()


def _challenge_destination_name_keys(challenge: dict) -> set[str]:
    thread_base = make_thread_name(challenge)
    name = challenge.get("name", "Unknown")
    category = challenge.get("category", "")
    channel_base = make_challenge_channel_name(challenge)
    variants = {
        thread_base,
        thread_base[:100],
        channel_base,
        make_challenge_channel_name(challenge, solved=True),
    }
    if category:
        solved = f"[solved][{category}] {name}"
    else:
        solved = f"[solved] {name}"
    variants.update({solved, solved[:100]})
    return {
        key for key in (_normalize_discord_destination_name(v) for v in variants)
        if key
    }


def _discord_interaction_channel_ids(interaction: dict) -> list[str]:
    ids = []
    for value in (
        interaction.get("channel_id"),
        (interaction.get("channel") or {}).get("id"),
    ):
        if value:
            ids.append(str(value))
    return list(dict.fromkeys(ids))


def _challenge_id_from_discord_interaction(interaction: dict) -> str | None:
    for channel_id in _discord_interaction_channel_ids(interaction):
        ch_id = _discord_destination_to_challenge_id(channel_id)
        if ch_id:
            return ch_id

    channel = interaction.get("channel") or {}
    destination_name = channel.get("name", "")
    name_key = _normalize_discord_destination_name(destination_name)
    if not name_key:
        return None

    for ch_id, challenge in challenges.items():
        if name_key not in _challenge_destination_name_keys(challenge):
            continue
        channel_id = str(channel.get("id") or interaction.get("channel_id") or "")
        if not channel_id:
            return ch_id
        channel_type = channel.get("type")
        if channel_type in (10, 11, 12):
            id_field = "_discord_thread_id"
            layout = "threads"
        else:
            id_field = "_discord_channel_id"
            layout = "channels"
            if channel.get("parent_id"):
                challenge["_discord_category_id"] = str(channel["parent_id"])
        if str(challenge.get(id_field, "")) != channel_id:
            challenge[id_field] = channel_id
            challenge["_discord_challenge_layout"] = layout
            save_metadata(challenge)
            log.info(
                "Recovered Discord destination mapping by name: %s -> %s",
                destination_name,
                channel_id,
            )
        return ch_id
    return None


def _discord_challenges_for_category(category: str) -> list[dict]:
    target = str(category or "").strip().casefold()
    if not target:
        return []
    result = []
    for challenge in challenges.values():
        if not challenge.get("_discord_thread_id"):
            continue
        if target == "all" or str(challenge.get("category", "")).strip().casefold() == target:
            result.append(challenge)
    result.sort(key=lambda ch: (str(ch.get("category", "")), str(ch.get("name", ""))))
    return result


def _discord_category_choices() -> str:
    categories = sorted({
        str(ch.get("category", "")).strip()
        for ch in challenges.values()
        if ch.get("_discord_thread_id") and str(ch.get("category", "")).strip()
    })
    if not categories:
        return "No joinable Discord thread categories are available."
    preview = ", ".join(categories[:20])
    if len(categories) > 20:
        preview += f", and {len(categories) - 20} more"
    return f"Joinable thread categories: {preview}"


def _discord_option_map(raw_options: list[dict]) -> tuple[str, dict]:
    if raw_options and raw_options[0].get("type") == 1:
        subcommand = str(raw_options[0].get("name", ""))
        nested = raw_options[0].get("options", [])
        return subcommand, {
            o["name"]: o.get("value")
            for o in nested
            if "name" in o
        }
    return "", {
        o["name"]: o.get("value")
        for o in raw_options
        if "name" in o
    }


def _discord_search_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold()).strip()


def _discord_challenge_label(challenge: dict) -> str:
    category = str(challenge.get("category", "") or "Uncategorized")
    return f"[{category}] {challenge.get('name', '?')}"


def _discord_join_candidates(query: str) -> list[tuple[float, str, dict]]:
    query_key = _discord_search_key(query)
    if not query_key:
        return []

    candidates = []
    for ch_id, challenge in challenges.items():
        if not challenge.get("_discord_thread_id"):
            continue
        fields = [
            challenge.get("name", ""),
            challenge.get("category", ""),
            _discord_challenge_label(challenge),
            challenge.get("_remote_id", ""),
        ]
        keys = [_discord_search_key(field) for field in fields if field]
        if not keys:
            continue
        score = max(
            1.0 if key == query_key
            else 0.92 if query_key in key
            else difflib.SequenceMatcher(None, query_key, key).ratio()
            for key in keys
        )
        candidates.append((score, ch_id, challenge))
    candidates.sort(key=lambda item: (-item[0], _discord_challenge_label(item[2])))
    return candidates


def _format_discord_tokens(value: int | float) -> str:
    value = int(value or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(value)


def _format_discord_duration(ms: int | float) -> str:
    seconds = int((ms or 0) / 1000)
    if seconds <= 0:
        return "-"
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _discord_status_message(challenge: dict) -> str:
    lines = [f"**{challenge.get('name', '?')}** — {challenge.get('status', '?')}"]
    for run in challenge["runs"].values():
        agent = run.get("agent", "?")
        model = run.get("model", "")
        status = run.get("status", "?")
        emoji = {
            "solving": "\u25b6",
            "solved": "\u2705",
            "failed": "\u274c",
            "completed": "\u2714",
            "pending": "\u23f8",
        }.get(status, "\u2753")
        line = f"{emoji} `{agent}` ({model}) — {status}"
        if run.get("error"):
            line += f": {run['error']}"
        lines.append(line)
    return _truncate("\n".join(lines))


def _discord_flags_message(challenge: dict) -> str:
    detected = challenge.get("detected_flags", {})
    if not detected:
        return "No flags detected yet"
    lines = []
    for flag, status in detected.items():
        emoji = {
            "correct": "\u2705",
            "wrong": "\u274c",
            "pending": "\u23f3",
        }.get(status, "\u2753")
        lines.append(f"{emoji} `{flag}` — {status}")
    return _truncate("\n".join(lines))


def _discord_stats_message(challenge_id: str, challenge: dict) -> str:
    lines = [
        f"**Stats: {challenge.get('name', '?')}**",
        f"Status: `{challenge.get('status', '?')}`",
    ]
    detected = challenge.get("detected_flags", {})
    if detected:
        correct = sum(1 for status in detected.values() if status == "correct")
        lines.append(f"Flags: {correct} correct / {len(detected)} detected")

    total = _empty_stats()
    for run_id, run in challenge.get("runs", {}).items():
        events = iter_output_log_events(challenge_id, run_id)
        stats = _aggregate_run_stats(run, events)
        for key in ("inputTokens", "outputTokens", "cacheReadTokens",
                    "cacheCreationTokens", "toolCalls", "turns",
                    "durationMs", "durationApiMs"):
            total[key] += stats.get(key, 0)
        total["costUsd"] += stats.get("costUsd", 0)

        token_bits = [
            f"in {_format_discord_tokens(stats.get('inputTokens', 0))}",
            f"out {_format_discord_tokens(stats.get('outputTokens', 0))}",
        ]
        if stats.get("cacheReadTokens"):
            token_bits.append(f"cache {_format_discord_tokens(stats['cacheReadTokens'])}")
        if stats.get("cacheCreationTokens"):
            token_bits.append(f"write {_format_discord_tokens(stats['cacheCreationTokens'])}")
        cost = f", ${stats['costUsd']:.4f}" if stats.get("costUsd") else ""
        turns = f", {int(stats['turns'])} turns" if stats.get("turns") else ""
        tools = f", {int(stats['toolCalls'])} tools" if stats.get("toolCalls") else ""
        lines.append(
            f"- `{run.get('agent', '?')}` `{run.get('status', '?')}` "
            f"{_format_discord_duration(stats.get('durationMs', 0))}: "
            f"{', '.join(token_bits)}{turns}{tools}{cost}"
        )

    if len(challenge.get("runs", {})) > 1:
        lines.append(
            "Total: "
            f"in {_format_discord_tokens(total['inputTokens'])}, "
            f"out {_format_discord_tokens(total['outputTokens'])}, "
            f"runtime {_format_discord_duration(total['durationMs'])}"
        )
    return _truncate("\n".join(lines))


def _discord_event_summary(event: dict) -> str:
    etype = event.get("type", "")
    if etype == "assistant":
        blocks = event.get("message", {}).get("content", [])
        parts = []
        for block in blocks:
            btype = block.get("type")
            if btype == "text" and block.get("text"):
                parts.append(block["text"])
            elif btype == "tool_use":
                name = block.get("name", "tool")
                parts.append(f"[tool] {name}")
            elif btype == "thinking":
                text = block.get("thinking") or ""
                parts.append(f"[thinking] {text}")
        return "Assistant: " + " | ".join(parts)
    if etype == "user":
        blocks = event.get("message", {}).get("content", [])
        parts = []
        for block in blocks:
            if block.get("type") != "tool_result":
                continue
            content = block.get("content", "")
            tool_id = block.get("tool_use_id", "tool")
            parts.append(f"[result {tool_id}] {content}")
        return "Tool result: " + " | ".join(parts)
    if etype in {"user_prompt", "user_steer"}:
        label = "Prompt" if etype == "user_prompt" else "Steer"
        return f"{label}: {event.get('message', '')}"
    if etype == "result":
        return f"Result: {event.get('result', '')}"
    if etype == "error":
        return f"Error: {event.get('message', '')}"
    if etype == "system":
        return f"System: {event.get('message', '')}"
    if etype == "codex_usage":
        usage = event.get("usage") or {}
        return (
            "Usage: "
            f"in {_format_discord_tokens(usage.get('input_tokens', 0))}, "
            f"out {_format_discord_tokens(usage.get('output_tokens', 0))}"
        )
    text = _event_search_text(event)
    return f"{etype or 'event'}: {text}"


def _discord_tail_message(
    challenge_id: str,
    challenge: dict,
    agent_filter: str = "",
    lines: int = 10,
) -> str:
    lines = max(1, min(int(lines or 10), 25))
    agent_key = str(agent_filter or "").strip().casefold()
    selected = []
    for run_id, run in challenge.get("runs", {}).items():
        searchable = " ".join([
            run_id,
            str(run.get("agent", "")),
            str(run.get("model", "")),
        ]).casefold()
        if agent_key and agent_key not in searchable:
            continue
        selected.append((run_id, run))
    if not selected:
        return f"No runs matched `{agent_filter}`."

    per_run = lines if len(selected) == 1 else max(1, min(5, lines))
    out = [f"**Tail: {challenge.get('name', '?')}**"]
    for run_id, run in selected:
        tail = [
            (idx + 1, event)
            for idx, event in tail_output_log_events(
                challenge_id,
                run_id,
                per_run,
                skip_types={"run_status", "challenge_status", "flag_found"},
            )
        ]
        out.append(f"**{run.get('agent', '?')}** `{run_id}`")
        if not tail:
            out.append("- No transcript events")
            continue
        for idx, event in tail:
            summary = " ".join(_discord_event_summary(event).split())
            out.append(f"{idx}. {_truncate(summary, 240)}")
    return _truncate("\n".join(out))


def _discord_select_run(
    challenge: dict,
    selector: str,
) -> tuple[str | None, dict | None, str]:
    selector_key = str(selector or "").strip().casefold()
    if not selector_key:
        return None, None, "Agent or run id required."

    scored = []
    for run_id, run in challenge.get("runs", {}).items():
        fields = {
            "run_id": run_id,
            "agent": str(run.get("agent", "")),
            "model": str(run.get("model", "")),
            "notes": str(run.get("notes_label", "")),
        }
        exact = [
            key for key, value in fields.items()
            if value.casefold() == selector_key
        ]
        prefix = [
            key for key, value in fields.items()
            if value.casefold().startswith(selector_key)
        ]
        contains = [
            key for key, value in fields.items()
            if selector_key in value.casefold()
        ]
        if exact:
            score = 3
        elif prefix:
            score = 2
        elif contains:
            score = 1
        else:
            continue
        running_bonus = 0.1 if run.get("status") == "solving" else 0
        scored.append((score + running_bonus, run_id, run))

    if not scored:
        return None, None, f"No run matched `{selector}`."

    scored.sort(key=lambda item: (-item[0], item[1]))
    top_score = int(scored[0][0])
    tied = [item for item in scored if int(item[0]) == top_score]
    if len(tied) > 1:
        choices = "\n".join(
            f"- `{run_id}` `{run.get('agent', '?')}` "
            f"({run.get('model', '')}) — {run.get('status', '?')}"
            for _, run_id, run in tied[:8]
        )
        return (
            None,
            None,
            f"`{selector}` matched multiple runs. Use a run id:\n{choices}",
        )

    _, run_id, run = scored[0]
    return run_id, run, ""


def _discord_actor(interaction: dict) -> tuple[str, str]:
    """Return (display_name, user_id) for the Discord user who issued an interaction."""
    member_user = interaction.get("member", {}).get("user", {}) or {}
    top_user = interaction.get("user", {}) or {}
    author_user = member_user or top_user
    name = author_user.get("username") or "Discord"
    return name, str(author_user.get("id", ""))


async def _discord_stop_runs(
    challenge_id: str, challenge: dict, actor: str = ""
) -> str:
    stopped_ids = []
    for run_id, run in challenge["runs"].items():
        if run["status"] != "solving":
            continue
        run["status"] = "failed"
        run["error"] = None
        stop_event = {
            "type": "system",
            "message": (
                f"Agent stopped from Discord by {actor}."
                if actor
                else "Agent stopped from Discord."
            ),
        }
        await _append_run_event(challenge_id, run_id, run, stop_event)
        await stop_run(run, "discord_stop")
        finish_run_timer(run)
        stopped_ids.append(run_id)

    if not stopped_ids:
        return "No agents are currently running"

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    for run_id in stopped_ids:
        run = challenge["runs"][run_id]
        await broadcast(challenge_id, run_id, {
            "type": "run_status",
            "run_id": run_id,
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": effective_run_duration_ms(run),
        })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    n = len(stopped_ids)
    return f"{actor} stopped {n} agent(s)" if actor else f"Stopped {n} agent(s)"


async def _discord_resume_runs(
    challenge_id: str,
    challenge: dict,
    continue_msg: str = "Continue solving the challenge.",
    actor: str = "",
) -> str:
    resumed = []
    for run_id, run in challenge["runs"].items():
        if run["status"] not in ("failed", "completed"):
            continue
        run["status"] = "solving"
        run.pop("_stop_reason", None)
        run["task"] = asyncio.create_task(
            run_agent_task(challenge_id, run_id, continue_msg=continue_msg)
        )
        resumed.append(run_id)

    if not resumed:
        return "No agents to resume"

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    for run_id in resumed:
        run = challenge["runs"][run_id]
        await broadcast(challenge_id, run_id, {
            "type": "run_status",
            "run_id": run_id,
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": effective_run_duration_ms(run),
        })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    n = len(resumed)
    return f"{actor} resumed {n} agent(s)" if actor else f"Resumed {n} agent(s)"


def _discord_help_message() -> str:
    return _truncate(
        "**CTF Solver Bot Help**\n\n"
        "**Works anywhere**\n"
        "`/ctf` — show all challenges grouped by category.\n"
        "`/add category:<name>` — add yourself to every challenge thread in a category.\n"
        "`/add category:all` — add yourself to all challenge threads.\n"
        "`/join challenge:<name>` — add yourself to one challenge thread by fuzzy name.\n"
        "`/help` — show this help message.\n\n"
        "**Use inside a challenge thread or channel**\n"
        "`/status` — show challenge and agent run status.\n"
        "`/stats` — show runtime, token, tool, and flag stats.\n"
        "`/tail agent:<name> lines:<n>` — show recent transcript events.\n"
        "`/flags` — list detected flags and submission state.\n"
        "`/flags add:<flag>` — manually add a detected flag candidate.\n"
        "`/broadcast message:<text>` — inject a message into all active agents.\n"
        "`/steer agent:<name|run_id> message:<text>` — stop one agent now and resume it with a message.\n"
        "`/submit flag:<flag>` — submit a flag to the connected CTF platform.\n"
        "`/solved flag:<flag>` — manually mark the challenge solved; flag is optional.\n"
        "`/stop` — stop currently running agents for this challenge.\n"
        "`/resume` — resume failed or completed agents.\n"
        "`/files` — list files in agent work directories.\n"
        "`/files path:<path>` — print a small file from an agent work directory.\n"
        "`/files path:<path> agent:<claude|codex>` — fetch from a specific agent run.\n\n"
        f"{_discord_category_choices()}"
    )


def _discord_parse_component_id(custom_id: str) -> tuple[str, str, str]:
    parts = str(custom_id or "").split(":")
    if len(parts) < 3 or parts[0] != DISCORD_COMPONENT_PREFIX:
        return "", "", ""
    challenge_id, action = parts[1], parts[2]
    token = parts[3] if len(parts) > 3 else ""
    if action in DISCORD_FLAG_REVIEW_ACTIONS:
        return (challenge_id, action, token) if token else ("", "", "")
    if action not in DISCORD_BUTTON_ACTIONS and action not in {
        "submit_modal",
        "solved_modal",
    }:
        return "", "", ""
    return challenge_id, action, token


def _discord_detected_flag_from_token(challenge: dict, token: str) -> str:
    for flag in challenge.get("detected_flags", {}):
        if _discord_flag_token(flag) == token:
            return flag
    return ""


def _discord_modal_value(interaction: dict, field_id: str) -> str:
    for row in (interaction.get("data") or {}).get("components", []):
        for component in row.get("components", []):
            if component.get("custom_id") == field_id:
                return str(component.get("value", ""))
    return ""


async def _discord_submit_flag_from_interaction(
    bot: DiscordBot,
    interaction_token: str,
    challenge_id: str,
    challenge: dict,
    flag: str,
    author: str,
) -> None:
    if not flag:
        await bot.followup_interaction(interaction_token, "Flag required.")
        return
    plugin, config = _resolve_plugin_config(challenge)
    if not plugin or not config:
        await bot.followup_interaction(
            interaction_token,
            "No platform connection for this challenge",
        )
        return
    remote_id = challenge.get("_remote_id", "")
    try:
        submit_flag = normalize_flag_for_submission(
            flag,
            challenge_flag_formats(challenge),
        )
        result = await plugin.submit_flag(config, remote_id, submit_flag)
        if result.correct:
            stored_flag = set_detected_flag_status(challenge, submit_flag, "correct")
            record_flag_submission(
                challenge,
                stored_flag,
                submitted_flag=submit_flag,
                correct=True,
                message=result.message,
                auto=False,
            )
            await apply_solved_status(
                challenge_id,
                challenge,
                flag=submit_flag,
                stop_reason="discord_submit_solved",
            )
            await _broadcast_detected_flag_state(
                challenge_id,
                challenge,
                stored_flag,
                correct=True,
                message=result.message,
            )
            solved_by = f"{author} (Discord)"
            await bot.followup_interaction(
                interaction_token,
                embed=make_solve_embed(challenge, submit_flag, solved_by),
            )
            await discord_mark_solved(challenge, submit_flag, solved_by)
        else:
            stored_flag = set_detected_flag_status(challenge, submit_flag, "wrong")
            record_flag_submission(
                challenge,
                stored_flag,
                submitted_flag=submit_flag,
                correct=False,
                message=result.message,
                auto=False,
            )
            save_metadata(challenge)
            await _broadcast_detected_flag_state(
                challenge_id,
                challenge,
                stored_flag,
                correct=False,
                message=result.message,
            )
            await bot.followup_interaction(
                interaction_token,
                f"{author} submitted `{submit_flag}` — Incorrect: {result.message}",
            )
    except Exception as exc:
        await bot.followup_interaction(interaction_token, f"Submit error: {exc}")


async def _broadcast_detected_flag_state(
    challenge_id: str,
    challenge: dict,
    flag: str,
    *,
    correct: bool | None = None,
    message: str = "",
) -> None:
    event = {
        "type": "flag_result",
        "challenge_id": challenge_id,
        "challenge_name": challenge.get("name", ""),
        "flag": flag,
        "status": challenge.get("detected_flags", {}).get(flag, "pending"),
        "meta": detected_flag_meta(challenge, flag),
    }
    if correct is not None:
        event["correct"] = correct
    if message:
        event["message"] = message
    await broadcast_global(event)


async def _handle_discord_flag_review(
    bot: DiscordBot,
    interaction: dict,
    challenge_id: str,
    challenge: dict,
    action: str,
    token: str,
) -> None:
    try:
        from .agents.broadcast import _queues
    except ImportError:
        from agents.broadcast import _queues

    interaction_id = interaction["id"]
    interaction_token = interaction["token"]
    author, _author_id = _discord_actor(interaction)
    flag = _discord_detected_flag_from_token(challenge, token)
    if not flag:
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            "Flag candidate not found.",
            flags=64,
        )
        return

    if action == "flag_submit":
        await bot.defer_interaction(interaction_id, interaction_token)
        await _discord_submit_flag_from_interaction(
            bot,
            interaction_token,
            challenge_id,
            challenge,
            flag,
            author,
        )
        return

    if action == "flag_reject":
        stored_flag = set_detected_flag_status(challenge, flag, "wrong")
        save_metadata(challenge)
        await _broadcast_detected_flag_state(
            challenge_id,
            challenge,
            stored_flag,
            correct=False,
            message=f"Rejected by {author} via Discord",
        )
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            f"{author} rejected flag candidate: `{stored_flag}`",
        )
        return

    if action == "flag_correct":
        await bot.defer_interaction(interaction_id, interaction_token)
        stored_flag = set_detected_flag_status(challenge, flag, "correct")
        record_flag_submission(
            challenge,
            stored_flag,
            submitted_flag=stored_flag,
            correct=True,
            message=f"Marked correct by {author} via Discord",
            manual_mark=True,
        )
        solved_by = f"{author} (Discord)"
        await apply_solved_status(
            challenge_id,
            challenge,
            flag=stored_flag,
            stop_reason="discord_flag_review_correct",
        )
        await _broadcast_detected_flag_state(
            challenge_id,
            challenge,
            stored_flag,
            correct=True,
            message="Marked correct via Discord review",
        )
        await bot.followup_interaction(
            interaction_token,
            embed=make_solve_embed(challenge, stored_flag, solved_by),
        )
        await discord_mark_solved(challenge, stored_flag, solved_by)
        return

    if action == "flag_broadcast":
        q = _queues.get(challenge_id, {})
        message = f"[{author} via Discord flag review]: Candidate flag `{flag}`"
        for queue in q.values():
            await queue.put(message)
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            f"{author} broadcast flag candidate to {len(q)} active agent(s): `{flag}`",
        )


async def _handle_discord_component_interaction(interaction: dict) -> None:
    bot = get_bot(load_settings())
    if not bot:
        return
    interaction_id = interaction["id"]
    interaction_token = interaction["token"]
    author, _author_id = _discord_actor(interaction)
    custom_id = (interaction.get("data") or {}).get("custom_id", "")
    challenge_id, action, token = _discord_parse_component_id(custom_id)
    challenge = challenges.get(challenge_id)
    if not challenge:
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            "Challenge not found.",
            flags=64,
        )
        return

    if action in DISCORD_FLAG_REVIEW_ACTIONS:
        await _handle_discord_flag_review(
            bot,
            interaction,
            challenge_id,
            challenge,
            action,
            token,
        )
        return

    if action == "submit":
        await bot.open_modal(
            interaction_id,
            interaction_token,
            _discord_component_id(challenge_id, "submit_modal"),
            "Submit Flag",
            _discord_flag_modal_components(
                "flag",
                "Flag",
                required=True,
                placeholder=challenge_flag_formats(challenge)[0]
                if challenge_flag_formats(challenge)
                else "flag{...}",
            ),
        )
        return

    if action == "solved":
        await bot.open_modal(
            interaction_id,
            interaction_token,
            _discord_component_id(challenge_id, "solved_modal"),
            "Mark Solved",
            _discord_flag_modal_components(
                "flag",
                "Flag (optional)",
                required=False,
                placeholder=challenge_flag_formats(challenge)[0]
                if challenge_flag_formats(challenge)
                else "flag{...}",
            ),
        )
        return

    if action == "status":
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_status_message(challenge),
            flags=64,
        )
    elif action == "stats":
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_stats_message(challenge_id, challenge),
            flags=64,
        )
    elif action == "tail":
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_tail_message(challenge_id, challenge),
            flags=64,
        )
    elif action == "flags":
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_flags_message(challenge),
            flags=64,
        )
    elif action == "stop":
        await bot.defer_interaction(interaction_id, interaction_token)
        await bot.followup_interaction(
            interaction_token,
            await _discord_stop_runs(challenge_id, challenge, actor=author),
        )
    elif action == "resume":
        await bot.defer_interaction(interaction_id, interaction_token)
        await bot.followup_interaction(
            interaction_token,
            await _discord_resume_runs(challenge_id, challenge, actor=author),
        )


async def _handle_discord_modal_submit(interaction: dict) -> None:
    bot = get_bot(load_settings())
    if not bot:
        return
    custom_id = (interaction.get("data") or {}).get("custom_id", "")
    challenge_id, action, _token = _discord_parse_component_id(custom_id)
    challenge = challenges.get(challenge_id)
    interaction_id = interaction["id"]
    interaction_token = interaction["token"]
    author, _author_id = _discord_actor(interaction)
    if not challenge:
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            "Challenge not found.",
            flags=64,
        )
        return

    flag = _discord_modal_value(interaction, "flag").strip()
    if action == "submit_modal":
        await bot.defer_interaction(interaction_id, interaction_token)
        await _discord_submit_flag_from_interaction(
            bot,
            interaction_token,
            challenge_id,
            challenge,
            flag,
            author,
        )
    elif action == "solved_modal":
        await bot.defer_interaction(interaction_id, interaction_token)
        solved_by = f"{author} (Discord)"
        await apply_solved_status(
            challenge_id,
            challenge,
            flag=flag,
            stop_reason="discord_solved",
        )
        await bot.followup_interaction(
            interaction_token,
            embed=make_solve_embed(challenge, flag or "\u2014", solved_by),
        )
        await discord_mark_solved(challenge, flag or "", solved_by)


async def _handle_discord_interaction(interaction: dict) -> None:
    """Handle a Discord slash command interaction."""
    try:
        from .agents.broadcast import _queues
    except ImportError:
        from agents.broadcast import _queues

    itype = interaction.get("type")
    if itype == 3:  # MESSAGE_COMPONENT
        await _handle_discord_component_interaction(interaction)
        return
    if itype == 5:  # MODAL_SUBMIT
        await _handle_discord_modal_submit(interaction)
        return
    if itype != 2:  # APPLICATION_COMMAND
        return

    data = interaction.get("data", {})
    cmd = data.get("name", "")
    subcommand, options = _discord_option_map(data.get("options", []))
    interaction_id = interaction["id"]
    interaction_token = interaction["token"]
    author, author_id = _discord_actor(interaction)

    bot = get_bot(load_settings())
    if not bot:
        return

    if cmd == "help":
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_help_message(),
            flags=64,
        )
        return

    # /ctf works from any channel
    if cmd == "ctf":
        by_cat: dict[str, list[dict]] = {}
        for c in challenges.values():
            cat = c.get("category", "") or "Uncategorized"
            by_cat.setdefault(cat, []).append(c)
        if not by_cat:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "No challenges loaded")
            return
        status_emoji = {
            "solved": "\u2705", "solving": "\u25b6", "pending": "\u23f8",
            "failed": "\u274c", "completed": "\u2714",
        }
        lines = []
        total = sum(len(v) for v in by_cat.values())
        solved = sum(1 for c in challenges.values() if c.get("status") == "solved")
        lines.append(f"**CTF Dashboard** — {solved}/{total} solved\n")
        for cat in sorted(by_cat.keys()):
            lines.append(f"**{cat}**")
            for c in sorted(by_cat[cat], key=lambda x: x.get("name", "")):
                emoji = status_emoji.get(c.get("status", ""), "\u2753")
                name = c.get("name", "?")
                agents = ", ".join(
                    f"{r.get('agent', '?')}" for r in c.get("runs", {}).values()
                )
                points = c.get("_points", 0)
                pts = f" [{points}pts]" if points else ""
                lines.append(f"{emoji} {name}{pts} — {c.get('status', '?')} ({agents})")
            lines.append("")
        await bot.respond_to_interaction(
            interaction_id, interaction_token,
            _truncate("\n".join(lines)))
        return

    # /add works from any channel so users can join challenge threads by category.
    if cmd == "add":
        category = str(options.get("category", "")).strip()
        if not category:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                "Category required.",
                flags=64,
            )
            return
        if not author_id:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                "Could not identify the Discord user to add.",
                flags=64,
            )
            return
        matches = _discord_challenges_for_category(category)
        if not matches:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                f"No joinable Discord challenge threads matched `{category}`.\n{_discord_category_choices()}",
                flags=64,
            )
            return

        await bot.defer_interaction(interaction_id, interaction_token)
        added = 0
        failed = []
        for challenge in matches:
            thread_id = str(challenge.get("_discord_thread_id", ""))
            ok, error = await bot.add_thread_member(thread_id, author_id)
            if ok:
                added += 1
            else:
                failed.append(f"{challenge.get('name', '?')}: {error}")

        label = "all categories" if category.casefold() == "all" else category
        message = f"Added you to {added}/{len(matches)} thread(s) for `{label}`."
        if failed:
            message += "\nFailed:\n" + "\n".join(f"- {item}" for item in failed[:10])
            if len(failed) > 10:
                message += f"\n... and {len(failed) - 10} more"
            message = _truncate(message)
        await bot.followup_interaction(interaction_token, message)
        return

    # /join works from any channel so users can add themselves to one
    # challenge thread without joining a whole category.
    if cmd == "join":
        query = str(options.get("challenge", "")).strip()
        if not query:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                "Challenge name required.",
                flags=64,
            )
            return
        if not author_id:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                "Could not identify the Discord user to add.",
                flags=64,
            )
            return

        matches = _discord_join_candidates(query)
        if not matches or matches[0][0] < 0.35:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                f"No challenge thread matched `{query}`.",
                flags=64,
            )
            return
        if len(matches) > 1 and matches[1][0] >= matches[0][0] - 0.08:
            choices = "\n".join(
                f"- {_discord_challenge_label(ch)}"
                for _, _, ch in matches[:5]
            )
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                f"`{query}` is ambiguous. Try a more specific name:\n{choices}",
                flags=64,
            )
            return

        _, _, challenge_match = matches[0]
        ok, error = await bot.add_thread_member(
            str(challenge_match.get("_discord_thread_id", "")),
            author_id,
        )
        if ok:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                f"Added you to {_discord_challenge_label(challenge_match)}.",
                flags=64,
            )
        else:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                f"Could not add you to {_discord_challenge_label(challenge_match)}: {error}",
                flags=64,
            )
        return

    ch_id = _challenge_id_from_discord_interaction(interaction)
    if not ch_id:
        await bot.respond_to_interaction(
            interaction_id, interaction_token,
            "This command must be used in a challenge thread or channel.",
            flags=64,  # EPHEMERAL
        )
        return
    challenge = challenges.get(ch_id)
    if not challenge:
        await bot.respond_to_interaction(
            interaction_id, interaction_token, "Challenge not found.", flags=64)
        return

    if cmd == "broadcast":
        message = options.get("message", "")
        if not message:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "Message required.", flags=64)
            return
        q = _queues.get(ch_id, {})
        for queue in q.values():
            await queue.put(f"[{author} via Discord]: {message}")
        await bot.respond_to_interaction(
            interaction_id, interaction_token,
            f"{author} broadcast to {len(q)} agent(s): {message}")

    elif cmd == "steer":
        selector = str(options.get("agent", "") or "").strip()
        message = str(options.get("message", "") or "").strip()
        if not message:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "Message required.", flags=64)
            return

        target_run_id, target_run, error = _discord_select_run(
            challenge, selector
        )
        if error or not target_run_id or not target_run:
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                error or "Agent run not found.",
                flags=64,
            )
            return

        steer_message = f"[{author} via Discord]: {message}"
        await _steer_run_with_message(
            ch_id,
            target_run_id,
            target_run,
            steer_message,
            stop_reason="discord_steer",
        )
        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            f"{author} steered `{target_run.get('agent', '?')}` (`{target_run_id}`): {message}",
        )

    elif cmd == "submit":
        flag = options.get("flag", "")
        if not flag:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "Flag required.", flags=64)
            return
        await bot.defer_interaction(interaction_id, interaction_token)
        plugin, config = _resolve_plugin_config(challenge)
        if not plugin or not config:
            await bot.followup_interaction(
                interaction_token, "No platform connection for this challenge")
            return
        remote_id = challenge.get("_remote_id", "")
        try:
            submit_flag = normalize_flag_for_submission(
                flag, challenge_flag_formats(challenge)
            )
            result = await plugin.submit_flag(config, remote_id, submit_flag)
            if result.correct:
                await apply_solved_status(
                    ch_id,
                    challenge,
                    flag=submit_flag,
                    stop_reason="discord_submit_solved",
                )
                solved_by = f"{author} (Discord)"
                await bot.followup_interaction(
                    interaction_token,
                    embed=make_solve_embed(challenge, submit_flag, solved_by))
                await discord_mark_solved(challenge, submit_flag, solved_by)
            else:
                set_detected_flag_status(challenge, submit_flag, "wrong")
                save_metadata(challenge)
                await bot.followup_interaction(
                    interaction_token,
                    f"{author} submitted `{submit_flag}` — Incorrect: {result.message}")
        except Exception as exc:
            await bot.followup_interaction(
                interaction_token, f"Submit error: {exc}")

    elif cmd == "status":
        lines = [f"**{challenge.get('name', '?')}** — {challenge.get('status', '?')}"]
        for run in challenge["runs"].values():
            agent = run.get("agent", "?")
            model = run.get("model", "")
            status = run.get("status", "?")
            emoji = {"solving": "\u25b6", "solved": "\u2705", "failed": "\u274c",
                     "completed": "\u2714", "pending": "\u23f8"}.get(status, "\u2753")
            line = f"{emoji} `{agent}` ({model}) — {status}"
            if run.get("error"):
                line += f": {run['error']}"
            lines.append(line)
        await bot.respond_to_interaction(
            interaction_id, interaction_token, "\n".join(lines))

    elif cmd == "stats":
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_stats_message(ch_id, challenge),
        )

    elif cmd == "tail":
        try:
            line_count = int(options.get("lines") or 10)
        except (TypeError, ValueError):
            line_count = 10
        await bot.respond_to_interaction(
            interaction_id,
            interaction_token,
            _discord_tail_message(
                ch_id,
                challenge,
                agent_filter=str(options.get("agent", "") or ""),
                lines=line_count,
            ),
        )

    elif cmd == "flags":
        manual_flag = str(options.get("add", "") or "").strip()
        if manual_flag:
            detected = challenge.setdefault("detected_flags", {})
            stored_flag = detected_flag_key(detected, manual_flag)
            added = stored_flag not in detected
            if added:
                stored_flag = set_detected_flag_status(
                    challenge, manual_flag, "pending"
                )
            record_detected_flag_source(
                challenge,
                stored_flag,
                agent=author,
                source_type="manual",
            )
            save_metadata(challenge)
            flag_event = {
                "type": "flag_found",
                "flag": stored_flag,
                "meta": detected_flag_meta(challenge, stored_flag),
                "run_id": "",
                "agent": author,
                "challenge_id": ch_id,
                "challenge_name": challenge.get("name", ""),
            }
            await broadcast_global(flag_event)
            await bot.respond_to_interaction(
                interaction_id,
                interaction_token,
                f"{author} added flag candidate: `{stored_flag}`"
                if added
                else f"Flag already existed: `{stored_flag}`",
            )
            return

        detected = challenge.get("detected_flags", {})
        if not detected:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "No flags detected yet")
            return
        lines = []
        for flag, status in detected.items():
            emoji = {"correct": "\u2705", "wrong": "\u274c",
                     "pending": "\u23f3"}.get(status, "\u2753")
            lines.append(f"{emoji} `{flag}` — {status}")
        await bot.respond_to_interaction(
            interaction_id, interaction_token, "\n".join(lines))

    elif cmd == "stop":
        stopped_ids = []
        for run_id, run in challenge["runs"].items():
            if run["status"] == "solving":
                run["status"] = "failed"
                run["error"] = None
                stop_event = {
                    "type": "system",
                    "message": f"Agent stopped from Discord by {author}.",
                }
                await _append_run_event(ch_id, run_id, run, stop_event)
                await stop_run(run, "discord_stop")
                finish_run_timer(run)
                stopped_ids.append(run_id)
        if stopped_ids:
            challenge["status"] = derive_challenge_status(challenge)
            save_metadata(challenge)
            for run_id in stopped_ids:
                run = challenge["runs"][run_id]
                await broadcast(ch_id, run_id, {
                    "type": "run_status",
                    "run_id": run_id,
                    "status": run["status"],
                    "error": run.get("error"),
                    "duration_ms": effective_run_duration_ms(run),
                })
            await broadcast_challenge(ch_id, {
                "type": "challenge_status",
                "status": challenge["status"],
            })
            await bot.respond_to_interaction(
                interaction_id, interaction_token,
                f"{author} stopped {len(stopped_ids)} agent(s)")
        else:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "No agents are currently running")

    elif cmd == "resume":
        count = 0
        for run_id, run in challenge["runs"].items():
            if run["status"] in ("failed", "completed"):
                run["status"] = "solving"
                run.pop("_stop_reason", None)
                run["task"] = asyncio.create_task(
                    run_agent_task(
                        ch_id,
                        run_id,
                        continue_msg="Continue solving the challenge",
                    )
                )
                count += 1
        if count:
            challenge["status"] = derive_challenge_status(challenge)
            save_metadata(challenge)
            await bot.respond_to_interaction(
                interaction_id, interaction_token,
                f"{author} resumed {count} agent(s)")
        else:
            await bot.respond_to_interaction(
                interaction_id, interaction_token, "No agents to resume")

    elif cmd == "solved":
        flag = options.get("flag", "")
        solved_by = f"{author} (Discord)"
        await apply_solved_status(
            ch_id,
            challenge,
            flag=flag,
            stop_reason="discord_solved",
        )
        await bot.respond_to_interaction(
            interaction_id, interaction_token,
            embed=make_solve_embed(challenge, flag or "—", solved_by))
        await discord_mark_solved(challenge, flag or "", solved_by)

    elif cmd == "files":
        file_path = options.get("path", "")
        agent_filter = options.get("agent", "")
        ch_id_short = ch_id
        ch_dir = CHALLENGES_DIR / ch_id_short

        if file_path:
            # Fetch a specific file
            await bot.defer_interaction(interaction_id, interaction_token)
            found = False
            for rid, run in challenge["runs"].items():
                if agent_filter and run.get("agent") != agent_filter:
                    continue
                run_cwd = get_run_cwd(ch_id, run)
                allowed_roots = [
                    run_cwd,
                    ch_dir / "_files",
                    ch_dir / "_shared",
                ]
                target = resolve_allowed_path(
                    run_cwd, file_path, allowed_roots
                )
                if target and target.exists() and target.is_file():
                    try:
                        if target.stat().st_size > MAX_DISCORD_FILE_READ:
                            await bot.followup_interaction(
                                interaction_token,
                                f"File too large to display over Discord: `{file_path}`",
                            )
                            found = True
                            break
                        content = target.read_text(errors="replace")
                        agent = run.get("agent", "?")
                        header = f"**{agent}** — `{file_path}`\n"
                        await bot.followup_interaction(
                            interaction_token,
                            header + f"```\n{_truncate(content, 1800)}\n```")
                        found = True
                        break
                    except Exception as exc:
                        await bot.followup_interaction(
                            interaction_token, f"Error reading {file_path}: {exc}")
                        found = True
                        break
            if not found:
                await bot.followup_interaction(
                    interaction_token, f"File not found: `{file_path}`")
        else:
            # List files
            lines = []
            for rid, run in challenge["runs"].items():
                if agent_filter and run.get("agent") != agent_filter:
                    continue
                agent = run.get("agent", "?")
                run_cwd = get_run_cwd(ch_id, run)
                if not run_cwd.exists():
                    continue
                files = []
                allowed_roots = [
                    run_cwd,
                    ch_dir / "_files",
                    ch_dir / "_shared",
                ]
                resolved_roots = [
                    root.resolve() for root in allowed_roots if root.exists()
                ]
                for f in sorted(run_cwd.rglob("*")):
                    if f.is_file():
                        resolved = f.resolve()
                        if not any(
                            _is_relative_to(resolved, root)
                            for root in resolved_roots
                        ):
                            continue
                        rel = f.relative_to(run_cwd)
                        # Skip symlinks to shared dirs and working notes
                        if str(rel).startswith("_shared") or str(rel).startswith("WORKING_NOTES_"):
                            continue
                        size = f.stat().st_size
                        if size > 1024 * 1024:
                            size_str = f"{size / 1024 / 1024:.1f}MB"
                        elif size > 1024:
                            size_str = f"{size / 1024:.1f}KB"
                        else:
                            size_str = f"{size}B"
                        files.append(f"`{rel}` ({size_str})")
                if files:
                    lines.append(f"**{agent}:**")
                    lines.extend(files[:30])
                    if len(files) > 30:
                        lines.append(f"... and {len(files) - 30} more")
            if lines:
                await bot.respond_to_interaction(
                    interaction_id, interaction_token,
                    _truncate("\n".join(lines)))
            else:
                await bot.respond_to_interaction(
                    interaction_id, interaction_token, "No files found")


_discord_gateway: DiscordGateway | None = None
_discord_gateway_key: tuple[str, str, str] | None = None


async def _stop_discord_gateway() -> None:
    global _discord_gateway, _discord_gateway_key
    if _discord_gateway:
        await _discord_gateway.stop()
    _discord_gateway = None
    _discord_gateway_key = None


async def _reconcile_discord_gateway() -> None:
    """Start, stop, or restart the Discord gateway to match settings."""
    global _discord_gateway, _discord_gateway_key
    settings = load_settings()
    bot = get_bot(settings)
    if not bot:
        await _stop_discord_gateway()
        return

    guild_id = settings.get("discord_guild_id", "").strip()
    key = (bot.token, bot.channel_id, guild_id)
    if _discord_gateway and _discord_gateway_key == key:
        return

    await _stop_discord_gateway()
    try:
        await bot.register_slash_commands(guild_id)
    except Exception as exc:
        log.error("Failed to register slash commands: %s", exc)
    _discord_gateway = DiscordGateway(bot, _handle_discord_interaction)
    _discord_gateway_key = key
    asyncio.create_task(_discord_gateway.run_forever())
    log.info("Discord gateway started")


@asynccontextmanager
async def lifespan(app):
    asyncio.create_task(_reconcile_discord_gateway())
    asyncio.create_task(_swarm_idle_loop())
    yield
    await _stop_discord_gateway()
    for challenge in challenges.values():
        for run in challenge["runs"].values():
            await stop_run(run, "shutdown")
    for preview in _bulk_previews.values():
        shutil.rmtree(preview["base_dir"], ignore_errors=True)
    _bulk_previews.clear()


# ---------------------------------------------------------------------------
# Advisor agent — read-only kibitzer + web researcher per challenge
# ---------------------------------------------------------------------------

ADVISOR_RUN_ID = "advisor"
ADVISOR_MAX_MESSAGES = 400
# The advisor defaults to Claude Sonnet 4.6 (fast/cheap for read+research),
# independent of the solver default. Other providers use their own default.
ADVISOR_DEFAULT_MODEL = "claude-sonnet-4-6"


def _advisor_default_model(agent: str) -> str:
    if agent == "claude":
        return ADVISOR_DEFAULT_MODEL
    return resolved_default_model(agent)

# Ephemeral in-memory advisor sessions (NOT persisted): challenge_id -> session.
advisor_sessions: dict[str, dict] = {}

ADVISOR_PREAMBLE = """You are the **CTF Advisor** for the challenge "{name}".

Other AI agents are actively solving this challenge. You are a read-only
assistant for the human operator. You can:
- `list_runs()` — list the solver agents and their status/goals.
- `read_transcript(run_id?, tail?, grep?)` — read what the solvers have actually
  done (tool calls, outputs, errors). Omit run_id to scan all runs.
- `read_working_notes()` — read solvers' working notes.
- Web search / fetch — research recent techniques, CVEs, exploits, write-ups.
- `notify_solvers(message)` — push ONE concise, high-signal hint to the live
  solver agents. Use sparingly; never relay noise or unverified guesses.

Answer the operator's questions, diagnose where solvers are stuck by reading
their transcripts (do not fabricate — read), and research useful techniques.
Be concise and concrete.

Challenge description:
{description}
"""


def _advisor_broadcast_bus():
    try:
        from .agents.broadcast import broadcast_to_teammates
    except ImportError:
        from agents.broadcast import broadcast_to_teammates
    return broadcast_to_teammates


def _advisor_event_text(ev: dict) -> str:
    """Compact one-line-ish summary of a transcript event for the advisor."""
    et = ev.get("type", "")
    if et in ("assistant", "user"):
        parts = []
        for block in ev.get("content", []) or []:
            bt = block.get("type")
            if bt == "text" and block.get("text"):
                parts.append(f"[text] {block['text']}")
            elif bt == "thinking" and block.get("thinking"):
                parts.append(f"[thinking] {block['thinking'][:400]}")
            elif bt == "tool_use":
                parts.append(f"[tool_use {block.get('name','?')}] "
                              f"{json.dumps(block.get('input', {}))[:400]}")
            elif bt == "tool_result":
                parts.append(f"[tool_result] {str(block.get('content',''))[:600]}")
        return "\n".join(parts)
    if et in ("system", "error", "user_prompt", "user_steer"):
        msg = ev.get("message", "")
        return f"[{et}] {msg}" if msg else ""
    return ""


def _advisor_make_tools(cid: str) -> dict:
    async def read_transcript(params: dict) -> str:
        challenge = challenges.get(cid)
        if not challenge:
            return "challenge not found"
        run_id = str(params.get("run_id", "") or "").strip()
        try:
            tail = max(1, min(int(params.get("tail", 40) or 40), 200))
        except (TypeError, ValueError):
            tail = 40
        grep = str(params.get("grep", "") or "").strip().lower()
        rids = [run_id] if run_id else list(challenge["runs"].keys())
        blocks = []
        for rid in rids:
            if rid not in challenge["runs"]:
                continue
            path = _run_output_path(cid, rid)
            lines = []
            if path.exists():
                for ln in path.read_text(errors="replace").splitlines():
                    try:
                        ev = json.loads(ln)
                    except json.JSONDecodeError:
                        continue
                    txt = _advisor_event_text(ev)
                    if not txt:
                        continue
                    if grep and grep not in txt.lower():
                        continue
                    lines.append(txt)
            sel = lines[-tail:]
            agent = challenge["runs"][rid].get("agent", "?")
            blocks.append(
                f"=== run {rid} ({agent}) — last {len(sel)} of {len(lines)} "
                f"events ===\n" + "\n".join(sel))
        return "\n\n".join(blocks) or "no transcript events yet"

    async def list_runs(params: dict) -> str:
        challenge = challenges.get(cid)
        if not challenge:
            return "challenge not found"
        rows = []
        for rid, run in challenge["runs"].items():
            goal = normalize_run_goal(run.get("goal")) or {}
            desc = (goal.get("description") or "") if isinstance(goal, dict) else ""
            rows.append(
                f"- {rid}: agent={run.get('agent')} model={run.get('model')} "
                f"status={run.get('status')} goal={desc[:80]}")
        return (f"Challenge: {challenge.get('name')} [{challenge.get('status')}]\n"
                f"Runs:\n" + "\n".join(rows))

    async def read_working_notes(params: dict) -> str:
        challenge = challenges.get(cid)
        if not challenge:
            return "challenge not found"
        out = []
        for rid, run in challenge["runs"].items():
            try:
                notes = get_run_cwd(cid, run) / run_notes_filename(challenge, run)
                if notes.exists():
                    out.append(f"=== {rid} notes ===\n"
                               f"{notes.read_text(errors='replace')[:4000]}")
            except OSError:
                continue
        return "\n\n".join(out) or "no working notes found (solvers may run remotely)"

    async def notify_solvers(params: dict) -> str:
        msg = str(params.get("message", "") or "").strip()
        if not msg:
            return "message required"
        count = await _advisor_broadcast_bus()(cid, ADVISOR_RUN_ID,
                                                f"[Advisor]: {msg}")
        return f"Sent hint to {count} solver(s)"

    obj = {"type": "object", "properties": {}}
    return {
        "read_transcript": {
            "description": "Read recent transcript events from solver agents. "
            "Args: run_id (optional), tail (default 40, max 200), grep (optional "
            "substring filter).",
            "schema": {"type": "object", "properties": {
                "run_id": {"type": "string"},
                "tail": {"type": "integer"},
                "grep": {"type": "string"}}},
            "fn": read_transcript},
        "list_runs": {
            "description": "List the solver agents on this challenge with their "
            "status and goals.", "schema": obj, "fn": list_runs},
        "read_working_notes": {
            "description": "Read the solver agents' working notes.",
            "schema": obj, "fn": read_working_notes},
        "notify_solvers": {
            "description": "Push one concise, high-signal hint to the live solver "
            "agents. Use sparingly.",
            "schema": {"type": "object", "properties": {
                "message": {"type": "string"}}, "required": ["message"]},
            "fn": notify_solvers},
    }


def _get_advisor_session(cid: str) -> dict:
    s = advisor_sessions.get(cid)
    if s is None:
        s = {
            "agent": "", "model": "", "effort": "",
            "session_state": {}, "messages": [], "ws_clients": set(),
            "status": "idle", "started": False, "lock": asyncio.Lock(),
        }
        advisor_sessions[cid] = s
    return s


async def _advisor_emit(cid: str, data: dict) -> None:
    s = advisor_sessions.get(cid)
    if s:
        await _broadcast_to_ws_set(s["ws_clients"], data)


async def run_advisor_turn(cid: str, text: str) -> None:
    s = _get_advisor_session(cid)
    challenge = challenges.get(cid)
    if not challenge:
        return
    provider = get_provider(s["agent"])
    async with s["lock"]:
        s["status"] = "thinking"
        s["messages"].append({"role": "user", "text": text})
        await _advisor_emit(cid, {"type": "advisor_user", "text": text})
        await _advisor_emit(cid, {"type": "advisor_status", "status": "thinking"})
        adv_cwd = CHALLENGES_DIR / cid / "_advisor"
        adv_cwd.mkdir(parents=True, exist_ok=True)
        is_continue = s["started"]
        if is_continue:
            prompt = text
        else:
            prompt = ADVISOR_PREAMBLE.format(
                name=challenge.get("name", ""),
                description=str(challenge.get("description", ""))[:2000],
            ) + "\n\nOperator: " + text
        try:
            async for event in provider.run_agent(
                prompt=prompt, model=s["model"], effort=s["effort"],
                cwd=str(adv_cwd), continue_session=is_continue,
                session_state=s["session_state"], challenge_id=cid, run_id="",
                _advisor_tools=_advisor_make_tools(cid),
                _env=agent_runtime_env(s["agent"]),
            ):
                if not isinstance(event, dict):
                    continue
                s["messages"].append({"role": "agent", "event": event})
                del s["messages"][:-ADVISOR_MAX_MESSAGES]
                await _advisor_emit(cid, {"type": "advisor_event", "event": event})
                if event.get("type") == "result":
                    break
            s["started"] = True
        except Exception as exc:  # noqa: BLE001
            await _advisor_emit(cid, {"type": "advisor_event",
                                      "event": {"type": "error", "message": str(exc)}})
        finally:
            s["status"] = "idle"
            await _advisor_emit(cid, {"type": "advisor_status", "status": "idle"})


async def advisor_get(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    cid = request.path_params["id"]
    if cid not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)
    s = advisor_sessions.get(cid)
    if not s:
        return JSONResponse({
            "config": {"agent": DEFAULT_AGENT,
                       "model": _advisor_default_model(DEFAULT_AGENT),
                       "effort": ""},
            "messages": [], "status": "idle", "started": False,
            "agents": [_provider_choice(p) for p in PROVIDERS.values()],
        })
    return JSONResponse({
        "config": {"agent": s["agent"] or DEFAULT_AGENT,
                   "model": s["model"], "effort": s["effort"]},
        "messages": s["messages"][-ADVISOR_MAX_MESSAGES:],
        "status": s["status"], "started": s["started"],
        "agents": [_provider_choice(p) for p in PROVIDERS.values()],
    })


def _provider_choice(provider) -> dict:
    return {"name": provider.name, "label": provider.label,
            "models": [{"value": v, "label": l}
                       for v, l in provider.resolved_models()],
            "default_model": provider.resolved_default_model()}


async def advisor_send(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    cid = request.path_params["id"]
    if cid not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)
    body, json_err = await read_json_object(request)
    if json_err:
        return json_err
    message = str_field(body.get("message", "")).strip()
    if not message:
        return JSONResponse({"error": "message required"}, status_code=400)
    s = _get_advisor_session(cid)
    if s["status"] == "thinking":
        return JSONResponse({"error": "advisor is busy"}, status_code=409)
    # Configure provider/model before the first turn (locked once started).
    if not s["started"]:
        agent = str_field(body.get("agent", "")) or DEFAULT_AGENT
        if agent not in VALID_AGENTS:
            return JSONResponse({"error": f"invalid agent: {agent}"},
                                status_code=400)
        s["agent"] = agent
        s["model"] = str_field(body.get("model", "")) or _advisor_default_model(agent)
        s["effort"] = str_field(body.get("effort", ""))
    asyncio.create_task(run_advisor_turn(cid, message))
    return JSONResponse({"ok": True})


async def advisor_reset(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err
    cid = request.path_params["id"]
    s = advisor_sessions.get(cid)
    if s:
        if s["status"] == "thinking":
            return JSONResponse({"error": "advisor is busy"}, status_code=409)
        s.update({"session_state": {}, "messages": [], "started": False,
                  "agent": "", "model": "", "effort": ""})
        await _advisor_emit(cid, {"type": "advisor_reset"})
    return JSONResponse({"ok": True})


async def advisor_ws(websocket: WebSocket):
    if not websocket_origin_allowed(websocket):
        await websocket.close(code=4003)
        return
    if not websocket.session.get("authenticated"):
        if not _check_basic_auth(websocket.headers.get("authorization", "")):
            await websocket.close(code=4001)
            return
    cid = websocket.path_params["id"]
    if cid not in challenges:
        await websocket.close(code=4004)
        return
    await websocket.accept()
    s = _get_advisor_session(cid)
    s["ws_clients"].add(websocket)
    try:
        await _send_ws_json(websocket, {"type": "advisor_status",
                                        "status": s["status"]})
        while True:
            await websocket.receive_text()
    except Exception:  # noqa: BLE001 - normal disconnect
        pass
    finally:
        s["ws_clients"].discard(websocket)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

routes = [
    Route("/", index),
    Route("/api/login", login, methods=["POST"]),
    Route("/api/logout", logout, methods=["POST"]),
    Route("/api/csrf-token", csrf_token, methods=["GET"]),
    Route("/api/agents", list_agents, methods=["GET"]),
    Route("/api/agents/auth/status", agent_auth_status, methods=["GET"]),
    Route("/api/agents/auth/start", start_agent_auth, methods=["POST"]),
    Route("/api/agents/auth/env", set_agent_env_auth, methods=["POST"]),
    Route("/api/usage", get_usage, methods=["GET"]),
    Route("/api/vpn", vpn_status, methods=["GET"]),
    Route("/api/vpn/configure", vpn_configure, methods=["POST"]),
    Route("/api/vpn/toggle", vpn_toggle, methods=["POST"]),
    Route("/api/plugins", list_plugins, methods=["GET"]),
    Route("/api/plugins/test", plugin_test_connection, methods=["POST"]),
    Route("/api/plugins/fetch", plugin_fetch_challenges, methods=["POST"]),
    Route("/api/plugins/import", plugin_import_challenges, methods=["POST"]),
    Route(
        "/api/plugins/import/progress/{progress_id}",
        plugin_import_progress,
        methods=["GET"],
    ),
    Route("/api/plugins/submit-flag", plugin_submit_flag, methods=["POST"]),
    Route("/api/agent/submit-answer", agent_submit_answer, methods=["POST"]),
    Route("/api/connections", list_connections, methods=["GET"]),
    Route("/api/connections/delete", delete_connection, methods=["POST"]),
    Route("/api/connections/sync", sync_connection, methods=["POST"]),
    Route("/api/connections/poll", poll_connections, methods=["GET"]),
    Route("/api/settings", get_settings, methods=["GET"]),
    Route("/api/settings", update_settings, methods=["PUT"]),
    Route("/api/swarm", swarm_status, methods=["GET"]),
    Route("/api/swarm/config", swarm_save_config, methods=["POST"]),
    Route("/api/swarm/test", swarm_test, methods=["POST"]),
    Route("/api/swarm/refresh", swarm_refresh, methods=["POST"]),
    Route("/api/swarm/image/build", swarm_build_image, methods=["POST"]),
    Route("/api/swarm/instances", swarm_create_instances, methods=["POST"]),
    Route("/api/swarm/instances/{name}/{action}", swarm_instance_action,
          methods=["POST"]),
    Route("/api/swarm/instances/{name}", swarm_delete_instance, methods=["DELETE"]),
    Route("/api/skills", get_skills, methods=["GET"]),
    Route("/api/skills/upload", upload_skill, methods=["POST"]),
    Route("/api/discord/test", discord_test, methods=["POST"]),
    Route("/api/discord/channels", discord_channels, methods=["POST"]),
    Route("/api/challenges", list_challenges, methods=["GET"]),
    Route("/api/challenges", create_challenge, methods=["POST"]),
    Route(
        "/api/challenges/bulk-preview",
        bulk_preview,
        methods=["POST"],
    ),
    Route("/api/challenges/bulk", bulk_upload, methods=["POST"]),
    Route("/api/challenges/export", export_challenges_bulk, methods=["POST"]),
    Route("/api/challenges/{id}/solve", solve_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/prompt-template", get_challenge_prompt_template, methods=["POST"]),
    Route("/api/challenges/{id}/runs", add_challenge_runs, methods=["POST"]),
    Route("/api/challenges/{id}/stop", stop_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/broadcast", broadcast_to_agents, methods=["POST"]),
    Route("/api/challenges/{id}/steer", steer_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/unsolve", unsolve_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/mark-solved", mark_solved, methods=["POST"]),
    Route("/api/challenges/{id}/flag-formats", add_flag_format, methods=["POST"]),
    Route("/api/challenges/{id}/flags", add_manual_flag, methods=["POST"]),
    Route("/api/challenges/{id}/skills", update_challenge_skills, methods=["PUT"]),
    Route("/api/challenges/{id}/runs/{run_id}/goal", update_run_goal, methods=["PUT"]),
    Route("/api/challenges/{id}/runs/{run_id}/goal", clear_run_goal, methods=["DELETE"]),
    Route("/api/challenges/{id}/runs/{run_id}/skills", update_run_skills, methods=["PUT"]),
    Route("/api/challenges/{id}/stats", get_challenge_stats, methods=["GET"]),
    Route(
        "/api/challenges/{id}/runs/{run_id}/events/{event_index:int}/tool-output",
        get_run_event_tool_output,
        methods=["GET"],
    ),
    Route("/api/challenges/{id}/runs/{run_id}/events", list_run_events, methods=["GET"]),
    Route("/api/challenges/{id}/transcript-search", search_challenge_transcript, methods=["GET"]),
    Route("/api/challenges/{id}", get_challenge, methods=["GET"]),
    Route("/api/challenges/{id}", delete_challenge, methods=["DELETE"]),
    Route("/api/challenges/{id}/files", list_files, methods=["GET"]),
    Route("/api/challenges/{id}/files/{path:path}", get_file, methods=["GET"]),
    Route("/api/challenges/{id}/download/{path:path}", download_file, methods=["GET"]),
    Route("/api/challenges/{id}/export", export_challenge, methods=["GET"]),
    Route("/api/challenges/{id}/advisor", advisor_get, methods=["GET"]),
    Route("/api/challenges/{id}/advisor", advisor_send, methods=["POST"]),
    Route("/api/challenges/{id}/advisor/reset", advisor_reset, methods=["POST"]),
    WebSocketRoute("/ws/agents/auth/{session_id}", agent_auth_ws),
    WebSocketRoute("/ws/events", global_events_ws),
    WebSocketRoute("/ws/{id}/advisor", advisor_ws),
    WebSocketRoute("/ws/{id}/{run_id}", challenge_ws),
    Mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    ),
]

class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                csp = (
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "connect-src 'self' ws: wss:; "
                    "object-src 'none'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'none'; "
                    "form-action 'self'"
                )
                headers.extend([
                    (b"content-security-policy", csp.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (
                        b"permissions-policy",
                        b"camera=(), microphone=(), geolocation=()",
                    ),
                    (b"cross-origin-opener-policy", b"same-origin"),
                ])
                if TLS_ENABLED:
                    headers.append((
                        b"strict-transport-security",
                        b"max-age=31536000; includeSubDomains",
                    ))
                message["headers"] = headers
            await send(message)

        return await self.app(scope, receive, send_with_headers)


class NoCacheStaticMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].startswith("/static/"):
            async def send_with_nocache(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.append((b"cache-control", b"no-cache, no-store, must-revalidate"))
                    message["headers"] = headers
                await send(message)
            return await self.app(scope, receive, send_with_nocache)
        return await self.app(scope, receive, send)

app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[
        Middleware(
            SessionMiddleware,
            secret_key=SESSION_SECRET,
            max_age=86400,
            session_cookie="ctf_session",
            same_site="lax",
            https_only=TLS_ENABLED,
        ),
    ],
)
app = SecurityHeadersMiddleware(app)
app = NoCacheStaticMiddleware(app)

if __name__ == "__main__":
    import uvicorn

    ssl_certfile = os.environ.get("TLS_CERTFILE")
    ssl_keyfile = os.environ.get("TLS_KEYFILE")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=443,
        log_level="info",
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
