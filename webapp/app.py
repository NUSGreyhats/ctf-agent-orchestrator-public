#!/usr/bin/env python3
"""CTF Challenge Solver Web App.

Spawns CLI coding agents to solve CTF challenges, streaming JSONL
output to authenticated users via WebSocket.

Supports 2 solving modes:
- single: One run.
- parallel: Multiple runs (one per agent). Auto-stop on solve.
"""

import asyncio
import base64
import json
import logging
import re

log = logging.getLogger("ctf-solver")
import mimetypes
import os
import secrets
import subprocess
import shutil
import tempfile
import uuid
import time as _time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

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
    from .plugins.base import RemoteFile
except ImportError:
    from plugins import get_plugins, get_plugin  # type: ignore
    from plugins.base import RemoteFile  # type: ignore

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
APP_ROOT_DIR = Path("/root/all-things-ai")
CHALLENGES_DIR = APP_ROOT_DIR / "challenges"
CHALLENGES_DIR.mkdir(parents=True, exist_ok=True)
STATE_ROOT_DIR = Path("/root/.ctf-solver-state")
STATE_ROOT_DIR.mkdir(parents=True, exist_ok=True)

# Rate limiting for login
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_login_attempts: dict[str, list[float]] = defaultdict(list)

challenges: dict[str, dict] = {}

CONNECTIONS_FILE = STATE_ROOT_DIR / "connections.json"


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


VALID_MODES = {"single", "parallel"}

_FLAG_PATTERNS = [
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"FLAG\{[^}]+\}"),
    re.compile(r"CTF\{[^}]+\}"),
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"picoCTF\{[^}]+\}"),
]


def detect_flag(text: str, flag_format: str = "") -> str | None:
    """Return the first flag found in text, or None."""
    patterns = list(_FLAG_PATTERNS)
    if flag_format:
        prefix = flag_format.split("{")[0] if "{" in flag_format else flag_format
        if len(prefix) >= 2:
            patterns.append(
                re.compile(
                    re.escape(prefix) + r"\{[^}]+\}",
                )
            )
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None

METADATA_FILE = "challenge.json"
OUTPUT_FILE = "output.jsonl"
SETTINGS_FILE = CHALLENGES_DIR / "settings.json"
_PREVIEW_TTL = 3600
_bulk_previews: dict[str, dict] = {}

_SKILLS_ROOT = "/root/all-things-ai/skills"
_METHODOLOGY_SKILL = f"{_SKILLS_ROOT}/methodology/SKILL.md"


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
        "ws_clients": set(),
        "error": None,
        "solve_start": None,
        "duration_ms": None,
        "_codex_thread_id": None,
        "_opencode_session_id": None,
        "_saw_provider_message": False,
        "_last_stream_error": None,
        "_last_stderr_lines": [],
        "_last_unknown_events": [],
    }


def get_run_cwd(challenge_id: str, run: dict) -> Path:
    """Return the working directory for a run."""
    challenge = challenges[challenge_id]
    if challenge["mode"] == "parallel":
        return CHALLENGES_DIR / challenge_id / "_runs" / run["id"]
    return CHALLENGES_DIR / challenge_id


def setup_parallel_shared_dir(challenge_id: str) -> Path:
    """Create the shared directory for parallel challenges."""
    shared_dir = CHALLENGES_DIR / challenge_id / "_shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    # Create empty BREAKTHROUGHS.md
    bt = shared_dir / "BREAKTHROUGHS.md"
    if not bt.exists():
        bt.write_text("# Breakthroughs\n\n")
    return shared_dir


def setup_parallel_run_dir(challenge_id: str, run_id: str) -> Path:
    """Create run directory with symlinks to challenge files and shared dir."""
    challenge_dir = CHALLENGES_DIR / challenge_id
    files_dir = challenge_dir / "_files"
    shared_dir = challenge_dir / "_shared"
    run_dir = challenge_dir / "_runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Symlink challenge files
    if files_dir.exists():
        for item in files_dir.iterdir():
            link = run_dir / item.name
            if not link.exists():
                link.symlink_to(item)

    # Symlink shared directory
    shared_link = run_dir / "_shared"
    if shared_dir.exists() and not shared_link.exists():
        shared_link.symlink_to(shared_dir)

    return run_dir


def setup_parallel_cross_notes(challenge_id: str, runs: dict | None = None) -> None:
    """Symlink each agent's WORKING_NOTES into other agents' run dirs."""
    if runs is None:
        challenge = challenges.get(challenge_id)
        if not challenge:
            return
        runs = challenge["runs"]
    runs_dir = CHALLENGES_DIR / challenge_id / "_runs"
    run_items = list(runs.items())
    for rid, run in run_items:
        run_dir = runs_dir / rid
        if not run_dir.exists():
            continue
        for other_rid, other_run in run_items:
            if other_rid == rid:
                continue
            notes_name = f"WORKING_NOTES_{other_run['agent']}.md"
            other_notes = runs_dir / other_rid / notes_name
            link = run_dir / notes_name
            if not link.exists():
                # Create a symlink even if the file doesn't exist yet
                # (the agent will create it)
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


def normalize_uploaded_path(raw_path: str) -> str | None:
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
    return "/".join(parts)


# ---------------------------------------------------------------------------
# Provider state helpers
# ---------------------------------------------------------------------------

def provider_state_for_metadata(run: dict) -> dict:
    """Extract provider-specific state from a run dict."""
    state = {}
    if run.get("_codex_thread_id"):
        state["codex_thread_id"] = run["_codex_thread_id"]
    if run.get("_opencode_session_id"):
        state["opencode_session_id"] = run["_opencode_session_id"]
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
        f.write(json.dumps(event) + "\n")


def clear_output_log(challenge_id: str, run_id: str) -> None:
    """Clear the output log file for a fresh run."""
    out_path = _run_output_path(challenge_id, run_id)
    if out_path.exists():
        out_path.unlink()


def load_output_log(challenge_id: str, run_id: str) -> list[dict]:
    """Load saved output events from disk for a specific run."""
    out_path = _run_output_path(challenge_id, run_id)
    if not out_path.exists():
        return []
    events = []
    for line in out_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _load_legacy_output_log(challenge_id: str) -> list[dict]:
    """Load legacy output log (pre-runs format)."""
    out_path = _legacy_output_log_path(challenge_id)
    if not out_path.exists():
        return []
    events = []
    for line in out_path.read_text().splitlines():
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


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def load_settings() -> dict:
    """Load global settings from disk."""
    defaults = {
        "default_agent": DEFAULT_AGENT,
        "default_flag_format": "",
        "theme": "dark",
        "auto_submit_flags": False,
    }
    if SETTINGS_FILE.exists():
        try:
            loaded = json.loads(SETTINGS_FILE.read_text())
            if isinstance(loaded, dict):
                defaults.update({
                    k: v for k, v in loaded.items()
                    if k in defaults
                })
        except (json.JSONDecodeError, OSError):
            pass
    return defaults


def save_settings(settings: dict) -> None:
    """Persist global settings to disk."""
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))


# ---------------------------------------------------------------------------
# Metadata persistence
# ---------------------------------------------------------------------------

def _serialize_runs(challenge: dict) -> dict:
    """Serialize runs for metadata (strip non-serializable fields)."""
    serialized = {}
    for run_id, run in challenge["runs"].items():
        serialized[run_id] = {
            "id": run["id"],
            "agent": run["agent"],
            "model": run["model"],
            "effort": run.get("effort", ""),
            "status": run["status"],
            "error": run.get("error"),
            "duration_ms": run.get("duration_ms"),
            "solve_start": run.get("solve_start"),
            "provider_state": provider_state_for_metadata(run),
        }
    return serialized


def save_metadata(challenge: dict) -> None:
    """Persist challenge metadata to disk."""
    if challenge.get("_deleted"):
        return
    meta = {
        "id": challenge["id"],
        "name": challenge["name"],
        "description": challenge["description"],
        "flag_format": challenge["flag_format"],
        "mode": challenge["mode"],
        "autonomous": challenge.get("autonomous", False),
        "status": challenge["status"],
        "created_at": challenge["created_at"],
        "files": challenge["files"],
        "error": challenge.get("error"),
        "runs": _serialize_runs(challenge),
        "_plugin": challenge.get("_plugin", ""),
        "_remote_id": challenge.get("_remote_id", ""),
        "_source_url": challenge.get("_source_url", ""),
        "_connection_id": challenge.get("_connection_id", ""),
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
                        "agent": entry.get("agent", "") if isinstance(entry, dict) else str(entry),
                        "model": entry.get("model", "") if isinstance(entry, dict) else "",
                    }
                    for entry in parsed
                ]
        except json.JSONDecodeError:
            pass
    return [{"agent": a.strip(), "model": ""} for a in agents_str.split(",") if a.strip()]


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
                run_status = run_meta.get("status", "unknown")
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
                run["_codex_thread_id"] = provider_state.get(
                    "codex_thread_id"
                )
                run["_opencode_session_id"] = provider_state.get(
                    "opencode_session_id"
                )
                run["output_lines"] = _normalize_output_lines(
                    load_output_log(challenge_id, run_id),
                    run_agent,
                )
                runs[run_id] = run
        else:
            # Legacy format: migrate to single run
            old_agent = meta.get("agent", DEFAULT_AGENT)
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
            run["_opencode_session_id"] = provider_state.get(
                "opencode_session_id"
            )
            # Try legacy output log
            legacy_events = _load_legacy_output_log(challenge_id)
            run["output_lines"] = _normalize_output_lines(
                legacy_events, old_agent
            )
            # Migrate legacy output to run-specific file
            if legacy_events:
                out_path = _run_output_path(challenge_id, run_id)
                if not out_path.exists():
                    with out_path.open("w") as f:
                        for evt in legacy_events:
                            f.write(json.dumps(evt) + "\n")
            runs[run_id] = run

        challenge = {
            "id": challenge_id,
            "name": meta.get("name", f"Challenge {challenge_id}"),
            "description": meta.get("description", ""),
            "flag_format": meta.get("flag_format", ""),
            "mode": mode,
            "autonomous": meta.get("autonomous", False),
            "status": "pending",
            "created_at": meta.get(
                "created_at", datetime.now().isoformat()
            ),
            "files": meta.get("files", []),
            "error": meta.get("error"),
            "runs": runs,
            "_plugin": meta.get("_plugin", ""),
            "_remote_id": meta.get("_remote_id", ""),
            "_source_url": meta.get("_source_url", ""),
            "_connection_id": meta.get("_connection_id", ""),
        }
        challenge["status"] = derive_challenge_status(challenge)
        challenges[challenge_id] = challenge


load_challenges_from_disk()


# ---------------------------------------------------------------------------
# Auth and CSRF
# ---------------------------------------------------------------------------

def require_auth(request: Request) -> JSONResponse | None:
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return None


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


# ---------------------------------------------------------------------------
# Basic routes
# ---------------------------------------------------------------------------

async def index(request: Request) -> Response:
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(html_path.read_text())


async def login(request: Request) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    if err := _check_rate_limit(client_ip):
        return err

    body = await request.json()
    if body.get("password") == APP_PASSWORD:
        _login_attempts.pop(client_ip, None)
        csrf_token = secrets.token_hex(32)
        request.session["authenticated"] = True
        request.session["csrf_token"] = csrf_token
        return JSONResponse({"ok": True, "csrf_token": csrf_token})

    _login_attempts[client_ip].append(_time.monotonic())
    return JSONResponse({"error": "invalid password"}, status_code=403)


async def logout(request: Request) -> JSONResponse:
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

async def broadcast(challenge_id: str, run_id: str, data: dict):
    """Send data to a specific run's WebSocket clients."""
    challenge = challenges.get(challenge_id)
    if not challenge:
        return
    run = challenge["runs"].get(run_id)
    if not run:
        return
    dead = []
    for ws in list(run["ws_clients"]):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        run["ws_clients"].discard(ws)


async def broadcast_challenge(challenge_id: str, data: dict):
    """Send data to ALL runs' WebSocket clients (challenge-level updates)."""
    challenge = challenges.get(challenge_id)
    if not challenge:
        return
    for run in challenge["runs"].values():
        dead = []
        for ws in list(run["ws_clients"]):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            run["ws_clients"].discard(ws)


# ---------------------------------------------------------------------------
# Challenge listing
# ---------------------------------------------------------------------------

async def list_challenges(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    result = []
    for c in challenges.values():
        runs_summary = []
        for run in c["runs"].values():
            runs_summary.append({
                "id": run["id"],
                "agent": run["agent"],
                "model": run["model"],
                "status": run["status"],
                "error": run.get("error"),
                "duration_ms": run.get("duration_ms"),
            })
        result.append({
            "id": c["id"],
            "name": c["name"],
            "description": c["description"],
            "flag_format": c["flag_format"],
            "mode": c["mode"],
            "status": c["status"],
            "error": c.get("error"),
            "created_at": c["created_at"],
            "files": c["files"],
            "runs": runs_summary,
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return JSONResponse(result)


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
    autonomous = form.get("autonomous", "").strip() == "true"

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

    # Read uploaded files into memory
    file_data: dict[str, bytes] = {}
    for _, field in form.multi_items():
        if hasattr(field, "filename") and field.filename:
            safe_path = normalize_uploaded_path(field.filename)
            if not safe_path:
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
        # Files go to _files/ subdirectory
        files_dir = challenge_dir / "_files"
        files_dir.mkdir(parents=True, exist_ok=True)
        for rel_path, fdata in file_data.items():
            dest = files_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fdata)
    else:
        # Files go directly to challenge root
        for rel_path, fdata in file_data.items():
            dest = challenge_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fdata)

    # Create runs
    runs: dict[str, dict] = {}
    for entry in agent_entries:
        agent_name = entry["agent"]
        run_id = uuid.uuid4().hex[:8]
        run_model = entry.get("model") or model or resolved_default_model(agent_name)
        run_effort = normalize_effort_for_agent(agent_name, effort)
        run = make_run(
            run_id=run_id,
            agent=agent_name,
            model=run_model,
            effort=run_effort,
            status="solving",
        )
        runs[run_id] = run

        if is_parallel:
            setup_parallel_run_dir(challenge_id, run_id)

    # Set up cross-agent note visibility for parallel mode
    if is_parallel:
        setup_parallel_cross_notes(challenge_id, runs)

    challenge = {
        "id": challenge_id,
        "name": display_name,
        "description": description,
        "flag_format": flag_format,
        "mode": mode,
        "autonomous": autonomous,
        "status": "solving",
        "created_at": datetime.now().isoformat(),
        "files": sorted(file_data.keys()),
        "error": None,
        "runs": runs,
    }
    challenges[challenge_id] = challenge
    save_metadata(challenge)

    # Start all runs
    for run_id, run in runs.items():
        run["task"] = asyncio.create_task(
            run_agent_task(challenge_id, run_id)
        )

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

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            {"error": "Expected JSON body with preview_token"},
            status_code=400,
        )
    token = body.get("preview_token", "")
    if not token or token not in _bulk_previews:
        return JSONResponse(
            {"error": "Invalid or expired preview token"},
            status_code=400,
        )

    preview = _bulk_previews.pop(token)
    base_dir = preview["base_dir"]
    preview_folders = preview["folders"]

    try:
        global_flag_format = body.get("flag_format", "").strip()
        mode = body.get("mode", "single").strip()
        if mode not in VALID_MODES:
            mode = "single"

        # Determine agents with per-agent models
        agents_str = body.get("agents", "")
        if isinstance(agents_str, list):
            agents_str = json.dumps(agents_str)
        agents_str = str(agents_str).strip()
        agent_entries = parse_agents_field(agents_str)
        if not agent_entries:
            single_agent = body.get("agent", "").strip() or DEFAULT_AGENT
            agent_entries = [{"agent": single_agent, "model": ""}]

        # Validate agents
        agent_entries = [
            e for e in agent_entries if e["agent"] in VALID_AGENTS
        ]
        if not agent_entries:
            agent_entries = [{"agent": DEFAULT_AGENT, "model": ""}]

        if mode == "single":
            agent_entries = agent_entries[:1]

        model = body.get("model", "").strip()
        effort = body.get("effort", "").strip()
        autonomous = bool(body.get("autonomous", False))
        paused = bool(body.get("paused", False))
        challenges_cfg = body.get("challenges", [])

        is_parallel = mode == "parallel"
        created = []

        for cfg in challenges_cfg:
            if not cfg.get("enabled", True):
                continue
            folder_name = cfg.get("folder_name", "")
            folder_info = preview_folders.get(folder_name)
            if not folder_info:
                continue
            folder_dir = Path(folder_info["dir"])
            file_names = folder_info["files"]

            ch_name = cfg.get("name", "").strip() or folder_name
            ch_description = cfg.get("description", "").strip()
            ch_flag_format = (
                cfg.get("flag_format", "").strip()
                or global_flag_format
            )

            challenge_id = uuid.uuid4().hex[:12]
            challenge_dir = CHALLENGES_DIR / challenge_id
            challenge_dir.mkdir(parents=True)

            if is_parallel:
                setup_parallel_shared_dir(challenge_id)
                files_dest = challenge_dir / "_files"
                files_dest.mkdir(parents=True, exist_ok=True)
            else:
                files_dest = challenge_dir

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
                run_effort = normalize_effort_for_agent(agent_name, effort)
                run = make_run(
                    run_id=run_id,
                    agent=agent_name,
                    model=run_model,
                    effort=run_effort,
                    status=challenge_status,
                )
                runs[run_id] = run
                if is_parallel:
                    setup_parallel_run_dir(challenge_id, run_id)

            if is_parallel:
                setup_parallel_cross_notes(challenge_id, runs)

            challenge = {
                "id": challenge_id,
                "name": ch_name,
                "description": ch_description,
                "flag_format": ch_flag_format,
                "mode": mode,
                "autonomous": autonomous,
                "status": challenge_status,
                "created_at": datetime.now().isoformat(),
                "files": file_names,
                "error": None,
                "runs": runs,
            }
            challenges[challenge_id] = challenge
            save_metadata(challenge)

            if challenge_status == "solving":
                for run_id, run in runs.items():
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

    if target_run_id:
        # Restart a specific run
        run = challenge["runs"].get(target_run_id)
        if not run:
            return JSONResponse(
                {"error": "run not found"}, status_code=404
            )
        run["status"] = "solving"
        run["output_lines"] = []
        clear_output_log(challenge_id, target_run_id)
        run["task"] = asyncio.create_task(
            run_agent_task(challenge_id, target_run_id)
        )
    else:
        # Restart all runs
        for run_id, run in challenge["runs"].items():
            run["status"] = "solving"
            run["output_lines"] = []
            clear_output_log(challenge_id, run_id)
            run["task"] = asyncio.create_task(
                run_agent_task(challenge_id, run_id)
            )

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

    for run_id, run in runs_to_stop.items():
        if not run:
            continue
        proc = run.get("process")
        if proc and proc.returncode is None:
            run["_stop_reason"] = "user_stop"
            proc.terminate()
            run["status"] = "failed"
            stop_event = {
                "type": "system",
                "message": "Agent stopped by user.",
            }
            run["output_lines"].append(stop_event)
            append_output_event(challenge_id, run_id, stop_event)
            await broadcast(challenge_id, run_id, stop_event)

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    return JSONResponse({"status": challenge["status"]})


async def steer_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    body = await request.json()
    message = body.get("message", "").strip()
    if not message:
        return JSONResponse(
            {"error": "message required"}, status_code=400
        )

    target_run_id = body.get("run_id")

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

    # Stop current process if running
    proc = run.get("process")
    if proc and proc.returncode is None:
        run["_stop_reason"] = "steer"
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()

    steer_event = {"type": "user_steer", "message": message}
    run["output_lines"].append(steer_event)
    append_output_event(challenge_id, target_run_id, steer_event)
    await broadcast(challenge_id, target_run_id, steer_event)

    run["status"] = "solving"
    run["error"] = None
    run["task"] = asyncio.create_task(
        run_agent_task(
            challenge_id, target_run_id, continue_msg=message
        )
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

    body = await request.json()
    run_id = body.get("run_id", "")

    if run_id and run_id in challenge["runs"]:
        target_runs = [challenge["runs"][run_id]]
    else:
        # Mark the first completed/solving run
        target_runs = [
            r for r in challenge["runs"].values()
            if r["status"] in ("completed", "solving")
        ][:1]

    if not target_runs:
        return JSONResponse(
            {"error": "no eligible run to mark as solved"},
            status_code=409,
        )

    # Collect run IDs for the solved run(s)
    solved_run_ids = []
    for run_id, run in challenge["runs"].items():
        if run in target_runs:
            run["status"] = "solved"
            run["error"] = None
            solved_run_ids.append(run_id)

    # Auto-stop other runs in parallel mode
    if challenge["mode"] == "parallel":
        solved_run = target_runs[0]
        for other_id, other_run in challenge["runs"].items():
            if other_run is solved_run:
                continue
            proc = other_run.get("process")
            if proc and proc.returncode is None:
                other_run["_stop_reason"] = "sibling_solved"
                proc.terminate()
                other_run["status"] = "failed"
                other_run["process"] = None
                stop_event = {
                    "type": "system",
                    "message": (
                        f"Stopped: {solved_run['agent']} solved "
                        "the challenge."
                    ),
                }
                other_run["output_lines"].append(stop_event)
                append_output_event(
                    challenge_id, other_id, stop_event
                )
                await broadcast(
                    challenge_id, other_id, stop_event
                )
                await broadcast(challenge_id, other_id, {
                    "type": "run_status",
                    "run_id": other_id,
                    "status": "failed",
                })

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    for rid in solved_run_ids:
        await broadcast(challenge_id, rid, {
            "type": "run_status",
            "run_id": rid,
            "status": "solved",
        })
    await broadcast_challenge(challenge_id, {
        "type": "challenge_status",
        "status": challenge["status"],
    })
    return JSONResponse({"status": challenge["status"]})


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
        proc = run.get("process")
        if proc and proc.returncode is None:
            run["_stop_reason"] = "deleted"
            proc.terminate()

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
    is_parallel = challenge["mode"] == "parallel"

    if run_id and is_parallel and run_id in challenge["runs"]:
        return challenge_dir / "_runs" / run_id

    # In parallel mode without a run_id, show the shared _files/ dir
    # instead of the challenge root (which exposes _files/ and _runs/)
    if is_parallel:
        files_dir = challenge_dir / "_files"
        if files_dir.is_dir():
            return files_dir

    return challenge_dir


async def list_files(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)

    run_id = request.query_params.get("run_id")
    challenge_dir = _resolve_file_dir(challenge_id, run_id)
    if not challenge_dir or not challenge_dir.exists():
        return JSONResponse({"error": "not found"}, status_code=404)

    files = []
    for p in sorted(challenge_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(challenge_dir))
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

    run_id = request.query_params.get("run_id")
    challenge_dir = _resolve_file_dir(challenge_id, run_id)
    if not challenge_dir:
        return JSONResponse({"error": "not found"}, status_code=404)

    full_path = (challenge_dir / file_path).resolve()

    try:
        full_path.relative_to(challenge_dir.resolve())
    except ValueError:
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

    run_id = request.query_params.get("run_id")
    challenge_dir = _resolve_file_dir(challenge_id, run_id)
    if not challenge_dir:
        return JSONResponse({"error": "not found"}, status_code=404)

    full_path = (challenge_dir / file_path).resolve()

    try:
        full_path.relative_to(challenge_dir.resolve())
    except ValueError:
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



# ---------------------------------------------------------------------------
# Build prompt
# ---------------------------------------------------------------------------

def build_prompt(challenge: dict, run: dict) -> str:
    """Build the CTF solving prompt."""
    agent_name = run["agent"]
    is_parallel = challenge["mode"] == "parallel"

    # Determine notes filename
    if is_parallel:
        notes_file = f"WORKING_NOTES_{agent_name}.md"
    else:
        notes_file = "WORKING_NOTES.md"

    parts = [
        "You are solving a CTF challenge.",
        f"Read {_METHODOLOGY_SKILL} first and follow it for the full "
        "solve. It contains the triage workflow and routes you to the "
        "correct category and tool skills.",
        "",
        "Key tool rules:",
        "- For ANY binary (ELF/PE): use IDA Pro for static analysis "
        f"(read {_SKILLS_ROOT}/tools/ida/SKILL.md). Do NOT use objdump "
        "or readelf as primary analysis — IDA is installed and licensed.",
        "- For runtime debugging: use libdebug (read "
        f"{_SKILLS_ROOT}/tools/libdebug/SKILL.md), not raw GDB.",
        "- For kernel challenges: use GDB+GEF via MCP (read "
        f"{_SKILLS_ROOT}/tools/kernel-gef/SKILL.md).",
        "- Run ctfgrep first for a quick flag search across encodings.",
        "",
        f"Maintain `{notes_file}` with this structure:",
        "```",
        f"# Working Notes — {agent_name}",
        "## Challenge Understanding",
        "## Hypotheses",
        "[ ] untested  [x] failed  [>] active",
        "## Key Findings",
        "## Tools & Techniques Tried",
        "## Dead Ends",
        "## Next Steps",
        "```",
        "Update this file as you work. Your context may be compacted "
        "during long solves — this file is your persistent memory. "
        "If you lose context, re-read it first.",
    ]

    # Parallel mode: team awareness
    if is_parallel:
        teammates = []
        for rid, r in challenge["runs"].items():
            if r["agent"] != agent_name:
                teammates.append(r["agent"])
        if teammates:
            parts.extend([
                "",
                f"You are working in a team with: {', '.join(teammates)}.",
                "Work independently first — try your own approaches before "
                "looking at what others are doing.",
                "",
                "Teammates' notes are available at:",
            ])
            for t in teammates:
                parts.append(f"  - WORKING_NOTES_{t}.md")
            parts.extend([
                "",
                "Only read teammates' notes if you have exhausted your "
                "own ideas or are completely stuck. Try your own approaches "
                "first.",
                "",
                "A shared file `_shared/BREAKTHROUGHS.md` exists. Append "
                "to it ONLY when you have made a significant, validated "
                "breakthrough — something you are certain about and have "
                "confirmed works (e.g., found the correct vulnerability, "
                "extracted a key, decoded the flag format). Do NOT post "
                "hypotheses, partial findings, or anything you haven't "
                "verified. False breakthroughs waste your teammates' time.",
            ])

    parts.extend([
        "",
        f"Challenge: {challenge['name']}",
    ])
    if challenge["description"]:
        parts.append(f"Description: {challenge['description']}")
    if challenge["flag_format"]:
        parts.append(f"Flag format: {challenge['flag_format']}")
    else:
        parts.append(
            "No flag format specified. Look for common "
            "formats like flag{{...}}, FLAG{{...}}, "
            "CTF{{...}}, or ask."
        )
    parts.extend([
        "",
        "The challenge files are in the current directory.",
        "Do not inspect parent directories, repository root files, .git metadata, "
        "or unrelated system paths.",
        "If the current directory has no challenge files, report that clearly and stop. "
        "Do not search elsewhere for surrogate targets.",
        "Keep command output bounded: avoid unbounded recursive listings, and use "
        "targeted commands with limits (for example, head/tail).",
    ])
    if challenge.get("autonomous"):
        parts.extend([
            "",
            "IMPORTANT: Do not stop or ask for guidance. Keep "
            "trying different approaches until you find the "
            "flag. If one technique fails, move on to the "
            "next. Exhaust all options before giving up.",
        ])

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Run agent
# ---------------------------------------------------------------------------

def _try_auto_submit_flag(
    challenge_id: str, run_id: str, event: dict, challenge: dict
) -> None:
    """Check event for flags and auto-submit if enabled."""
    settings = load_settings()
    if not settings.get("auto_submit_flags"):
        return

    plugin_name = challenge.get("_plugin")
    remote_id = challenge.get("_remote_id")
    if not plugin_name or not remote_id:
        return

    plugin = get_plugin(plugin_name)
    if not plugin:
        return

    # Extract text from assistant message
    msg = event.get("message", {})
    text_parts = []
    for block in msg.get("content", []):
        if block.get("type") == "text" and block.get("text"):
            text_parts.append(block["text"])
    if not text_parts:
        return

    full_text = "\n".join(text_parts)
    flag = detect_flag(full_text, challenge.get("flag_format", ""))
    if not flag:
        return

    run = challenge["runs"].get(run_id)
    if not run:
        return

    # Guard: track which flags have been submitted or are in-flight
    submitted = run.setdefault("_flags_submitted", set())
    if flag in submitted:
        return
    # Mark immediately to prevent duplicate concurrent submissions
    submitted.add(flag)

    # Find saved connection config
    config = {}
    source_url = challenge.get("_source_url", "")
    if source_url:
        conn_id = challenge.get("_connection_id", "")
        for conn in load_connections():
            if conn_id and conn.get("id") == conn_id:
                config = conn["config"]
                break
            if conn.get("plugin") == plugin_name and conn.get("config", {}).get("url") == source_url:
                config = conn["config"]
                break

    if not config:
        return

    async def _submit():
        try:
            result = await plugin.submit_flag(config, remote_id, flag)
            submit_event = {
                "type": "system",
                "subtype": "flag_submit",
                "message": (
                    f"Auto-submitted flag: {flag}\n"
                    f"Result: {'Correct!' if result.correct else result.message}"
                ),
            }
            run["output_lines"].append(submit_event)
            append_output_event(challenge_id, run_id, submit_event)
            await broadcast(challenge_id, run_id, submit_event)

            if result.correct:
                run["status"] = "solved"
                run["error"] = None
                challenge["status"] = derive_challenge_status(challenge)
                save_metadata(challenge)
                await broadcast(challenge_id, run_id, {
                    "type": "run_status",
                    "run_id": run_id,
                    "status": "solved",
                })
                await broadcast_challenge(challenge_id, {
                    "type": "challenge_status",
                    "status": challenge["status"],
                })
            else:
                # Allow resubmission of different flags
                submitted.discard(flag)
                wrong_event = {
                    "type": "system",
                    "message": (
                        f"Flag '{flag}' was incorrect: {result.message}. "
                        "Keep trying."
                    ),
                }
                run["output_lines"].append(wrong_event)
                append_output_event(challenge_id, run_id, wrong_event)
                await broadcast(challenge_id, run_id, wrong_event)
        except Exception:
            submitted.discard(flag)

    asyncio.create_task(_submit())


async def run_agent_task(
    challenge_id: str,
    run_id: str,
    continue_msg: str | None = None,
):
    """Run an agent for a specific run of a challenge."""
    challenge = challenges[challenge_id]
    run = challenge["runs"][run_id]
    run_cwd = get_run_cwd(challenge_id, run)
    run["solve_start"] = _time.monotonic()
    provider = get_provider(run["agent"])

    if continue_msg:
        prompt = (
            f"{continue_msg}\n\n"
            "Continue working on the CTF challenge. Do not stop after "
            "addressing the above — keep going until you find the flag "
            "or exhaust all approaches. Read your WORKING_NOTES if you "
            "need to recall what was tried."
        )
    else:
        prompt = build_prompt(challenge, run)

    if continue_msg:
        sys_event = {
            "type": "system",
            "message": f"Continuing {provider.label} conversation "
            "with guidance...",
        }
    else:
        sys_event = {
            "type": "system",
            "message": f"{provider.label} agent starting...",
        }
    run["output_lines"].append(sys_event)
    append_output_event(challenge_id, run_id, sys_event)
    await broadcast(challenge_id, run_id, sys_event)

    env = os.environ.copy()
    env["IS_SANDBOX"] = "1"

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
        "autonomous": challenge.get("autonomous", False),
        "_codex_thread_id": run.get("_codex_thread_id"),
        "_opencode_session_id": run.get("_opencode_session_id"),
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
        limit=2 ** 24,  # 16 MB — default 64 KB is too small for large JSON events
    )
    run["process"] = proc
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

                run["output_lines"].append(event)
                append_output_event(challenge_id, run_id, event)
                await broadcast(challenge_id, run_id, event)

                # Auto-submit flag detection
                if (
                    not run.get("_flag_submitted")
                    and event.get("type") == "assistant"
                ):
                    _try_auto_submit_flag(
                        challenge_id, run_id, event, challenge
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
                    other_proc = other_run.get("process")
                    if other_proc and other_proc.returncode is None:
                        other_proc.terminate()
                        other_run["_stop_reason"] = "sibling_solved"
                        other_run["status"] = "failed"
                        other_run["error"] = None
        elif run["status"] == "solved":
            # Auto-submit marked it solved during streaming
            if challenge["mode"] == "parallel":
                for other_id, other_run in challenge["runs"].items():
                    if other_id == run_id:
                        continue
                    other_proc = other_run.get("process")
                    if other_proc and other_proc.returncode is None:
                        other_proc.terminate()
                        other_run["_stop_reason"] = "sibling_solved"
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
            run["output_lines"].append(err_event)
            append_output_event(challenge_id, run_id, err_event)
            await broadcast(challenge_id, run_id, err_event)

    except Exception as exc:
        stop_reason = run.pop("_stop_reason", None)
        if not stop_reason:
            run["status"] = "failed"
            run["error"] = str(exc)
            err_event = {"type": "error", "message": str(exc)}
            run["output_lines"].append(err_event)
            append_output_event(challenge_id, run_id, err_event)
            await broadcast(challenge_id, run_id, err_event)
    finally:
        # Only clear process if it's still OUR process (not a replacement
        # started by a steer/handoff while we were unwinding)
        if run.get("process") is proc:
            run["process"] = None
        if run.get("solve_start") and run.get("process") is None:
            elapsed = _time.monotonic() - run["solve_start"]
            run["duration_ms"] = int(elapsed * 1000)
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
        })
        await broadcast_challenge(challenge_id, {
            "type": "challenge_status",
            "status": challenge["status"],
        })


# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------

async def challenge_ws(websocket: WebSocket):
    if not websocket.session.get("authenticated"):
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

    # Send history
    for event in run["output_lines"]:
        await websocket.send_json(event)

    # Send current run status
    await websocket.send_json({
        "type": "run_status", "run_id": run_id,
        "status": run["status"],
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


# ---------------------------------------------------------------------------
# Settings / Agents / Usage
# ---------------------------------------------------------------------------

async def get_settings(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse(load_settings())


def _static_provider_metadata(provider) -> dict:
    """Return provider metadata using static models only (no PTY discovery).

    This avoids the 3-8 second PTY subprocess that _discover_models_from_cli
    spawns for Claude and Copilot. The static models list is always available
    and sufficient for the UI.
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
        "autonomous_default": provider.autonomous_default,
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
    body = await request.json()
    settings = load_settings()
    if "default_agent" in body:
        agent = body["default_agent"]
        if agent not in VALID_AGENTS:
            return JSONResponse(
                {"error": f"invalid agent: {agent}"},
                status_code=400,
            )
        settings["default_agent"] = agent
    if "default_flag_format" in body:
        settings["default_flag_format"] = str(
            body["default_flag_format"]
        )
    if "theme" in body:
        theme = str(body["theme"])
        if theme in ("dark", "light"):
            settings["theme"] = theme
    if "auto_submit_flags" in body:
        settings["auto_submit_flags"] = bool(body["auto_submit_flags"])
    save_settings(settings)
    return JSONResponse(settings)


def get_challenge_stats() -> dict:
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
            if run.get("duration_ms"):
                bucket["total_duration_ms"] += run["duration_ms"]
    return stats


async def get_usage(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    result = {
        "agents": {
            name: provider.get_usage_data()
            for name, provider in PROVIDERS.items()
        },
        "challenges": get_challenge_stats(),
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

    body = await request.json()
    plugin_name = body.get("plugin", "")
    config = body.get("config", {})

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

    body = await request.json()
    plugin_name = body.get("plugin", "")
    config = body.get("config", {})

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
                "files": [
                    {"name": f.name, "url": f.url}
                    for f in c.files
                ],
                "solved": c.solved,
                "tags": c.tags,
            }
            for c in remote_challenges
        ])
    except Exception as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )


async def plugin_import_challenges(request: Request) -> JSONResponse:
    """Download files and create challenges from a plugin fetch."""
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body = await request.json()
    plugin_name = body.get("plugin", "")
    config = body.get("config", {})
    selected = body.get("challenges", [])
    mode = body.get("mode", "single")
    if mode not in VALID_MODES:
        mode = "single"
    agents = body.get("agents", "").strip()
    model = body.get("model", "")
    effort = body.get("effort", "")
    autonomous = bool(body.get("autonomous", False))
    flag_format = body.get("flag_format", "").strip()
    paused = bool(body.get("paused", False))

    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Unknown plugin: {plugin_name}"},
            status_code=404,
        )

    # Pre-compute connection ID for challenge linkage
    _ident = config.get("username") or ""
    if not _ident:
        for _k in ("token", "team_token"):
            _v = config.get(_k, "")
            if _v:
                _ident = _v[:8] + "..."
                break
    _conn_id = f"{plugin_name}:{config.get('url', '')}:{_ident}"

    created = []
    for ch_cfg in selected:
        if not ch_cfg.get("enabled", True):
            continue

        ch_name = ch_cfg.get("name", "")
        ch_description = ch_cfg.get("description", "")
        ch_remote_id = ch_cfg.get("remote_id", "")
        ch_category = ch_cfg.get("category", "")
        ch_flag_format = ch_cfg.get("flag_format", "") or flag_format
        remote_files = ch_cfg.get("files", [])

        # Download files (preserve paths, report failures)
        file_data: dict[str, bytes] = {}
        download_errors: list[str] = []
        for rf in remote_files:
            try:
                data = await plugin.download_file(
                    config,
                    RemoteFile(name=rf["name"], url=rf["url"]),
                )
                safe_name = normalize_uploaded_path(rf["name"])
                if not safe_name:
                    safe_name = rf["name"].split("/")[-1].split("?")[0]
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
                        f"{rf['name']}: renamed to {safe_name} (path collision)"
                    )
                file_data[safe_name] = data
            except Exception as exc:
                download_errors.append(
                    f"{rf['name']}: {exc}"
                )

        if not file_data and download_errors:
            created.append({
                "id": "",
                "name": ch_name,
                "status": "error",
                "error": f"All downloads failed: {'; '.join(download_errors)}",
            })
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

        challenge_id = uuid.uuid4().hex[:12]
        challenge_dir = CHALLENGES_DIR / challenge_id

        if mode == "parallel":
            setup_parallel_shared_dir(challenge_id)
            files_dir = challenge_dir / "_files"
            files_dir.mkdir(parents=True)
            for fname, fdata in file_data.items():
                dest = files_dir / fname
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(fdata)
        else:
            challenge_dir.mkdir(parents=True)
            for fname, fdata in file_data.items():
                dest = challenge_dir / fname
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(fdata)

        runs = {}
        challenge_status = "pending" if paused else "solving"
        for entry in agent_entries:
            agent_name = entry["agent"]
            run_id = uuid.uuid4().hex[:8]
            run_model = entry.get("model") or model or resolved_default_model(agent_name)
            run_effort = normalize_effort_for_agent(agent_name, effort)
            runs[run_id] = make_run(
                run_id=run_id,
                agent=agent_name,
                model=run_model,
                effort=run_effort,
                status=challenge_status,
            )
            if mode == "parallel":
                setup_parallel_run_dir(challenge_id, run_id)

        if mode == "parallel":
            setup_parallel_cross_notes(challenge_id, runs)

        challenge = {
            "id": challenge_id,
            "name": ch_name,
            "description": ch_description,
            "flag_format": ch_flag_format,
            "mode": mode,
            "autonomous": autonomous,
            "status": challenge_status,
            "created_at": datetime.now().isoformat(),
            "files": sorted(file_data.keys()),
            "error": None,
            "runs": runs,
            "_plugin": plugin_name,
            "_remote_id": ch_remote_id,
            "_source_url": config.get("url", ""),
            "_connection_id": _conn_id,
        }
        challenges[challenge_id] = challenge
        save_metadata(challenge)

        if challenge_status == "solving":
            for run_id, run in runs.items():
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

    # Save connection for future syncs
    if created:
        connections = load_connections()
        # Build identity from URL + account info to distinguish
        # multiple accounts on the same platform
        identity = config.get("username") or ""
        if not identity:
            for key in ("token", "team_token"):
                val = config.get(key, "")
                if val:
                    identity = val[:8] + "..."
                    break
        conn_id = f"{plugin_name}:{config.get('url', '')}:{identity}"
        label_suffix = f" ({identity})" if identity and "..." not in identity else ""
        existing = next(
            (c for c in connections if c.get("id") == conn_id), None
        )
        if existing:
            existing["config"] = config
            existing["last_sync"] = datetime.now().isoformat()
        else:
            connections.append({
                "id": conn_id,
                "plugin": plugin_name,
                "label": f"{get_plugin(plugin_name).label} — {config.get('url', '')}{label_suffix}",
                "config": config,
                "last_sync": datetime.now().isoformat(),
            })
        save_connections(connections)

    return JSONResponse({"created": created}, status_code=201)


async def plugin_submit_flag(request: Request) -> JSONResponse:
    """Submit a flag to the remote platform.

    Resolves connection config from the challenge's _connection_id,
    falling back to _source_url lookup if needed.
    """
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body = await request.json()
    challenge_id = body.get("challenge_id", "")
    flag = body.get("flag", "").strip()

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

    # Resolve config from saved connections
    config = {}
    conn_id = challenge.get("_connection_id", "")
    source_url = challenge.get("_source_url", "")
    for conn in load_connections():
        if conn_id and conn.get("id") == conn_id:
            config = conn["config"]
            break
        if (
            conn.get("plugin") == plugin_name
            and conn.get("config", {}).get("url") == source_url
        ):
            config = conn["config"]
            break

    if not config:
        return JSONResponse(
            {"error": "No saved connection found for this challenge. "
             "Re-import or sync to save credentials."},
            status_code=400,
        )

    try:
        result = await plugin.submit_flag(config, remote_id, flag)

        # If correct, mark the challenge as solved
        if result.correct:
            for run in challenge["runs"].values():
                if run["status"] in ("solving", "completed"):
                    run["status"] = "solved"
                    run["error"] = None
                    break
            challenge["status"] = derive_challenge_status(challenge)
            save_metadata(challenge)

        return JSONResponse({
            "correct": result.correct,
            "message": result.message,
        })
    except Exception as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )


async def list_connections(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse(load_connections())


async def delete_connection(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body = await request.json()
    conn_id = body.get("id", "")
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

    body = await request.json()
    conn_id = body.get("id", "")

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
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )

    # Filter out already-imported challenges
    imported_ids = _imported_remote_ids(
        plugin_name, config.get("url", "")
    )
    new_challenges = [
        c for c in remote_challenges
        if str(c.remote_id) not in imported_ids
    ]

    # Update last_sync
    conn["last_sync"] = datetime.now().isoformat()
    save_connections(connections)

    return JSONResponse({
        "connection": {
            "id": conn["id"],
            "plugin": conn["plugin"],
            "label": conn["label"],
        },
        "total": len(remote_challenges),
        "new": len(new_challenges),
        "challenges": [
            {
                "remote_id": c.remote_id,
                "name": c.name,
                "description": c.description,
                "category": c.category,
                "points": c.points,
                "files": [
                    {"name": f.name, "url": f.url}
                    for f in c.files
                ],
                "solved": c.solved,
                "tags": c.tags,
            }
            for c in new_challenges
        ],
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


def _build_wg_server_conf(
    client_public_key: str,
    client_networks: str,
    dns_forward: bool,
) -> str:
    server_private_key = WG_SERVER_PRIVATE_KEY.read_text().strip()
    allowed_ips = f"{VPN_SUBNET}.2/32"
    if client_networks.strip():
        allowed_ips += f", {client_networks.strip()}"
    egress_iface_cmd = "$(ip -4 route list default | awk '{print $5; exit}')"

    conf = f"""[Interface]
# dns_forward={"true" if dns_forward else "false"}
Address = {VPN_SUBNET}.1/24
ListenPort = 51820
PrivateKey = {server_private_key}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {egress_iface_cmd} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {egress_iface_cmd} -j MASQUERADE

[Peer]
PublicKey = {client_public_key}
AllowedIPs = {allowed_ips}
"""
    return conf


def _build_wg_client_conf(
    client_private_key_placeholder: str,
    client_networks: str,
    dns_forward: bool,
) -> str:
    server_public_key = WG_SERVER_PUBLIC_KEY.read_text().strip()
    server_ip = _get_server_public_ip()

    dns_line = f"DNS = {VPN_SUBNET}.1" if dns_forward else ""
    # Client routes the VPN subnet + internal networks through the tunnel
    allowed_ips = f"{VPN_SUBNET}.0/24"
    if client_networks.strip():
        allowed_ips += f", {client_networks.strip()}"

    conf = f"""[Interface]
Address = {VPN_SUBNET}.2/24
PrivateKey = {client_private_key_placeholder}
{dns_line}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_ip}:51820
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    return conf


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
        f"listen-address={VPN_SUBNET}.1\n"
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

    body = await request.json()
    client_public_key = body.get("client_public_key", "").strip()
    client_networks = body.get("client_networks", "").strip()
    dns_forward = bool(body.get("dns_forward", True))

    if not client_public_key:
        return JSONResponse(
            {"error": "client_public_key required"}, status_code=400
        )

    # Validate key format (base64, 44 chars with =)
    if len(client_public_key) != 44 or not client_public_key.endswith("="):
        return JSONResponse(
            {"error": "Invalid WireGuard public key format"},
            status_code=400,
        )

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
        "<YOUR_PRIVATE_KEY>", client_networks, dns_forward
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

    body = await request.json()
    action = body.get("action", "").strip()

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


@asynccontextmanager
async def lifespan(app):
    yield
    for challenge in challenges.values():
        for run in challenge["runs"].values():
            proc = run.get("process")
            if proc and proc.returncode is None:
                run["_stop_reason"] = "shutdown"
                proc.terminate()
    for preview in _bulk_previews.values():
        shutil.rmtree(preview["base_dir"], ignore_errors=True)
    _bulk_previews.clear()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

routes = [
    Route("/", index),
    Route("/api/login", login, methods=["POST"]),
    Route("/api/logout", logout, methods=["POST"]),
    Route("/api/csrf-token", csrf_token, methods=["GET"]),
    Route("/api/agents", list_agents, methods=["GET"]),
    Route("/api/usage", get_usage, methods=["GET"]),
    Route("/api/vpn", vpn_status, methods=["GET"]),
    Route("/api/vpn/configure", vpn_configure, methods=["POST"]),
    Route("/api/vpn/toggle", vpn_toggle, methods=["POST"]),
    Route("/api/plugins", list_plugins, methods=["GET"]),
    Route("/api/plugins/test", plugin_test_connection, methods=["POST"]),
    Route("/api/plugins/fetch", plugin_fetch_challenges, methods=["POST"]),
    Route("/api/plugins/import", plugin_import_challenges, methods=["POST"]),
    Route("/api/plugins/submit-flag", plugin_submit_flag, methods=["POST"]),
    Route("/api/connections", list_connections, methods=["GET"]),
    Route("/api/connections/delete", delete_connection, methods=["POST"]),
    Route("/api/connections/sync", sync_connection, methods=["POST"]),
    Route("/api/settings", get_settings, methods=["GET"]),
    Route("/api/settings", update_settings, methods=["PUT"]),
    Route("/api/challenges", list_challenges, methods=["GET"]),
    Route("/api/challenges", create_challenge, methods=["POST"]),
    Route(
        "/api/challenges/bulk-preview",
        bulk_preview,
        methods=["POST"],
    ),
    Route("/api/challenges/bulk", bulk_upload, methods=["POST"]),
    Route("/api/challenges/{id}/solve", solve_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/stop", stop_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/steer", steer_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/unsolve", unsolve_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/mark-solved", mark_solved, methods=["POST"]),
    Route("/api/challenges/{id}", delete_challenge, methods=["DELETE"]),
    Route("/api/challenges/{id}/files", list_files, methods=["GET"]),
    Route("/api/challenges/{id}/files/{path:path}", get_file, methods=["GET"]),
    Route("/api/challenges/{id}/download/{path:path}", download_file, methods=["GET"]),
    WebSocketRoute("/ws/{id}/{run_id}", challenge_ws),
    Mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    ),
]

app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[
        Middleware(
            SessionMiddleware,
            secret_key=SESSION_SECRET,
            max_age=86400,
            session_cookie="ctf_session",
            same_site="strict",
            https_only=TLS_ENABLED,
        ),
    ],
)

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
