#!/usr/bin/env python3
"""CTF Challenge Solver Web App.

Spawns CLI coding agents to solve CTF challenges, streaming JSONL
output to authenticated users via WebSocket.

Supports 4 solving modes:
- single: One run, no manager.
- single_managed: One active run with manager (STEER, HANDOFF, SHELVE).
- parallel: Multiple runs (one per agent), no manager. Auto-stop on solve.
- parallel_managed: Multiple runs with manager (WAIT, SUMMARIZE, SHELVE).
"""

import asyncio
import base64
import json
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
except ImportError:
    from plugins import get_plugins, get_plugin  # type: ignore

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

VALID_MODES = {"single", "single_managed", "parallel", "parallel_managed"}

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
    if "solved" in statuses:
        return "solved"
    if "solving" in statuses:
        return "solving"
    if "shelved" in statuses and not (statuses - {"shelved", "failed"}):
        return "shelved"
    if statuses <= {"failed"}:
        return "failed"
    if statuses <= {"pending"}:
        return "pending"
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
    if challenge["mode"] in ("parallel", "parallel_managed"):
        return CHALLENGES_DIR / challenge_id / "_runs" / run["id"]
    return CHALLENGES_DIR / challenge_id


def setup_parallel_run_dir(challenge_id: str, run_id: str) -> Path:
    """Create run directory with symlinks to challenge files."""
    files_dir = CHALLENGES_DIR / challenge_id / "_files"
    run_dir = CHALLENGES_DIR / challenge_id / "_runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    if files_dir.exists():
        for item in files_dir.iterdir():
            link = run_dir / item.name
            if not link.exists():
                link.symlink_to(item)
    return run_dir


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


def _default_manager_state() -> dict:
    return {
        "steer_count": 0,
        "last_summary": "",
        "shelve_reason": None,
        "review_history": [],
    }


def manager_state_for_metadata(challenge: dict) -> dict:
    state = challenge.get("manager", {})
    return {
        "steer_count": state.get("steer_count", 0),
        "last_summary": state.get("last_summary", ""),
        "shelve_reason": state.get("shelve_reason"),
        "review_history": state.get("review_history", []),
    }


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
        "manager_interval": 10,
        "manager_agent": DEFAULT_AGENT,
        "manager_model": "sonnet",
        "manager_effort": "",
        "manager_min_solve_time": 5,
        "manager_agent_pool": [
            {"agent": a, "model": ""} for a in VALID_AGENTS
        ],
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
        "manager": manager_state_for_metadata(challenge),
        "runs": _serialize_runs(challenge),
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
            "manager": {
                **_default_manager_state(),
                **meta.get("manager", {}),
            },
            "runs": runs,
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
            "manager": manager_state_for_metadata(c),
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

    # For single modes, only use first agent
    if mode in ("single", "single_managed"):
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

    is_parallel = mode in ("parallel", "parallel_managed")

    if is_parallel:
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
        "manager": _default_manager_state(),
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
            flat_name = filename.replace("/", "_")
            (folder_dir / flat_name).write_bytes(raw)
            file_names.append(flat_name)
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

        if mode in ("single", "single_managed"):
            agent_entries = agent_entries[:1]

        model = body.get("model", "").strip()
        effort = body.get("effort", "").strip()
        autonomous = bool(body.get("autonomous", False))
        paused = bool(body.get("paused", False))
        challenges_cfg = body.get("challenges", [])

        is_parallel = mode in ("parallel", "parallel_managed")
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
                files_dest = challenge_dir / "_files"
                files_dest.mkdir(parents=True, exist_ok=True)
            else:
                files_dest = challenge_dir

            for fname in file_names:
                src = folder_dir / fname
                if src.exists():
                    shutil.copy2(src, files_dest / fname)

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
                "manager": _default_manager_state(),
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
# Solve / Stop / Steer / Unshelve / Unsolve / Delete
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


async def unshelve_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    if challenge["status"] != "shelved":
        return JSONResponse(
            {"error": "challenge is not shelved"}, status_code=409
        )

    manager_state = challenge.get("manager", {})
    last_summary = manager_state.get("last_summary", "")
    continue_msg = last_summary if last_summary else None

    for run_id, run in challenge["runs"].items():
        if run["status"] == "shelved":
            unshelve_event = {
                "type": "system",
                "message": "Challenge un-shelved by user.",
            }
            run["output_lines"].append(unshelve_event)
            append_output_event(challenge_id, run_id, unshelve_event)
            await broadcast(challenge_id, run_id, unshelve_event)

            run["status"] = "solving"
            run["error"] = None
            run["task"] = asyncio.create_task(
                run_agent_task(
                    challenge_id, run_id, continue_msg=continue_msg
                )
            )

    manager_state["shelve_reason"] = None
    challenge["manager"] = manager_state
    challenge["error"] = None
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

    changed = False
    for run in challenge["runs"].values():
        if run["status"] == "solved":
            run["status"] = "failed"
            changed = True

    if not changed:
        return JSONResponse(
            {"error": "no solved runs to unsolve"}, status_code=409
        )

    challenge["status"] = derive_challenge_status(challenge)
    save_metadata(challenge)
    await broadcast_challenge(challenge_id, {
        "type": "status",
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

    # Stop all runs
    for run in challenge["runs"].values():
        proc = run.get("process")
        if proc and proc.returncode is None:
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
    if (
        run_id
        and challenge["mode"] in ("parallel", "parallel_managed")
        and run_id in challenge["runs"]
    ):
        return CHALLENGES_DIR / challenge_id / "_runs" / run_id
    return CHALLENGES_DIR / challenge_id


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
# Manager agent
# ---------------------------------------------------------------------------

def _tool_summary_for_log(name: str, input_data: dict) -> str:
    """One-line summary of a tool call for the manager log."""
    if name == "Bash":
        return input_data.get("description") or str(
            input_data.get("command", "")
        )[:120]
    if name in ("Read", "Write", "Edit"):
        return input_data.get("file_path", "")
    if name == "Grep":
        return f'"{input_data.get("pattern", "")}" {input_data.get("path", "")}'
    if name == "Glob":
        return input_data.get("pattern", "")
    if name == "Agent":
        return input_data.get("description", "")[:80]
    return json.dumps(input_data, default=str)[:100]


def truncate_log_for_manager(
    output_lines: list[dict], max_chars: int = 32_000
) -> str:
    """Extract decision-relevant content from the output log."""
    entries: list[str] = []
    for event in output_lines:
        etype = event.get("type", "")
        if etype == "assistant":
            msg = event.get("message", {})
            for block in msg.get("content", []):
                btype = block.get("type", "")
                if btype == "text" and block.get("text"):
                    entries.append(f"ASSISTANT: {block['text']}")
                elif btype == "thinking" and block.get("thinking"):
                    thinking = block["thinking"]
                    if len(thinking) > 300:
                        thinking = thinking[:300] + "..."
                    entries.append(f"THINKING: {thinking}")
                elif btype == "tool_use":
                    summary = _tool_summary_for_log(
                        block.get("name", "tool"),
                        block.get("input", {}),
                    )
                    entries.append(
                        f"TOOL CALL: {block.get('name', 'tool')} — "
                        f"{summary}"
                    )
        elif etype == "user":
            msg = event.get("message", {})
            for block in msg.get("content", []):
                if block.get("type") != "tool_result":
                    continue
                is_error = block.get("is_error", False)
                status = "ERROR" if is_error else "OK"
                content = block.get("content", "")
                if isinstance(content, str) and len(content) > 400:
                    content = content[:200] + "\n...\n" + content[-200:]
                entries.append(f"TOOL RESULT ({status}): {content}")
        elif etype == "error":
            entries.append(f"ERROR: {event.get('message', '')}")
        elif etype == "user_steer":
            entries.append(
                f"USER STEERED: {event.get('message', '')}"
            )
        elif etype == "system":
            msg = event.get("message", "")
            if msg:
                entries.append(f"SYSTEM: {msg}")

    text = "\n".join(entries)
    if len(text) > max_chars:
        # Keep the most recent context
        text = "... (earlier output truncated) ...\n" + text[
            -max_chars:
        ]
    return text


def build_manager_prompt(challenge: dict, truncated_log: str) -> str:
    """Build the prompt sent to the manager LLM (single_managed mode)."""
    manager_state = challenge.get("manager", {})

    # Find the active run for elapsed time
    active_run = None
    for run in challenge["runs"].values():
        if run["status"] == "solving":
            active_run = run
            break
    if not active_run:
        active_run = next(iter(challenge["runs"].values()), None)

    elapsed_ms = 0
    if active_run and active_run.get("solve_start"):
        elapsed_ms = int(
            (_time.monotonic() - active_run["solve_start"]) * 1000
        )
    elif active_run:
        elapsed_ms = active_run.get("duration_ms") or 0
    elapsed_min = elapsed_ms / 60_000

    agent_name = active_run["agent"] if active_run else "unknown"

    settings = load_settings()
    pool = settings.get("manager_agent_pool", [])
    pool_names = _pool_agent_names(pool) or list(VALID_AGENTS)

    parts = [
        "You are a CTF challenge manager agent. Your job is to review "
        "the progress of a solver agent working on a CTF challenge and "
        "decide what to do next.",
        "",
        f"Challenge: {challenge['name']}",
    ]
    if challenge.get("description"):
        parts.append(f"Description: {challenge['description']}")
    if challenge.get("flag_format"):
        parts.append(f"Flag format: {challenge['flag_format']}")
    parts.extend([
        f"Agent: {agent_name}",
        f"Elapsed time: {elapsed_min:.1f} minutes",
        f"Times steered so far: {manager_state.get('steer_count', 0)}",
        f"Available agents for handoff: {', '.join(pool_names)}",
    ])

    last_summary = manager_state.get("last_summary", "")
    if last_summary:
        parts.extend([
            "",
            "Summary from your previous review:",
            last_summary,
        ])

    review_history = manager_state.get("review_history", [])
    if review_history:
        parts.append("")
        parts.append("Previous manager decisions:")
        for entry in review_history[-5:]:
            parts.append(
                f"  [{entry.get('verdict', '?')}] "
                f"{entry.get('reasoning', '')[:200]}"
            )

    parts.extend([
        "",
        "=== SOLVER OUTPUT LOG ===",
        truncated_log,
        "=== END OF LOG ===",
        "",
        "Analyze the solver's progress and decide ONE of:",
        "",
        "STEER — The solver is stuck, going in circles, or missing an "
        "obvious approach. Provide specific, actionable instructions "
        "for what to try next. Be concrete: name specific tools, "
        "techniques, or commands.",
        "",
        "HANDOFF — The current agent is not well-suited for this "
        "challenge. Hand off to a different agent from the pool. "
        "Specify which agent and provide context/findings for them.",
        "",
        "SHELVE — The solver has exhausted reasonable approaches and "
        "further steering is unlikely to yield progress. The challenge "
        "may require capabilities the agent doesn't have, or the "
        "approach is fundamentally wrong. Do NOT shelve simply because "
        "of a high steer count — if each steer is making incremental "
        "progress, continue steering.",
        "",
        "WAIT — The solver is making reasonable progress and doesn't "
        "need intervention right now.",
        "",
        "Consider:",
        "- What has the solver tried? What hasn't it tried?",
        "- Is it repeating the same failed approaches?",
        "- Are there unconventional techniques worth suggesting?",
        "- Is partial progress being made with each attempt?",
        "- Would a different agent handle this better?",
        "",
        "Respond in EXACTLY this format:",
        "VERDICT: STEER | HANDOFF | SHELVE | WAIT",
        "REASONING: <your analysis>",
        "INSTRUCTIONS: <specific instructions for the solver, "
        "only if VERDICT is STEER>",
        "HANDOFF_AGENT: <agent name from pool, only if VERDICT is HANDOFF>",
        "HANDOFF_CONTEXT: <findings and instructions for the new agent, "
        "only if VERDICT is HANDOFF>",
        "SUMMARY: <concise summary of what has been tried and current "
        "state, for future reference>",
    ])
    return "\n".join(parts)


def build_parallel_manager_prompt(
    challenge: dict, run_logs: dict[str, str]
) -> str:
    """Build the prompt for parallel_managed mode."""
    manager_state = challenge.get("manager", {})

    parts = [
        "You are a CTF challenge manager agent coordinating multiple "
        "solver agents working on the same CTF challenge in parallel.",
        "",
        f"Challenge: {challenge['name']}",
    ]
    if challenge.get("description"):
        parts.append(f"Description: {challenge['description']}")
    if challenge.get("flag_format"):
        parts.append(f"Flag format: {challenge['flag_format']}")

    last_summary = manager_state.get("last_summary", "")
    if last_summary:
        parts.extend([
            "",
            "Summary from your previous review:",
            last_summary,
        ])

    review_history = manager_state.get("review_history", [])
    if review_history:
        parts.append("")
        parts.append("Previous manager decisions:")
        for entry in review_history[-5:]:
            parts.append(
                f"  [{entry.get('verdict', '?')}] "
                f"{entry.get('reasoning', '')[:200]}"
            )

    parts.append("")
    for agent_name, log_text in run_logs.items():
        parts.extend([
            f"=== {agent_name} OUTPUT LOG ===",
            log_text,
            f"=== END {agent_name} LOG ===",
            "",
        ])

    parts.extend([
        "Analyze ALL agents' progress and decide ONE of:",
        "",
        "SUMMARIZE — Cross-pollinate findings between agents. Provide "
        "a summary of what ALL agents have found, and provide tailored "
        "steering instructions for each agent based on what others found.",
        "",
        "SHELVE — All agents have exhausted reasonable approaches.",
        "",
        "WAIT — Agents are making reasonable progress.",
        "",
        "Respond in EXACTLY this format:",
        "VERDICT: SUMMARIZE | SHELVE | WAIT",
        "REASONING: <your analysis>",
        "SUMMARY: <overall summary of findings across all agents>",
    ])

    # Add per-agent steer fields
    for agent_name in run_logs:
        parts.append(
            f"STEER_{agent_name}: <tailored instructions for "
            f"{agent_name}, only if VERDICT is SUMMARIZE>"
        )

    return "\n".join(parts)


def parse_manager_response(text: str) -> dict:
    """Parse the structured response from the manager LLM."""
    result = {
        "verdict": "WAIT",
        "reasoning": "",
        "instructions": "",
        "summary": "",
        "handoff_agent": "",
        "handoff_context": "",
    }
    current_field = None
    current_lines: list[str] = []

    field_prefixes = [
        ("VERDICT:", "verdict"),
        ("REASONING:", "reasoning"),
        ("INSTRUCTIONS:", "instructions"),
        ("HANDOFF_AGENT:", "handoff_agent"),
        ("HANDOFF_CONTEXT:", "handoff_context"),
        ("SUMMARY:", "summary"),
    ]

    # Dynamically detect STEER_<agent> fields
    for line in text.splitlines():
        stripped = line.strip()
        for prefix_str, field_name in field_prefixes:
            if stripped.upper().startswith(prefix_str):
                break
        else:
            # Check for STEER_<agent> pattern
            upper = stripped.upper()
            if upper.startswith("STEER_"):
                colon_idx = stripped.find(":")
                if colon_idx > 0:
                    dynamic_field = stripped[:colon_idx].strip()
                    field_prefixes.append(
                        (f"{dynamic_field.upper()}:", dynamic_field.lower())
                    )

    # Re-parse with all fields
    for line in text.splitlines():
        stripped = line.strip()
        matched = False
        for prefix, field in field_prefixes:
            if stripped.upper().startswith(prefix):
                if current_field:
                    result[current_field] = "\n".join(
                        current_lines
                    ).strip()
                current_field = field
                current_lines = [stripped[len(prefix):].strip()]
                matched = True
                break
        if not matched and current_field:
            current_lines.append(line)

    if current_field:
        result[current_field] = "\n".join(current_lines).strip()

    verdict = result["verdict"].upper().strip()
    if verdict not in ("STEER", "SHELVE", "WAIT", "HANDOFF", "SUMMARIZE"):
        if "STEER" in verdict:
            verdict = "STEER"
        elif "HANDOFF" in verdict:
            verdict = "HANDOFF"
        elif "SUMMARIZE" in verdict:
            verdict = "SUMMARIZE"
        elif "SHELVE" in verdict:
            verdict = "SHELVE"
        else:
            verdict = "WAIT"
    result["verdict"] = verdict
    return result


def _manager_should_review(challenge: dict, settings: dict) -> bool:
    """Check if a challenge is due for manager review."""
    if challenge["status"] != "solving":
        return False
    if challenge["mode"] not in ("single_managed", "parallel_managed"):
        return False

    now = _time.monotonic()
    min_time = settings.get("manager_min_solve_time", 5) * 60

    if challenge["mode"] == "single_managed":
        # Check the active run's solve_start
        for run in challenge["runs"].values():
            if run["status"] == "solving" and run.get("solve_start"):
                elapsed = now - run["solve_start"]
                if elapsed >= min_time:
                    break
        else:
            return False
    elif challenge["mode"] == "parallel_managed":
        # Check if any run is solving with enough time
        has_solving = False
        for run in challenge["runs"].values():
            if run["status"] == "solving" and run.get("solve_start"):
                elapsed = now - run["solve_start"]
                if elapsed >= min_time:
                    has_solving = True
                    break
        if not has_solving:
            return False

    manager_state = challenge.get("manager", {})
    last_review = manager_state.get("last_review_at")
    interval = settings.get("manager_interval", 10) * 60
    if last_review and (now - last_review) < interval:
        return False

    return True


def _pool_agent_names(pool: list) -> list[str]:
    """Extract agent names from pool (handles both old and new format)."""
    names = []
    for entry in pool:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict) and entry.get("agent"):
            names.append(entry["agent"])
    return names


def _pool_model_for_agent(pool: list, agent: str) -> str:
    """Look up the configured model for an agent in the pool."""
    for entry in pool:
        if isinstance(entry, dict) and entry.get("agent") == agent:
            return entry.get("model", "")
    return ""


async def _run_manager_llm(
    settings: dict, prompt: str, cwd: Path
) -> str:
    """Run a manager LLM call using any configured provider."""
    agent_name = settings.get("manager_agent", DEFAULT_AGENT)
    model = settings.get("manager_model", "")
    effort = settings.get("manager_effort", "")
    provider = get_provider(agent_name)

    # Build a minimal challenge-like dict for the provider's build_command
    fake_challenge = {"model": model, "effort": effort}
    cmd = provider.build_command(fake_challenge, prompt, False)

    env = {**os.environ, "IS_SANDBOX": "1"}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=2 ** 24,
        )
        stdout_data, stderr_data = await asyncio.wait_for(
            proc.communicate(), timeout=180
        )
    except (asyncio.TimeoutError, Exception):
        return ""

    raw_output = stdout_data.decode("utf-8", errors="replace")

    # Extract assistant text from the provider's output format.
    # Try JSONL parsing first (works for all providers), fall back to raw text.
    text_parts: list[str] = []
    fake_state: dict = {}
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            # Not JSON — could be plain text output (e.g. claude -p --output-format text)
            text_parts.append(line)
            continue

        normalized = provider.normalize_live_event(event, fake_state)
        if normalized is None:
            continue
        if normalized.get("type") == "assistant":
            msg = normalized.get("message", {})
            for block in msg.get("content", []):
                if block.get("type") == "text" and block.get("text"):
                    text_parts.append(block["text"])

    return "\n".join(text_parts)


async def run_manager_review(challenge_id: str) -> None:
    """Run a single manager review for a challenge."""
    challenge = challenges.get(challenge_id)
    if not challenge or challenge["status"] != "solving":
        return

    settings = load_settings()
    manager_state = challenge.setdefault("manager", _default_manager_state())
    manager_state["last_review_at"] = _time.monotonic()

    # Notify all runs about manager review
    review_event = {
        "type": "system",
        "subtype": "manager_review",
        "message": "Manager agent reviewing progress...",
    }
    for run_id, run in challenge["runs"].items():
        if run["status"] == "solving":
            run["output_lines"].append(review_event)
            append_output_event(challenge_id, run_id, review_event)
            await broadcast(challenge_id, run_id, review_event)

    if challenge["mode"] == "single_managed":
        # Find active run
        active_run = None
        active_run_id = None
        for rid, run in challenge["runs"].items():
            if run["status"] == "solving":
                active_run = run
                active_run_id = rid
                break
        if not active_run:
            return

        truncated_log = truncate_log_for_manager(
            active_run["output_lines"]
        )
        prompt = build_manager_prompt(challenge, truncated_log)
    elif challenge["mode"] == "parallel_managed":
        run_logs: dict[str, str] = {}
        for rid, run in challenge["runs"].items():
            if run["status"] == "solving":
                run_logs[run["agent"]] = truncate_log_for_manager(
                    run["output_lines"]
                )
        if not run_logs:
            return
        prompt = build_parallel_manager_prompt(challenge, run_logs)
    else:
        return

    response_text = await _run_manager_llm(
        settings, prompt, CHALLENGES_DIR / challenge_id
    )

    if not response_text.strip():
        err_event = {
            "type": "system",
            "subtype": "manager_review",
            "message": "Manager review failed — no response.",
        }
        for run_id, run in challenge["runs"].items():
            if run["status"] == "solving":
                run["output_lines"].append(err_event)
                append_output_event(challenge_id, run_id, err_event)
                await broadcast(challenge_id, run_id, err_event)
        return

    parsed = parse_manager_response(response_text)
    verdict = parsed["verdict"]

    review_entry = {
        "timestamp": datetime.now().isoformat(),
        "verdict": verdict,
        "reasoning": parsed["reasoning"],
        "instructions": parsed.get("instructions", ""),
        "summary": parsed.get("summary", ""),
    }
    manager_state["review_history"].append(review_entry)
    if parsed.get("summary"):
        manager_state["last_summary"] = parsed["summary"]

    if challenge["mode"] == "single_managed":
        await _handle_single_managed_verdict(
            challenge_id, challenge, parsed, manager_state, settings
        )
    elif challenge["mode"] == "parallel_managed":
        await _handle_parallel_managed_verdict(
            challenge_id, challenge, parsed, manager_state
        )


async def _handle_single_managed_verdict(
    challenge_id: str,
    challenge: dict,
    parsed: dict,
    manager_state: dict,
    settings: dict,
) -> None:
    """Handle manager verdict for single_managed mode."""
    verdict = parsed["verdict"]

    # Find active run
    active_run = None
    active_run_id = None
    for rid, run in challenge["runs"].items():
        if run["status"] == "solving":
            active_run = run
            active_run_id = rid
            break
    if not active_run or not active_run_id:
        return

    if verdict == "STEER" and parsed.get("instructions"):
        manager_state["steer_count"] = (
            manager_state.get("steer_count", 0) + 1
        )
        save_metadata(challenge)

        steer_msg = (
            f"[Manager Agent — Steer #{manager_state['steer_count']}]\n"
            f"Reasoning: {parsed['reasoning']}\n\n"
            f"{parsed['instructions']}"
        )

        # Stop current process
        proc = active_run.get("process")
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()

        steer_event = {
            "type": "system",
            "subtype": "manager_steer",
            "message": steer_msg,
        }
        active_run["output_lines"].append(steer_event)
        append_output_event(challenge_id, active_run_id, steer_event)
        await broadcast(challenge_id, active_run_id, steer_event)

        active_run["status"] = "solving"
        active_run["error"] = None
        active_run["task"] = asyncio.create_task(
            run_agent_task(
                challenge_id,
                active_run_id,
                continue_msg=parsed["instructions"],
            )
        )

    elif verdict == "HANDOFF" and parsed.get("handoff_agent"):
        target_agent = parsed["handoff_agent"].strip()
        pool = settings.get("manager_agent_pool", [])
        pool_names = _pool_agent_names(pool) or list(VALID_AGENTS)
        if target_agent not in pool_names:
            target_agent = pool_names[0] if pool_names else DEFAULT_AGENT

        # Stop current run
        proc = active_run.get("process")
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
        active_run["status"] = "failed"
        active_run["error"] = f"Handed off to {target_agent}"

        handoff_event = {
            "type": "system",
            "subtype": "manager_handoff",
            "message": (
                f"[Manager Agent — Handoff to {target_agent}]\n"
                f"Reasoning: {parsed['reasoning']}"
            ),
        }
        active_run["output_lines"].append(handoff_event)
        append_output_event(challenge_id, active_run_id, handoff_event)
        await broadcast(challenge_id, active_run_id, handoff_event)

        # Write FINDINGS.md in challenge dir for the new agent
        findings_context = parsed.get("handoff_context", "")
        if not findings_context and parsed.get("summary"):
            findings_context = parsed["summary"]
        if findings_context:
            cwd = get_run_cwd(challenge_id, active_run)
            findings_path = cwd / "FINDINGS.md"
            findings_path.write_text(
                f"# Findings from previous agent ({active_run['agent']})\n\n"
                f"{findings_context}\n"
            )

        # Create new run using pool-configured model or provider default
        pool_model = _pool_model_for_agent(pool, target_agent)
        new_run_id = uuid.uuid4().hex[:8]
        new_run = make_run(
            run_id=new_run_id,
            agent=target_agent,
            model=pool_model or resolved_default_model(target_agent),
            effort=resolved_default_effort(target_agent),
            status="solving",
        )
        challenge["runs"][new_run_id] = new_run

        # For single mode, the new run works in the same dir
        # so FINDINGS.md is already there

        continue_context = None
        if findings_context:
            continue_context = (
                f"Previous agent ({active_run['agent']}) findings:\n"
                f"{findings_context}\n\n"
                "Continue from where the previous agent left off. "
                "Check FINDINGS.md for details."
            )

        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)

        new_run["task"] = asyncio.create_task(
            run_agent_task(
                challenge_id,
                new_run_id,
                continue_msg=continue_context,
            )
        )

    elif verdict == "SHELVE":
        manager_state["shelve_reason"] = parsed["reasoning"]

        # Stop current process
        proc = active_run.get("process")
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()

        active_run["status"] = "shelved"
        active_run["error"] = None
        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)

        shelve_event = {
            "type": "system",
            "subtype": "manager_shelve",
            "message": (
                f"[Manager Agent — Shelved]\n"
                f"Reasoning: {parsed['reasoning']}"
            ),
        }
        active_run["output_lines"].append(shelve_event)
        append_output_event(challenge_id, active_run_id, shelve_event)
        await broadcast(challenge_id, active_run_id, shelve_event)
        await broadcast_challenge(challenge_id, {
            "type": "status",
            "status": "shelved",
        })

    else:
        # WAIT
        save_metadata(challenge)
        wait_event = {
            "type": "system",
            "subtype": "manager_wait",
            "message": (
                f"[Manager Agent — No intervention needed]\n"
                f"Reasoning: {parsed['reasoning']}"
            ),
        }
        active_run["output_lines"].append(wait_event)
        append_output_event(challenge_id, active_run_id, wait_event)
        await broadcast(challenge_id, active_run_id, wait_event)


async def _handle_parallel_managed_verdict(
    challenge_id: str,
    challenge: dict,
    parsed: dict,
    manager_state: dict,
) -> None:
    """Handle manager verdict for parallel_managed mode."""
    verdict = parsed["verdict"]

    if verdict == "SUMMARIZE":
        summary = parsed.get("summary", "")
        manager_state["steer_count"] = (
            manager_state.get("steer_count", 0) + 1
        )

        for run_id, run in challenge["runs"].items():
            if run["status"] != "solving":
                continue

            # Write SUMMARY_FINDINGS.md to each run's dir
            if summary:
                run_cwd = get_run_cwd(challenge_id, run)
                findings_path = run_cwd / "SUMMARY_FINDINGS.md"
                findings_path.write_text(
                    f"# Cross-Agent Summary (from manager)\n\n"
                    f"{summary}\n"
                )

            # Find tailored steer for this run's agent
            steer_key = f"steer_{run['agent']}"
            tailored_steer = parsed.get(steer_key, "")

            if tailored_steer:
                # Stop current process
                proc = run.get("process")
                if proc and proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        proc.kill()

                steer_event = {
                    "type": "system",
                    "subtype": "manager_steer",
                    "message": (
                        f"[Manager Agent — Summarize & Steer]\n"
                        f"Summary: {summary}\n\n"
                        f"Instructions: {tailored_steer}"
                    ),
                }
                run["output_lines"].append(steer_event)
                append_output_event(challenge_id, run_id, steer_event)
                await broadcast(challenge_id, run_id, steer_event)

                run["status"] = "solving"
                run["error"] = None
                run["task"] = asyncio.create_task(
                    run_agent_task(
                        challenge_id,
                        run_id,
                        continue_msg=tailored_steer,
                    )
                )

        save_metadata(challenge)

    elif verdict == "SHELVE":
        manager_state["shelve_reason"] = parsed["reasoning"]

        for run_id, run in challenge["runs"].items():
            if run["status"] != "solving":
                continue
            proc = run.get("process")
            if proc and proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
            run["status"] = "shelved"
            run["error"] = None

            shelve_event = {
                "type": "system",
                "subtype": "manager_shelve",
                "message": (
                    f"[Manager Agent — Shelved]\n"
                    f"Reasoning: {parsed['reasoning']}"
                ),
            }
            run["output_lines"].append(shelve_event)
            append_output_event(challenge_id, run_id, shelve_event)
            await broadcast(challenge_id, run_id, shelve_event)

        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)
        await broadcast_challenge(challenge_id, {
            "type": "status",
            "status": challenge["status"],
        })

    else:
        # WAIT
        save_metadata(challenge)
        for run_id, run in challenge["runs"].items():
            if run["status"] != "solving":
                continue
            wait_event = {
                "type": "system",
                "subtype": "manager_wait",
                "message": (
                    f"[Manager Agent — No intervention needed]\n"
                    f"Reasoning: {parsed['reasoning']}"
                ),
            }
            run["output_lines"].append(wait_event)
            append_output_event(challenge_id, run_id, wait_event)
            await broadcast(challenge_id, run_id, wait_event)


async def manager_loop() -> None:
    """Background loop that periodically reviews solving challenges."""
    while True:
        await asyncio.sleep(60)
        settings = load_settings()
        for challenge_id, challenge in list(challenges.items()):
            if _manager_should_review(challenge, settings):
                asyncio.create_task(run_manager_review(challenge_id))


# ---------------------------------------------------------------------------
# Build prompt
# ---------------------------------------------------------------------------

def build_prompt(challenge: dict, run: dict) -> str:
    """Build the CTF solving prompt."""
    parts = [
        "You are solving a CTF challenge.",
        f"Read {_METHODOLOGY_SKILL} first and follow it for the full "
        "solve. It contains the triage workflow and routes you to the "
        "correct category and tool skills.",
        "",
        f"Challenge: {challenge['name']}",
    ]
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

    # For managed modes, instruct about FINDINGS.md
    if challenge["mode"] in ("single_managed", "parallel_managed"):
        if challenge["mode"] == "parallel_managed":
            findings_name = f"FINDINGS_{run['agent']}.md"
        else:
            findings_name = "FINDINGS.md"
        parts.extend([
            "",
            f"Maintain a {findings_name} file in your working directory. "
            "Document: files analyzed, tools/techniques tried, results found, dead ends, hypotheses. "
            "Update it as you work — it will be read by the next agent if there's a handoff.",
        ])

    # For retry-with-context: if the run already has output_lines, summarize
    if run.get("output_lines"):
        log_summary = truncate_log_for_manager(
            run["output_lines"], max_chars=4000
        )
        if log_summary.strip():
            parts.extend([
                "",
                "Previous attempt summary (avoid repeating failed approaches):",
                log_summary,
            ])

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Run agent
# ---------------------------------------------------------------------------

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
        prompt = continue_msg
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

        await asyncio.gather(
            stream_events(proc.stdout, "stdout"),
            stream_events(proc.stderr, "stderr"),
        )

        await proc.wait()

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

        if proc.returncode == 0 and not stream_error and saw_provider_message:
            run["status"] = "solved"
            run["error"] = None

            # Auto-stop other runs in parallel modes
            if challenge["mode"] in ("parallel", "parallel_managed"):
                for other_id, other_run in challenge["runs"].items():
                    if other_id != run_id and other_run.get("process"):
                        other_proc = other_run["process"]
                        if other_proc.returncode is None:
                            other_proc.terminate()
                            other_run["status"] = "failed"
                            other_run["process"] = None
                            stop_event = {
                                "type": "system",
                                "message": f"Stopped: another agent ({run['agent']}) solved the challenge.",
                            }
                            other_run["output_lines"].append(stop_event)
                            append_output_event(
                                challenge_id, other_id, stop_event
                            )
                            await broadcast(
                                challenge_id, other_id, stop_event
                            )
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
        run["status"] = "failed"
        run["error"] = str(exc)
        err_event = {"type": "error", "message": str(exc)}
        run["output_lines"].append(err_event)
        append_output_event(challenge_id, run_id, err_event)
        await broadcast(challenge_id, run_id, err_event)
    finally:
        run["process"] = None
        if run.get("solve_start"):
            elapsed = _time.monotonic() - run["solve_start"]
            run["duration_ms"] = int(elapsed * 1000)
        challenge["status"] = derive_challenge_status(challenge)
        save_metadata(challenge)
        await broadcast(challenge_id, run_id, {
            "type": "status",
            "status": run["status"],
            "error": run.get("error"),
        })
        await broadcast_challenge(challenge_id, {
            "type": "status",
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

    # Send current status
    await websocket.send_json({
        "type": "status", "status": run["status"]
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


async def list_agents(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    return JSONResponse({
        "agents": [
            provider.metadata()
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
    if "manager_interval" in body:
        val = int(body["manager_interval"])
        if 1 <= val <= 120:
            settings["manager_interval"] = val
    if "manager_agent" in body:
        agent = str(body["manager_agent"])
        if agent in VALID_AGENTS:
            settings["manager_agent"] = agent
    if "manager_model" in body:
        settings["manager_model"] = str(body["manager_model"])
    if "manager_effort" in body:
        settings["manager_effort"] = str(body["manager_effort"])
    if "manager_min_solve_time" in body:
        val = int(body["manager_min_solve_time"])
        if 1 <= val <= 60:
            settings["manager_min_solve_time"] = val
    if "manager_agent_pool" in body:
        pool = body["manager_agent_pool"]
        if isinstance(pool, list):
            validated = []
            for entry in pool:
                if isinstance(entry, str) and entry in VALID_AGENTS:
                    validated.append({"agent": entry, "model": ""})
                elif (
                    isinstance(entry, dict)
                    and entry.get("agent") in VALID_AGENTS
                ):
                    validated.append({
                        "agent": entry["agent"],
                        "model": str(entry.get("model", "")),
                    })
            if validated:
                settings["manager_agent_pool"] = validated
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


async def get_manager_state(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(manager_state_for_metadata(challenge))


# ---------------------------------------------------------------------------
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

        # Download files
        file_data: dict[str, bytes] = {}
        for rf in remote_files:
            try:
                from plugins.base import RemoteFile
                data = await plugin.download_file(
                    config,
                    RemoteFile(name=rf["name"], url=rf["url"]),
                )
                safe_name = rf["name"].replace("/", "_").replace("\\", "_")
                file_data[safe_name] = data
            except Exception:
                continue

        # Determine which agents to create runs for
        agent_entries = parse_agents_field(agents)
        if not agent_entries:
            agent_entries = [{"agent": DEFAULT_AGENT, "model": ""}]
        if mode in ("single", "single_managed"):
            agent_entries = agent_entries[:1]

        challenge_id = uuid.uuid4().hex[:12]
        challenge_dir = CHALLENGES_DIR / challenge_id

        if mode in ("parallel", "parallel_managed"):
            files_dir = challenge_dir / "_files"
            files_dir.mkdir(parents=True)
            for fname, fdata in file_data.items():
                (files_dir / fname).write_bytes(fdata)
        else:
            challenge_dir.mkdir(parents=True)
            for fname, fdata in file_data.items():
                (challenge_dir / fname).write_bytes(fdata)

        runs = {}
        challenge_status = "pending" if paused else "solving"
        for entry in agent_entries:
            agent_name = entry["agent"]
            if agent_name not in VALID_AGENTS:
                continue
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
            if mode in ("parallel", "parallel_managed"):
                setup_parallel_run_dir(challenge_id, run_id)

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
            "manager": _default_manager_state(),
            "runs": runs,
            "_plugin": plugin_name,
            "_remote_id": ch_remote_id,
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


async def plugin_submit_flag(request: Request) -> JSONResponse:
    """Submit a flag to the remote platform."""
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

    config = body.get("config", {})
    plugin = get_plugin(plugin_name)
    if not plugin:
        return JSONResponse(
            {"error": f"Plugin {plugin_name} not found"},
            status_code=404,
        )

    try:
        result = await plugin.submit_flag(config, remote_id, flag)
        return JSONResponse({
            "correct": result.correct,
            "message": result.message,
        })
    except Exception as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400
        )


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

_manager_task: asyncio.Task | None = None


async def on_startup():
    global _manager_task
    _manager_task = asyncio.create_task(manager_loop())


async def on_shutdown():
    if _manager_task and not _manager_task.done():
        _manager_task.cancel()
    for challenge in challenges.values():
        for run in challenge["runs"].values():
            proc = run.get("process")
            if proc and proc.returncode is None:
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
    Route("/api/challenges/{id}/unshelve", unshelve_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/unsolve", unsolve_challenge, methods=["POST"]),
    Route("/api/challenges/{id}/manager", get_manager_state, methods=["GET"]),
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
    on_startup=[on_startup],
    on_shutdown=[on_shutdown],
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
        port=8080,
        log_level="info",
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
