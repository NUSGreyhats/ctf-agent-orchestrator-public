#!/usr/bin/env python3
"""CTF Challenge Solver Web App.

Spawns CLI coding agents to solve CTF challenges, streaming JSONL
output to authenticated users via WebSocket.
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

METADATA_FILE = "challenge.json"
OUTPUT_FILE = "output.jsonl"
SETTINGS_FILE = CHALLENGES_DIR / "settings.json"
_PREVIEW_TTL = 3600
_bulk_previews: dict[str, dict] = {}

SKILL_CATALOG = (
    (
        "/root/all-things-ai/skills/ctf-methodology/SKILL.md",
        "overall CTF workflow, triage, and flag-finding process",
    ),
    (
        "/root/all-things-ai/skills/memory-forensics/SKILL.md",
        "memory dumps, Volatility 3, mquire, processes, files, and network artifacts",
    ),
    (
        "/root/all-things-ai/skills/disk-forensics/SKILL.md",
        "disk images, partitions, filesystem analysis, carving, and timelines",
    ),
    (
        "/root/all-things-ai/skills/file-forensics/SKILL.md",
        "steganography, corrupted files, embedded data, PDFs, and Office documents",
    ),
    (
        "/root/all-things-ai/skills/network-forensics/SKILL.md",
        "PCAP/PCAPNG analysis, stream reconstruction, credential recovery, and file extraction",
    ),
    (
        "/root/all-things-ai/skills/web/SKILL.md",
        "web app exploitation, auth/session flaws, injection, traversal, and API abuse",
    ),
    (
        "/root/all-things-ai/skills/rev/SKILL.md",
        "reverse engineering binaries, custom VMs, anti-debugging, and runtime checks",
    ),
    (
        "/root/all-things-ai/skills/pwn/SKILL.md",
        "binary exploitation, mitigations, ROP, heap bugs, shellcode, and seccomp bypasses",
    ),
    (
        "/root/all-things-ai/skills/crypto/SKILL.md",
        "cryptography, RSA, AES, lattices, PRNGs, ECC, and Z3/SageMath style attacks",
    ),
    (
        "/root/all-things-ai/skills/misc/SKILL.md",
        "miscellaneous CTF workflows for mixed, ambiguous, or layered challenge types",
    ),
    (
        "/root/all-things-ai/skills/apk-analysis/SKILL.md",
        "Android APK triage with apktool, jadx, and native library analysis",
    ),
    (
        "/root/all-things-ai/skills/headless-ida-analysis/SKILL.md",
        "headless IDA Pro analysis using ida-domain and idalib",
    ),
    (
        "/root/all-things-ai/skills/kernel-gef-debugging/SKILL.md",
        "kernel debugging with GDB + GEF via persistent MCP tools",
    ),
    (
        "/root/all-things-ai/skills/libdebug-debugging/SKILL.md",
        "scripted Linux ELF debugging with libdebug instead of gdb",
    ),
)


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


def provider_state_for_metadata(challenge: dict) -> dict:
    state = {}
    if challenge.get("_codex_thread_id"):
        state["codex_thread_id"] = challenge["_codex_thread_id"]
    if challenge.get("_opencode_session_id"):
        state["opencode_session_id"] = challenge[
            "_opencode_session_id"
        ]
    return state


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


def output_log_path(challenge_id: str) -> Path:
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

def load_settings() -> dict:
    """Load global settings from disk."""
    defaults = {
        "default_agent": DEFAULT_AGENT,
        "default_flag_format": "",
        "theme": "dark",
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


def save_metadata(challenge: dict) -> None:
    """Persist challenge metadata to disk."""
    meta = {
        "id": challenge["id"],
        "name": challenge["name"],
        "description": challenge["description"],
        "flag_format": challenge["flag_format"],
        "agent": challenge["agent"],
        "model": challenge["model"],
        "effort": challenge.get("effort", ""),
        "autonomous": challenge.get("autonomous", False),
        "status": challenge["status"],
        "created_at": challenge["created_at"],
        "files": challenge["files"],
        "error": challenge["error"],
        "duration_ms": challenge.get("duration_ms"),
        "provider_state": provider_state_for_metadata(challenge),
    }
    meta_path = ensure_state_dir(challenge["id"]) / METADATA_FILE
    meta_path.write_text(json.dumps(meta, indent=2))


def append_output_event(challenge_id: str, event: dict) -> None:
    """Append a single event to the output log on disk."""
    out_path = ensure_state_dir(challenge_id) / OUTPUT_FILE
    with out_path.open("a") as f:
        f.write(json.dumps(event) + "\n")


def clear_output_log(challenge_id: str) -> None:
    """Clear the output log file for a fresh run."""
    out_path = output_log_path(challenge_id)
    if out_path.exists():
        out_path.unlink()


def load_output_log(challenge_id: str) -> list[dict]:
    """Load saved output events from disk."""
    out_path = output_log_path(challenge_id)
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


def expand_agent_selection(
    agent: str, model: str
) -> list[tuple[str, str]]:
    if agent in {PARALLEL_AGENT_VALUE, "both"}:
        return [
            (
                provider.name,
                provider.resolved_default_model(),
            )
            for provider in PROVIDERS.values()
        ]

    provider = get_provider(agent)
    return [(provider.name, model or provider.resolved_default_model())]


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
        provider_state = meta.get("provider_state", {})

        # If it was solving when the app died, mark failed
        status = meta.get("status", "unknown")
        if status == "solving":
            status = "failed"

        challenges[challenge_id] = {
            "id": challenge_id,
            "name": meta.get("name", f"Challenge {challenge_id}"),
            "description": meta.get("description", ""),
            "flag_format": meta.get("flag_format", ""),
            "agent": meta.get("agent", DEFAULT_AGENT),
            "model": meta.get(
                "model",
                resolved_default_model(meta.get("agent", DEFAULT_AGENT)),
            ),
            "effort": meta.get(
                "effort",
                resolved_default_effort(meta.get("agent", DEFAULT_AGENT)),
            ),
            "autonomous": meta.get("autonomous", False),
            "status": status,
            "created_at": meta.get(
                "created_at", datetime.now().isoformat()
            ),
            "files": meta.get("files", []),
            "process": None,
            "task": None,
            "output_lines": _normalize_output_lines(
                load_output_log(challenge_id),
                meta.get("agent", DEFAULT_AGENT),
            ),
            "ws_clients": set(),
            "error": meta.get("error"),
            "duration_ms": meta.get("duration_ms"),
            "solve_start": None,
            "_codex_thread_id": provider_state.get(
                "codex_thread_id"
            ),
            "_opencode_session_id": provider_state.get(
                "opencode_session_id"
            ),
        }


load_challenges_from_disk()


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


async def list_challenges(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    result = []
    for c in challenges.values():
        result.append({
            "id": c["id"],
            "name": c["name"],
            "description": c["description"],
            "flag_format": c["flag_format"],
            "agent": c["agent"],
            "model": c["model"],
            "effort": c.get("effort", ""),
            "status": c["status"],
            "error": c["error"],
            "created_at": c["created_at"],
            "files": c["files"],
            "duration_ms": c.get("duration_ms"),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return JSONResponse(result)


async def create_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    form = await request.form()
    name = form.get("name", "").strip()
    description = form.get("description", "").strip()
    flag_format = form.get("flag_format", "").strip()
    agent = form.get("agent", "").strip() or DEFAULT_AGENT
    model = form.get("model", "").strip()
    effort = form.get("effort", "").strip()
    autonomous = form.get("autonomous", "").strip() == "true"

    # Read uploaded files into memory so we can copy to multiple dirs
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

    agents_to_run = expand_agent_selection(agent, model)

    created = []
    for run_agent_name, run_model in agents_to_run:
        challenge_id = uuid.uuid4().hex[:12]
        display_name = name or f"Challenge {challenge_id}"
        if len(agents_to_run) > 1:
            prefix = f"[{get_provider(run_agent_name).label}] "
            display_name = f"{prefix}{display_name}"

        challenge_dir = CHALLENGES_DIR / challenge_id
        challenge_dir.mkdir(parents=True)
        for rel_path, fdata in file_data.items():
            dest = challenge_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fdata)

        challenge = {
            "id": challenge_id,
            "name": display_name,
            "description": description,
            "flag_format": flag_format,
            "agent": run_agent_name,
            "model": run_model,
            "effort": normalize_effort_for_agent(run_agent_name, effort),
            "autonomous": autonomous,
            "status": "solving",
            "created_at": datetime.now().isoformat(),
            "files": sorted(file_data.keys()),
            "process": None,
            "task": None,
            "output_lines": [],
            "ws_clients": set(),
            "error": None,
            "duration_ms": None,
            "solve_start": None,
        }
        challenges[challenge_id] = challenge
        save_metadata(challenge)
        challenge["task"] = asyncio.create_task(
            run_agent(challenge_id)
        )
        created.append({"id": challenge_id, "name": display_name})

    if len(created) == 1:
        return JSONResponse(
            {"id": created[0]["id"], "status": "solving"},
            status_code=201,
        )
    return JSONResponse(
        {"created": created, "status": "solving"},
        status_code=201,
    )


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
        agent = body.get("agent", "").strip() or DEFAULT_AGENT
        model = body.get("model", "").strip()
        effort = body.get("effort", "").strip()
        autonomous = bool(body.get("autonomous", False))
        paused = bool(body.get("paused", False))
        challenges_cfg = body.get("challenges", [])

        agents_to_run = expand_agent_selection(agent, model)

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

            for run_agent_name, run_model in agents_to_run:
                challenge_id = uuid.uuid4().hex[:12]
                challenge_dir = CHALLENGES_DIR / challenge_id
                challenge_dir.mkdir(parents=True)
                for fname in file_names:
                    src = folder_dir / fname
                    if src.exists():
                        shutil.copy2(src, challenge_dir / fname)

                prefix = (
                    f"[{get_provider(run_agent_name).label}] "
                    if len(agents_to_run) > 1
                    else ""
                )
                display_name = f"{prefix}{ch_name}"
                challenge_status = "pending" if paused else "solving"
                challenge = {
                    "id": challenge_id,
                    "name": display_name,
                    "description": ch_description,
                    "flag_format": ch_flag_format,
                    "agent": run_agent_name,
                    "model": run_model,
                    "effort": normalize_effort_for_agent(
                        run_agent_name, effort
                    ),
                    "autonomous": autonomous,
                    "status": challenge_status,
                    "created_at": datetime.now().isoformat(),
                    "files": file_names,
                    "process": None,
                    "task": None,
                    "output_lines": [],
                    "ws_clients": set(),
                    "error": None,
                    "duration_ms": None,
                    "solve_start": None,
                }
                challenges[challenge_id] = challenge
                save_metadata(challenge)
                if challenge_status == "solving":
                    challenge["task"] = asyncio.create_task(
                        run_agent(challenge_id)
                    )
                created.append({
                    "id": challenge_id,
                    "name": display_name,
                    "status": challenge_status,
                })

        return JSONResponse({"created": created}, status_code=201)
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


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

    challenge["status"] = "solving"
    challenge["output_lines"] = []
    clear_output_log(challenge_id)
    challenge["task"] = asyncio.create_task(run_agent(challenge_id))
    return JSONResponse({"status": "solving"})


async def stop_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    proc = challenge.get("process")
    if proc and proc.returncode is None:
        proc.terminate()
        challenge["status"] = "failed"
        save_metadata(challenge)
        stop_event = {
            "type": "system", "message": "Agent stopped by user.",
        }
        challenge["output_lines"].append(stop_event)
        append_output_event(challenge_id, stop_event)
        await broadcast(challenge_id, stop_event)
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

    # Stop current process if running
    proc = challenge.get("process")
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()

    steer_event = {"type": "user_steer", "message": message}
    challenge["output_lines"].append(steer_event)
    append_output_event(challenge_id, steer_event)
    await broadcast(challenge_id, steer_event)

    challenge["status"] = "solving"
    challenge["error"] = None
    challenge["task"] = asyncio.create_task(
        run_agent(challenge_id, continue_msg=message)
    )
    return JSONResponse({"status": "solving"})


async def delete_challenge(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    challenge_id = request.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        return JSONResponse({"error": "not found"}, status_code=404)

    proc = challenge.get("process")
    if proc and proc.returncode is None:
        proc.terminate()

    challenge_dir = CHALLENGES_DIR / challenge_id
    if challenge_dir.exists():
        shutil.rmtree(challenge_dir)
    shutil.rmtree(challenge_state_dir(challenge_id), ignore_errors=True)

    del challenges[challenge_id]
    return JSONResponse({"ok": True})


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


async def list_files(request: Request) -> JSONResponse:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)
    challenge_dir = CHALLENGES_DIR / challenge_id
    if not challenge_dir.exists():
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

    challenge_dir = CHALLENGES_DIR / challenge_id
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


async def broadcast(challenge_id: str, data: dict):
    challenge = challenges.get(challenge_id)
    if not challenge:
        return
    dead = []
    for ws in list(challenge["ws_clients"]):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        challenge["ws_clients"].discard(ws)


def build_prompt(challenge: dict) -> str:
    """Build the CTF solving prompt."""
    skill_lines = [
        "Available skill files you can read if they become relevant:",
    ]
    for path, summary in SKILL_CATALOG:
        skill_lines.append(f"- {path} — {summary}")

    parts = [
        "You are solving a CTF challenge.",
        "The source of truth for all methodology and domain skills is "
        "/root/all-things-ai/skills/.",
        "Start by reading "
        "/root/all-things-ai/skills/ctf-methodology/SKILL.md and "
        "follow it for the full solve.",
        "Do not read every skill up front. Read a skill file only after "
        "you decide it is relevant to the current challenge.",
        "",
        *skill_lines,
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
        "The shared skill files are under /root/all-things-ai/skills/.",
        "Do not inspect parent directories, repository root files, .git metadata, "
        "or unrelated system paths.",
        "If the current directory has no challenge files, report that clearly and stop. "
        "Do not search elsewhere for surrogate targets.",
        "Keep command output bounded: avoid unbounded recursive listings, and use "
        "targeted commands with limits (for example, head/tail).",
        "",
        "Follow the methodology strictly:",
        "1. Run ctfgrep first for a quick flag search "
        "across all encodings",
        "2. Triage the files (file, exiftool, strings, "
        "binwalk)",
        "3. Identify the category and then read only the relevant "
        "skill file from the catalog above before using specialized tools",
        "4. Work methodically, save outputs, correlate "
        "findings",
        "5. When you find the flag, print it clearly",
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


async def run_agent(
    challenge_id: str, continue_msg: str | None = None
):
    challenge = challenges[challenge_id]
    challenge_dir = CHALLENGES_DIR / challenge_id
    challenge["solve_start"] = _time.monotonic()
    provider = get_provider(challenge.get("agent", DEFAULT_AGENT))

    if continue_msg:
        prompt = continue_msg
    else:
        prompt = build_prompt(challenge)

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
    challenge["output_lines"].append(sys_event)
    append_output_event(challenge_id, sys_event)
    await broadcast(challenge_id, sys_event)

    env = os.environ.copy()
    env["IS_SANDBOX"] = "1"

    cmd = provider.build_command(
        challenge, prompt, bool(continue_msg)
    )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(challenge_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        limit=2 ** 24,  # 16 MB — default 64 KB is too small for large JSON events
    )
    challenge["process"] = proc
    challenge["_saw_provider_message"] = False
    challenge["_last_stream_error"] = None
    challenge["_last_stderr_lines"] = []
    challenge["_last_unknown_events"] = []

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

                provider_state_before = provider_state_for_metadata(
                    challenge
                )
                event = provider.normalize_live_event(event, challenge)
                if (
                    provider_state_for_metadata(challenge)
                    != provider_state_before
                ):
                    save_metadata(challenge)
                if event is None:
                    continue

                if event.get("type") in {"assistant", "user", "result"}:
                    challenge["_saw_provider_message"] = True
                elif (
                    event.get("type") == "raw"
                    and event.get("stream") == "stdout"
                ):
                    challenge["_saw_provider_message"] = True

                if event.get("type") == "error":
                    challenge["_last_stream_error"] = event.get(
                        "message"
                    )
                elif (
                    event.get("type") == "raw"
                    and event.get("stream") == "stderr"
                    and event.get("text")
                ):
                    stderr_lines = challenge.setdefault(
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
                    unknown_events = challenge.setdefault(
                        "_last_unknown_events", []
                    )
                    try:
                        preview = json.dumps(event, default=str)
                    except TypeError:
                        preview = str(event)
                    unknown_events.append(preview[:2000])
                    if len(unknown_events) > 5:
                        del unknown_events[:-5]

                challenge["output_lines"].append(event)
                append_output_event(challenge_id, event)
                await broadcast(challenge_id, event)

        await asyncio.gather(
            stream_events(proc.stdout, "stdout"),
            stream_events(proc.stderr, "stderr"),
        )

        await proc.wait()

        stream_error = challenge.get("_last_stream_error")
        saw_provider_message = challenge.get(
            "_saw_provider_message", False
        )
        stderr_tail = "\n".join(
            challenge.get("_last_stderr_lines", [])
        ).strip()
        unknown_tail = "\n".join(
            challenge.get("_last_unknown_events", [])
        ).strip()

        if proc.returncode == 0 and not stream_error and saw_provider_message:
            challenge["status"] = "solved"
            challenge["error"] = None
        else:
            challenge["status"] = "failed"
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
            challenge["error"] = error_msg
            err_event = {
                "type": "error",
                "message": error_msg,
                "exit_code": proc.returncode,
            }
            challenge["output_lines"].append(err_event)
            append_output_event(challenge_id, err_event)
            await broadcast(challenge_id, err_event)

    except Exception as exc:
        challenge["status"] = "failed"
        challenge["error"] = str(exc)
        err_event = {"type": "error", "message": str(exc)}
        challenge["output_lines"].append(err_event)
        append_output_event(challenge_id, err_event)
        await broadcast(challenge_id, err_event)
    finally:
        challenge["process"] = None
        if challenge.get("solve_start"):
            elapsed = _time.monotonic() - challenge["solve_start"]
            challenge["duration_ms"] = int(elapsed * 1000)
        save_metadata(challenge)
        await broadcast(challenge_id, {
            "type": "status",
            "status": challenge["status"],
            "error": challenge.get("error"),
        })


async def challenge_ws(websocket: WebSocket):
    if not websocket.session.get("authenticated"):
        await websocket.close(code=4001)
        return

    challenge_id = websocket.path_params["id"]
    challenge = challenges.get(challenge_id)
    if not challenge:
        await websocket.close(code=4004)
        return

    await websocket.accept()
    challenge["ws_clients"].add(websocket)

    # Send history
    for event in challenge["output_lines"]:
        await websocket.send_json(event)

    # Send current status
    await websocket.send_json({
        "type": "status", "status": challenge["status"]
    })

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        challenge["ws_clients"].discard(websocket)


async def download_file(request: Request) -> Response:
    if err := require_auth(request):
        return err

    challenge_id = request.path_params["id"]
    if challenge_id not in challenges:
        return JSONResponse({"error": "not found"}, status_code=404)
    file_path = request.path_params["path"]

    challenge_dir = CHALLENGES_DIR / challenge_id
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
    save_settings(settings)
    return JSONResponse(settings)


def get_challenge_stats() -> dict:
    """Aggregate per-agent stats from challenge metadata."""
    stats = {
        name: {
            "total": 0, "solved": 0, "failed": 0,
            "total_duration_ms": 0,
        }
        for name in VALID_AGENTS
    }
    for c in challenges.values():
        agent = c.get("agent", DEFAULT_AGENT)
        bucket = stats.setdefault(agent, {
            "total": 0,
            "solved": 0,
            "failed": 0,
            "total_duration_ms": 0,
        })
        bucket["total"] += 1
        if c["status"] == "solved":
            bucket["solved"] += 1
        elif c["status"] == "failed":
            bucket["failed"] += 1
        if c.get("duration_ms"):
            bucket["total_duration_ms"] += c["duration_ms"]
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


async def on_shutdown():
    for challenge in challenges.values():
        proc = challenge.get("process")
        if proc and proc.returncode is None:
            proc.terminate()
    for preview in _bulk_previews.values():
        shutil.rmtree(preview["base_dir"], ignore_errors=True)
    _bulk_previews.clear()


routes = [
    Route("/", index),
    Route("/api/login", login, methods=["POST"]),
    Route("/api/logout", logout, methods=["POST"]),
    Route("/api/csrf-token", csrf_token, methods=["GET"]),
    Route("/api/agents", list_agents, methods=["GET"]),
    Route("/api/usage", get_usage, methods=["GET"]),
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
    Route("/api/challenges/{id}", delete_challenge, methods=["DELETE"]),
    Route("/api/challenges/{id}/files", list_files, methods=["GET"]),
    Route("/api/challenges/{id}/files/{path:path}", get_file, methods=["GET"]),
    Route("/api/challenges/{id}/download/{path:path}", download_file, methods=["GET"]),
    WebSocketRoute("/ws/{id}", challenge_ws),
    Mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    ),
]

app = Starlette(
    routes=routes,
    on_shutdown=[on_shutdown],
    middleware=[
        Middleware(
            SessionMiddleware,
            secret_key=SESSION_SECRET,
            session_cookie="ctf_session",
            max_age=86400,
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
