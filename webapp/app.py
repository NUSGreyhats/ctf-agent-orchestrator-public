#!/usr/bin/env python3
"""CTF Challenge Solver Web App.

Spawns Claude Code or GitHub Copilot CLI agents to solve CTF
challenges, streaming JSONL output to authenticated users via
WebSocket.
"""

import asyncio
import base64
import json
import mimetypes
import os
import secrets
import shutil
import subprocess
import uuid
import tempfile
import time as _time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

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
CHALLENGES_DIR = Path("/root/all-things-ai/challenges")
CHALLENGES_DIR.mkdir(parents=True, exist_ok=True)

# Rate limiting for login
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_login_attempts: dict[str, list[float]] = defaultdict(list)

challenges: dict[str, dict] = {}

METADATA_FILE = "challenge.json"
OUTPUT_FILE = "output.jsonl"
SETTINGS_FILE = CHALLENGES_DIR / "settings.json"

VALID_AGENTS = {"claude", "copilot"}

# Temporary storage for bulk-upload previews: token -> {base_dir, created_at, folders}
_bulk_previews: dict[str, dict] = {}
_PREVIEW_TTL = 3600  # seconds


def _cleanup_old_previews() -> None:
    now = _time.monotonic()
    expired = [
        t for t, p in _bulk_previews.items()
        if now - p["created_at"] > _PREVIEW_TTL
    ]
    for token in expired:
        base_dir = _bulk_previews.pop(token)["base_dir"]
        shutil.rmtree(base_dir, ignore_errors=True)


def load_settings() -> dict:
    """Load global settings from disk."""
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"default_agent": "claude", "default_flag_format": ""}


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
        "autonomous": challenge.get("autonomous", False),
        "status": challenge["status"],
        "created_at": challenge["created_at"],
        "files": challenge["files"],
        "error": challenge["error"],
        "duration_ms": challenge.get("duration_ms"),
    }
    meta_path = CHALLENGES_DIR / challenge["id"] / METADATA_FILE
    meta_path.write_text(json.dumps(meta, indent=2))


def append_output_event(challenge_id: str, event: dict) -> None:
    """Append a single event to the output log on disk."""
    out_path = CHALLENGES_DIR / challenge_id / OUTPUT_FILE
    with out_path.open("a") as f:
        f.write(json.dumps(event) + "\n")


def clear_output_log(challenge_id: str) -> None:
    """Clear the output log file for a fresh run."""
    out_path = CHALLENGES_DIR / challenge_id / OUTPUT_FILE
    if out_path.exists():
        out_path.unlink()


def load_output_log(challenge_id: str) -> list[dict]:
    """Load saved output events from disk."""
    out_path = CHALLENGES_DIR / challenge_id / OUTPUT_FILE
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


def normalize_copilot_events(events: list[dict]) -> list[dict]:
    """Normalize Copilot events to match Claude format for batch loading.

    Handles both raw Copilot events and already-normalized events
    (from output.jsonl written by the live normalizer). For raw
    events, maps subagent lifecycle and preserves parentToolCallId
    as parent_tool_use_id for subagent tab routing.
    """
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


def _normalize_copilot_live(
    event: dict, challenge: dict
) -> dict | None:
    """Normalize a single raw Copilot event during live streaming.

    Transforms raw Copilot events into Claude-compatible format.
    Subagent routing uses data.parentToolCallId from the raw event,
    mapped to parent_tool_use_id on the normalized output.
    """
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
        # Track task descriptions for subagent tab names
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

    # Skip ephemeral/streaming events
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


def _normalize_output_lines(
    events: list[dict], agent: str
) -> list[dict]:
    if agent != "copilot":
        return events
    return normalize_copilot_events(events)


def load_challenges_from_disk() -> None:
    """Scan CHALLENGES_DIR for existing challenges on startup."""
    for d in sorted(CHALLENGES_DIR.iterdir()):
        if not d.is_dir():
            continue
        challenge_id = d.name
        if challenge_id in challenges:
            continue
        meta_path = d / METADATA_FILE
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except (json.JSONDecodeError, OSError):
                meta = {}
        else:
            meta = {}

        # If it was solving when the app died, mark failed
        status = meta.get("status", "unknown")
        if status == "solving":
            status = "failed"

        challenges[challenge_id] = {
            "id": challenge_id,
            "name": meta.get("name", f"Challenge {challenge_id}"),
            "description": meta.get("description", ""),
            "flag_format": meta.get("flag_format", ""),
            "agent": meta.get("agent", "claude"),
            "model": meta.get("model", "opus"),
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
                meta.get("agent", "claude"),
            ),
            "ws_clients": set(),
            "error": meta.get("error"),
            "duration_ms": meta.get("duration_ms"),
            "solve_start": None,
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
    agent = form.get("agent", "").strip() or "claude"
    model = form.get("model", "").strip() or "opus"
    autonomous = form.get("autonomous", "").strip() == "true"

    # Read uploaded files into memory so we can copy to multiple dirs
    file_data: dict[str, bytes] = {}
    for _, field in form.multi_items():
        if hasattr(field, "filename") and field.filename:
            safe_name = Path(field.filename).name
            if not safe_name:
                continue
            file_data[safe_name] = await field.read()

    if agent == "both":
        agents_to_run = [
            ("claude", model or "opus"),
            ("copilot", model or "opus"),
        ]
    else:
        agents_to_run = [(agent, model)]

    created = []
    for run_agent_name, run_model in agents_to_run:
        challenge_id = uuid.uuid4().hex[:12]
        display_name = name or f"Challenge {challenge_id}"
        if len(agents_to_run) > 1:
            prefix = f"[{run_agent_name.capitalize()}] "
            display_name = f"{prefix}{display_name}"

        challenge_dir = CHALLENGES_DIR / challenge_id
        challenge_dir.mkdir(parents=True)
        for fname, fdata in file_data.items():
            (challenge_dir / fname).write_bytes(fdata)

        challenge = {
            "id": challenge_id,
            "name": display_name,
            "description": description,
            "flag_format": flag_format,
            "agent": run_agent_name,
            "model": run_model,
            "autonomous": autonomous,
            "status": "solving",
            "created_at": datetime.now().isoformat(),
            "files": list(file_data.keys()),
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
    """Unzip an uploaded archive and return a preview of the challenges found.

    Returns a preview_token (valid for 1 hour) and the list of challenges
    extracted from the zip's top-level folders. The caller uses the token
    with POST /api/challenges/bulk to create the actual challenges after
    the user has reviewed and optionally edited each entry.
    """
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    import zipfile
    import io

    form = await request.form()
    zip_field = form.get("zipfile")
    if not zip_field or not hasattr(zip_field, "read"):
        return JSONResponse(
            {"error": "No archive uploaded"}, status_code=400
        )

    zip_bytes = await zip_field.read()
    original_name = (getattr(zip_field, "filename", None) or "").lower()
    is_7z = original_name.endswith(".7z")

    _cleanup_old_previews()
    token = uuid.uuid4().hex[:16]
    base_dir = Path(tempfile.mkdtemp(prefix=f"ctf-bulk-{token}-"))

    archive_files: dict[str, bytes] = {}
    try:
        if is_7z:
            tmp_archive = base_dir / "_archive.7z"
            tmp_archive.write_bytes(zip_bytes)
            extract_dir = base_dir / "_extract"
            extract_dir.mkdir()
            result = subprocess.run(
                ["7z", "x", f"-o{extract_dir}", "-y", str(tmp_archive)],
                capture_output=True, text=True,
            )
            tmp_archive.unlink(missing_ok=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr or result.stdout)
            for p in extract_dir.rglob("*"):
                if p.is_file():
                    archive_files[p.relative_to(extract_dir).as_posix()] = p.read_bytes()
        else:
            try:
                zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
            except zipfile.BadZipFile:
                shutil.rmtree(base_dir, ignore_errors=True)
                return JSONResponse({"error": "Invalid zip file"}, status_code=400)
            archive_files = {
                name: zf.read(name)
                for name in zf.namelist()
                if not name.endswith("/")
            }
    except Exception as exc:
        shutil.rmtree(base_dir, ignore_errors=True)
        return JSONResponse({"error": f"Failed to read archive: {exc}"}, status_code=400)

    # Group entries by top-level folder
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

    _DESCRIPTION_FILES = {"description.txt", "prompt.txt"}

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
            if filename.lower() in _DESCRIPTION_FILES:
                description = raw.decode("utf-8", errors="replace").strip()
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
    return JSONResponse(
        {"preview_token": token, "challenges": challenges_preview}
    )


async def bulk_upload(request: Request) -> JSONResponse:
    """Create challenges from a previously previewed zip.

    Expects a JSON body with:
      preview_token  – token returned by bulk_preview
      flag_format    – global default flag format
      agent          – "claude", "copilot", or "both"
      model          – model slug
      autonomous     – bool
      challenges     – list of per-challenge overrides:
          { folder_name, name, description, flag_format, enabled }
    """
    if err := require_auth(request):
        return err
    if err := require_csrf(request):
        return err

    body = await request.json()
    token = body.get("preview_token", "")
    if not token or token not in _bulk_previews:
        return JSONResponse(
            {"error": "Invalid or expired preview token"},
            status_code=400,
        )

    preview = _bulk_previews.pop(token)
    base_dir = preview["base_dir"]
    preview_folders = preview["folders"]

    global_flag_format = body.get("flag_format", "").strip()
    agent = body.get("agent", "claude").strip() or "claude"
    model = body.get("model", "opus").strip() or "opus"
    autonomous = bool(body.get("autonomous", False))
    paused = bool(body.get("paused", False))
    challenges_cfg = body.get("challenges", [])

    if agent == "both":
        agents_to_run = [("claude", model), ("copilot", model)]
    else:
        agents_to_run = [(agent, model)]

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
        ch_flag_format = cfg.get("flag_format", "").strip() or global_flag_format

        for run_agent_name, run_model in agents_to_run:
            challenge_id = uuid.uuid4().hex[:12]
            challenge_dir = CHALLENGES_DIR / challenge_id
            challenge_dir.mkdir(parents=True)
            for fname in file_names:
                src = folder_dir / fname
                if src.exists():
                    shutil.copy2(src, challenge_dir / fname)

            prefix = (
                f"[{run_agent_name.capitalize()}] "
                if len(agents_to_run) > 1
                else ""
            )
            display_name = f"{prefix}{ch_name}"
            challenge = {
                "id": challenge_id,
                "name": display_name,
                "description": ch_description,
                "flag_format": ch_flag_format,
                "agent": run_agent_name,
                "model": run_model,
                "autonomous": autonomous,
                "status": "pending" if paused else "solving",
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
            if not paused:
                challenge["task"] = asyncio.create_task(run_agent(challenge_id))
            created.append({"id": challenge_id, "name": display_name})

    shutil.rmtree(base_dir, ignore_errors=True)
    return JSONResponse({"created": created}, status_code=201)


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

    if not str(full_path).startswith(str(challenge_dir.resolve())):
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
    for ws in challenge["ws_clients"]:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        challenge["ws_clients"].discard(ws)


def build_prompt(challenge: dict) -> str:
    """Build the CTF solving prompt."""
    parts = [
        "You are solving a CTF challenge. Start by running: "
        "/ctf-methodology",
        "This will load the CTF methodology skill with the "
        "full solving process, tools, and flag-finding "
        "techniques.",
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
        "",
        "Follow the methodology strictly:",
        "1. Run ctfgrep first for a quick flag search "
        "across all encodings",
        "2. Triage the files (file, exiftool, strings, "
        "binwalk)",
        "3. Identify the category and load the relevant "
        "domain skill (memory-forensics, "
        "network-forensics, file-forensics, "
        "disk-forensics, headless-ida-analysis, "
        "libdebug-debugging, apk-analysis)",
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


COPILOT_MODEL_MAP = {
    "opus": "claude-opus-4.6",
    "sonnet": "claude-sonnet-4.6",
    "haiku": "claude-haiku-4.5",
}


def build_agent_cmd(
    challenge: dict, prompt: str, is_continue: bool
) -> list[str]:
    """Build the CLI command for the selected agent."""
    agent = challenge.get("agent", "claude")

    if agent == "copilot":
        model = challenge["model"]
        model = COPILOT_MODEL_MAP.get(model, model)
        cmd = [
            "copilot",
            "-p", prompt,
            "--yolo",
            "--output-format", "json",
            "--model", model,
        ]
        if is_continue:
            cmd.append("--continue")
        return cmd

    # Default: Claude Code
    cmd = [
        "claude", "-p",
        "--dangerously-skip-permissions",
        "--output-format", "stream-json",
        "--verbose",
        "--model", challenge["model"],
    ]
    if is_continue:
        cmd.append("--continue")
    cmd.append(prompt)
    return cmd


async def run_agent(
    challenge_id: str, continue_msg: str | None = None
):
    challenge = challenges[challenge_id]
    challenge_dir = CHALLENGES_DIR / challenge_id
    challenge["solve_start"] = _time.monotonic()
    agent_type = challenge.get("agent", "claude")

    if continue_msg:
        prompt = continue_msg
    else:
        prompt = build_prompt(challenge)

    agent_label = "Copilot" if agent_type == "copilot" else "Claude"
    if continue_msg:
        sys_event = {
            "type": "system",
            "message": f"Continuing {agent_label} conversation "
            "with guidance...",
        }
    else:
        sys_event = {
            "type": "system",
            "message": f"{agent_label} agent starting...",
        }
    challenge["output_lines"].append(sys_event)
    append_output_event(challenge_id, sys_event)
    await broadcast(challenge_id, sys_event)

    env = os.environ.copy()
    env["IS_SANDBOX"] = "1"

    cmd = build_agent_cmd(
        challenge, prompt, is_continue=bool(continue_msg)
    )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(challenge_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        limit=2 ** 24,  # 16 MB — default 64 KB is too small for large Claude JSON events
    )
    challenge["process"] = proc

    try:
        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"type": "raw", "text": line}

            if challenge.get("agent") == "copilot":
                event = _normalize_copilot_live(
                    event, challenge
                )
                if event is None:
                    continue

            challenge["output_lines"].append(event)
            append_output_event(challenge_id, event)
            await broadcast(challenge_id, event)

        await proc.wait()

        if proc.returncode == 0:
            challenge["status"] = "solved"
            challenge["error"] = None
        else:
            stderr_out = ""
            if proc.stderr:
                stderr_bytes = await proc.stderr.read()
                stderr_out = stderr_bytes.decode(
                    "utf-8", errors="replace"
                ).strip()
            challenge["status"] = "failed"
            error_msg = (
                f"Agent exited with code {proc.returncode}"
            )
            if stderr_out:
                error_msg += f"\n{stderr_out}"
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

    if not str(full_path).startswith(str(challenge_dir.resolve())):
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
        settings["default_flag_format"] = str(body["default_flag_format"])
    if "theme" in body:
        theme = str(body["theme"])
        if theme in ("dark", "light"):
            settings["theme"] = theme
    save_settings(settings)
    return JSONResponse(settings)


CLAUDE_STATS_FILE = Path.home() / ".claude" / "stats-cache.json"
COPILOT_CONFIG_FILE = Path.home() / ".copilot" / "config.json"
COPILOT_SESSIONS_DIR = Path.home() / ".copilot" / "session-state"


def get_claude_auth() -> dict | None:
    """Get Claude auth status via CLI."""
    try:
        result = subprocess.run(
            ["claude", "auth", "status", "--json"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def get_claude_stats() -> dict | None:
    """Read Claude's stats cache from disk."""
    if CLAUDE_STATS_FILE.exists():
        try:
            return json.loads(CLAUDE_STATS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return None


def get_copilot_auth() -> dict | None:
    """Read Copilot auth info from config."""
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


def get_copilot_session_count() -> int:
    """Count Copilot session directories."""
    if COPILOT_SESSIONS_DIR.is_dir():
        return sum(
            1 for d in COPILOT_SESSIONS_DIR.iterdir()
            if d.is_dir()
        )
    return 0


def get_challenge_stats() -> dict:
    """Aggregate per-agent stats from challenge metadata."""
    stats = {
        "claude": {
            "total": 0, "solved": 0, "failed": 0,
            "total_duration_ms": 0,
        },
        "copilot": {
            "total": 0, "solved": 0, "failed": 0,
            "total_duration_ms": 0,
        },
    }
    for c in challenges.values():
        agent = c.get("agent", "claude")
        bucket = stats.get(agent, stats["claude"])
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

    result = {"claude": None, "copilot": None, "challenges": {}}

    claude_auth = get_claude_auth()
    if claude_auth and claude_auth.get("loggedIn"):
        claude_data = {"auth": claude_auth}
        stats = get_claude_stats()
        if stats:
            claude_data["totalSessions"] = stats.get(
                "totalSessions", 0
            )
            claude_data["totalMessages"] = stats.get(
                "totalMessages", 0
            )
            claude_data["dailyActivity"] = stats.get(
                "dailyActivity", []
            )
            claude_data["modelUsage"] = stats.get(
                "modelUsage", {}
            )
        result["claude"] = claude_data

    copilot_auth = get_copilot_auth()
    if copilot_auth and copilot_auth.get("loggedIn"):
        result["copilot"] = {
            "auth": copilot_auth,
            "totalSessions": get_copilot_session_count(),
        }

    result["challenges"] = get_challenge_stats()
    return JSONResponse(result)


async def on_shutdown():
    for challenge in challenges.values():
        proc = challenge.get("process")
        if proc and proc.returncode is None:
            proc.terminate()
    for preview in _bulk_previews.values():
        shutil.rmtree(preview["base_dir"], ignore_errors=True)


routes = [
    Route("/", index),
    Route("/api/login", login, methods=["POST"]),
    Route("/api/logout", logout, methods=["POST"]),
    Route("/api/csrf-token", csrf_token, methods=["GET"]),
    Route("/api/usage", get_usage, methods=["GET"]),
    Route("/api/settings", get_settings, methods=["GET"]),
    Route("/api/settings", update_settings, methods=["PUT"]),
    Route("/api/challenges", list_challenges, methods=["GET"]),
    Route("/api/challenges", create_challenge, methods=["POST"]),
    Route("/api/challenges/bulk-preview", bulk_preview, methods=["POST"]),
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
        port=80,
        log_level="info",
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
