"""Worker-side run helper for the swarm (Model B / B3).

The controller launches this over SSH, once per agent run:

    python3 -m webapp.swarm_runner /path/to/spec.json

It reads a run-spec, sets up the run workspace on the worker, runs the agent
*locally on this worker* via the existing provider, and emits the provider's
event dicts as NDJSON on stdout. The controller reads that stream and feeds it
into the same persistence/broadcast path it uses for local runs.

Control channel: JSON lines on stdin. Currently supports ``{"cmd": "stop"}``,
which asks the run to wind down (mirrors the controller's ``_stop_reason``).

This module reuses the full webapp's workspace + provider helpers, so behaviour
matches local execution exactly. Importing ``app`` requires APP_PASSWORD and
SESSION_SECRET; we set throwaway values if absent since no server is started.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys


def _emit(event: dict) -> None:
    """Write one NDJSON event to stdout and flush immediately."""
    try:
        sys.stdout.write(json.dumps(event) + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        # Controller closed the channel; nothing more we can do.
        pass


def _load_app():
    # app.py reads these at import time and hard-fails if unset.
    os.environ.setdefault("APP_PASSWORD", "swarm-worker")
    os.environ.setdefault("SESSION_SECRET", "x" * 48)
    try:
        from . import app as app_mod
    except ImportError:
        import app as app_mod
    return app_mod


async def _stdin_control(run: dict) -> None:
    """Read control messages from stdin; set the run's stop flag on stop."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    try:
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    except (ValueError, OSError):
        return
    while True:
        line = await reader.readline()
        if not line:
            return
        try:
            msg = json.loads(line.decode().strip())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        cmd = msg.get("cmd")
        if cmd == "stop":
            run["_stop_reason"] = msg.get("reason", "controller_stop")
            return
        if cmd == "inject":
            # Teammate/broadcast injection: route through the in-process bus.
            text = msg.get("text", "")
            cid = run.get("_challenge_id", "")
            try:
                from .agents.broadcast import _queues
            except ImportError:
                from agents.broadcast import _queues
            for q in (_queues.get(cid, {}) or {}).values():
                q.put_nowait(text)


async def _run(spec: dict) -> int:
    app = _load_app()
    challenge = spec["challenge"]
    run = spec["run"]
    prompt = spec["prompt"]
    is_continue = bool(spec.get("is_continue"))
    env = spec.get("env") or {}
    cid = challenge["id"]
    rid = run["id"]
    run["_challenge_id"] = cid

    # Register the challenge so app's workspace helpers (which look it up in the
    # global dict) work unchanged.
    app.challenges[cid] = challenge

    # Build the run workspace on this worker (the controller has already synced
    # the challenge _files into place).
    if challenge.get("mode") == "parallel":
        app.setup_parallel_shared_dir(cid)
    app.setup_run_dir(cid, rid)
    app.sync_run_skill_links(challenge, run)
    app.seed_working_notes(cid, run)
    app.write_submit_answer_helper(cid, rid)

    run_cwd = app.get_run_cwd(cid, run)
    provider = app.get_provider(run["agent"])
    session_state = run.setdefault("_session_state", {})

    is_parallel = challenge.get("mode") == "parallel"
    if is_parallel:
        try:
            from .agents.broadcast import register_run, unregister_run
        except ImportError:
            from agents.broadcast import register_run, unregister_run
        register_run(cid, rid)

    control_task = asyncio.create_task(_stdin_control(run))
    last_error = None
    try:
        async for event in provider.run_agent(
            prompt=prompt,
            model=run.get("model", ""),
            effort=run.get("effort", ""),
            cwd=str(run_cwd),
            continue_session=is_continue,
            session_state=session_state,
            challenge_id=cid if is_parallel else "",
            run_id=rid if is_parallel else "",
            _codex_skill_mentions=spec.get("codex_skill_mentions") or [],
            _env=env,
            _run=run,
        ):
            if run.get("_stop_reason"):
                break
            if isinstance(event, dict):
                _emit(event)
                if event.get("type") == "error":
                    last_error = event.get("message", "")
    except asyncio.CancelledError:
        pass
    except Exception as exc:  # noqa: BLE001 - report and exit cleanly
        last_error = str(exc)
        _emit({"type": "error", "message": str(exc)})
    finally:
        control_task.cancel()
        if is_parallel:
            unregister_run(cid, rid)
        # Hand the updated session state back so the controller can resume.
        _emit({
            "type": "_swarm_done",
            "session_state": session_state,
            "stop_reason": run.get("_stop_reason"),
            "error": last_error,
        })
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        _emit({"type": "error", "message": "usage: swarm_runner <spec.json>"})
        return 2
    try:
        spec = json.loads(open(sys.argv[1]).read())
    except (OSError, json.JSONDecodeError) as exc:
        _emit({"type": "error", "message": f"bad spec: {exc}"})
        return 2
    try:
        return asyncio.run(_run(spec))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
