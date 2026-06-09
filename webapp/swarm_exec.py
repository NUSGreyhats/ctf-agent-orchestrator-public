"""Controller-side remote execution for the swarm.

``remote_run_agent`` is an async generator with the same yield contract as a
provider's ``run_agent`` (it yields normalized event dicts), but the agent
actually runs on a worker VM. It rsyncs the challenge files to the worker,
launches ``webapp.swarm_runner`` over SSH, and relays the worker's NDJSON event
stream. Two control events from the worker are consumed here rather than
yielded: ``_swarm_done`` (carries the final session state for resume) and
``_swarm_session`` (intermediate session-state updates).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from . import swarm as swarm_mod
from .gcp import GCPError

APP_ROOT_DIR = Path(os.environ.get("APP_ROOT_DIR", "/root/ctf-agent-wrapper"))
CHALLENGES_DIR = APP_ROOT_DIR / "challenges"
REMOTE_ROOT = swarm_mod.REMOTE_ROOT

# Run/challenge fields safe and relevant to ship to the worker.
_RUN_FIELDS = (
    "id", "agent", "model", "effort", "custom_prompt", "custom_prompt_mode",
    "goal", "notes_label", "enabled_skills", "_session_state",
)
_CHALLENGE_FIELDS = (
    "id", "name", "description", "flag_format", "mode", "category",
    "enabled_skills",
)


def _json_safe(value):
    """Recursively keep only JSON-serializable content."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return None


def _build_spec(challenge: dict, run: dict, prompt: str, is_continue: bool,
                env: dict, codex_skill_mentions: list[str]) -> dict:
    return {
        "challenge": {k: _json_safe(challenge.get(k)) for k in _CHALLENGE_FIELDS},
        "run": {k: _json_safe(run.get(k)) for k in _RUN_FIELDS},
        "prompt": prompt,
        "is_continue": is_continue,
        "env": _json_safe(env or {}),
        "codex_skill_mentions": list(codex_skill_mentions or []),
    }


async def _push_spec(ip: str, spec: dict, remote_path: str) -> None:
    """Write the spec JSON to the worker via SSH stdin."""
    args = ["ssh", "-i", str(swarm_mod.SWARM_KEY), *swarm_mod.SSH_OPTS,
            f"root@{ip}", f"cat > {remote_path}"]
    proc = await asyncio.create_subprocess_exec(
        *args, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate(json.dumps(spec).encode())
    if proc.returncode != 0:
        raise GCPError(f"failed to push run spec: {err.decode(errors='replace')}")


async def sync_challenge_files(ip: str, challenge_id: str) -> None:
    """rsync this challenge's _files (and ensure dirs) onto the worker."""
    remote_chal = f"{REMOTE_ROOT}/challenges/{challenge_id}"
    await swarm_mod.ssh_run(
        ip, f"mkdir -p {remote_chal}/_files {remote_chal}/_runs", check=False)
    files_dir = CHALLENGES_DIR / challenge_id / "_files"
    if files_dir.is_dir() and any(files_dir.iterdir()):
        await swarm_mod.rsync_to(ip, f"{files_dir}/", f"{remote_chal}/_files/")


async def remote_run_agent(
    challenge: dict, run: dict, prompt: str, is_continue: bool, ip: str, *,
    env: dict | None = None, codex_skill_mentions: list[str] | None = None,
):
    """Async generator yielding the worker's agent events (provider-compatible)."""
    cid = challenge["id"]
    rid = run["id"]
    await sync_challenge_files(ip, cid)

    spec = _build_spec(challenge, run, prompt, is_continue, env or {},
                       codex_skill_mentions or [])
    remote_spec = f"/tmp/ctf-swarm-spec-{cid}-{rid}.json"
    await _push_spec(ip, spec, remote_spec)

    launch = (
        f"cd {REMOTE_ROOT} && APP_ROOT_DIR={REMOTE_ROOT} "
        f"python3 -m webapp.swarm_runner {remote_spec}"
    )
    args = ["ssh", "-i", str(swarm_mod.SWARM_KEY), *swarm_mod.SSH_OPTS,
            f"root@{ip}", launch]
    proc = await asyncio.create_subprocess_exec(
        *args, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        limit=2 ** 24,
    )
    # Expose handles so stop/steer can reach the remote run.
    run["_swarm_proc"] = proc
    run["_swarm_stdin"] = proc.stdin

    try:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            try:
                event = json.loads(line.decode(errors="replace").strip())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(event, dict):
                continue
            etype = event.get("type")
            if etype in ("_swarm_session", "_swarm_done"):
                state = event.get("session_state")
                if isinstance(state, dict):
                    run.setdefault("_session_state", {}).update(state)
                if etype == "_swarm_done":
                    break
                continue
            yield event
    finally:
        run.pop("_swarm_stdin", None)
        run.pop("_swarm_proc", None)
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            pass


async def send_control(run: dict, message: dict) -> bool:
    """Send a JSON control line to a running remote agent. Returns success."""
    stdin = run.get("_swarm_stdin")
    if stdin is None:
        return False
    try:
        stdin.write((json.dumps(message) + "\n").encode())
        await stdin.drain()
        return True
    except (BrokenPipeError, ConnectionResetError, RuntimeError):
        return False


async def stop_remote_run(run: dict, reason: str = "controller_stop") -> None:
    """Ask the worker to stop, then kill the SSH process if it lingers."""
    await send_control(run, {"cmd": "stop", "reason": reason})
    proc = run.get("_swarm_proc")
    if proc is not None and proc.returncode is None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=8)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass


def is_remote_run(run: dict) -> bool:
    return run.get("_swarm_proc") is not None
