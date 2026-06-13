"""Swarm manager — provision and control GCP worker VMs for CTF challenges.

The controller (web app host) uses this to build a golden image, clone worker
instances from it, manage their lifecycle, and SSH into them. Challenge
execution itself is driven by ``swarm_runner`` on the worker; this module owns
provisioning, the instance registry (``state/swarm.json``), and the SSH plumbing.

Design: see SWARM.md. This module never imports ``app`` (app imports it), so it
resolves paths from the same ``APP_ROOT_DIR`` environment variable that app uses.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Awaitable, Callable

try:  # works whether the app is imported as a package or run as a script
    from .gcp import GCPClient, GCPError, zone_to_region
except ImportError:
    from gcp import GCPClient, GCPError, zone_to_region

# ---------------------------------------------------------------------------
# Paths (kept in sync with app.py via the shared APP_ROOT_DIR env var)
# ---------------------------------------------------------------------------

APP_ROOT_DIR = Path(os.environ.get("APP_ROOT_DIR", "/root/ctf-agent-wrapper"))
STATE_ROOT_DIR = APP_ROOT_DIR / "state"
SWARM_FILE = STATE_ROOT_DIR / "swarm.json"
SWARM_KEY = STATE_ROOT_DIR / "swarm_key"
SWARM_KEY_PUB = STATE_ROOT_DIR / "swarm_key.pub"

# Runtime files synced to a worker (mirrors infra/gcp provisioning).
SYNC_PATHS = [
    "install_scripts", "webapp", "skills", "mcps", "README.md", "DESIGN.md",
    "SWARM.md",
]
# Agent credential dirs baked into the golden image / resynced on demand.
AGENT_CRED_DIRS = [".claude", ".codex"]

GOLDEN_IMAGE_NAME = "ctf-swarm-base"
GOLDEN_IMAGE_FAMILY = "ctf-swarm"
BASE_UBUNTU_IMAGE = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
REMOTE_ROOT = "/root/ctf-agent-wrapper"

SSH_OPTS = [
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15",
]

LogFn = Callable[[str], Awaitable[None]] | Callable[[str], None] | None


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

def swarm_config(settings: dict) -> dict:
    """Extract the swarm config block from global settings."""
    cfg = settings.get("swarm") if isinstance(settings, dict) else None
    return cfg if isinstance(cfg, dict) else {}


DEFAULT_ADC_TOKEN_COMMAND = "gcloud auth print-access-token"


def is_configured(settings: dict) -> bool:
    cfg = swarm_config(settings)
    if not cfg.get("zone"):
        return False
    # ADC and pasted-token modes have no embedded project, so one is required.
    if cfg.get("use_adc") or cfg.get("access_token"):
        return bool(cfg.get("project"))
    return bool(cfg.get("service_account"))


def make_client(settings: dict) -> GCPClient:
    cfg = swarm_config(settings)
    project = cfg.get("project") or None
    zone = cfg.get("zone", "")
    # Priority: host ADC (auto-refreshing) > pasted access token > SA key.
    if cfg.get("use_adc"):
        return GCPClient(
            project=project, zone=zone,
            token_command=cfg.get("gcloud_token_command") or DEFAULT_ADC_TOKEN_COMMAND,
        )
    if cfg.get("access_token"):
        return GCPClient(
            project=project, zone=zone, access_token=cfg["access_token"])
    sa = cfg.get("service_account")
    if isinstance(sa, str):
        try:
            sa = json.loads(sa)
        except json.JSONDecodeError as exc:
            raise GCPError(f"service account key is not valid JSON: {exc}") from exc
    if not sa:
        raise GCPError("no GCP service account configured")
    return GCPClient(sa, project=project, zone=zone)


# ---------------------------------------------------------------------------
# Registry (state/swarm.json)
# ---------------------------------------------------------------------------

def load_registry() -> dict:
    if SWARM_FILE.exists():
        try:
            data = json.loads(SWARM_FILE.read_text())
            if isinstance(data, dict) and isinstance(data.get("instances"), dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"instances": {}, "image": {}}


def save_registry(registry: dict) -> None:
    STATE_ROOT_DIR.mkdir(parents=True, exist_ok=True)
    SWARM_FILE.write_text(json.dumps(registry, indent=2))
    try:
        os.chmod(SWARM_FILE, 0o600)
    except OSError:
        pass


def upsert_instance(name: str, **fields) -> dict:
    reg = load_registry()
    inst = reg["instances"].get(name, {"name": name})
    inst.update(fields)
    reg["instances"][name] = inst
    save_registry(reg)
    return inst


def remove_instance(name: str) -> None:
    reg = load_registry()
    reg["instances"].pop(name, None)
    save_registry(reg)


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------

async def ensure_ssh_key() -> str:
    """Generate the controller's dedicated swarm keypair if absent; return pubkey."""
    STATE_ROOT_DIR.mkdir(parents=True, exist_ok=True)
    if not SWARM_KEY.exists() or not SWARM_KEY_PUB.exists():
        proc = await asyncio.create_subprocess_exec(
            "ssh-keygen", "-t", "ed25519", "-N", "", "-q",
            "-C", "ctf-swarm", "-f", str(SWARM_KEY),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, err = await proc.communicate()
        if proc.returncode != 0:
            raise GCPError(f"ssh-keygen failed: {err.decode(errors='replace')}")
        try:
            os.chmod(SWARM_KEY, 0o600)
        except OSError:
            pass
    return SWARM_KEY_PUB.read_text().strip()


# ---------------------------------------------------------------------------
# SSH / file transfer helpers
# ---------------------------------------------------------------------------

async def ssh_run(
    ip: str, command: str, *, timeout: float = 600.0, check: bool = True,
) -> tuple[int, str, str]:
    """Run a command on a worker over SSH. Returns (rc, stdout, stderr)."""
    args = ["ssh", "-i", str(SWARM_KEY), *SSH_OPTS, f"root@{ip}", command]
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise GCPError(f"ssh command timed out after {timeout:.0f}s: {command[:80]}")
    rc = proc.returncode or 0
    so, se = out.decode(errors="replace"), err.decode(errors="replace")
    if check and rc != 0:
        raise GCPError(f"ssh command failed (rc={rc}): {se.strip() or so.strip()}")
    return rc, so, se


async def ssh_write_file(ip: str, remote_path: str, content: str,
                         *, mode: str = "600") -> None:
    """Write text to a file on the worker over SSH (content via stdin)."""
    args = ["ssh", "-i", str(SWARM_KEY), *SSH_OPTS, f"root@{ip}",
            f"cat > {remote_path} && chmod {mode} {remote_path}"]
    proc = await asyncio.create_subprocess_exec(
        *args, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate(content.encode())
    if proc.returncode != 0:
        raise GCPError(f"failed to write {remote_path}: "
                       f"{err.decode(errors='replace').strip()}")


async def ssh_wait_ready(ip: str, *, timeout: float = 300.0) -> None:
    """Block until the worker accepts SSH."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = await ssh_run(ip, "true", timeout=15, check=False)
        if rc == 0:
            return
        await asyncio.sleep(5)
    raise GCPError(f"timed out waiting for SSH on {ip}")


async def rsync_to(ip: str, local: str, remote: str, *, delete: bool = False,
                   timeout: float = 600.0) -> None:
    """rsync a local path to the worker using the swarm key."""
    ssh_cmd = "ssh -i {} {}".format(SWARM_KEY, " ".join(SSH_OPTS))
    args = ["rsync", "-az", "-e", ssh_cmd]
    if delete:
        args.append("--delete")
    args += [local, f"root@{ip}:{remote}"]
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise GCPError(f"rsync to {ip} timed out")
    if proc.returncode != 0:
        raise GCPError(f"rsync failed: {err.decode(errors='replace').strip()}")


# ---------------------------------------------------------------------------
# Instance body construction
# ---------------------------------------------------------------------------

def normalize_machine_type(machine_type: str, cpus: int = 0, mem_mb: int = 0) -> str:
    """Return a machine-type short name. Custom RAM/CPU -> e2-custom-{cpu}-{mem}."""
    if machine_type and machine_type != "custom":
        return machine_type
    if cpus and mem_mb:
        return f"e2-custom-{cpus}-{mem_mb}"
    return "e2-standard-4"


def _instance_body(
    name: str, client: GCPClient, *, source_image: str, machine_type: str,
    disk_size_gb: int, disk_type: str, pubkey: str, network: str,
    subnetwork: str, tags: list[str], startup_script: str = "",
) -> dict:
    zone = client.zone
    body: dict = {
        "name": name,
        "machineType": f"zones/{zone}/machineTypes/{machine_type}",
        "disks": [{
            "boot": True,
            "autoDelete": True,
            "initializeParams": {
                "sourceImage": source_image,
                "diskSizeGb": int(disk_size_gb),
                "diskType": f"zones/{zone}/diskTypes/{disk_type}",
            },
        }],
        "networkInterfaces": [{
            "network": f"projects/{client.project}/global/networks/{network}",
            "accessConfigs": [{"type": "ONE_TO_ONE_NAT", "name": "External NAT"}],
        }],
        "metadata": {"items": [{"key": "ssh-keys", "value": f"root:{pubkey}"}]},
        "tags": {"items": tags},
    }
    if subnetwork:
        region = zone_to_region(zone)
        body["networkInterfaces"][0]["subnetwork"] = (
            f"projects/{client.project}/regions/{region}/subnetworks/{subnetwork}"
        )
    if startup_script:
        body["metadata"]["items"].append(
            {"key": "startup-script", "value": startup_script}
        )
    return body


# ---------------------------------------------------------------------------
# Golden image build
# ---------------------------------------------------------------------------

async def _emit(log: LogFn, msg: str) -> None:
    if log is None:
        return
    res = log(msg)
    if asyncio.iscoroutine(res):
        await res


async def _sync_runtime_files(ip: str, repo_root: Path) -> None:
    """tar the runtime files to the worker, preserving challenges/state/all-skills."""
    keep = "-not -name challenges -not -name state -not -name all-skills"
    remote = (
        f"TMP=$(mktemp -d {REMOTE_ROOT}.sync.XXXXXX) && trap 'rm -rf \"$TMP\"' EXIT && "
        f"mkdir -p {REMOTE_ROOT} {REMOTE_ROOT}/challenges {REMOTE_ROOT}/state "
        f"{REMOTE_ROOT}/all-skills && tar -C \"$TMP\" -xf - && "
        f"find {REMOTE_ROOT} -mindepth 1 -maxdepth 1 {keep} -exec rm -rf {{}} + && "
        f"cp -a \"$TMP\"/. {REMOTE_ROOT}/"
    )
    tar_args = [
        "tar", "-C", str(repo_root), "--exclude-vcs", "--exclude=__pycache__",
        "--exclude=*.pyc", "--exclude=*.pyo", "--exclude=.DS_Store", "-cf", "-",
        *[p for p in SYNC_PATHS if (repo_root / p).exists()],
    ]
    ssh_args = ["ssh", "-i", str(SWARM_KEY), *SSH_OPTS, f"root@{ip}", remote]
    # Connect tar's stdout to ssh's stdin via an OS pipe (a StreamReader cannot be
    # used directly as another subprocess's stdin).
    pipe_r, pipe_w = os.pipe()
    tar_proc = await asyncio.create_subprocess_exec(
        *tar_args, stdout=pipe_w, stderr=asyncio.subprocess.PIPE,
    )
    os.close(pipe_w)
    ssh_proc = await asyncio.create_subprocess_exec(
        *ssh_args, stdin=pipe_r,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    os.close(pipe_r)
    _, ssh_err = await ssh_proc.communicate()
    _, tar_err = await tar_proc.communicate()
    if tar_proc.returncode != 0:
        raise GCPError(f"tar failed: {tar_err.decode(errors='replace').strip()}")
    if ssh_proc.returncode != 0:
        raise GCPError(f"file sync failed: {ssh_err.decode(errors='replace').strip()}")


async def sync_agent_credentials(ip: str, *, home: Path | None = None) -> list[str]:
    """rsync the controller's ~/.claude and ~/.codex to a worker. Returns synced dirs."""
    home = home or Path(os.path.expanduser("~"))
    synced = []
    await ssh_run(ip, "mkdir -p /root", check=False)
    for cred in AGENT_CRED_DIRS:
        src = home / cred
        if src.is_dir():
            await rsync_to(ip, f"{src}/", f"/root/{cred}/", delete=False)
            synced.append(cred)
    return synced


async def build_golden_image(
    settings: dict, *, repo_root: Path, machine_type: str = "e2-standard-4",
    disk_size_gb: int = 100, disk_type: str = "pd-ssd", network: str = "default",
    subnetwork: str = "default", log: LogFn = None,
) -> dict:
    """Provision a base VM, run install scripts, bake creds, snapshot to an image.

    Returns the registry image record. Long-running (~10-15 min for installs).
    """
    client = make_client(settings)
    pubkey = await ensure_ssh_key()
    base_name = "ctf-swarm-builder"

    await _emit(log, "Creating base instance from Ubuntu image")
    body = _instance_body(
        base_name, client, source_image=BASE_UBUNTU_IMAGE,
        machine_type=machine_type, disk_size_gb=disk_size_gb, disk_type=disk_type,
        pubkey=pubkey, network=network, subnetwork=subnetwork, tags=["ctf-swarm"],
    )
    # Clean up any stale builder first.
    try:
        await client.delete_instance(base_name)
    except GCPError:
        pass
    await client.insert_instance(body)
    ip = await client.instance_external_ip(base_name)
    if not ip:
        raise GCPError("base instance has no external IP")

    await _emit(log, f"Waiting for SSH on {ip}")
    await ssh_wait_ready(ip)

    await _emit(log, "Syncing runtime files")
    await _sync_runtime_files(ip, repo_root)

    await _emit(log, "Running install scripts (this takes a while)")
    await ssh_run(ip, f"bash {REMOTE_ROOT}/install_scripts/run.sh", timeout=2400.0)

    await _emit(log, "Baking agent credentials into the image")
    synced = await sync_agent_credentials(ip)
    await _emit(log, f"Baked credentials: {', '.join(synced) or 'none found'}")

    await _emit(log, "Stopping base instance before snapshot")
    await client.stop_instance(base_name)

    await _emit(log, f"Creating image {GOLDEN_IMAGE_NAME} (deleting any prior one)")
    if await client.image_exists(GOLDEN_IMAGE_NAME):
        # Images are immutable; delete the old one first.
        await client.delete_image(GOLDEN_IMAGE_NAME)
    source_disk = (
        f"projects/{client.project}/zones/{client.zone}/disks/{base_name}"
    )
    await client.insert_image_from_disk(
        GOLDEN_IMAGE_NAME, source_disk, family=GOLDEN_IMAGE_FAMILY
    )

    await _emit(log, "Deleting base instance")
    await client.delete_instance(base_name)

    record = {
        "name": GOLDEN_IMAGE_NAME,
        "family": GOLDEN_IMAGE_FAMILY,
        "built_at": int(time.time()),
        "baked_credentials": synced,
        "zone": client.zone,
    }
    reg = load_registry()
    reg["image"] = record
    save_registry(reg)
    await _emit(log, "Golden image ready")
    return record


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------

async def create_worker(
    settings: dict, name: str, *, machine_type: str = "e2-standard-4",
    cpus: int = 0, mem_mb: int = 0, disk_size_gb: int = 100,
    disk_type: str = "pd-ssd", network: str = "default", subnetwork: str = "default",
) -> dict:
    """Clone a worker from the golden image and register it."""
    client = make_client(settings)
    if not await client.image_exists(GOLDEN_IMAGE_NAME):
        raise GCPError(
            f"golden image '{GOLDEN_IMAGE_NAME}' not found — build it first"
        )
    pubkey = await ensure_ssh_key()
    mtype = normalize_machine_type(machine_type, cpus, mem_mb)
    source_image = f"projects/{client.project}/global/images/{GOLDEN_IMAGE_NAME}"
    body = _instance_body(
        name, client, source_image=source_image, machine_type=mtype,
        disk_size_gb=disk_size_gb, disk_type=disk_type, pubkey=pubkey,
        network=network, subnetwork=subnetwork, tags=["ctf-swarm"],
    )
    await client.insert_instance(body)
    ip = await client.instance_external_ip(name)
    rec = upsert_instance(
        name, status="running", external_ip=ip, machine_type=mtype,
        disk_size_gb=disk_size_gb, zone=client.zone, created_at=int(time.time()),
        challenge_id=None, idle_since=int(time.time()),
    )
    return rec


async def start_worker(settings: dict, name: str) -> dict:
    client = make_client(settings)
    await client.start_instance(name)
    ip = await client.instance_external_ip(name)
    return upsert_instance(name, status="running", external_ip=ip,
                           idle_since=int(time.time()))


async def stop_worker(settings: dict, name: str) -> dict:
    client = make_client(settings)
    await client.stop_instance(name)
    return upsert_instance(name, status="stopped", external_ip="")


async def delete_worker(settings: dict, name: str) -> None:
    client = make_client(settings)
    try:
        await client.delete_instance(name)
    finally:
        remove_instance(name)


async def refresh_workers(settings: dict) -> list[dict]:
    """Reconcile the registry with GCP's actual instance states."""
    client = make_client(settings)
    live = {i.get("name"): i for i in await client.list_instances()}
    reg = load_registry()
    for name, inst in list(reg["instances"].items()):
        gcp_inst = live.get(name)
        if gcp_inst is None:
            inst["status"] = "missing"
            inst["external_ip"] = ""
            continue
        gcp_status = (gcp_inst.get("status") or "").lower()
        inst["status"] = "running" if gcp_status == "running" else gcp_status
        ip = ""
        for nic in gcp_inst.get("networkInterfaces", []):
            for cfg in nic.get("accessConfigs", []):
                if cfg.get("natIP"):
                    ip = cfg["natIP"]
        inst["external_ip"] = ip
    save_registry(reg)
    return list(reg["instances"].values())
