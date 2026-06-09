# Swarm — remote GCP execution for CTF agents

The **swarm** lets the web app dispatch a challenge to a dedicated GCP Compute
Engine instance instead of solving it on the same machine as the web app. The
goal is isolation: a single challenge's agents can hammer CPU/RAM/disk on their
own throwaway VM without degrading the controller (web app) host.

This document is the authoritative design. Status: **in progress** (branch
`swarm`).

## Decisions (locked)

| Area | Decision |
|------|----------|
| Execution model | **Model B** — the `claude`/`codex` process runs *on the worker VM*, not the controller. |
| Run mechanism | **B3 thin run-helper** — controller SSHes in and runs `python -m webapp.swarm_runner`, which drives the existing `provider.run_agent()` on the worker and streams events home. |
| Instance granularity | **Per-challenge** — a challenge is pinned to one worker; *all* its agent runs execute there (native collaboration on one filesystem). |
| GCP auth | **Service-account JSON key** (Compute Admin), stored in settings (file `0600`, kept out of logs). |
| Image strategy | **Golden machine image** — provision one base VM with `install_scripts`, snapshot to a reusable image, clone workers from it (~60s spin-up). |
| Lifecycle | **Start / Stop / Delete** per instance (no per-instance snapshots); one golden image for cloning. |
| Workspace | **Stream + live SSH browse** — events (notes/flags/output) come home over the stream; the Files tab reads the worker workspace live over SSH. No rsync-back. |
| Remote agent auth | `claude`/`codex` creds **baked into the golden image** + a "sync credentials from host" action to refresh rotated tokens. |
| VPN | **Solution 2 (hub-and-spoke)** — workers proxy reverse-tunnel VPN traffic through the controller's existing `wg0`; user VPN setup is unchanged. Opt-in toggle; **Local** run target is the fallback. |
| Idle auto-stop | Configurable; **default 30 min** with no active run. Can be disabled. |
| Firewall | Worker SSH (22) ingress locked to the controller's public IP (fallback `0.0.0.0/0` + warning if detection fails). |
| Security | Accepted: workers run as root, hold platform creds + baked agent tokens; firewall lock-to-controller is the main mitigation. Disposable-VM model. |

## Architecture

```
┌─────────────── Controller (the web app host) ───────────────────────┐
│  GCP control plane: create golden image, clone/start/stop/delete     │
│  Owns ALL state: challenges, runs, logs, flags, state/swarm.json     │
│  Per challenge assigned to a worker:                                 │
│    1. rsync challenge _files/ -> worker workspace                    │
│    2. open ONE SSH session: stdin=control, stdout=NDJSON events      │
│    3. persist + WebSocket-broadcast events (the SAME path as local)  │
│  WireGuard server (wg0) — also peers workers for VPN (Solution 2)    │
└───────────────┬──────────────────────────────────────────────────────┘
                │ SSH (controller's dedicated swarm keypair)
                ▼
┌─────────────── Swarm worker (cloned from golden image) ──────────────┐
│  python -m webapp.swarm_runner   (ONE daemon per challenge)          │
│    • hosts all the challenge's runs in-process                       │
│    • calls the EXISTING provider.run_agent() per run                 │
│    • shared filesystem => WORKING_NOTES, _shared, notify_teammates   │
│      and broadcast queues all work natively (no relay)               │
│    • control protocol over stdin: start/steer/stop/add-run/broadcast │
│    • emits merged NDJSON events on stdout, tagged by run_id          │
│  agent + gdb MCP + IDA + all tools run HERE                          │
│  ~/.claude & ~/.codex baked into the image (+ resync action)         │
│  Optional wg client -> controller for VPN-routed internal CIDRs      │
└──────────────────────────────────────────────────────────────────────┘
```

## Components

- **`webapp/gcp.py`** — thin GCP Compute client. Mints an access token from the
  service-account JSON via `google-auth` (RS256 JWT → token), then drives the
  Compute REST API with `httpx` (consistent with the platform plugins).
  Operations: create/get/list/start/stop/delete instance, create image, clone
  from image, wait-on-operation, manage instance metadata (SSH keys).
- **`webapp/swarm.py`** — swarm manager. Instance registry in
  `state/swarm.json`; SSH keypair generation (`state/swarm_key`, `0600`);
  golden-image build; clone/start/stop/delete; idle auto-stop loop; per-worker
  WireGuard peer enrollment (Solution 2).
- **`webapp/swarm_runner.py`** — present on every worker via the image. One
  daemon per challenge; control protocol on stdin (JSON lines), merged event
  stream on stdout (JSON lines). Reuses `agents/*` + `agents/broadcast.py`.
- **`app.py` glue** — when a challenge is assigned to a worker, `run_agent_task`
  takes the remote branch: rsync files, launch/attach the per-challenge daemon,
  feed its NDJSON stream into the existing event consumer. Steering/stop/add-run
  become control-protocol messages. Runs are sticky-pinned to the worker (the
  agent session state lives there).
- **Settings + UI** — `settings.json` gains a `swarm` block (registered in
  `load_settings` defaults so it persists). New Swarm management page: paste
  service-account JSON + project/zone, build golden image, spin up N workers
  with configurable specs (E2 predefined **or** `e2-custom-{vCPU}-{MB}` + disk
  GB), Start/Stop/Delete, sync credentials, toggle VPN routing. Challenge
  create + run controls get a **Run target: Local | Swarm (auto) | Swarm:
  <instance>** selector.

## VPN (Solution 2 — hub-and-spoke)

The controller stays the single WireGuard server. A VPN-enabled worker is
enrolled as an extra `wg0` peer; the worker routes the internal CIDRs through
the tunnel to the controller, which forwards into the existing reverse dial-in
client. The existing server rules already allow this:

- `iptables -A FORWARD -i wg0 ... -o wg0 ACCEPT` permits wg0↔wg0 forwarding.
- the dial-in client's `-s {VPN_CIDR} -d {net} MASQUERADE` covers worker-sourced
  packets (workers get IPs inside `VPN_CIDR`).

New work: per-worker keypair, allocate a VPN IP in the existing `/24`, add/remove
the `[Peer]` on the controller's `wg0.conf`, and push a small wg config to the
worker (`Endpoint = <controller_pub_ip>:51820`, `AllowedIPs = {VPN_CIDR} + internal
CIDRs`, `DNS = {VPN_SERVER_IP}` when dns_forward is on). User-facing VPN setup is
unchanged.

## Build order / status

1. ✅ GCP client (`gcp.py`) + creds settings + connectivity test.
2. ✅ Golden-image build (provision base via `install_scripts`, bake creds, snapshot).
3. ✅ Clone/start/stop/delete + `state/swarm.json` + Swarm UI.
4. ✅ `swarm_runner.py` + controller dispatch (`swarm_exec.py`) + event plumbing.
5. ✅ Run-target selector + per-challenge pinning + stop over SSH.
6. ✅ Creds resync + idle auto-stop + VPN hub-and-spoke peering + live SSH file browse.

### Validated against live GCP (us-central1)

All paths exercised end-to-end on a real project:

- Auth (service-account **and** ADC token mode), connectivity, instance
  create/start/stop/delete, SSH, rsync, `ssh_write_file`.
- **Golden image build**: full `install_scripts/run.sh` ran clean (~12 min on
  e2-standard-8), creds baked, snapshot created — 16.8 min total.
- **Live agent execution**: a cloned worker ran a real Claude agent via
  `swarm_runner`; it `Read` `./challenge_files/flag.txt` and the flag streamed
  back through `remote_run_agent` into the normal event pipeline (~6s).
- **SSH file browse**: listing, symlink resolution into `_files`, text+binary
  read, traversal blocked.
- **VPN hub-and-spoke**: worker enrolled as a `wg0` peer handshakes with the
  hub and reaches a service on the hub's VPN IP (`10.13.37.1`).

### Firewall requirement (found in testing)

The controller must allow **`udp:51820` ingress** for workers to establish the
WireGuard tunnel. The Terraform-provisioned controller VM already opens this
(`allow-<name>-wireguard`), so production is covered — but the swarm does **not**
itself create that rule. If the controller runs outside that Terraform, add a
`udp:51820` ingress rule. (SSH/22 currently relies on the project's existing
`default-allow-ssh`; the design's "lock SSH to controller IP" rule is not yet
implemented.)

## Follow-ups (not yet implemented)

The swarm works end-to-end without these, but they are hardening items the
design calls for. The swarm currently relies on firewall rules that already
exist rather than managing its own.

- **Auto-create the `udp:51820` (WireGuard) ingress rule.** Today the VPN relies
  on the Terraform controller VM already opening 51820. The swarm should create
  this rule (scoped to the worker tag / controller) when VPN routing is enabled,
  so a controller running outside that Terraform still works. *Found in testing:
  the rule had to be added by hand for the worker→controller handshake.*
- **Lock worker SSH (port 22) to the controller IP.** Workers currently accept
  SSH from `0.0.0.0/0` via the project's `default-allow-ssh` (key-only auth, but
  not IP-restricted). The design wants a dedicated rule restricting 22 to the
  controller's egress IP, created at worker provisioning time.
- **Re-enroll VPN on Stop→Start.** A worker's external IP changes across a
  stop/start; the wg peer is not re-enrolled automatically (see below).

## Known limitations

- A worker holds one challenge's state on its local disk; **Delete destroys the
  workspace** (centralized logs/flags/notes survive on the controller via the
  event stream). Stop preserves the disk.
- **VPN on start/stop**: a worker is enrolled on VPN at create time and removed
  at delete. Stop/Start (which changes the external IP) does not yet re-enroll —
  re-create or re-enroll the peer if you cycle a VPN worker.
- VPN routing is the reverse-tunnel model only. CTF-provided *forward* VPN
  configs (drop a config directly on the worker) are a possible future add-on.
- `notify_teammates` across agents works via the shared worker filesystem
  (same instance per challenge); the controller-side relay path exists for
  cross-process injection (`swarm_runner` `inject` control message).
