# Swarm — remote GCP execution for CTF agents

The **swarm** lets the web app dispatch a challenge to a dedicated GCP Compute
Engine worker instead of solving it on the controller (the web app host). The
goal is isolation: one challenge's agents can hammer CPU/RAM/disk on their own
throwaway VM without degrading the controller or other challenges.

Workers are cloned from a pre-built **golden image** (~60s spin-up), pinned
per-challenge, and disposable. The controller owns all durable state (challenges,
runs, logs, flags); a deleted worker loses only its local workspace.

## How it works

The `claude`/`codex` process runs **on the worker**, not the controller. The
controller SSHes in and runs `python -m webapp.swarm_runner`, a thin daemon that
drives the existing `provider.run_agent()` and streams events home — the same
event pipeline as a local run, so persistence, WebSocket broadcast, steering, and
stop all work unchanged.

A challenge is pinned to **one** worker, so all its agent runs share a single
filesystem. Collaboration (`WORKING_NOTES`, `_shared/`, `notify_teammates`,
broadcast queues) therefore works natively, with no cross-host relay.

```
┌─────────────── Controller (web app host) ───────────────────────────┐
│  GCP control plane: build golden image, clone/start/stop/delete      │
│  Owns ALL state: challenges, runs, logs, flags, state/swarm.json     │
│  Per challenge assigned to a worker:                                 │
│    1. rsync challenge _files/ -> worker workspace                    │
│    2. open ONE SSH session: stdin=control, stdout=NDJSON events      │
│    3. persist + WebSocket-broadcast events (the SAME path as local)  │
│  WireGuard server (wg0) — also peers workers for VPN routing         │
└───────────────┬──────────────────────────────────────────────────────┘
                │ SSH (controller's dedicated swarm keypair)
                ▼
┌─────────────── Swarm worker (cloned from golden image) ──────────────┐
│  python -m webapp.swarm_runner   (ONE daemon per challenge)          │
│    • hosts all the challenge's runs in-process                       │
│    • calls the EXISTING provider.run_agent() per run                 │
│    • shared filesystem => WORKING_NOTES, _shared, notify_teammates   │
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
  Compute REST API with `httpx`. Operations: create/get/list/start/stop/delete
  instance, create image, clone from image, wait-on-operation, manage instance
  metadata (SSH keys). Also supports ADC token mode.
- **`webapp/swarm.py`** — swarm manager. Instance registry in
  `state/swarm.json`; SSH keypair generation (`state/swarm_key`, `0600`);
  golden-image build; clone/start/stop/delete; idle auto-stop loop; per-worker
  WireGuard peer enrollment.
- **`webapp/swarm_runner.py`** — present on every worker via the image. One
  daemon per challenge; control protocol on stdin (JSON lines), merged event
  stream on stdout (JSON lines). Reuses `agents/*` + `agents/broadcast.py`.
- **`webapp/swarm_exec.py`** — controller-side dispatch: rsync files, launch/
  attach the per-challenge daemon, and feed its NDJSON stream into the existing
  event consumer. Steering/stop/add-run/broadcast become control messages. Runs
  are sticky-pinned to the worker (session state lives there).
- **Settings + UI** — `settings.json` gains a `swarm` block. The Swarm page
  takes a service-account JSON + project/zone, builds the golden image, and spins
  up workers with configurable specs (E2 predefined or `e2-custom-{vCPU}-{MB}` +
  disk GB), Start/Stop/Delete, credential sync, and VPN toggle. Challenge create
  and run controls get a **Run target: Local | Swarm (auto) | Swarm: \<instance\>**
  selector.

## Configuration & lifecycle

| Area | Behavior |
|------|----------|
| GCP auth | Service-account JSON key (Compute Admin), stored in settings (file `0600`, kept out of logs). ADC token mode also supported. |
| Image strategy | One golden image: provision a base VM with `install_scripts`, bake `~/.claude`/`~/.codex` creds, snapshot. Workers clone from it. |
| Credentials | Baked into the image, plus a "sync credentials from host" action to refresh rotated tokens. |
| Idle auto-stop | Configurable; **default 30 min** with no active run. Can be disabled. |
| Run target fallback | **Local** execution is always the fallback when no worker is assigned. |

### Security model

Accepted trade-off of the disposable-VM model: workers run as root and hold
platform creds plus baked agent tokens. The intended mitigation is locking
worker SSH to the controller's IP — see follow-ups below.

## VPN (hub-and-spoke)

The controller stays the single WireGuard server. A VPN-enabled worker is
enrolled as an extra `wg0` peer and routes internal CIDRs through the tunnel to
the controller, which forwards into the existing reverse dial-in client. The
existing server rules already permit this (`wg0`↔`wg0` FORWARD ACCEPT; the
dial-in client's MASQUERADE covers worker-sourced packets, since workers get IPs
inside `VPN_CIDR`). User-facing VPN setup is unchanged.

Per worker: a keypair, a VPN IP allocated in the existing `/24`, a `[Peer]` on
the controller's `wg0.conf`, and a small wg config pushed to the worker
(`Endpoint = <controller_pub_ip>:51820`, `AllowedIPs = {VPN_CIDR}` + internal
CIDRs, `DNS = {VPN_SERVER_IP}` when dns_forward is on).

**Peer persistence.** Worker peers are persisted into the controller's
`wg0.conf`, not just added at runtime, so they survive `wg-quick down/up`.
`_build_wg_server_conf` appends a `[Peer]` per enrolled worker; `_wg_persist_and_sync`
rebuilds the config (preserving the dial-in client) and applies it live with
`wg syncconf` — no interface bounce, so the client and other workers stay
connected.

**Firewall requirement.** The controller must allow **`udp:51820` ingress** for
workers to establish the tunnel. The Terraform-provisioned controller VM already
opens this (`allow-<name>-wireguard`), so production is covered — but the swarm
does not create the rule itself. A controller running outside that Terraform must
add a `udp:51820` ingress rule by hand.

## Known limitations

- **Delete destroys the worker's workspace.** Centralized logs/flags/notes
  survive on the controller via the event stream; Stop preserves the disk.
- **VPN on worker reboot.** The controller keeps the worker's peer, but the
  worker doesn't auto-bring-up wg on boot, so a stopped/restarted worker needs
  re-enrolling to reconnect its side.
- **Reverse-tunnel VPN only.** CTF-provided *forward* VPN configs (dropped
  directly on the worker) are a possible future add-on.
- **Single dial-in client.** The base reverse-VPN feature uses a hardcoded
  `VPN_CLIENT_IP`; multiple dial-in clients would require a larger refactor.

## Hardening follow-ups (not yet implemented)

The swarm works end-to-end without these, but the design calls for them. It
currently relies on firewall rules that already exist rather than managing its
own.

- **Auto-create the `udp:51820` ingress rule** (scoped to the worker tag /
  controller) when VPN routing is enabled, so a controller outside the Terraform
  setup works without manual firewall edits.
- **Lock worker SSH (port 22) to the controller IP.** Workers currently accept
  SSH from `0.0.0.0/0` via the project's `default-allow-ssh` (key-only, but not
  IP-restricted).
- **Enable wg on worker boot** (`systemctl enable wg-quick@wg0`) so a worker
  reboot/Stop→Start keeps its tunnel without re-enrollment.
</content>
