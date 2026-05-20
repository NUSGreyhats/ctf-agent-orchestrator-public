"""Hack The Box CTF platform plugin (ctf.hackthebox.com)."""

from __future__ import annotations

import asyncio
import logging

from .base import (
    CTFPlatformPlugin,
    ConfigField,
    RemoteChallenge,
    RemoteFile,
    SubmitResult,
    read_limited_response,
)

log = logging.getLogger("ctf-solver.htb")

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

# The event endpoint exposes numeric category IDs. The frontend resolves them
# through /api/public/challenge-categories; this map is only a fallback.
_CATEGORY_MAP: dict[int, str] = {
    1: "Fullpwn",
    2: "Web",
    3: "Pwn",
    4: "Crypto",
    5: "Reversing",
    6: "Stego",
    7: "Forensics",
    8: "Misc",
    9: "Start",
    10: "PCAP",
    11: "Coding",
    12: "Mobile",
    13: "OSINT",
    14: "Blockchain",
    15: "Hardware",
    16: "Warmup",
    17: "Attack",
    18: "Defence",
    20: "Cloud",
    21: "ICS",
    23: "ML",
    25: "TTX",
    26: "Trivia",
    30: "Sherlocks",
    33: "AI",
    36: "Secure Coding",
    37: "Quantum",
    38: "Physical",
    39: "Payment Systems",
    40: "Satellite",
}

_PREFIX_TO_CATEGORY: dict[str, str] = {
    "web": "Web",
    "pwn": "Pwn",
    "crypto": "Crypto",
    "rev": "Reversing",
    "forensics": "Forensics",
    "misc": "Misc",
    "blockchain": "Blockchain",
    "hw": "Hardware",
    "ml": "ML / AI",
    "osint": "OSINT",
    "stego": "Stego",
    "mobile": "Mobile",
    "nuclear": "ML / AI",
    "quant": "Quantum",
    "quantum": "Quantum",
}


def _require_httpx():
    if httpx is None:
        raise RuntimeError(
            "httpx is required for the HTB CTF plugin. "
            "Install it with: pip install httpx"
        )


async def _fetch_category_map(client: httpx.AsyncClient) -> dict[int, str]:
    try:
        resp = await client.get("/api/public/challenge-categories")
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        log.warning("Could not fetch HTB challenge categories: %s", exc)
        return {}

    items = payload.get("data", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return {}

    categories: dict[int, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("title") or "").strip()
        if not name:
            continue
        try:
            categories[int(item.get("id"))] = name
        except (TypeError, ValueError):
            continue
    return categories


def _resolve_category(
    challenge: dict, category_map: dict[int, str] | None = None
) -> str:
    cat_id = challenge.get("challenge_category_id")
    cat_id_int = None
    if cat_id is not None:
        try:
            cat_id_int = int(cat_id)
        except (TypeError, ValueError):
            pass
    if cat_id_int is not None:
        if category_map and cat_id_int in category_map:
            return category_map[cat_id_int]
        if cat_id_int in _CATEGORY_MAP:
            return _CATEGORY_MAP[cat_id_int]
    filename = challenge.get("filename", "") or ""
    if filename:
        prefix = filename.split("_")[0].lower()
        if prefix in _PREFIX_TO_CATEGORY:
            return _PREFIX_TO_CATEGORY[prefix]
    if cat_id is not None:
        return f"Category {cat_id}"
    return ""


def _find_challenge(ctf_data: dict, remote_id: str) -> dict | None:
    for challenge in ctf_data.get("challenges", []) or []:
        if str(challenge.get("id")) == str(remote_id):
            return challenge
    return None


async def _fetch_challenge(
    client: httpx.AsyncClient, ctf_id: str, remote_id: str
) -> dict | None:
    resp = await client.get(f"/api/ctfs/{ctf_id}")
    resp.raise_for_status()
    return _find_challenge(resp.json(), remote_id)


def _response_message(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return resp.text.strip()[:300]
    if isinstance(data, dict):
        message = data.get("message") or data.get("error")
        if message:
            return str(message)
    return str(data)[:300]


def _normalize_ports(ports) -> list:
    if isinstance(ports, list):
        values = ports
    else:
        values = [ports]
    return [port for port in values if port not in (None, "")]


def _docker_remote_info(hostname: str, port, docker_type: str) -> dict:
    result: dict = {
        "host": hostname,
        "port": port,
    }
    kind = str(docker_type or "").lower()
    if kind == "web":
        result["url"] = f"http://{hostname}:{port}"
        result["type"] = "web"
    elif kind == "tcp":
        result["connection"] = f"nc {hostname} {port}"
        result["type"] = "tcp"
    else:
        result["connection"] = f"{hostname}:{port}"
        result["type"] = "unknown"
    return result


def _docker_instance_info(challenge: dict) -> dict | None:
    hostname = challenge.get("hostname")
    ports = challenge.get("docker_ports")
    if not hostname or not ports:
        return None

    docker_type = challenge.get("docker_instance_type") or ""
    port_list = _normalize_ports(ports)
    if not port_list:
        return None

    remotes = [
        _docker_remote_info(str(hostname), port, docker_type)
        for port in port_list
    ]
    result: dict = {
        "host": str(hostname),
        "ports": port_list,
        "remotes": remotes,
    }
    result.update(remotes[0])
    urls = [remote["url"] for remote in remotes if remote.get("url")]
    connections = [
        remote["connection"] for remote in remotes if remote.get("connection")
    ]
    if urls:
        result["urls"] = urls
    if connections:
        result["connections"] = connections
    return result


def _machine_instance_info(challenge: dict) -> dict | None:
    machine = challenge.get("machine")
    if not isinstance(machine, dict):
        return None
    if str(machine.get("status", "")).lower() != "active":
        return None
    ip = str(machine.get("ip") or "").strip()
    if not ip:
        return None

    result: dict = {
        "host": ip,
        "connection": f"Target IP: {ip}",
        "type": "machine",
    }
    expires_at = machine.get("expires_at")
    if expires_at:
        result["expires_at"] = expires_at
    return result


def _client(config: dict) -> httpx.AsyncClient:
    _require_httpx()
    token = config.get("token", "").strip()
    if not token:
        raise ValueError("Bearer token is required")
    return httpx.AsyncClient(
        base_url="https://ctf.hackthebox.com",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        verify=True,
        follow_redirects=True,
        timeout=30,
    )


class HTBCTFPlugin(CTFPlatformPlugin):
    name = "htb_ctf"
    label = "HTB CTF"

    def source_url(self, config: dict) -> str:
        ctf_id = config.get("ctf_id", "").strip()
        return f"https://ctf.hackthebox.com/event/{ctf_id}" if ctf_id else ""

    def config_schema(self) -> list[ConfigField]:
        return [
            ConfigField(
                name="ctf_id",
                label="CTF Event ID",
                field_type="text",
                placeholder="3264 (from the URL: ctf.hackthebox.com/event/3264)",
            ),
            ConfigField(
                name="token",
                label="Bearer Token (JWT)",
                field_type="password",
                placeholder="Copy from browser DevTools (Authorization header)",
            ),
        ]

    async def test_connection(self, config: dict) -> str:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            raise ValueError("CTF Event ID is required")

        async with _client(config) as client:
            resp = await client.get(f"/api/ctfs/{ctf_id}")
            if resp.status_code == 401:
                raise ValueError("Authentication failed — token may be expired")
            resp.raise_for_status()
            data = resp.json()

            ctf_name = data.get("name", f"CTF {ctf_id}")
            team = data.get("participating_team", {})
            team_name = team.get("name", "")
            n_challenges = len(data.get("challenges", []))
            status = data.get("status", "")

            parts = [f"Connected to {ctf_name}"]
            if team_name:
                parts.append(f"team {team_name}")
            parts.append(f"{n_challenges} challenges")
            if status:
                parts.append(f"({status})")
            return " — ".join(parts)

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            raise ValueError("CTF Event ID is required")

        async with _client(config) as client:
            resp = await client.get(f"/api/ctfs/{ctf_id}")
            resp.raise_for_status()
            data = resp.json()
            category_map = await _fetch_category_map(client)

            results = []
            for ch in data.get("challenges", []):
                ch_id = ch.get("id")
                filename = (ch.get("filename") or "").strip()

                files = []
                if filename:
                    download_url = f"https://ctf.hackthebox.com/api/challenges/{ch_id}/download"
                    files.append(RemoteFile(name=filename, url=download_url))

                tags = []
                difficulty = ch.get("difficulty", "")
                if difficulty:
                    tags.append(difficulty)
                if ch.get("hasMachine"):
                    tags.append("machine")
                if ch.get("hasDocker"):
                    docker_type = ch.get("docker_instance_type") or ""
                    tags.append(f"docker:{docker_type}" if docker_type else "docker")

                flag_questions = []
                for item in ch.get("flagsInfo", []) or []:
                    if not isinstance(item, dict):
                        continue
                    question = str(item.get("question") or "").strip()
                    identifier = str(item.get("identifier") or "").strip()
                    flag_id = item.get("flag_id")
                    if not question and identifier:
                        question = f"{identifier} flag"
                    if question and flag_id is not None:
                        flag_questions.append({
                            "flag_id": flag_id,
                            "identifier": identifier,
                            "question": question,
                            "solved": bool(item.get("solved")),
                        })

                results.append(RemoteChallenge(
                    remote_id=str(ch_id),
                    name=ch.get("name", f"Challenge {ch_id}"),
                    description=ch.get("description", ""),
                    category=_resolve_category(ch, category_map),
                    points=ch.get("points", 0),
                    solves=ch.get("solves", 0),
                    files=files,
                    solved=bool(ch.get("solved")),
                    tags=tags,
                    flag_questions=flag_questions,
                ))

            return results

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None,
        progress_cb=None,
    ) -> bytes:
        async with _client(config) as client:
            async with client.stream("GET", file.url) as resp:
                return await read_limited_response(resp, max_bytes, progress_cb)

    async def start_instance(
        self, config: dict, remote_id: str
    ) -> dict | None:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            return None

        async with _client(config) as client:
            challenge = await _fetch_challenge(client, ctf_id, remote_id)
            if not challenge:
                raise ValueError(f"Challenge {remote_id} not found in CTF {ctf_id}")

            machine_info = _machine_instance_info(challenge)
            if machine_info:
                log.info("Machine already ready for %s: %s", remote_id, machine_info)
                return machine_info

            docker_info = _docker_instance_info(challenge)
            if docker_info:
                log.info("Container already ready for %s: %s", remote_id, docker_info)
                return docker_info

            has_machine = bool(challenge.get("hasMachine"))
            has_docker = bool(challenge.get("hasDocker"))

            if has_machine:
                machine = challenge.get("machine")
                machine_status = (
                    str(machine.get("status") or "").lower()
                    if isinstance(machine, dict)
                    else ""
                )
                if machine_status not in {"active", "deploying", "resetting"}:
                    resp = await client.post(
                        f"/api/challenges/machines/spawn/{int(remote_id)}"
                    )
                    if resp.status_code >= 400:
                        raise ValueError(
                            f"Machine spawn failed: {_response_message(resp)}"
                        )
                    log.info(
                        "Machine spawn requested for %s: %s",
                        remote_id,
                        _response_message(resp),
                    )
                else:
                    log.info(
                        "Machine %s is already %s; waiting for readiness",
                        remote_id,
                        machine_status,
                    )

                for _ in range(60):
                    await asyncio.sleep(3)
                    challenge = await _fetch_challenge(client, ctf_id, remote_id)
                    if not challenge:
                        continue
                    machine_info = _machine_instance_info(challenge)
                    if machine_info:
                        log.info("Machine ready for %s: %s", remote_id, machine_info)
                        return machine_info

                log.warning("Machine for %s did not become ready in time", remote_id)
                return None

            if has_docker:
                resp = await client.post(
                    "/api/challenges/containers/start",
                    json={"id": int(remote_id)},
                )
                if resp.status_code >= 400:
                    raise ValueError(
                        f"Container start failed: {_response_message(resp)}"
                    )
                log.info(
                    "Container start for %s: %s",
                    remote_id,
                    _response_message(resp),
                )

                for _ in range(12):
                    await asyncio.sleep(3)
                    challenge = await _fetch_challenge(client, ctf_id, remote_id)
                    if not challenge:
                        continue
                    docker_info = _docker_instance_info(challenge)
                    if docker_info:
                        log.info("Container ready for %s: %s", remote_id, docker_info)
                        return docker_info

                log.warning("Container for %s did not become ready in time", remote_id)
                return None

            return None

    async def stop_instance(
        self, config: dict, remote_id: str
    ) -> None:
        async with _client(config) as client:
            ctf_id = config.get("ctf_id", "").strip()
            challenge = (
                await _fetch_challenge(client, ctf_id, remote_id)
                if ctf_id
                else None
            )
            if challenge and challenge.get("hasMachine"):
                resp = await client.post(
                    f"/api/challenges/machines/destroy/{int(remote_id)}"
                )
                log.info(
                    "Machine destroy for %s: %s",
                    remote_id, _response_message(resp),
                )
                return

            resp = await client.post(
                "/api/challenges/containers/stop",
                json={"id": int(remote_id)},
            )
            log.info(
                "Container stop for %s: %s",
                remote_id, _response_message(resp),
            )

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str,
        flag_id: str | int | None = None,
    ) -> SubmitResult:
        ctf_id = config.get("ctf_id", "").strip()
        if not ctf_id:
            raise ValueError("CTF Event ID is required for flag submission")

        async with _client(config) as client:
            payload: dict = {
                "flag": flag,
                "ctf_id": int(ctf_id),
                "challenge_id": int(remote_id),
            }
            if flag_id not in (None, ""):
                payload["flag_id"] = int(flag_id)
            resp = await client.post(
                "/api/flags/global/own",
                json=payload,
            )
            data = resp.json()
            message = data.get("message", "")

            message_l = message.lower()
            success_value = data.get("success", data.get("status"))
            if isinstance(success_value, bool):
                correct = success_value
            elif isinstance(success_value, (int, float)):
                correct = success_value == 1
            elif isinstance(success_value, str):
                correct = success_value.strip().lower() in {
                    "1", "true", "ok", "success", "correct", "solved",
                }
            else:
                bad_terms = ("wrong", "incorrect", "invalid", "rate limit")
                good_terms = ("correct", "solved", "success", "congrat", "already")
                correct = (
                    resp.status_code == 200
                    and any(term in message_l for term in good_terms)
                    and not any(term in message_l for term in bad_terms)
                )

            if correct:
                return SubmitResult(correct=True, message=message or "Correct!")
            return SubmitResult(correct=False, message=message or "Incorrect flag")
