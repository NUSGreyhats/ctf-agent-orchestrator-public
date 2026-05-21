"""Discord bot integration for CTF challenge notifications."""

from __future__ import annotations

import asyncio
import json as _json
import logging
from typing import Any, Callable, Awaitable

log = logging.getLogger("ctf-solver.discord")
logging.getLogger("websockets").setLevel(logging.WARNING)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

try:
    import websockets
except ImportError:
    websockets = None  # type: ignore

DISCORD_API = "https://discord.com/api/v10"
GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"
MAX_CONTENT = 2000
MAX_EMBED_DESC = 4096

SLASH_COMMANDS = [
    {
        "name": "broadcast",
        "description": "Broadcast a breakthrough message to all agents",
        "options": [{
            "name": "message",
            "description": "The message to broadcast",
            "type": 3,  # STRING
            "required": True,
        }],
    },
    {
        "name": "steer",
        "description": "Stop one agent immediately and resume it with a message",
        "options": [{
            "name": "agent",
            "description": "Agent name or run id",
            "type": 3,
            "required": True,
        }, {
            "name": "message",
            "description": "The message to send when resuming",
            "type": 3,
            "required": True,
        }],
    },
    {
        "name": "submit",
        "description": "Submit a flag to the CTF platform",
        "options": [{
            "name": "flag",
            "description": "The flag to submit",
            "type": 3,
            "required": True,
        }],
    },
    {
        "name": "status",
        "description": "Show challenge status and agent info",
    },
    {
        "name": "flags",
        "description": "List all detected flags for this challenge",
        "options": [{
            "name": "add",
            "description": "Manually add a flag candidate",
            "type": 3,
            "required": False,
        }],
    },
    {
        "name": "stop",
        "description": "Stop all running agents on this challenge",
    },
    {
        "name": "resume",
        "description": "Resume stopped agents on this challenge",
    },
    {
        "name": "ctf",
        "description": "Show overall CTF status — all challenges grouped by category",
    },
    {
        "name": "help",
        "description": "Show how to use the CTF solver Discord bot",
    },
    {
        "name": "join",
        "description": "Add yourself to one challenge thread by fuzzy name",
        "options": [{
            "name": "challenge",
            "description": "Challenge name to join",
            "type": 3,
            "required": True,
        }],
    },
    {
        "name": "stats",
        "description": "Show agent runtime and token stats for this challenge",
    },
    {
        "name": "tail",
        "description": "Show recent transcript messages for this challenge",
        "options": [{
            "name": "agent",
            "description": "Agent name or run id to filter",
            "type": 3,
            "required": False,
        }, {
            "name": "lines",
            "description": "Number of recent events to show",
            "type": 4,
            "required": False,
        }],
    },
    {
        "name": "files",
        "description": "List files or fetch a file from agent working directories",
        "options": [{
            "name": "path",
            "description": "File path to fetch (omit to list files)",
            "type": 3,
            "required": False,
        }, {
            "name": "agent",
            "description": "Agent name (claude/codex, defaults to all)",
            "type": 3,
            "required": False,
        }],
    },
    {
        "name": "add",
        "description": "Add yourself to challenge threads by category",
        "options": [{
            "name": "category",
            "description": "Category to join, or all",
            "type": 3,
            "required": True,
        }],
    },
    {
        "name": "solved",
        "description": "Mark this challenge as solved",
        "options": [{
            "name": "flag",
            "description": "The flag (optional)",
            "type": 3,
            "required": False,
        }],
    },
]


def _truncate(text: str, limit: int = MAX_CONTENT) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 4] + "\n..."


class DiscordBot:
    def __init__(self, token: str, channel_id: str):
        if httpx is None:
            raise RuntimeError("httpx is required for Discord integration")
        self.token = token
        self.channel_id = channel_id
        self.application_id: str = ""
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=DISCORD_API,
                headers={
                    "Authorization": f"Bot {self.token}",
                    "Content-Type": "application/json",
                },
                timeout=15,
            )
        return self._client

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make a request with automatic rate-limit retry."""
        client = self._get_client()
        for attempt in range(5):
            resp = await client.request(method, url, **kwargs)
            if resp.status_code == 429:
                retry_after = resp.json().get("retry_after", 5)
                log.warning("Discord rate limited, retrying in %.1fs", retry_after)
                await asyncio.sleep(float(retry_after))
                continue
            return resp
        return resp  # return last response even if still 429

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def fetch_application_id(self) -> str:
        if self.application_id:
            return self.application_id
        client = self._get_client()
        resp = await self._request("GET", "/users/@me")
        if resp.status_code == 200:
            self.application_id = resp.json().get("id", "")
        return self.application_id

    async def register_slash_commands(self, guild_id: str = "") -> None:
        app_id = await self.fetch_application_id()
        if not app_id:
            log.error("Cannot register slash commands: no application ID")
            return
        client = self._get_client()
        if guild_id:
            url = f"/applications/{app_id}/guilds/{guild_id}/commands"
            scope = f"guild {guild_id}"
        else:
            url = f"/applications/{app_id}/commands"
            scope = "global"
        resp = await self._request("PUT", url, json=SLASH_COMMANDS)
        if resp.status_code == 200:
            log.info("Registered %d %s slash commands", len(SLASH_COMMANDS), scope)
        else:
            log.error("Failed to register slash commands (%s): %s %s",
                       scope, resp.status_code, resp.text[:300])

    async def respond_to_interaction(
        self, interaction_id: str, interaction_token: str,
        content: str = "", embed: dict | None = None,
        flags: int = 0,
    ) -> None:
        data: dict[str, Any] = {}
        if content:
            data["content"] = _truncate(content)
        if embed:
            data["embeds"] = [embed]
        if flags:
            data["flags"] = flags
        try:
            await self._request(
                "POST",
                f"/interactions/{interaction_id}/{interaction_token}/callback",
                json={"type": 4, "data": data},
            )
        except Exception as exc:
            log.error("Failed to respond to interaction: %s", exc)

    async def defer_interaction(
        self, interaction_id: str, interaction_token: str,
    ) -> None:
        try:
            await self._request(
                "POST",
                f"/interactions/{interaction_id}/{interaction_token}/callback",
                json={"type": 5},
            )
        except Exception as exc:
            log.error("Failed to defer interaction: %s", exc)

    async def followup_interaction(
        self, interaction_token: str,
        content: str = "", embed: dict | None = None,
    ) -> None:
        app_id = self.application_id
        if not app_id:
            return
        payload: dict[str, Any] = {}
        if content:
            payload["content"] = _truncate(content)
        if embed:
            payload["embeds"] = [embed]
        try:
            await self._request(
                "POST",
                f"/webhooks/{app_id}/{interaction_token}",
                json=payload,
            )
        except Exception as exc:
            log.error("Failed to send followup: %s", exc)

    async def create_thread(self, name: str, initial_message: str = "") -> str | None:
        try:
            resp = await self._request(
                "POST",
                f"/channels/{self.channel_id}/threads",
                json={
                    "name": name[:100],
                    "type": 11,
                    "auto_archive_duration": 10080,
                },
            )
            if resp.status_code not in (200, 201):
                log.error("Failed to create thread %s: %s %s",
                          name, resp.status_code, resp.text[:200])
                return None
            thread_id = resp.json().get("id")
            if thread_id and initial_message:
                await self.send_message(thread_id, initial_message)
            return thread_id
        except Exception as exc:
            log.error("Discord create_thread error: %s", exc)
            return None

    async def send_message(
        self, thread_id: str, content: str = "", embed: dict | None = None
    ) -> dict | None:
        payload: dict[str, Any] = {}
        if content:
            payload["content"] = _truncate(content)
        if embed:
            payload["embeds"] = [embed]
        if not payload:
            return None
        try:
            resp = await self._request(
                "POST",
                f"/channels/{thread_id}/messages",
                json=payload,
            )
            if resp.status_code not in (200, 201):
                log.error("Failed to send message to %s: %s %s",
                          thread_id, resp.status_code, resp.text[:200])
                return None
            return resp.json()
        except Exception as exc:
            log.error("Discord send_message error: %s", exc)
            return None

    async def send_channel_message(
        self, content: str = "", embed: dict | None = None
    ) -> dict | None:
        return await self.send_message(self.channel_id, content, embed)

    async def rename_thread(self, thread_id: str, name: str) -> bool:
        try:
            resp = await self._request(
                "PATCH",
                f"/channels/{thread_id}",
                json={"name": name[:100]},
            )
            return resp.status_code == 200
        except Exception as exc:
            log.error("Discord rename_thread error: %s", exc)
            return False

    async def add_thread_member(self, thread_id: str, user_id: str) -> tuple[bool, str]:
        """Add a guild member to a thread."""
        try:
            resp = await self._request(
                "PUT",
                f"/channels/{thread_id}/thread-members/{user_id}",
            )
            if resp.status_code in (200, 201, 204):
                return True, ""
            return False, f"{resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            log.error("Discord add_thread_member error: %s", exc)
            return False, str(exc)

    async def list_active_threads(self, channel_id: str = "") -> list[dict]:
        """List active threads in a channel (or the bot's default channel)."""
        cid = channel_id or self.channel_id
        try:
            resp = await self._request("GET", f"/channels/{cid}/threads/active")
            if resp.status_code == 200:
                return resp.json().get("threads", [])
            # Fallback: guild-level active threads
            resp2 = await self._request("GET", f"/channels/{cid}")
            if resp2.status_code == 200:
                guild_id = resp2.json().get("guild_id")
                if guild_id:
                    resp3 = await self._request("GET", f"/guilds/{guild_id}/threads/active")
                    if resp3.status_code == 200:
                        threads = resp3.json().get("threads", [])
                        return [t for t in threads if t.get("parent_id") == cid]
        except Exception as exc:
            log.error("Discord list_active_threads error: %s", exc)
        return []

    async def find_thread_by_name(self, name: str) -> str | None:
        """Find an existing thread by name. Returns thread ID or None."""
        threads = await self.list_active_threads()
        for t in threads:
            if t.get("name") == name:
                return t.get("id")
        return None

    async def list_guild_channels(self) -> list[dict]:
        try:
            resp = await self._request("GET", "/users/@me/guilds")
            if resp.status_code != 200:
                return []
            guilds = resp.json()
            channels = []
            for guild in guilds:
                resp = await self._request("GET", f"/guilds/{guild['id']}/channels")
                if resp.status_code != 200:
                    continue
                for ch in resp.json():
                    if ch.get("type") in (0, 5, 15):
                        channels.append({
                            "id": ch["id"],
                            "name": f"#{ch['name']}",
                            "guild": guild.get("name", ""),
                        })
            return channels
        except Exception as exc:
            log.error("Discord list_channels error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Gateway (WebSocket) connection for receiving slash commands
# ---------------------------------------------------------------------------

class DiscordGateway:
    """Minimal Discord gateway client for receiving interactions."""

    def __init__(self, bot: DiscordBot,
                 on_interaction: Callable[[dict], Awaitable[None]]):
        self.bot = bot
        self.on_interaction = on_interaction
        self._ws = None
        self._heartbeat_interval: float = 45
        self._sequence: int | None = None
        self._session_id: str = ""
        self._resume_url: str = ""
        self._running = False
        self._heartbeat_task: asyncio.Task | None = None

    async def run_forever(self):
        self._running = True
        while self._running:
            try:
                await self._connect_and_listen()
            except asyncio.CancelledError:
                self._running = False
                break
            except Exception as exc:
                log.warning("Gateway disconnected: %s — reconnecting in 5s", exc)
                await asyncio.sleep(5)

    async def stop(self):
        self._running = False
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except (Exception, asyncio.CancelledError):
                pass

    async def _connect_and_listen(self):
        if websockets is None:
            log.error("websockets library required for Discord gateway")
            self._running = False
            return

        url = self._resume_url or GATEWAY_URL
        log.info("Connecting to Discord gateway: %s", url)
        async with websockets.connect(url) as ws:
            self._ws = ws
            async for raw in ws:
                data = _json.loads(raw)
                op = data.get("op")
                seq = data.get("s")
                if seq is not None:
                    self._sequence = seq

                if op == 10:  # Hello
                    self._heartbeat_interval = data["d"]["heartbeat_interval"] / 1000
                    self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
                    if self._session_id:
                        await self._send_resume(ws)
                    else:
                        await self._send_identify(ws)

                elif op == 11:  # Heartbeat ACK
                    pass

                elif op == 1:  # Heartbeat request
                    await ws.send(_json.dumps({"op": 1, "d": self._sequence}))

                elif op == 7:  # Reconnect
                    log.info("Gateway requested reconnect")
                    break

                elif op == 9:  # Invalid session
                    log.warning("Invalid session, re-identifying")
                    self._session_id = ""
                    self._sequence = None
                    await asyncio.sleep(2)
                    await self._send_identify(ws)

                elif op == 0:  # Dispatch
                    event = data.get("t", "")
                    if event == "READY":
                        self._session_id = data["d"].get("session_id", "")
                        self._resume_url = data["d"].get("resume_gateway_url", "")
                        if self._resume_url:
                            self._resume_url += "?v=10&encoding=json"
                        log.info("Discord gateway READY (session=%s)", self._session_id)
                    elif event == "INTERACTION_CREATE":
                        asyncio.create_task(self._safe_handle_interaction(data["d"]))

        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()

    async def _heartbeat_loop(self, ws):
        try:
            while True:
                await asyncio.sleep(self._heartbeat_interval)
                await ws.send(_json.dumps({"op": 1, "d": self._sequence}))
        except (asyncio.CancelledError, Exception):
            pass

    async def _send_identify(self, ws):
        await ws.send(_json.dumps({
            "op": 2,
            "d": {
                "token": self.bot.token,
                "intents": 0,
                "properties": {
                    "os": "linux",
                    "browser": "ctf-solver",
                    "device": "ctf-solver",
                },
            },
        }))

    async def _send_resume(self, ws):
        await ws.send(_json.dumps({
            "op": 6,
            "d": {
                "token": self.bot.token,
                "session_id": self._session_id,
                "seq": self._sequence,
            },
        }))

    async def _safe_handle_interaction(self, interaction: dict):
        try:
            await self.on_interaction(interaction)
        except Exception as exc:
            log.error("Error handling interaction: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_bot: DiscordBot | None = None


def get_bot(settings: dict) -> DiscordBot | None:
    global _bot
    if not settings.get("discord_enabled"):
        return None
    token = settings.get("discord_bot_token", "").strip()
    channel_id = settings.get("discord_channel_id", "").strip()
    if not token or not channel_id:
        return None
    if _bot is None or _bot.token != token or _bot.channel_id != channel_id:
        if _bot:
            try:
                asyncio.get_event_loop().create_task(_bot.close())
            except Exception as exc:
                log.debug("Discord bot close error: %s", exc)
        _bot = DiscordBot(token, channel_id)
    return _bot


# ---------------------------------------------------------------------------
# Embed helpers
# ---------------------------------------------------------------------------

def make_thread_name(challenge: dict) -> str:
    category = challenge.get("category", "")
    name = challenge.get("name", "Unknown")
    if category:
        return f"[{category}] {name}"
    return name


def make_challenge_embed(challenge: dict) -> dict:
    desc_parts = []
    if challenge.get("description"):
        desc_parts.append(challenge["description"][:500])
    if challenge.get("flag_format"):
        desc_parts.append(f"**Flag format:** `{challenge['flag_format']}`")
    files = challenge.get("files", [])
    if files:
        desc_parts.append(f"**Files:** {', '.join(f'`{f}`' for f in files[:10])}")
    tags = challenge.get("_tags", [])
    if tags:
        desc_parts.append(f"**Tags:** {', '.join(tags)}")
    runs = challenge.get("runs", {})
    if runs:
        agents = [f"`{r.get('agent', '?')}` ({r.get('model', '?')})"
                  for r in runs.values()]
        desc_parts.append(f"**Agents:** {', '.join(agents)}")
    return {
        "title": make_thread_name(challenge),
        "description": _truncate("\n".join(desc_parts), MAX_EMBED_DESC),
        "color": 0x5865F2,
    }


def make_solve_embed(challenge: dict, flag: str, agent: str = "") -> dict:
    title = f"Solved: {challenge.get('name', 'Unknown')}"
    desc = f"**Flag:** `{flag}`"
    if agent:
        desc += f"\n**Solved by:** `{agent}`"
    return {
        "title": title,
        "description": desc,
        "color": 0x57F287,
    }


def make_stop_embed(challenge: dict, run: dict, last_message: str = "") -> dict:
    agent = run.get("agent", "?")
    status = run.get("status", "?")
    error = run.get("error", "")
    desc_parts = [f"**Status:** {status}"]
    if error:
        desc_parts.append(f"**Error:** {error}")
    if last_message:
        desc_parts.append(f"**Last message:**\n```\n{_truncate(last_message, 1000)}\n```")
    return {
        "title": f"{agent} stopped — {challenge.get('name', '')}",
        "description": "\n".join(desc_parts),
        "color": 0xED4245 if status == "failed"
                 else 0xFEE75C if status == "completed"
                 else 0x57F287,
    }
