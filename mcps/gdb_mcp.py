#!/usr/bin/env python3
"""GDB MCP Server — persistent GDB passthrough for Claude Code."""

import asyncio
import signal

from mcp.server.fastmcp import FastMCP

PROMPT = "(gdb-mcp) "

mcp = FastMCP("gdb")


class GDBSession:
    """Manages a persistent GDB subprocess."""

    def __init__(self):
        self.proc = None

    @property
    def alive(self):
        return self.proc is not None and self.proc.returncode is None

    async def start(self, cmd: list[str]) -> str:
        if self.alive:
            await self.stop()
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        startup = await self._read_until("(gdb) ")
        # Set custom prompt for reliable output boundary detection
        await self._send(f"set prompt {PROMPT}")
        await self._read_until(PROMPT)
        # Configure for non-interactive use
        for setup in [
            "set pagination off",
            "set confirm off",
            "set width 0",
        ]:
            await self._send(setup)
            await self._read_until(PROMPT)
        return startup.strip()

    async def execute(self, command: str, timeout: float = 30.0) -> str:
        if not self.alive:
            raise RuntimeError(
                "No active GDB session. Call gdb_start first."
            )
        await self._send(command)
        try:
            output = await asyncio.wait_for(
                self._read_until(PROMPT), timeout=timeout
            )
        except asyncio.TimeoutError:
            return (
                f"[Timed out after {timeout}s. "
                "Target may be running — send 'interrupt' to stop.]"
            )
        return output.strip()

    async def interrupt(self) -> str:
        if not self.alive:
            raise RuntimeError("No active GDB session.")
        self.proc.send_signal(signal.SIGINT)
        try:
            output = await asyncio.wait_for(
                self._read_until(PROMPT), timeout=5.0
            )
        except asyncio.TimeoutError:
            return "[Interrupt sent but no response within 5s.]"
        return output.strip()

    async def _send(self, text: str):
        self.proc.stdin.write(f"{text}\n".encode())
        await self.proc.stdin.drain()

    async def _read_until(self, marker: str) -> str:
        buf = b""
        encoded = marker.encode()
        while True:
            chunk = await self.proc.stdout.read(4096)
            if not chunk:
                break
            buf += chunk
            if encoded in buf:
                idx = buf.index(encoded)
                return buf[:idx].decode(errors="replace")
        return buf.decode(errors="replace")

    async def stop(self):
        if not self.alive:
            return
        try:
            self.proc.stdin.write(b"quit\ny\n")
            await self.proc.stdin.drain()
            await asyncio.wait_for(self.proc.wait(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError, BrokenPipeError):
            try:
                self.proc.kill()
            except ProcessLookupError:
                pass
        self.proc = None


session = GDBSession()


@mcp.tool()
async def gdb_start(
    binary: str = "",
    remote: str = "",
    args: str = "",
    init_script: str = "",
) -> str:
    """Start a new GDB session.

    binary: path to ELF binary or vmlinux to load symbols from
    remote: GDB remote target (e.g. "localhost:1234" for QEMU -s)
    args: additional GDB CLI flags
    init_script: path to a GDB Python script to source at startup
                 (e.g. "/opt/gef/gef.py" for bata24 GEF)
    """
    cmd = ["gdb", "-q", "-nx"]
    if args:
        cmd.extend(args.split())
    if binary:
        cmd.append(binary)

    startup = await session.start(cmd)
    parts = [startup] if startup else []

    # Load init script (e.g. GEF) before connecting to remote
    if init_script:
        out = await session.execute(
            f"source {init_script}", timeout=180
        )
        parts.append(out)
        # Suppress noisy output for MCP use
        for gef_setup in [
            "gef config gef.disable_color True",
            "gef config context.enable False",
        ]:
            await session.execute(gef_setup, timeout=5)


    if remote:
        out = await session.execute(
            f"target remote {remote}", timeout=10
        )
        parts.append(out)

    return "\n".join(parts) or "GDB session started."


@mcp.tool()
async def gdb_exec(command: str, timeout: float = 30.0) -> str:
    """Send a command to GDB and return the output.

    command: any GDB command (e.g. "break main", "bt", "x/16gx $rsp").
             Use "interrupt" to send SIGINT and stop a running target.
    timeout: max seconds to wait (default 30). Increase for run/continue.
    """
    if command.strip().lower() == "interrupt":
        return await session.interrupt()
    return await session.execute(command, timeout=timeout)


@mcp.tool()
async def gdb_stop() -> str:
    """Terminate the current GDB session."""
    if not session.alive:
        return "No active session."
    await session.stop()
    return "GDB session terminated."


if __name__ == "__main__":
    mcp.run(transport="stdio")
