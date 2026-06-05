# CLI to SDK Porting Guide

How to programmatically control Claude, Codex, Copilot, and OpenCode
using their respective SDKs instead of spawning CLI subprocesses.

## Common Interface

All providers implement the same async generator signature:

```python
async def run_agent(
    prompt: str,
    model: str = "",
    effort: str = "",
    cwd: str | Path = ".",
    continue_session: bool = False,
    session_state: dict | None = None,
    **kwargs,
) -> AsyncIterator[dict]:
```

Each `yield`ed dict is a normalized event:

```python
# Assistant text/thinking/tool_use
{"type": "assistant", "message": {"content": [
    {"type": "text", "text": "..."},
    {"type": "thinking", "thinking": "..."},
    {"type": "tool_use", "id": "...", "name": "Bash", "input": {...}},
]}}

# Tool result
{"type": "user", "message": {"content": [
    {"type": "tool_result", "tool_use_id": "...", "content": "...", "is_error": False},
]}}

# System message
{"type": "system", "message": "..."}

# Error
{"type": "error", "message": "..."}

# Result (end of conversation)
{"type": "result", "result": "...", "total_cost_usd": 0.05}
```

---

## Claude — `claude-agent-sdk`

**Install:** `pip install claude-agent-sdk`

### Setup

```python
from claude_agent_sdk import (
    ClaudeSDKClient, ClaudeAgentOptions,
    AssistantMessage, UserMessage, SystemMessage, ResultMessage,
    StreamEvent, RateLimitEvent,
    TextBlock, ThinkingBlock, ToolUseBlock, ToolResultBlock,
)

options = ClaudeAgentOptions(
    permission_mode="bypassPermissions",
    cwd="/path/to/workdir",
    model="opus",          # or "sonnet", "haiku", None for default
    effort="medium",       # "low", "medium", "high", "max", None
)

client = ClaudeSDKClient(options)
```

### Send prompt and stream events

```python
await client.connect(prompt)

async for msg in client.receive_messages():
    if isinstance(msg, AssistantMessage):
        for block in msg.content:
            if isinstance(block, TextBlock):
                print(f"Text: {block.text}")
            elif isinstance(block, ThinkingBlock):
                print(f"Thinking: {block.thinking}")
            elif isinstance(block, ToolUseBlock):
                print(f"Tool: {block.name}({block.input})")
            elif isinstance(block, ToolResultBlock):
                print(f"Result: {block.content}")

    elif isinstance(msg, UserMessage):
        # Tool results from the agent's tool calls
        for block in msg.content:
            if isinstance(block, ToolResultBlock):
                print(f"Tool result: {block.content}")

    elif isinstance(msg, ResultMessage):
        print(f"Done. Cost: ${msg.total_cost_usd}")
        break

await client.disconnect()
```

### Continue a conversation

```python
# First run — save session_id from any message
session_id = msg.session_id  # or from StreamEvent init

# Second run — resume
options = ClaudeAgentOptions(
    permission_mode="bypassPermissions",
    continue_conversation=True,
    session_id=session_id,
)
client = ClaudeSDKClient(options)
await client.connect("continue with this new instruction")
```

### Multi-turn (send follow-up after turn completes)

```python
await client.connect(first_prompt)
async for msg in client.receive_messages():
    # process events...
    pass

# Turn finished — send follow-up
await client.query("here's additional context, keep going")
async for msg in client.receive_messages():
    # process second turn events...
    pass
```

### Register custom tools (MCP)

```python
from claude_agent_sdk import create_sdk_mcp_server, tool

@tool(
    "my_tool",
    "Description of what this tool does",
    {
        "type": "object",
        "properties": {
            "param1": {"type": "string", "description": "..."},
        },
        "required": ["param1"],
    },
)
async def my_tool_handler(params):
    result = do_something(params["param1"])
    return {"output": result}

mcp_server = create_sdk_mcp_server("my-server", tools=[my_tool_handler])

options = ClaudeAgentOptions(
    permission_mode="bypassPermissions",
    mcp_servers={"my-server": mcp_server},
)
```

The tool appears to the agent as `mcp__my-server__my_tool`. When the
agent calls it, your Python handler runs in-process.

---

## Codex — `codex app-server` (JSON-RPC 2.0)

**Install:** `npm install -g @openai/codex@latest`

Codex doesn't have a Python SDK — it exposes a JSON-RPC 2.0 server
over stdio. You spawn `codex app-server` as a subprocess and
communicate via newline-delimited JSON on stdin/stdout.

### Protocol source of truth

Do not infer the app-server event surface from old CLI JSON examples.
The local Codex binary can generate the current protocol bindings:

```bash
codex app-server generate-ts --experimental --out /tmp/codex-proto-ts
codex app-server generate-json-schema --experimental --out /tmp/codex-proto-schema
```

Review `ServerNotification.ts`, `ServerRequest.ts`, and
`v2/ThreadItem.ts` whenever updating the parser. As of Codex CLI
0.135.0, important notifications include:

- `item/started`, `item/completed`, `rawResponseItem/completed`
- `item/agentMessage/delta`, `item/reasoning/textDelta`,
  `item/reasoning/summaryTextDelta`, `item/reasoning/summaryPartAdded`
- `item/commandExecution/outputDelta`, `command/exec/outputDelta`,
  `process/outputDelta`, `process/exited`
- `item/fileChange/patchUpdated`, `turn/diff/updated`
- `turn/plan/updated`, `item/plan/delta`
- `thread/goal/updated`, `thread/goal/cleared`
- `warning`, `guardianWarning`, `configWarning`, `deprecationNotice`
- `model/rerouted`, `model/verification`
- `thread/tokenUsage/updated`, `thread/status/changed`, `turn/completed`

Current server requests that need client responses include approvals,
dynamic tool calls, request-user-input, MCP elicitation, ChatGPT token
refresh, and attestation generation. Response payloads must match the
generated schemas; for example `item/tool/requestUserInput` returns
`{"answers": {...}}` and MCP elicitation uses
`{"action": "accept" | "decline" | "cancel", "content": ..., "_meta": ...}`.

### Spawn and handshake

```python
proc = await asyncio.create_subprocess_exec(
    "codex", "app-server", "--listen", "stdio://",
    stdin=asyncio.subprocess.PIPE,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)

# Send initialize request
await send_request("initialize", {
    "clientInfo": {"name": "my-app", "version": "1.0.0"},
    "capabilities": {"experimentalApi": True},
})
response = await read_response(request_id)

# Send initialized notification (no id)
await send_notification("initialized", {})
```

### JSON-RPC helpers

```python
request_counter = 0

async def send_request(method, params):
    nonlocal request_counter
    request_counter += 1
    msg = {
        "jsonrpc": "2.0",
        "id": request_counter,
        "method": method,
        "params": params,
    }
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()
    return request_counter

async def send_notification(method, params):
    msg = {"method": method}
    if params:
        msg["params"] = params
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()

async def read_response(expected_id):
    """Read lines until we get a response matching expected_id."""
    while True:
        line = await proc.stdout.readline()
        msg = json.loads(line)
        if msg.get("id") == expected_id:
            return msg.get("result", {})
        # Store non-matching messages for later processing
```

### Start a thread

```python
response = await send_request("thread/start", {
    "model": "gpt-5.4",              # or "gpt-5.3-codex", etc.
    "cwd": "/path/to/workdir",
    "approvalPolicy": "never",        # auto-approve everything
    "sandbox": "danger-full-access",   # no restrictions
    "dynamicTools": [                  # optional custom tools
        {
            "name": "my_tool",
            "description": "What it does",
            "inputSchema": {
                "type": "object",
                "properties": {"param": {"type": "string"}},
                "required": ["param"],
            },
        },
    ],
})
thread_result = await read_response(rid)
thread_id = thread_result["thread"]["id"]
```

### Send a turn (user message)

```python
await send_request("turn/start", {
    "threadId": thread_id,
    "input": [{"type": "text", "text": prompt}],
})
await read_response(rid)  # turn/start acknowledgement
```

### Read events

Messages come as JSON-RPC notifications (no `id` field):

```python
while True:
    line = await proc.stdout.readline()
    msg = json.loads(line)
    method = msg.get("method", "")
    params = msg.get("params", {})

    if method == "item/completed":
        item = params.get("item", {})
        if item["type"] == "agentMessage":
            print(f"Text: {item['text']}")
        elif item["type"] == "reasoning":
            print(f"Thinking: {item['content']}")
        elif item["type"] == "commandExecution":
            print(f"Bash: {item['command']} -> {item['aggregatedOutput']}")

    elif method == "turn/completed":
        print("Turn done")
        break

    # Server requests need responses (approval, tool calls)
    elif "id" in msg and "method" in msg:
        server_method = msg["method"]
        if server_method == "item/tool/call":
            # Handle custom dynamic tool call
            tool_name = msg["params"]["tool"]
            tool_args = msg["params"]["arguments"]
            result = handle_tool(tool_name, tool_args)
            await send_response(msg["id"], {
                "contentItems": [{"type": "text", "text": result}],
                "success": True,
            })
        elif server_method == "item/tool/requestUserInput":
            await send_response(msg["id"], {"answers": {}})
        elif server_method == "mcpServer/elicitation/request":
            await send_response(msg["id"], {
                "action": "accept",
                "content": {},
                "_meta": None,
            })
        else:
            # Approvals use method-specific generated response shapes.
            await send_response(msg["id"], {"decision": "accept"})
```

### Continue a conversation

```python
# Reuse the same thread_id — send another turn/start
await send_request("turn/start", {
    "threadId": thread_id,
    "input": [{"type": "text", "text": "follow-up instruction"}],
})
```

### Cleanup

```python
proc.terminate()
await proc.wait()
```

---

## Copilot — `github-copilot-sdk`

**Install:** `pip install github-copilot-sdk`

### Setup

```python
from copilot import (
    CopilotClient, CopilotSession, SessionEvent,
    PermissionRequestResult, define_tool, ToolInvocation,
)
import asyncio

client = CopilotClient()  # auto-starts copilot server

# Event callback — bridge sync to async
queue = asyncio.Queue()
loop = asyncio.get_running_loop()

def on_event(event: SessionEvent):
    event_dict = event.to_dict()
    loop.call_soon_threadsafe(queue.put_nowait, event_dict)

def on_permission(req, ctx):
    return PermissionRequestResult(allow=True)
```

### Create session

```python
session = client.create_session(
    on_permission_request=on_permission,
    on_event=on_event,
    model="gpt-5.3-codex",          # or "claude-opus-4.6", etc.
    working_directory="/path/to/workdir",
)
```

### Send prompt and consume events

```python
session.send(prompt)

while True:
    event_dict = await asyncio.wait_for(queue.get(), timeout=600)

    # Normalize event_dict to extract assistant messages, tool calls, etc.
    # The dict structure varies — check for keys like:
    #   "content", "toolRequests", "reasoningText", "result"

    event_type = event_dict.get("type", "")
    if event_type in ("result", "done", "session.end", "error"):
        break
```

### Register custom tools

```python
@define_tool(
    name="my_tool",
    description="What this tool does",
)
def my_tool_handler(session_ctx, invocation: ToolInvocation):
    param = invocation.args.get("param", "")
    result = do_something(param)
    return result  # string or ToolResult

session = client.create_session(
    on_permission_request=on_permission,
    on_event=on_event,
    tools=[my_tool_handler],
)
```

### Continue / send follow-up

```python
# Within the same session — send another message
session.send("follow-up instruction", mode="enqueue")
# mode="enqueue" waits for current turn to finish
# mode="immediate" interrupts (use with caution)
```

### Resume a previous session

```python
# Save session_id from first run
session_id = session.session_id

# Later — resume with full conversation history
session = client.resume_session(
    session_id,
    on_permission_request=on_permission,
    on_event=on_event,
    tools=[my_tool_handler],  # re-register tools
)
session.send("continue from where you left off")
```

### Model name mapping

Copilot uses full model names, not short aliases:

```python
COPILOT_MODEL_MAP = {
    "opus": "claude-opus-4.6",
    "sonnet": "claude-sonnet-4.6",
    "haiku": "claude-haiku-4.5",
}
```

### Cleanup

```python
session.destroy()
client.stop()
```

---

## OpenCode — `opencode-sdk`

**Install:** `pip install opencode-sdk`

OpenCode uses a REST API served by `opencode serve`. The Python SDK
is a synchronous HTTP client, so async callers need `run_in_executor`.

### Start the server

```python
import subprocess, socket

def is_port_open(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (OSError, ConnectionRefusedError):
        return False

if not is_port_open(4096):
    subprocess.Popen(
        ["opencode", "serve", "--port", "4096"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait for ready
    import time
    for _ in range(30):
        if is_port_open(4096):
            break
        time.sleep(0.5)
```

### Create client and session

```python
from opencode_sdk import OpencodeClient

client = OpencodeClient(base_url="http://127.0.0.1:4096")
session = client.create_session(title="My Session")
session_id = session["id"]
```

### Send message

```python
# Synchronous — wrap in executor for async
response = client.send_message(session_id, prompt)

# Response is a dict with the assistant's reply
# Parse response for text, tool calls, etc.
text = response.get("text") or response.get("content", "")
```

### Continue a conversation

```python
# Same session — just send another message
response2 = client.send_message(session_id, "follow-up instruction")
```

### Custom tools

OpenCode uses TypeScript tool files placed in `.opencode/tools/` or
`~/.config/opencode/tools/`:

```typescript
// ~/.config/opencode/tools/my_tool.ts
import { tool } from "@opencode-ai/plugin"

export default tool({
    description: "What this tool does",
    args: {
        param: tool.schema.string().describe("Parameter description"),
    },
    async execute(args, ctx) {
        // ctx has: directory, sessionId, messageId, agentName
        const result = doSomething(args.param)
        return result
    },
})
```

The tool is automatically available to the agent. To detect when the
agent calls it (for integration with external systems), have the tool
write to a known file and poll for changes from Python:

```typescript
// Tool writes to a queue file
const fs = await import("fs")
fs.appendFileSync(`${ctx.directory}/_shared/.notify_queue`,
    `${Date.now()}|${args.message}\n`)
```

```python
# Python reads and processes the queue
queue_file = Path(cwd) / "_shared" / ".notify_queue"
if queue_file.exists():
    for line in queue_file.read_text().splitlines():
        timestamp, message = line.split("|", 1)
        handle_message(message)
    queue_file.unlink()
```

### Cleanup

```python
# The opencode serve process can be left running between sessions.
# To stop it:
proc.terminate()
```

---

## Comparison

| Feature | Claude | Codex | Copilot | OpenCode |
|---------|--------|-------|---------|----------|
| **Package** | `claude-agent-sdk` | CLI `codex app-server` | `github-copilot-sdk` | `opencode-sdk` |
| **Protocol** | Python native | JSON-RPC stdio | Python callbacks | REST HTTP |
| **Async** | Native async | Async subprocess I/O | Sync callbacks + queue | Sync (use executor) |
| **Streaming** | `receive_messages()` iterator | Read stdout lines | `on_event` callback | Poll / single response |
| **Custom tools** | `@tool` + MCP server | `dynamicTools` + RPC | `define_tool` decorator | TypeScript files |
| **Tool handler** | In-process Python | JSON-RPC response | In-process Python | File-based bridge |
| **Session resume** | `session_id` + `continue_conversation` (disk-persisted) | `thread_id` + `turn/start` (in-memory, lost if process dies) | `resume_session(session_id)` (server-persisted) | Same `session_id` (server-persisted while `opencode serve` runs) |
| **Permissions** | `permission_mode="bypassPermissions"` | `approvalPolicy: "never"` | `PermissionRequestResult(allow=True)` | N/A |
| **Model config** | `ClaudeAgentOptions(model=)` | `thread/start` params | `create_session(model=)` | N/A (configured globally) |
