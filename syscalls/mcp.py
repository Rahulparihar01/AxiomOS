import asyncio
import json
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from kernel.process import ProcessControlBlock
from syscalls.base import SyscallBase, SyscallResult

class McpToolDefinition(BaseModel):
    """MCP standard tool declaration."""
    name: str
    description: str
    inputSchema: Dict[str, Any] = Field(default_factory=dict)

class McpToolAdapter(SyscallBase):
    """
    Adapter exposing a Model Context Protocol (MCP) tool as an AI-OS System Call.
    Translates agent syscall invocations into standard MCP JSON-RPC requests.
    """
    def __init__(
        self,
        tool_def: McpToolDefinition,
        invoker_fn: Callable[[str, Dict[str, Any]], Any],
        is_mutating: bool = False
    ):
        self.name = f"mcp_{tool_def.name}"
        self.description = f"[MCP Tool] {tool_def.description}"
        self.is_mutating = is_mutating
        self.tool_def = tool_def
        self._invoker_fn = invoker_fn
        # Create empty BaseModel for input_schema attribute compatibility
        self.input_schema = BaseModel

    def get_tool_definition(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.tool_def.inputSchema or {"type": "object", "properties": {}}
            }
        }

    async def execute(self, pcb: ProcessControlBlock, **kwargs) -> SyscallResult:
        try:
            # Dispatch to MCP invoker
            if asyncio.iscoroutinefunction(self._invoker_fn):
                res = await self._invoker_fn(self.tool_def.name, kwargs)
            else:
                res = self._invoker_fn(self.tool_def.name, kwargs)
            return SyscallResult(success=True, data={"result": res})
        except Exception as exc:
            return SyscallResult(success=False, error=f"MCP Tool '{self.name}' failed: {str(exc)}")

class McpClientRegistry:
    """
    Registry managing connections to external MCP tool providers.
    Enables dynamic tool discovery and mounting as native AI-OS system calls.
    """
    def __init__(self, syscall_registry=None):
        self.syscall_registry = syscall_registry
        self._connected_servers: Dict[str, Dict[str, Any]] = {}

    def register_mcp_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[[str, Dict[str, Any]], Any],
        is_mutating: bool = False
    ) -> McpToolAdapter:
        """Register a single MCP tool dynamically."""
        tool_def = McpToolDefinition(
            name=name,
            description=description,
            inputSchema=input_schema
        )
        adapter = McpToolAdapter(tool_def=tool_def, invoker_fn=handler, is_mutating=is_mutating)
        if self.syscall_registry:
            self.syscall_registry.register(adapter)
        return adapter

    def mount_mcp_server(self, server_name: str, tools: List[Dict[str, Any]], invoker: Callable):
        """Mount an entire MCP server's tool manifest into the AI-OS kernel."""
        self._connected_servers[server_name] = {"tools": tools, "invoker": invoker}
        registered_adapters = []
        for tool_info in tools:
            adapter = self.register_mcp_tool(
                name=tool_info["name"],
                description=tool_info.get("description", ""),
                input_schema=tool_info.get("inputSchema", {}),
                handler=invoker,
                is_mutating=tool_info.get("is_mutating", False)
            )
            registered_adapters.append(adapter)
        return registered_adapters

    async def mount_stdio_server(
        self,
        server_name: str,
        command: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None
    ) -> List[McpToolAdapter]:
        """Spawn an external MCP server via stdio transport and mount its tools."""
        transport = McpStdioTransport(command=command, args=args, env=env)
        await transport.connect()
        tools = await transport.list_tools()
        return self.mount_mcp_server(
            server_name=server_name,
            tools=tools,
            invoker=lambda tool_name, kwargs: transport.call_tool(tool_name, kwargs)
        )

class McpStdioTransport:
    """
    Standard Stdio Client Transport for Model Context Protocol (MCP).
    Spawns an external MCP server process and manages bidirectional JSON-RPC 2.0 communication.
    """
    def __init__(self, command: str, args: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None):
        self.command = command
        self.args = args or []
        self.env = env
        self.proc: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._pending_responses: Dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None

    async def connect(self):
        """Spawn the external MCP server process and initialize the reader loop."""
        cmd_args = [self.command] + self.args
        self.proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env
        )
        self._reader_task = asyncio.create_task(self._listen_stdout())

        # Send MCP initialize handshake
        init_res = await self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ai-os", "version": "0.1.0"}
        })
        # Send initialized notification
        await self.send_notification("notifications/initialized")
        return init_res

    async def _listen_stdout(self):
        """Read newline-delimited JSON-RPC messages from server stdout."""
        while self.proc and self.proc.stdout and not self.proc.stdout.at_eof():
            try:
                line = await self.proc.stdout.readline()
                if not line:
                    break
                raw_str = line.decode("utf-8").strip()
                if not raw_str:
                    continue
                message = json.loads(raw_str)
                if "id" in message and message["id"] in self._pending_responses:
                    fut = self._pending_responses.pop(message["id"])
                    if not fut.done():
                        if "error" in message:
                            fut.set_exception(RuntimeError(message["error"].get("message", "MCP error")))
                        else:
                            fut.set_result(message.get("result"))
            except Exception:
                break

    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a JSON-RPC 2.0 request and await response."""
        if not self.proc or not self.proc.stdin:
            raise RuntimeError("MCP server process is not running.")
        self._request_id += 1
        req_id = self._request_id
        fut = asyncio.get_running_loop().create_future()
        self._pending_responses[req_id] = fut

        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {}
        }
        data = (json.dumps(payload) + "\n").encode("utf-8")
        self.proc.stdin.write(data)
        await self.proc.stdin.drain()
        return await fut

    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None):
        """Send a JSON-RPC 2.0 notification (no response expected)."""
        if not self.proc or not self.proc.stdin:
            return
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {}
        }
        data = (json.dumps(payload) + "\n").encode("utf-8")
        self.proc.stdin.write(data)
        await self.proc.stdin.drain()

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Query tools/list from server."""
        res = await self.send_request("tools/list")
        return res.get("tools", []) if isinstance(res, dict) else []

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Invoke tools/call on server."""
        res = await self.send_request("tools/call", {"name": name, "arguments": arguments})
        return res

    async def disconnect(self):
        """Terminate the server process."""
        if self._reader_task:
            self._reader_task.cancel()
        if self.proc:
            try:
                self.proc.terminate()
                await self.proc.wait()
            except Exception:
                pass
