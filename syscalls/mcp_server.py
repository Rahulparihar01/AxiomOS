import asyncio
import json
import sys
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from config.settings import settings
from kernel.process import PriorityLevel, ProcessState

class McpServerTool(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any] = Field(default_factory=dict)

class AIOSMcpServer:
    """
    Model Context Protocol (MCP) JSON-RPC 2.0 Server for AI-OS.
    Exposes kernel process scheduling, memory recall, and blackboard state to external
    AI developer environments (Claude Desktop, Cursor, VS Code, Windsurf, custom agents).
    Supports both stdio transport (CLI) and HTTP JSON-RPC transport (REST endpoint).
    """
    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, kernel=None):
        self.kernel = kernel
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        """Register the default AI-OS management and execution tools."""
        self.register_tool(
            name="aios_spawn_task",
            description="Spawn an autonomous AxiomOS agent task into the kernel scheduler.",
            input_schema={
                "type": "object",
                "properties": {
                    "instruction": {
                        "type": "string",
                        "description": "The goal or prompt for the agent to execute."
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["LOW", "NORMAL", "HIGH", "CRITICAL"],
                        "description": "Scheduling priority (default: NORMAL)."
                    },
                    "role": {
                        "type": "string",
                        "enum": ["base", "planner", "coder", "reviewer", "researcher", "conflict_resolver"],
                        "description": "Specialized persona role for the agent (default: base)."
                    },
                    "allocated_tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Allowed syscall tools (e.g. ['sys_calc', 'sys_fs_read']). Defaults to all tools."
                    },
                    "token_budget": {
                        "type": "integer",
                        "description": "Max tokens allocated to the process."
                    }
                },
                "required": ["instruction"]
            },
            handler=self._handle_spawn_task
        )

        self.register_tool(
            name="aios_run_task_and_wait",
            description="Spawn an agent task and execute the AI-OS kernel until completion or timeout, returning final output.",
            input_schema={
                "type": "object",
                "properties": {
                    "instruction": {
                        "type": "string",
                        "description": "The task instruction for the agent."
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["LOW", "NORMAL", "HIGH", "CRITICAL"],
                        "description": "Scheduling priority level."
                    },
                    "role": {
                        "type": "string",
                        "enum": ["base", "planner", "coder", "reviewer", "researcher", "conflict_resolver"],
                        "description": "Specialized agent role."
                    },
                    "allocated_tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of authorized syscall names."
                    },
                    "timeout_seconds": {
                        "type": "number",
                        "description": "Max seconds to wait before timing out (default: 60)."
                    }
                },
                "required": ["instruction"]
            },
            handler=self._handle_run_task_and_wait
        )

        self.register_tool(
            name="aios_list_processes",
            description="List all active, pending, completed, or failed agent processes managed by AI-OS.",
            input_schema={
                "type": "object",
                "properties": {
                    "state_filter": {
                        "type": "string",
                        "enum": ["READY", "RUNNING", "BLOCKED", "COMPLETED", "FAILED", "KILLED"],
                        "description": "Optional filter by process lifecycle state."
                    }
                }
            },
            handler=self._handle_list_processes
        )

        self.register_tool(
            name="aios_get_process",
            description="Retrieve detailed Process Control Block (PCB) telemetry, logs, state, and results for a process ID.",
            input_schema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "string",
                        "description": "Process ID (UUID) to inspect."
                    }
                },
                "required": ["pid"]
            },
            handler=self._handle_get_process
        )

        self.register_tool(
            name="aios_kill_process",
            description="Terminate an active or stalled process and optionally its entire child hierarchy.",
            input_schema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "string",
                        "description": "PID of the process to kill."
                    },
                    "cascade": {
                        "type": "boolean",
                        "description": "Whether to recursively terminate all descendant child processes (default: true)."
                    }
                },
                "required": ["pid"]
            },
            handler=self._handle_kill_process
        )

        self.register_tool(
            name="aios_query_memory",
            description="Perform semantic vector recall across AI-OS L3/L4 persistent memory.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language query to search related historical knowledge."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max memory records to retrieve (default: 5)."
                    }
                },
                "required": ["query"]
            },
            handler=self._handle_query_memory
        )

        self.register_tool(
            name="aios_list_facts",
            description="Retrieve authoritative long-term facts and versioned knowledge from L4 Archival Memory.",
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._handle_list_facts
        )

        self.register_tool(
            name="aios_store_fact",
            description="Store or update an authoritative fact in AI-OS L4 Archival Memory with conflict detection.",
            input_schema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Unique key or topic identifier for the fact."
                    },
                    "value": {
                        "type": "string",
                        "description": "Content of the fact."
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence rating from 0.0 to 1.0 (default: 1.0)."
                    }
                },
                "required": ["key", "value"]
            },
            handler=self._handle_store_fact
        )

        self.register_tool(
            name="aios_read_blackboard",
            description="Read shared multi-agent blackboard state, entries, or artifacts.",
            input_schema={
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Blackboard topic to read."
                    },
                    "key": {
                        "type": "string",
                        "description": "Specific entry key within the topic (optional, reads all topic entries if omitted)."
                    }
                },
                "required": ["topic"]
            },
            handler=self._handle_read_blackboard
        )

        self.register_tool(
            name="aios_write_blackboard",
            description="Publish an entry or milestone to the AI-OS shared multi-agent blackboard.",
            input_schema={
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Target blackboard topic."
                    },
                    "key": {
                        "type": "string",
                        "description": "Entry key."
                    },
                    "value": {
                        "description": "Data payload to store on the blackboard."
                    }
                },
                "required": ["topic", "key", "value"]
            },
            handler=self._handle_write_blackboard
        )

    def register_tool(self, name: str, description: str, input_schema: Dict[str, Any], handler: Callable):
        """Register a new tool handler on the MCP server."""
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "handler": handler
        }

    def get_tools_manifest(self) -> List[Dict[str, Any]]:
        """Return the standard MCP tools list format."""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["inputSchema"]
            }
            for t in self._tools.values()
        ]

    # --- Tool Handlers ---

    async def _handle_spawn_task(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel:
            raise RuntimeError("AI-OS Kernel is not attached to MCP server.")
        instruction = args["instruction"]
        name = args.get("name") or f"mcp_{instruction[:16].strip().replace(' ', '_')}"
        priority_str = args.get("priority", "NORMAL").upper()
        priority = getattr(PriorityLevel, priority_str, PriorityLevel.NORMAL)
        role = args.get("role", "base")
        allocated_tools = args.get("allocated_tools")
        token_budget = args.get("token_budget")

        pcb = self.kernel.spawn_process(
            name=name,
            task_instruction=instruction,
            priority=priority,
            role=role,
            allocated_tools=allocated_tools,
            token_budget=token_budget
        )
        return {
            "pid": pcb.pid,
            "name": pcb.name,
            "state": pcb.state.value,
            "priority": pcb.priority.name,
            "role": pcb.role,
            "trace_id": pcb.trace_id
        }

    async def _handle_run_task_and_wait(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel:
            raise RuntimeError("AI-OS Kernel is not attached to MCP server.")
        spawn_res = await self._handle_spawn_task(args)
        pid = spawn_res["pid"]
        timeout_seconds = args.get("timeout_seconds", 60.0)

        # Run kernel until idle or timeout
        try:
            await asyncio.wait_for(self.kernel.run_until_idle(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            pass

        pcb = self.kernel.scheduler.get_process(pid)
        if not pcb:
            return {"pid": pid, "status": "unknown"}

        return {
            "pid": pcb.pid,
            "state": pcb.state.value,
            "result": pcb.result,
            "tokens_consumed": pcb.tokens_consumed,
            "current_step": pcb.current_step,
            "error": pcb.error_message
        }

    async def _handle_list_processes(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel:
            return {"processes": []}
        all_procs = self.kernel.scheduler.list_processes()
        state_filter = args.get("state_filter")

        results = []
        for p in all_procs.values():
            if state_filter and p.state.value != state_filter:
                continue
            results.append({
                "pid": p.pid,
                "name": p.name,
                "state": p.state.value,
                "role": p.role,
                "priority": p.priority.name,
                "tokens_consumed": p.tokens_consumed,
                "current_step": p.current_step,
                "has_result": bool(p.result)
            })
        return {"processes": results, "total": len(results)}

    async def _handle_get_process(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel:
            raise RuntimeError("AI-OS Kernel is not attached.")
        pid = args["pid"]
        pcb = self.kernel.scheduler.get_process(pid)
        if not pcb:
            raise ValueError(f"Process with PID '{pid}' not found.")
        return {
            "pid": pcb.pid,
            "name": pcb.name,
            "state": pcb.state.value,
            "role": pcb.role,
            "priority": pcb.priority.name,
            "tokens_consumed": pcb.tokens_consumed,
            "token_budget": pcb.token_budget,
            "current_step": pcb.current_step,
            "child_pids": pcb.child_pids,
            "result": pcb.result,
            "error": pcb.error_message,
            "trace_id": pcb.trace_id
        }

    async def _handle_kill_process(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel:
            raise RuntimeError("AI-OS Kernel is not attached.")
        pid = args["pid"]
        cascade = args.get("cascade", True)
        killed = self.kernel.kill_process(pid, cascade=cascade)
        return {"pid": pid, "killed": killed}

    async def _handle_query_memory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel or not self.kernel.mmu:
            return {"matches": []}
        query = args["query"]
        limit = args.get("limit", 5)
        matches = await self.kernel.mmu.l3_recall.search(query, limit=limit)
        return {
            "query": query,
            "matches": [
                {
                    "content": m.content,
                    "score": round(m.score, 4),
                    "timestamp": m.timestamp
                }
                for m in matches
            ]
        }

    async def _handle_list_facts(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel or not self.kernel.mmu:
            return {"facts": {}, "versioned": []}
        facts = self.kernel.mmu.l4_archival.list_facts()
        versioned = [f.model_dump() for f in self.kernel.mmu.l4_archival.list_versioned_facts()]
        return {"facts": facts, "versioned": versioned}

    async def _handle_store_fact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel or not self.kernel.mmu:
            raise RuntimeError("MMU L4 archival store is not available.")
        key = args["key"]
        value = args["value"]
        confidence = args.get("confidence", 1.0)
        stored_rec, was_conflict = self.kernel.mmu.l4_archival.store_versioned_fact(
            key=key,
            value=value,
            written_by_pid="mcp_server",
            confidence=confidence
        )
        return {
            "key": stored_rec.key,
            "value": stored_rec.value,
            "version": stored_rec.version,
            "conflict_flag": stored_rec.conflict_flag,
            "confidence": stored_rec.confidence
        }

    async def _handle_read_blackboard(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel or not self.kernel.blackboard:
            return {"entries": {}}
        topic = args["topic"]
        key = args.get("key")
        if key:
            val = self.kernel.blackboard.read(topic, key)
            return {"topic": topic, "key": key, "value": val}
        else:
            entries = self.kernel.blackboard.get_topic_entries(topic)
            return {"topic": topic, "entries": {k: e.value for k, e in entries.items()}}

    async def _handle_write_blackboard(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.kernel or not self.kernel.blackboard:
            raise RuntimeError("Shared blackboard is not available.")
        topic = args["topic"]
        key = args["key"]
        value = args["value"]
        self.kernel.blackboard.write(
            topic=topic,
            key=key,
            value=value,
            author_pid="mcp_server"
        )
        return {"topic": topic, "key": key, "value": value, "status": "written"}

    # --- JSON-RPC 2.0 Protocol Engine ---

    async def handle_json_rpc(self, raw_data: Any) -> Optional[Dict[str, Any]]:
        """Process a raw JSON string or Python dictionary payload and return JSON-RPC 2.0 response."""
        if isinstance(raw_data, (str, bytes)):
            try:
                payload = json.loads(raw_data)
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
                }
        elif isinstance(raw_data, dict):
            payload = raw_data
        else:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON object"}
            }

        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id") if isinstance(payload, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request: 'jsonrpc' must be '2.0'"}
            }

        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params") or {}

        # 1. initialize handshake
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "ai-os",
                        "version": getattr(settings, "version", "0.2.0")
                    }
                }
            }

        # 2. notifications/initialized (notification: no response)
        elif method == "notifications/initialized":
            return None

        # 3. ping
        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # 4. tools/list
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_tools_manifest()
                }
            }

        # 5. tools/call
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments") or {}

            if not tool_name or tool_name not in self._tools:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool not found: '{tool_name}'"
                    }
                }

            handler = self._tools[tool_name]["handler"]
            try:
                if asyncio.iscoroutinefunction(handler):
                    output = await handler(tool_args)
                else:
                    output = handler(tool_args)

                text_content = json.dumps(output, default=str, indent=2)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": text_content
                            }
                        ],
                        "isError": False
                    }
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error executing tool '{tool_name}': {str(exc)}"
                            }
                        ],
                        "isError": True
                    }
                }

        # Unknown method
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: '{method}'"
                }
            }

    # --- Stdio Transport Loop ---

    async def run_stdio_server(self):
        """
        Run the MCP server over standard input and output (stdio).
        Allows Claude Desktop, Cursor, and other MCP clients to launch AI-OS directly.
        """
        sys.stderr.write(f"[ai-os] MCP Server (v{getattr(settings, 'version', '0.2.0')}) initialized on stdio.\n")
        sys.stderr.flush()

        loop = asyncio.get_running_loop()

        while True:
            try:
                # Read line asynchronously from stdin in default executor
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue

                response = await self.handle_json_rpc(stripped)
                if response is not None:
                    out_str = json.dumps(response) + "\n"
                    sys.stdout.write(out_str)
                    sys.stdout.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                sys.stderr.write(f"[ai-os] MCP stdio error: {str(e)}\n")
                sys.stderr.flush()
