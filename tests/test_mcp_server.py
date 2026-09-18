import asyncio
import gc
import json
from pathlib import Path
import tempfile
import unittest

from kernel.event_loop import Kernel
from syscalls.mcp_server import AIOSMcpServer
from starlette.testclient import TestClient
from server.app import create_app

class TestAIOSMcpServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_mcp.db"
        self.kernel = Kernel(provider_name="mock", db_path=self.db_path, auto_approve_hitl=True)
        self.mcp_server = self.kernel.mcp_server

    async def asyncTearDown(self):
        self.kernel.shutdown()
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_mcp_initialize_and_ping(self):
        """Verify MCP initialize handshake and ping."""
        # 1. initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        res = await self.mcp_server.handle_json_rpc(init_req)
        self.assertEqual(res["jsonrpc"], "2.0")
        self.assertEqual(res["id"], 1)
        self.assertIn("capabilities", res["result"])
        self.assertEqual(res["result"]["serverInfo"]["name"], "ai-os")

        # 2. notifications/initialized (notification produces no response)
        notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }
        notif_res = await self.mcp_server.handle_json_rpc(notif)
        self.assertIsNone(notif_res)

        # 3. ping
        ping_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping"
        }
        ping_res = await self.mcp_server.handle_json_rpc(ping_req)
        self.assertEqual(ping_res["id"], 2)
        self.assertEqual(ping_res["result"], {})

    async def test_mcp_tools_list(self):
        """Verify tools/list exposes AI-OS kernel tools with inputSchema."""
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }
        res = await self.mcp_server.handle_json_rpc(req)
        self.assertEqual(res["id"], 3)
        tools = res["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        
        expected_tools = {
            "aios_spawn_task",
            "aios_run_task_and_wait",
            "aios_list_processes",
            "aios_get_process",
            "aios_kill_process",
            "aios_query_memory",
            "aios_list_facts",
            "aios_store_fact",
            "aios_read_blackboard",
            "aios_write_blackboard"
        }
        self.assertTrue(expected_tools.issubset(tool_names))
        for t in tools:
            self.assertIn("inputSchema", t)
            self.assertIn("description", t)

    async def test_mcp_tool_call_spawn_and_get_process(self):
        """Verify tools/call can spawn an agent task and query its telemetry."""
        spawn_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "aios_spawn_task",
                "arguments": {
                    "instruction": "Test MCP agent task",
                    "priority": "HIGH",
                    "role": "planner"
                }
            }
        }
        spawn_res = await self.mcp_server.handle_json_rpc(spawn_req)
        self.assertFalse(spawn_res["result"]["isError"])
        content_text = spawn_res["result"]["content"][0]["text"]
        payload = json.loads(content_text)
        pid = payload["pid"]
        self.assertTrue(pid.startswith("proc-"))
        self.assertEqual(payload["role"], "planner")

        # Get process telemetry
        get_req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "aios_get_process",
                "arguments": {"pid": pid}
            }
        }
        get_res = await self.mcp_server.handle_json_rpc(get_req)
        self.assertFalse(get_res["result"]["isError"])
        get_payload = json.loads(get_res["result"]["content"][0]["text"])
        self.assertEqual(get_payload["pid"], pid)
        self.assertEqual(get_payload["role"], "planner")

    async def test_mcp_tool_call_run_and_wait(self):
        """Verify tools/call for aios_run_task_and_wait executes agent to completion."""
        req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "aios_run_task_and_wait",
                "arguments": {
                    "instruction": "Calculate sqrt(144) + 25 * 3",
                    "allocated_tools": ["sys_calc"]
                }
            }
        }
        res = await self.mcp_server.handle_json_rpc(req)
        self.assertFalse(res["result"]["isError"])
        payload = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(payload["state"], "COMPLETED")
        self.assertIsNotNone(payload["result"])

    async def test_mcp_memory_and_blackboard_tools(self):
        """Verify memory storage/listing and blackboard read/write via MCP."""
        # 1. Store and list facts
        store_req = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "aios_store_fact",
                "arguments": {
                    "key": "mcp.integration.status",
                    "value": "verified_active",
                    "confidence": 0.99
                }
            }
        }
        store_res = await self.mcp_server.handle_json_rpc(store_req)
        self.assertFalse(store_res["result"]["isError"])

        list_req = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "aios_list_facts",
                "arguments": {}
            }
        }
        list_res = await self.mcp_server.handle_json_rpc(list_req)
        self.assertFalse(list_res["result"]["isError"])
        facts_payload = json.loads(list_res["result"]["content"][0]["text"])
        self.assertEqual(facts_payload["facts"].get("mcp.integration.status"), "verified_active")

        # 2. Write and read blackboard
        write_req = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "aios_write_blackboard",
                "arguments": {
                    "topic": "mcp_milestones",
                    "key": "phase_1",
                    "value": {"status": "completed", "author": "external_agent"}
                }
            }
        }
        write_res = await self.mcp_server.handle_json_rpc(write_req)
        self.assertFalse(write_res["result"]["isError"])

        read_req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "aios_read_blackboard",
                "arguments": {
                    "topic": "mcp_milestones",
                    "key": "phase_1"
                }
            }
        }
        read_res = await self.mcp_server.handle_json_rpc(read_req)
        self.assertFalse(read_res["result"]["isError"])
        bb_payload = json.loads(read_res["result"]["content"][0]["text"])
        self.assertEqual(bb_payload["value"]["status"], "completed")

    async def test_mcp_error_handling(self):
        """Verify standard JSON-RPC 2.0 error codes for invalid requests and unknown tools."""
        # Unknown tool
        req_unknown_tool = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "non_existent_tool",
                "arguments": {}
            }
        }
        res = await self.mcp_server.handle_json_rpc(req_unknown_tool)
        self.assertEqual(res["error"]["code"], -32601)
        self.assertIn("Tool not found", res["error"]["message"])

        # Unknown method
        req_unknown_method = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "unknown_rpc_method"
        }
        res = await self.mcp_server.handle_json_rpc(req_unknown_method)
        self.assertEqual(res["error"]["code"], -32601)

        # Parse error
        res_parse = await self.mcp_server.handle_json_rpc("{invalid json string")
        self.assertEqual(res_parse["error"]["code"], -32700)

    async def test_mcp_http_endpoint(self):
        """Verify POST /api/mcp endpoint on FastAPI server."""
        app = create_app(self.kernel)
        client = TestClient(app)

        # 1. tools/list via HTTP POST
        res = client.post("/api/mcp", json={
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/list"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["id"], 100)
        self.assertIn("tools", data["result"])

        # 2. tools/call via HTTP POST
        call_res = client.post("/api/mcp", json={
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "aios_list_facts"
            }
        })
        self.assertEqual(call_res.status_code, 200)
        call_data = call_res.json()
        self.assertFalse(call_data["result"]["isError"])

    async def test_mcp_cli_stdio_transport_subprocess(self):
        """Verify CLI 'mcp-server' communicates over stdio using JSON-RPC 2.0."""
        import subprocess, sys
        proc = subprocess.Popen(
            [sys.executable, "cli.py", "mcp-server", "--provider", "mock", "--auto-approve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        try:
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-stdio", "version": "1.0"}
                }
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()

            line = proc.stdout.readline()
            self.assertTrue(line)
            data = json.loads(line.strip())
            self.assertEqual(data["id"], 1)
            self.assertEqual(data["result"]["serverInfo"]["name"], "ai-os")
        finally:
            proc.terminate()
            proc.wait()

if __name__ == "__main__":
    unittest.main()
