import asyncio
from pathlib import Path
import tempfile
import unittest
from fastapi.testclient import TestClient

from config.settings import settings
from kernel import Kernel
from security.vault import SecretsVault
from server.app import create_app
from aios.client import AIOSClient


class TestSecretsVault(unittest.TestCase):
    """Unit tests for the BYOK SecretsVault."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vault.db"
        self.vault = SecretsVault(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_set_get_and_mask_key(self):
        self.vault.set_key("workspace_alpha", "openai", "sk-proj-1234567890abcdef")
        raw = self.vault.get_key("workspace_alpha", "openai")
        self.assertEqual(raw, "sk-proj-1234567890abcdef")

        # Test case insensitivity
        self.assertEqual(self.vault.get_key("workspace_alpha", "OPENAI"), "sk-proj-1234567890abcdef")

        # Test masking
        masked = SecretsVault.mask_key("sk-proj-1234567890abcdef")
        self.assertTrue(masked.startswith("sk-p...cdef"))

        # Test listing
        keys = self.vault.list_keys("workspace_alpha")
        self.assertIn("openai", keys)
        self.assertEqual(keys["openai"]["masked_key"], masked)

    def test_delete_key(self):
        self.vault.set_key("ws_1", "gemini", "AIzaSyD-secret-key-1234")
        self.assertIsNotNone(self.vault.get_key("ws_1", "gemini"))
        
        deleted = self.vault.delete_key("ws_1", "gemini")
        self.assertTrue(deleted)
        self.assertIsNone(self.vault.get_key("ws_1", "gemini"))

        # Deleting nonexistent key returns False
        self.assertFalse(self.vault.delete_key("ws_1", "gemini"))


class TestAIOSClient(unittest.IsolatedAsyncioTestCase):
    """Integration tests for the AIOSClient remote SDK."""

    async def asyncSetUp(self):
        self.kernel = Kernel(provider_name="mock", auto_approve_hitl=False)
        self.kernel.start_daemon()
        self.app = create_app(self.kernel)
        self.test_http = TestClient(self.app)
        # Point AIOSClient directly through the in-process test client
        self.client = AIOSClient(
            base_url="http://testserver",
            api_token=settings.admin_token or None,
            http_client=self.test_http
        )

    async def asyncTearDown(self):
        if hasattr(self.kernel, "aclose"):
            await self.kernel.aclose()
        else:
            self.kernel.shutdown()

    async def test_client_health_and_status(self):
        health = self.client.health()
        self.assertEqual(health["status"], "healthy")
        self.assertTrue(health["scheduler_active"])

        status = self.client.status()
        self.assertIn("active_processes", status)
        self.assertIn("memory", status)

    async def test_client_process_lifecycle(self):
        spawned = self.client.spawn(
            name="sdk_agent",
            task_instruction="Calculate 10 + 20",
            priority="HIGH",
            role="coder",
            workspace_id="test_ws"
        )
        self.assertTrue(spawned["success"])
        pid = spawned["pid"]
        self.assertEqual(spawned["workspace_id"], "test_ws")

        # Get process
        p_detail = self.client.get_process(pid)
        self.assertEqual(p_detail["process"]["pid"], pid)

        # List processes
        procs = self.client.list_processes(workspace_id="test_ws")
        self.assertTrue(any(p["pid"] == pid for p in procs))

        # Kill process
        killed = self.client.kill(pid)
        self.assertTrue(killed)

    async def test_client_trace_and_export(self):
        # Spawn agent to generate a trace
        spawned = self.client.spawn(
            name="trace_test_agent",
            task_instruction="Compute 3 * 3",
            role="coder"
        )
        await self.kernel.run_until_idle()

        traces = self.client.list_traces()
        self.assertTrue(len(traces) > 0)
        trace_id = traces[0]["trace_id"]

        # Get sequential records
        records = self.client.get_trace(trace_id)
        self.assertTrue(len(records) > 0)

        # Replay trace
        replay = self.client.replay_trace(trace_id)
        self.assertEqual(replay["trace_id"], trace_id)
        self.assertTrue(replay["is_reproducible"])

        # Export trace
        export_pkg = self.client.export_trace(trace_id)
        self.assertEqual(export_pkg["trace_id"], trace_id)
        self.assertIn("audit_summary", export_pkg)
        self.assertTrue(export_pkg["audit_summary"]["deterministic_reproducibility"])

    async def test_client_vault_keys(self):
        set_res = self.client.set_key("team_sales", "openai", "sk-proj-abcdef1234567890")
        self.assertTrue(set_res["success"])
        self.assertEqual(set_res["provider"], "openai")

        keys = self.client.list_keys("team_sales")
        self.assertIn("openai", keys["keys"])
        self.assertTrue(keys["keys"]["openai"]["masked_key"].startswith("sk-p"))

        deleted = self.client.delete_key("team_sales", "openai")
        self.assertTrue(deleted)


if __name__ == "__main__":
    unittest.main()
