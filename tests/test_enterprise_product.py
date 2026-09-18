import asyncio
import unittest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from config.settings import settings
from kernel import Kernel, PriorityLevel
from server.app import create_app


class TestEnterpriseProduct(unittest.IsolatedAsyncioTestCase):
    """Integration and unit tests verifying the enterprise product enhancements."""

    async def asyncSetUp(self):
        self.kernel = Kernel(provider_name="mock", auto_approve_hitl=False)
        self.kernel.start_daemon()
        self.app = create_app(self.kernel)
        self.client = TestClient(self.app)

    async def asyncTearDown(self):
        if hasattr(self.kernel, "aclose"):
            await self.kernel.aclose()
        else:
            self.kernel.shutdown()

    async def test_workspace_scoping_in_process_spawning(self):
        """GAP-PROD: Test that workspace_id and tenant_id are stored on PCB and filterable."""
        pcb1 = self.kernel.spawn_process(
            name="worker_ws1",
            task_instruction="Task for alpha workspace",
            workspace_id="team_alpha",
            tenant_id="tenant_corp"
        )
        pcb2 = self.kernel.spawn_process(
            name="worker_ws2",
            task_instruction="Task for beta workspace",
            workspace_id="team_beta",
            tenant_id="tenant_corp"
        )

        self.assertEqual(pcb1.workspace_id, "team_alpha")
        self.assertEqual(pcb1.tenant_id, "tenant_corp")
        self.assertEqual(pcb2.workspace_id, "team_beta")

        # Test filtering via API
        resp_all = self.client.get("/api/processes")
        self.assertEqual(resp_all.status_code, 200)
        pids_all = [p["pid"] for p in resp_all.json()]
        self.assertIn(pcb1.pid, pids_all)
        self.assertIn(pcb2.pid, pids_all)

        resp_alpha = self.client.get("/api/processes?workspace_id=team_alpha")
        self.assertEqual(resp_alpha.status_code, 200)
        pids_alpha = [p["pid"] for p in resp_alpha.json()]
        self.assertIn(pcb1.pid, pids_alpha)
        self.assertNotIn(pcb2.pid, pids_alpha)

    async def test_trace_retrieval_and_replay_endpoints(self):
        """GAP-PROD: Verify /api/traces, /api/traces/{trace_id}, and /api/traces/{trace_id}/replay."""
        # Spawn and run an agent to generate trace records
        pcb = self.kernel.spawn_process(
            name="traced_agent",
            task_instruction="Compute 5 * 25",
            role="coder"
        )
        await self.kernel.run_until_idle()

        # 1. List traces
        resp_traces = self.client.get("/api/traces")
        self.assertEqual(resp_traces.status_code, 200)
        traces = resp_traces.json()
        self.assertTrue(len(traces) > 0)
        trace_ids = [t["trace_id"] for t in traces]
        self.assertIn(pcb.trace_id, trace_ids)

        # 2. Get trace sequential records
        resp_detail = self.client.get(f"/api/traces/{pcb.trace_id}")
        self.assertEqual(resp_detail.status_code, 200)
        records = resp_detail.json()
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0]["trace_id"], pcb.trace_id)

        # 3. Trigger offline deterministic replay via POST
        resp_replay = self.client.post(f"/api/traces/{pcb.trace_id}/replay")
        self.assertEqual(resp_replay.status_code, 200)
        report = resp_replay.json()
        self.assertEqual(report["trace_id"], pcb.trace_id)
        self.assertTrue(report["is_reproducible"])
        self.assertTrue(report["total_records"] > 0)

    async def test_hitl_listener_and_resolution_flow(self):
        """GAP-PROD: Verify HITLManager listener triggers and /api/hitl/resolve resolves requests."""
        events_received = []

        def on_hitl_event(event_type, req):
            events_received.append((event_type, req.request_id))

        self.kernel.hitl_manager.add_listener(on_hitl_event)

        # Create a destructive syscall request
        req = self.kernel.hitl_manager.create_request(
            pid="proc-test-hitl",
            syscall_name="sys_fs_delete",
            arguments={"path": "sensitive.db"}
        )

        self.assertEqual(len(events_received), 1)
        self.assertEqual(events_received[0][0], "hitl_requested")
        self.assertEqual(events_received[0][1], req.request_id)

        # Pending API should list it
        resp_pending = self.client.get("/api/hitl/pending")
        self.assertEqual(resp_pending.status_code, 200)
        pending_ids = [r["request_id"] for r in resp_pending.json()]
        self.assertIn(req.request_id, pending_ids)

        # Resolve via POST /api/hitl/resolve
        resp_resolve = self.client.post(
            "/api/hitl/resolve",
            json={"request_id": req.request_id, "approved": True}
        )
        self.assertEqual(resp_resolve.status_code, 200)
        self.assertTrue(resp_resolve.json()["approved"])

        # Listener should have received resolution
        self.assertEqual(len(events_received), 2)
        self.assertEqual(events_received[1][0], "hitl_resolved")
        self.assertEqual(events_received[1][1], req.request_id)


if __name__ == "__main__":
    unittest.main()
