import asyncio
import gc
import json
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

from starlette.testclient import TestClient

from config.settings import settings
from kernel.process import PriorityLevel, ProcessState, ProcessControlBlock
from kernel.event_loop import Kernel
from kernel.flight_recorder import FlightRecorder
from agents.researcher import ResearchAgent
from agents.conflict_resolver import ConflictResolverAgent
from models.router import AdaptiveModelRouter, ModelTier
from models.provider import BaseModelProvider, ModelResponse, MockProvider
from ipc.bus import MessageBus
from ipc.message import IPCMessage, IPCMessageType
from server.app import create_app

class FailingMockProvider(BaseModelProvider):
    """Mock provider that always raises an error simulating HTTP 429 / 503."""
    def __init__(self, error_msg: str = "HTTP 429 Too Many Requests"):
        self.error_msg = error_msg
        self.call_count = 0

    async def generate(self, system_prompt: str, messages: list, tools: list = None) -> ModelResponse:
        self.call_count += 1
        raise RuntimeError(self.error_msg)

class TestEnterpriseGaps(unittest.IsolatedAsyncioTestCase):
    """Comprehensive test suite for Enterprise Production Hardening (EGAP-01 through EGAP-06)."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_aios.db"
        self.kernel = Kernel(provider_name="mock", auto_approve_hitl=True, db_path=self.db_path)

    async def asyncTearDown(self):
        self.kernel.shutdown()
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    # =========================================================================
    # EGAP-01: Specialized Personas (ResearchAgent & ConflictResolverAgent)
    # =========================================================================
    async def test_egap01_researcher_agent_instantiation_and_recording(self):
        """Test ResearchAgent role mapping in Kernel and local finding recording."""
        pcb = self.kernel.spawn_process(
            name="deep_researcher",
            task_instruction="Synthesize recent advances in neurosymbolic AI",
            role="researcher"
        )
        self.assertEqual(pcb.role, "researcher")
        agent = self.kernel._active_agents[pcb.pid]
        self.assertIsInstance(agent, ResearchAgent)

        # Test researcher finding recorder
        finding = agent.record_finding(
            source_url="https://arxiv.org/abs/2401.12345",
            topic="Neurosymbolic Agents",
            content="Hybrid architectures combine LLM reasoning with verifiable symbolic execution."
        )
        self.assertEqual(len(agent.findings), 1)
        self.assertEqual(finding["topic"], "Neurosymbolic Agents")

    async def test_egap01_conflict_resolver_agent_instantiation_and_resolution(self):
        """Test ConflictResolverAgent role mapping and arbitration recording."""
        pcb = self.kernel.spawn_process(
            name="memory_arbitrator",
            task_instruction="Resolve contradictory server IP addresses in L4 memory",
            role="conflict_resolver"
        )
        self.assertEqual(pcb.role, "conflict_resolver")
        agent = self.kernel._active_agents[pcb.pid]
        self.assertIsInstance(agent, ConflictResolverAgent)

        # Test resolution recorder
        resolution = agent.record_resolution(
            key="config.primary_cluster_ip",
            conflicting_versions=[1, 2],
            chosen_value="10.240.0.1",
            rationale="Version 2 was signed by root administrator PID."
        )
        self.assertEqual(len(agent.resolutions), 1)
        self.assertEqual(resolution["chosen_value"], "10.240.0.1")

    # =========================================================================
    # EGAP-02: Deterministic Flight Replay Web Endpoints
    # =========================================================================
    async def test_egap02_replay_web_endpoints(self):
        """Test GET /api/replay/traces and GET /api/replay/traces/{trace_id} endpoints."""
        app = create_app(self.kernel)
        client = TestClient(app)

        # 1. Run a process to generate flight recorder trace records
        pcb = self.kernel.spawn_process(
            name="test_worker",
            task_instruction="Calculate 42",
            max_steps=2
        )
        await self.kernel.run_until_idle()

        # 2. Query traces list
        res = client.get("/api/replay/traces")
        self.assertEqual(res.status_code, 200)
        traces = res.json()
        self.assertIsInstance(traces, list)
        self.assertGreater(len(traces), 0)

        trace_id = traces[0]["trace_id"]
        self.assertEqual(trace_id, pcb.trace_id)

        # 3. Deterministically replay trace
        replay_res = client.get(f"/api/replay/traces/{trace_id}")
        self.assertEqual(replay_res.status_code, 200)
        replay_data = replay_res.json()
        self.assertEqual(replay_data["trace_id"], trace_id)
        self.assertTrue(replay_data["is_reproducible"])
        self.assertGreater(replay_data["total_records"], 0)
        self.assertEqual(replay_data["error"], None)

        # 4. Unknown trace returns 404
        not_found_res = client.get("/api/replay/traces/non_existent_trace_id")
        self.assertEqual(not_found_res.status_code, 404)

    # =========================================================================
    # EGAP-03: Memory Conflicts and Cost Estimation Web Endpoints
    # =========================================================================
    async def test_egap03_memory_and_cost_web_endpoints(self):
        """Test memory facts, detected conflicts, cost history, and cost estimation endpoints."""
        app = create_app(self.kernel)
        client = TestClient(app)

        # 1. Store a version 1 fact, then store a conflicting version 2 fact
        self.kernel.mmu.l4_archival.store_versioned_fact(
            key="sys.primary_db",
            value="postgresql://primary-01:5432",
            written_by_pid="pid-admin",
            confidence=1.0
        )
        _, was_conflict = self.kernel.mmu.l4_archival.store_versioned_fact(
            key="sys.primary_db",
            value="mysql://primary-backup:3306",
            written_by_pid="pid-rogue",
            confidence=0.5
        )
        self.assertTrue(was_conflict)

        # 2. Test GET /api/memory/conflicts
        conf_res = client.get("/api/memory/conflicts")
        self.assertEqual(conf_res.status_code, 200)
        conflicts = conf_res.json()
        self.assertIsInstance(conflicts, list)
        self.assertGreaterEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["key"], "sys.primary_db")
        self.assertTrue(conflicts[0]["conflict_flag"])

        # 3. Test GET /api/memory/facts
        facts_res = client.get("/api/memory/facts")
        self.assertEqual(facts_res.status_code, 200)
        facts_data = facts_res.json()
        self.assertIn("facts", facts_data)
        self.assertIn("sys.primary_db", facts_data["facts"])

        # 4. Test GET /api/costs/history and POST /api/costs/estimate
        self.kernel.mmu.l4_archival.log_task_cost(
            role="coder",
            instruction="Implement binary search tree algorithm",
            tokens_consumed=850,
            wall_time_seconds=1.2
        )
        cost_hist_res = client.get("/api/costs/history?role=coder")
        self.assertEqual(cost_hist_res.status_code, 200)
        cost_hist = cost_hist_res.json()
        self.assertEqual(len(cost_hist), 1)
        self.assertEqual(cost_hist[0]["tokens_consumed"], 850)

        est_res = client.post("/api/costs/estimate", json={
            "role": "coder",
            "instruction": "Implement binary search tree"
        })
        self.assertEqual(est_res.status_code, 200)
        est_data = est_res.json()
        self.assertIn("predicted_tokens_p90", est_data)
        self.assertGreater(est_data["predicted_tokens_p90"], 0)

    # =========================================================================
    # EGAP-04: AdaptiveModelRouter Circuit Breaker Failover
    # =========================================================================
    async def test_egap04_router_circuit_breaker_failover(self):
        """Test that router catches upstream errors and transparently fails over to fallback provider."""
        failing_primary = FailingMockProvider(error_msg="HTTP 429 Too Many Requests (Rate limit exceeded)")
        healthy_fallback = MockProvider()

        router = AdaptiveModelRouter(
            reasoning_provider=failing_primary,
            fast_provider=failing_primary,
            fallback_provider=healthy_fallback,
            failure_threshold=2
        )

        pcb = ProcessControlBlock(name="test_worker", role="planner", priority=PriorityLevel.CRITICAL)

        # Primary fails -> transparent failover to healthy fallback
        self.assertEqual(router.consecutive_failures, 0)
        self.assertFalse(router.circuit_open)

        resp = await router.generate_with_fallback(
            pcb=pcb,
            system_prompt="Test system",
            messages=[{"role": "user", "content": "Hello"}]
        )
        self.assertIsNotNone(resp)
        self.assertEqual(router.consecutive_failures, 1)
        self.assertEqual(router.fallback_invocations, 1)

        # Trigger second failure -> circuit trips open
        await router.generate_with_fallback(
            pcb=pcb,
            system_prompt="Test system",
            messages=[{"role": "user", "content": "Step 2"}]
        )
        self.assertEqual(router.consecutive_failures, 2)
        self.assertTrue(router.circuit_open)
        self.assertEqual(router.fallback_invocations, 2)

        # Subsequent call bypasses primary completely because circuit is open
        await router.generate_with_fallback(
            pcb=pcb,
            system_prompt="Test system",
            messages=[{"role": "user", "content": "Step 3"}]
        )
        self.assertEqual(router.fallback_invocations, 3)
        # Primary call count did not increase on 3rd call
        self.assertEqual(failing_primary.call_count, 2)

    # =========================================================================
    # EGAP-05: Durable SQLite WAL Queue Persistence Across Reboots
    # =========================================================================
    async def test_egap05_durable_ipc_message_recovery(self):
        """Test that in-flight IPC messages persist in SQLite WAL and recover across bus reboots."""
        ipc_db = Path(self.tmp_dir.name) / "durable_ipc.db"
        bus1 = MessageBus(db_path=ipc_db)
        bus1.register_mailbox("sender-agent")
        bus1.register_mailbox("target-agent")

        msg = IPCMessage(
            sender_pid="sender-agent",
            recipient_pid="target-agent",
            msg_type=IPCMessageType.TASK_DELEGATION,
            payload={"task_id": "job-101", "action": "compile_c_extension"}
        )

        # Send message through bus1, but do NOT receive it yet
        delivered = await bus1.send(msg)
        self.assertTrue(delivered)
        self.assertTrue(bus1.has_messages("target-agent"))

        # Simulate system shutdown / reboot by deleting bus1 and instantiating bus2 from the same SQLite DB
        del bus1
        gc.collect()

        bus2 = MessageBus(db_path=ipc_db)
        # Verify mailbox is not registered yet
        self.assertFalse(bus2.has_messages("target-agent"))

        # Registering the target mailbox automatically recovers unconsumed messages from WAL
        bus2.register_mailbox("target-agent")
        self.assertTrue(bus2.has_messages("target-agent"))

        # Dequeue the message in the new process session
        recovered_msg = await bus2.receive("target-agent", timeout=1.0)
        self.assertIsNotNone(recovered_msg)
        self.assertEqual(recovered_msg.sender_pid, "sender-agent")
        self.assertEqual(recovered_msg.payload["task_id"], "job-101")

        # Verify message is marked consumed and cannot be received again
        self.assertFalse(bus2.has_messages("target-agent"))

    # =========================================================================
    # EGAP-06: Storage Retention Pruning Daemon
    # =========================================================================
    async def test_egap06_flight_recorder_retention_pruning(self):
        """Test pruning of historical flight recorder traces older than retention threshold."""
        recorder = FlightRecorder(db_path=self.db_path)

        # 1. Insert a fresh trace (now)
        fresh_trace_id = "trace-fresh-001"
        recorder.record_model_call(
            trace_id=fresh_trace_id,
            step_seq=1,
            prompt=[{"role": "user", "content": "fresh task"}],
            response_content="done"
        )

        # 2. Insert an old trace with a simulated timestamp 30 days ago
        old_trace_id = "trace-stale-002"
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        import sqlite3
        with sqlite3.connect(recorder.db_path) as conn:
            conn.execute(
                "INSERT INTO flight_recorder_traces (id, trace_id, step_seq, record_type, prompt_hash, payload_json, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("rec-old-999", old_trace_id, 1, "model_call", None, json.dumps({"content": "old"}), old_time)
            )
            conn.commit()

        # Verify both traces are initially present
        traces_before = recorder.list_traces()
        trace_ids_before = {t["trace_id"] for t in traces_before}
        self.assertIn(fresh_trace_id, trace_ids_before)
        self.assertIn(old_trace_id, trace_ids_before)

        # 3. Prune traces older than 14 days
        pruned_count = recorder.prune_traces(retention_days=14)
        self.assertEqual(pruned_count, 1)

        # 4. Verify stale trace is gone, fresh trace remains
        traces_after = recorder.list_traces()
        trace_ids_after = {t["trace_id"] for t in traces_after}
        self.assertNotIn(old_trace_id, trace_ids_after)
        self.assertIn(fresh_trace_id, trace_ids_after)

if __name__ == "__main__":
    unittest.main()
