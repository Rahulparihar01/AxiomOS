import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from kernel.cost_estimator import CostEstimator
from kernel.event_loop import Kernel
from kernel.flight_recorder import FlightRecorder
from kernel.process import PriorityLevel, ProcessControlBlock, ProcessState
from kernel.replay import TraceReplayEngine
from memory.l4_archival import L4ArchivalStore
from security.capability import CapabilityIssuer, CapabilityToken
from syscalls import SyscallRegistry

class TestV2Features(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_v2.db"
        self.kernel = Kernel(provider_name="mock", auto_approve_hitl=True, db_path=self.db_path)

    async def asyncTearDown(self):
        self.kernel.shutdown()
        import gc
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_versioned_facts_and_conflict_flag(self):
        """Verify L4 versioned writes, contradiction detection, and MEMORY_CONFLICT broadcast."""
        l4 = self.kernel.mmu.l4_archival
        
        # 1. First write: initial fact
        rec1, conflict1 = l4.store_versioned_fact(
            key="cloud.provider",
            value="aws",
            written_by_pid="agent-1",
            confidence=0.9
        )
        self.assertEqual(rec1.version, 1)
        self.assertFalse(conflict1)
        self.assertFalse(rec1.conflict_flag)

        # 2. Second write: contradictory fact from another agent with lower/equal confidence
        rec2, conflict2 = l4.store_versioned_fact(
            key="cloud.provider",
            value="gcp",
            written_by_pid="agent-2",
            confidence=0.7
        )
        self.assertEqual(rec2.version, 2)
        self.assertTrue(conflict2)
        self.assertTrue(rec2.conflict_flag)
        self.assertEqual(rec2.superseded_fact_id, rec1.fact_id)

        # 3. Check history retains both versions (no silent data loss)
        history = l4.get_fact_history("cloud.provider")
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].value, "aws")
        self.assertEqual(history[1].value, "gcp")

        # 4. Verify SysMemStore triggers conflict alert
        pcb = self.kernel.spawn_process("test_worker", "store conflict memory")
        result = await self.kernel.syscalls.dispatch(
            pcb,
            "sys_mem_store",
            key="cloud.provider",
            value="azure",
            confidence=0.5
        )
        self.assertTrue(result.success)
        self.assertTrue(result.data["conflict_flag"])
        self.assertEqual(result.data["status"], "persisted_with_conflict")

    async def test_cost_estimator_and_admission_downgrade(self):
        """Verify historical task profiling and scheduler proactive admission downgrade."""
        l4 = self.kernel.mmu.l4_archival
        
        # Seed historical heavy tasks for "coder" role
        for i in range(5):
            l4.log_task_cost(
                role="coder",
                instruction=f"Build and compile large microservice module number {i}",
                tokens_consumed=85000,
                wall_time_seconds=12.5
            )

        estimator = CostEstimator(l4_store=l4)
        estimate = estimator.estimate("coder", "Build and compile large microservice module number 99")

        self.assertGreaterEqual(estimate.sample_size, 5)
        self.assertGreaterEqual(estimate.predicted_tokens_p90, 70000)
        self.assertGreater(estimate.confidence, 0.4)

        # Spawn task with token budget lower than predicted p90
        pcb = self.kernel.spawn_process(
            name="heavy_coder",
            task_instruction="Build and compile large microservice module number 99",
            priority=PriorityLevel.HIGH,
            token_budget=20000, # Much smaller than predicted 85,000 tokens
            role="coder"
        )

        # Admission control should proactively downgrade priority to BACKGROUND
        self.assertEqual(pcb.priority, PriorityLevel.BACKGROUND)
        self.assertEqual(pcb.predicted_tokens_p90, estimate.predicted_tokens_p90)

    async def test_capability_token_path_and_ttl_enforcement(self):
        """Verify CapabilityToken (VULN-06) path globs, syscall restrictions, and TTL expiry."""
        pcb = self.kernel.spawn_process(
            name="restricted_worker",
            task_instruction="Execute restricted commands",
            scope_paths=["sandbox/scratch/**"],
            allocated_tools=["sys_calc", "sys_fs_read"],
            ttl_seconds=120
        )
        token: CapabilityToken = pcb.capability_token
        self.assertIsNotNone(token)
        self.assertFalse(token.is_expired())

        # Path scoping test
        self.assertTrue(token.can_access_path("sandbox/scratch/temp.txt"))
        self.assertFalse(token.can_access_path("config/secrets.env"))

        # Syscall check test
        self.assertTrue(token.can_call_syscall("sys_calc"))
        self.assertFalse(token.can_call_syscall("sys_exec_python"))

        # Test syscall dispatch enforcement: allowed syscall
        calc_res = await self.kernel.syscalls.dispatch(pcb, "sys_calc", expression="25 * 4")
        self.assertTrue(calc_res.success)
        self.assertEqual(calc_res.data["result"], 100)

        # Test syscall dispatch enforcement: unauthorized syscall
        unauth_res = await self.kernel.syscalls.dispatch(pcb, "sys_fs_write", filepath="sandbox/scratch/temp.txt", content="hi")
        self.assertFalse(unauth_res.success)
        self.assertIn("Capability Denied", unauth_res.error)

        # Test TTL expiration
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.assertTrue(token.is_expired())
        expired_res = await self.kernel.syscalls.dispatch(pcb, "sys_calc", expression="1 + 1")
        self.assertFalse(expired_res.success)
        self.assertIn("Capability Denied: Capability token for PID", expired_res.error)

    async def test_deterministic_replay_flight_recorder(self):
        """Verify flight recorder trace logging and offline replay reproduction."""
        recorder = self.kernel.flight_recorder

        # Run an agent process to completion
        pcb = self.kernel.spawn_process(
            name="math_solver",
            task_instruction="Compute sqrt(100)",
            allocated_tools=["sys_calc"]
        )

        await self.kernel.run_until_idle()

        # Verify trace was persisted
        trace_records = recorder.get_trace(pcb.trace_id)
        self.assertGreater(len(trace_records), 0)

        # Verify trace appears in list_traces
        trace_list = recorder.list_traces()
        self.assertTrue(any(t["trace_id"] == pcb.trace_id for t in trace_list))

        # Replay the trace using TraceReplayEngine
        replay_engine = TraceReplayEngine(flight_recorder=recorder)
        report = replay_engine.replay_trace(pcb.trace_id)

        self.assertTrue(report.is_reproducible)
        self.assertEqual(report.total_records, len(trace_records))
        self.assertGreater(len(report.steps), 0)
        self.assertTrue(all(step.matched for step in report.steps))

if __name__ == "__main__":
    unittest.main()
