import asyncio
import gc
import json
from pathlib import Path
import tempfile
import unittest

from config.settings import settings
from kernel.event_loop import Kernel
from kernel.flight_recorder import FlightRecorder
from kernel.replay import TraceReplayEngine, ReplayReport

class TestDeterministicReplay(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_aios.db"
        self.kernel = Kernel(provider_name="mock", db_path=self.db_path)
        self.flight_recorder = self.kernel.flight_recorder
        self.replay_engine = self.kernel.replay_engine

    async def asyncTearDown(self):
        self.kernel.shutdown()
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_replay_full_agent_multi_step_trace(self):
        """Verify an end-to-end multi-step agent run produces an exact 100% reproducible offline replay."""
        pcb = self.kernel.spawn_process(
            name="math_solver",
            task_instruction="Compute sqrt(144)",
            allocated_tools=["sys_calc"]
        )
        await self.kernel.run_until_idle()

        trace_records = self.flight_recorder.get_trace(pcb.trace_id)
        self.assertGreater(len(trace_records), 0)

        # 1. Async replay test
        report_async: ReplayReport = await self.replay_engine.replay_trace_async(pcb.trace_id)
        self.assertTrue(report_async.is_reproducible)
        self.assertEqual(report_async.total_records, len(trace_records))
        self.assertIsNone(report_async.error)
        self.assertIsNone(report_async.divergence_step)
        self.assertTrue(all(s.matched for s in report_async.steps))

        # 2. Synchronous wrapper test (inside running loop)
        report_sync: ReplayReport = self.replay_engine.replay_trace(pcb.trace_id)
        self.assertTrue(report_sync.is_reproducible)
        self.assertEqual(report_sync.total_records, len(trace_records))
        self.assertTrue(all(s.matched for s in report_sync.steps))

    async def test_replay_detects_prompt_tampering(self):
        """Verify divergence detection when prompt_hash or prompt content is altered."""
        pcb = self.kernel.spawn_process(
            name="math_solver",
            task_instruction="Compute sqrt(64)",
            allocated_tools=["sys_calc"]
        )
        await self.kernel.run_until_idle()

        # Tamper with the prompt_hash in SQLite
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE flight_recorder_traces SET prompt_hash = 'tampered_hash_00' "
                "WHERE trace_id = ? AND record_type = 'model_call'",
                (pcb.trace_id,)
            )
            conn.commit()

        report = await self.replay_engine.replay_trace_async(pcb.trace_id)
        self.assertFalse(report.is_reproducible)
        self.assertIsNotNone(report.divergence_step)
        self.assertIn("Integrity check failed", report.error)

    async def test_replay_detects_syscall_argument_mismatch(self):
        """Verify divergence detection when a syscall's recorded arguments do not match simulation expectations."""
        pcb = self.kernel.spawn_process(
            name="math_solver",
            task_instruction="Calculate sqrt(81)",
            allocated_tools=["sys_calc"]
        )
        await self.kernel.run_until_idle()

        # Tamper with recorded syscall arguments in SQLite
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "SELECT id, payload_json FROM flight_recorder_traces "
                "WHERE trace_id = ? AND record_type = 'syscall'",
                (pcb.trace_id,)
            )
            row = cur.fetchone()
            self.assertIsNotNone(row)
            rec_id, payload_str = row[0], row[1]
            payload = json.loads(payload_str)
            payload["input_kwargs"] = {"expression": "tampered_expression_different()"}
            conn.execute(
                "UPDATE flight_recorder_traces SET payload_json = ? WHERE id = ?",
                (json.dumps(payload), rec_id)
            )
            conn.commit()

        report = await self.replay_engine.replay_trace_async(pcb.trace_id)
        self.assertFalse(report.is_reproducible)
        self.assertIsNotNone(report.divergence_step)
        self.assertIn("Syscall argument mismatch", report.error)

    async def test_replay_zero_side_effects(self):
        """Verify that offline replay executes without triggering live syscall side-effects."""
        test_file = Path(self.tmp_dir.name) / "canary_file.txt"
        test_file.write_text("initial content", encoding="utf-8")

        # Record an artificial trace containing a destructive SysFsDelete
        trace_id = "trace-side-effect-test"
        tool_call_dict = {"id": "c1", "name": "sys_fs_delete", "arguments": {"filepath": str(test_file)}}
        step1_prompt = [{"role": "user", "content": "Delete canary file"}]
        step2_prompt = [
            {"role": "user", "content": "Delete canary file"},
            {"role": "assistant", "content": "Deleting file", "tool_calls": [tool_call_dict]},
            {"role": "tool", "content": json.dumps({"deleted": True}), "tool_call_id": "c1", "name": "sys_fs_delete"}
        ]

        self.flight_recorder.record_model_call(
            trace_id=trace_id,
            step_seq=1,
            prompt=step1_prompt,
            response_content="Deleting file",
            tool_calls=[tool_call_dict]
        )
        self.flight_recorder.record_syscall(
            trace_id=trace_id,
            step_seq=1,
            syscall_name="sys_fs_delete",
            input_kwargs={"filepath": str(test_file)},
            success=True,
            data={"deleted": True}
        )
        self.flight_recorder.record_model_call(
            trace_id=trace_id,
            step_seq=2,
            prompt=step2_prompt,
            response_content="File successfully deleted.",
            tool_calls=[]
        )

        # Replay the trace offline
        report = await self.replay_engine.replay_trace_async(trace_id)
        self.assertTrue(report.is_reproducible)

        # Verify side effect isolation: canary_file.txt MUST still exist on disk!
        self.assertTrue(test_file.exists(), "Replay must NOT execute real destructive syscalls!")
        self.assertEqual(test_file.read_text(encoding="utf-8"), "initial content")

    async def test_replay_non_existent_trace(self):
        """Verify behavior when replaying a trace ID that does not exist."""
        report = await self.replay_engine.replay_trace_async("trace-non-existent-999")
        self.assertFalse(report.is_reproducible)
        self.assertEqual(report.total_records, 0)
        self.assertIn("No trace records found", report.error)

    async def test_server_endpoint_deterministic_replay(self):
        """Verify the FastAPI GET /api/replay/traces/{trace_id} returns reproducible replay report."""
        from starlette.testclient import TestClient
        from server.app import create_app

        pcb = self.kernel.spawn_process(
            name="math_solver",
            task_instruction="Calculate sqrt(144)",
            allocated_tools=["sys_calc"]
        )
        await self.kernel.run_until_idle()

        app = create_app(self.kernel)
        client = TestClient(app)

        res = client.get(f"/api/replay/traces/{pcb.trace_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["trace_id"], pcb.trace_id)
        self.assertTrue(data["is_reproducible"])
        self.assertIsNone(data["error"])
        self.assertGreater(data["total_records"], 0)

if __name__ == "__main__":
    unittest.main()
