import asyncio
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from ipc.blackboard import SharedBlackboard
from ipc.bus import MessageBus
from ipc.message import IPCMessage, IPCMessageType
from kernel.checkpoint import CheckpointManager
from kernel.flight_recorder import FlightRecorder
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from memory.l1_context import L1ContextManager
from memory.l4_archival import L4ArchivalStore

class TestAsyncStorageConcurrency(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_concurrency.db"

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    async def test_event_loop_responsiveness_during_heavy_concurrent_sqlite_io(self):
        """
        GAP-10 Verification: Prove the asyncio event loop remains responsive and does not
        freeze while high volumes of concurrent SQLite WAL writes are taking place across
        L4 Archival, CheckpointManager, FlightRecorder, MessageBus, and SharedBlackboard.
        """
        l4 = L4ArchivalStore(db_path=self.db_path)
        ckpt = CheckpointManager(db_path=self.db_path)
        recorder = FlightRecorder(db_path=self.db_path)
        bus = MessageBus(db_path=self.db_path)
        bb = SharedBlackboard(db_path=self.db_path)

        bus.register_mailbox("agent-worker-1")
        bus.register_mailbox("agent-worker-2")

        heartbeat_ticks = 0
        stop_heartbeat = asyncio.Event()

        async def heartbeat():
            nonlocal heartbeat_ticks
            while not stop_heartbeat.is_set():
                heartbeat_ticks += 1
                await asyncio.sleep(0.005)

        heartbeat_task = asyncio.create_task(heartbeat())

        # Launch multiple concurrent async operations across all subsystems
        async def l4_worker(idx: int):
            for j in range(10):
                await l4.add(
                    content=f"Telemetry report chunk {idx}-{j} with large text context " * 5,
                    metadata={"batch": idx, "seq": j}
                )
                await l4.store_fact_async(key=f"fact_{idx}_{j}", value=f"val_{idx}_{j}")

        async def checkpoint_worker(idx: int):
            for j in range(10):
                pcb = ProcessControlBlock(
                    pid=f"proc-{idx}-{j}",
                    name=f"task-{idx}",
                    priority=PriorityLevel.NORMAL
                )
                l1 = L1ContextManager(system_prompt="system test")
                l1.add_message("user", f"Hello from worker {idx} step {j}")
                await ckpt.save_snapshot_async(pcb, l1)

        async def flight_worker(idx: int):
            for j in range(10):
                await recorder.record_model_call_async(
                    trace_id=f"trace-{idx}",
                    step_seq=j,
                    prompt={"role": "user", "content": f"query {idx} {j}"},
                    response_content=f"answer {idx} {j}"
                )

        async def bus_worker(idx: int):
            for j in range(10):
                msg = IPCMessage(
                    sender_pid=f"worker-{idx}",
                    recipient_pid="agent-worker-1",
                    msg_type=IPCMessageType.DIRECT_MESSAGE,
                    payload={"step": j, "data": "payload content"}
                )
                await bus.send(msg)

        async def blackboard_worker(idx: int):
            for j in range(10):
                await bb.write_async(
                    topic=f"topic_{idx}",
                    key=f"key_{j}",
                    value={"counter": j, "author": f"proc_{idx}"},
                    author_pid=f"proc_{idx}"
                )

        workers = [
            l4_worker(1),
            l4_worker(2),
            checkpoint_worker(1),
            checkpoint_worker(2),
            flight_worker(1),
            bus_worker(1),
            blackboard_worker(1)
        ]

        await asyncio.gather(*workers)

        stop_heartbeat.set()
        await heartbeat_task

        # Verify heartbeat ticked significantly during execution
        self.assertGreater(heartbeat_ticks, 10, "Event loop heartbeat was starved or frozen during SQLite I/O!")

        # Verify records exist in database
        recovered_ckpts = await ckpt.load_uncompleted_snapshots_async()
        self.assertEqual(len(recovered_ckpts), 20)

        fact_val = await l4.get_fact_async("fact_1_0")
        self.assertEqual(fact_val, "val_1_0")

        trace_records = await recorder.get_trace_async("trace-1")
        self.assertEqual(len(trace_records), 10)

        bb_val = bb.read("topic_1", "key_0")
        self.assertEqual(bb_val["counter"], 0)

    async def test_checkpoint_async_snapshot_and_load(self):
        """Verify non-blocking checkpoint snapshot save, load, delete, and clear."""
        ckpt = CheckpointManager(db_path=self.db_path)
        pcb = ProcessControlBlock(pid="p-async-1", name="async-task", priority=PriorityLevel.HIGH)
        l1 = L1ContextManager(system_prompt="async test prompt")
        l1.add_message("user", "first message")

        await ckpt.save_snapshot_async(pcb, l1)

        snapshots = await ckpt.load_uncompleted_snapshots_async()
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0][0].pid, "p-async-1")
        self.assertEqual(snapshots[0][1]["system_prompt"], "async test prompt")

        await ckpt.delete_snapshot_async("p-async-1")
        snapshots_after_delete = await ckpt.load_uncompleted_snapshots_async()
        self.assertEqual(len(snapshots_after_delete), 0)

        # Clear all
        await ckpt.save_snapshot_async(pcb, l1)
        await ckpt.clear_all_async()
        snapshots_after_clear = await ckpt.load_uncompleted_snapshots_async()
        self.assertEqual(len(snapshots_after_clear), 0)

    async def test_flight_recorder_async_recording_and_retrieval(self):
        """Verify non-blocking flight recorder recording, retrieval, and pruning."""
        recorder = FlightRecorder(db_path=self.db_path)

        rec_id1 = await recorder.record_model_call_async(
            trace_id="tr-100",
            step_seq=1,
            prompt="Compute Pi",
            response_content="3.14159"
        )
        self.assertTrue(rec_id1.startswith("rec-"))

        rec_id2 = await recorder.record_syscall_async(
            trace_id="tr-100",
            step_seq=2,
            syscall_name="sys_write_file",
            input_kwargs={"filename": "pi.txt"},
            success=True,
            data={"bytes": 7}
        )
        self.assertTrue(rec_id2.startswith("rec-"))

        trace = await recorder.get_trace_async("tr-100")
        self.assertEqual(len(trace), 2)
        self.assertEqual(trace[0].record_type, "model_call")
        self.assertEqual(trace[1].record_type, "syscall")

        traces_list = await recorder.list_traces_async()
        self.assertEqual(len(traces_list), 1)
        self.assertEqual(traces_list[0]["trace_id"], "tr-100")

        await recorder.clear_async()
        self.assertEqual(len(await recorder.get_trace_async("tr-100")), 0)

    async def test_l4_archival_async_fact_and_cost_logging(self):
        """Verify non-blocking L4 archival fact versioning, conflict resolution, and cost logging."""
        l4 = L4ArchivalStore(db_path=self.db_path)

        # Versioned facts and conflict detection
        rec1, conflict1 = await l4.store_versioned_fact_async(
            key="server_ip",
            value="192.168.1.100",
            written_by_pid="agent-init",
            confidence=1.0
        )
        self.assertFalse(conflict1)
        self.assertEqual(rec1.version, 1)

        rec2, conflict2 = await l4.store_versioned_fact_async(
            key="server_ip",
            value="10.0.0.1",
            written_by_pid="agent-scout",
            confidence=0.7
        )
        self.assertTrue(conflict2)
        self.assertEqual(rec2.version, 2)

        conflicts = await l4.list_conflicts_async()
        self.assertEqual(len(conflicts), 1)

        # Asynchronous resolution
        resolved = await l4.resolve_conflict_async(
            key="server_ip",
            authoritative_value="10.0.0.1",
            resolved_by_pid="resolver-proc",
            reasoning="Scout confirmed new subnet"
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.value, "10.0.0.1")

        conflicts_after = await l4.list_conflicts_async()
        self.assertEqual(len(conflicts_after), 0)

        # Task cost logging
        cost_id = await l4.log_task_cost_async(
            role="coder",
            instruction="Implement quicksort",
            tokens_consumed=450,
            wall_time_seconds=1.25
        )
        self.assertTrue(cost_id.startswith("cost-"))

        history = await l4.get_task_cost_history_async(role="coder")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["tokens_consumed"], 450)

    async def test_blackboard_async_mutations(self):
        """Verify blackboard async write, delete, and clear operations."""
        bb = SharedBlackboard(db_path=self.db_path)

        await bb.write_async("alpha", "key1", 100, author_pid="proc-1")
        await bb.write_async("alpha", "key2", 200, author_pid="proc-2")
        await bb.write_async("beta", "key3", 300, author_pid="proc-3")

        self.assertEqual(bb.read("alpha", "key1"), 100)
        self.assertEqual(bb.read("beta", "key3"), 300)

        deleted = await bb.delete_entry_async("alpha", "key1")
        self.assertTrue(deleted)
        self.assertIsNone(bb.read("alpha", "key1"))
        self.assertEqual(bb.read("alpha", "key2"), 200)

        await bb.clear_async("alpha")
        self.assertNotIn("alpha", bb.list_topics())
        self.assertIn("beta", bb.list_topics())

        await bb.clear_async()
        self.assertEqual(len(bb.list_topics()), 0)

if __name__ == "__main__":
    unittest.main()
