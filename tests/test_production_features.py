import asyncio
import os
import unittest
from pathlib import Path
from starlette.testclient import TestClient

from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from kernel.checkpoint import CheckpointManager
from kernel.event_loop import Kernel
from memory.l1_context import L1ContextManager
from models.router import AdaptiveModelRouter, ModelTier
from server.app import create_app

class TestProductionFeatures(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.test_db = Path("./test_checkpoint_prod.db")
        self.checkpoint_mgr = CheckpointManager(db_path=self.test_db)
        self.checkpoint_mgr.clear_all()

    def tearDown(self):
        self.checkpoint_mgr.clear_all()
        if self.test_db.exists():
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def test_checkpoint_save_and_load(self):
        pcb = ProcessControlBlock(name="crash_test_proc", token_budget=20000)
        pcb.transition_to(ProcessState.RUNNING)
        pcb.consume_tokens(500)

        l1 = L1ContextManager(system_prompt="System Prompt Test", max_capacity_tokens=4000)
        l1.add_message("user", "Perform step 1 of data audit")

        # Save snapshot
        self.checkpoint_mgr.save_snapshot(pcb, l1)

        # Load back
        snapshots = self.checkpoint_mgr.load_uncompleted_snapshots()
        self.assertEqual(len(snapshots), 1)
        loaded_pcb, loaded_l1 = snapshots[0]

        self.assertEqual(loaded_pcb.pid, pcb.pid)
        self.assertEqual(loaded_pcb.name, "crash_test_proc")
        self.assertEqual(loaded_pcb.tokens_consumed, 500)
        self.assertEqual(len(loaded_l1["messages"]), 1)

    async def test_kernel_recovery_cycle(self):
        kernel = Kernel(provider_name="mock")
        kernel.checkpoint_mgr = self.checkpoint_mgr

        # Manually seed an interrupted process in the checkpoint store
        pcb = ProcessControlBlock(name="interrupted_worker", token_budget=10000)
        pcb.transition_to(ProcessState.READY)
        l1 = L1ContextManager(system_prompt="Test", max_capacity_tokens=2000)
        l1.add_message("user", "Calculate sqrt(144) + 50")
        self.checkpoint_mgr.save_snapshot(pcb, l1)

        # Ensure scheduler has no processes yet
        self.assertEqual(len(kernel.scheduler.list_processes()), 0)

        # Perform recovery
        recovered_count = kernel.recover_interrupted_processes()
        self.assertEqual(recovered_count, 1)
        self.assertIn(pcb.pid, kernel.scheduler.list_processes())

        # Execute recovered process until completion
        await kernel.run_until_idle()
        completed_pcb = kernel.scheduler.get_process(pcb.pid)
        self.assertEqual(completed_pcb.state, ProcessState.COMPLETED)

    def test_adaptive_model_router_tiering(self):
        router = AdaptiveModelRouter()

        # High priority planner process -> REASONING tier
        planner_pcb = ProcessControlBlock(name="lead_planner", priority=PriorityLevel.HIGH)
        self.assertEqual(router.get_tier_for_process(planner_pcb), ModelTier.REASONING)

        # Normal worker process -> FAST tier
        worker_pcb = ProcessControlBlock(name="data_extractor", priority=PriorityLevel.NORMAL)
        self.assertEqual(router.get_tier_for_process(worker_pcb), ModelTier.FAST)

    def test_websocket_stream_endpoint(self):
        kernel = Kernel(provider_name="mock")
        app = create_app(kernel)
        client = TestClient(app)

        with client.websocket_connect("/ws/stream") as websocket:
            websocket.send_text("ping")
            data = websocket.receive_json()
            self.assertEqual(data["type"], "pong")

if __name__ == "__main__":
    unittest.main()
