import asyncio
import unittest
from starlette.testclient import TestClient

from kernel.event_loop import Kernel
from kernel.process import PriorityLevel, ProcessState
from server.app import create_app
from config.settings import settings

class TestDaemonConcurrency(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying persistent multi-worker daemon loop and concurrent task execution."""

    async def test_daemon_multi_worker_concurrency(self):
        kernel = Kernel(provider_name="mock")
        # Start daemon workers
        tasks = kernel.start_daemon(num_workers=4)
        self.assertEqual(len(tasks), 4)

        # Enqueue multiple independent processes
        pids = []
        for i in range(4):
            pcb = kernel.spawn_process(
                name=f"worker_proc_{i}",
                task_instruction=f"Calculate sqrt({(i+1)*100})",
                priority=PriorityLevel.NORMAL
            )
            pids.append(pcb.pid)

        # Wait until all workers finish their assigned processes
        await kernel.run_until_idle()

        # All processes should be in COMPLETED state
        for pid in pids:
            proc = kernel.scheduler.get_process(pid)
            self.assertIsNotNone(proc)
            self.assertEqual(proc.state, ProcessState.COMPLETED)
            self.assertIsNotNone(proc.result)

        kernel.stop_daemon()

    async def test_dynamic_spawn_and_kill_endpoints(self):
        kernel = Kernel(provider_name="mock")
        kernel.start_daemon(num_workers=2)

        app = create_app(kernel)
        client = TestClient(app)

        # 1. Dynamically spawn process via REST
        res = client.post(
            "/api/processes/spawn",
            json={"name": "dynamic_agent", "task_instruction": "Calculate sqrt(64) + 10", "role": "coder"}
        )
        self.assertEqual(res.status_code, 200)
        pid = res.json()["pid"]

        # Wait for daemon workers to process it
        await kernel.run_until_idle()

        # 2. Inspect process details via GET /api/processes/{pid}
        res_detail = client.get(f"/api/processes/{pid}")
        self.assertEqual(res_detail.status_code, 200)
        data = res_detail.json()
        self.assertEqual(data["process"]["state"], ProcessState.COMPLETED.value)
        self.assertIn("messages", data)

        # 3. Test Kill action on a new long/running or ready process
        p_kill = kernel.spawn_process(
            name="process_to_kill",
            task_instruction="Calculate sqrt(100)",
            priority=PriorityLevel.BACKGROUND
        )
        # Terminate immediately via DELETE
        res_kill = client.delete(f"/api/processes/{p_kill.pid}")
        self.assertEqual(res_kill.status_code, 200)
        self.assertEqual(res_kill.json()["state"], "KILLED")

        updated_proc = kernel.scheduler.get_process(p_kill.pid)
        self.assertEqual(updated_proc.state, ProcessState.KILLED)

        kernel.stop_daemon()

if __name__ == "__main__":
    unittest.main()
