import asyncio
import unittest
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from kernel.governor import ResourceGovernor, ForkBombPrevented
from kernel.event_loop import Kernel
from ipc.message import IPCMessage, IPCMessageType
from ipc.bus import MessageBus
from ipc.blackboard import SharedBlackboard
from syscalls.process import SysProcSpawn, SysProcSendMsg, SysProcRecvMsg, SysProcWait, SysBlackboardWrite, SysBlackboardRead

class TestAIOSIPC(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.bus = MessageBus()
        self.bus.clear()
        self.blackboard = SharedBlackboard()
        self.governor = ResourceGovernor(max_process_depth=2, max_children_per_parent=3)

    async def test_ipc_point_to_point(self):
        self.bus.register_mailbox("pid-agent-1")
        self.bus.register_mailbox("pid-agent-2")

        msg = IPCMessage(
            sender_pid="pid-agent-1",
            recipient_pid="pid-agent-2",
            msg_type=IPCMessageType.TASK_DELEGATION,
            payload={"task": "analyze_logs", "lines": 50}
        )

        delivered = await self.bus.send(msg)
        self.assertTrue(delivered)
        self.assertTrue(self.bus.has_messages("pid-agent-2"))
        self.assertFalse(self.bus.has_messages("pid-agent-1"))

        received = await self.bus.receive("pid-agent-2", timeout=1.0)
        self.assertIsNotNone(received)
        self.assertEqual(received.sender_pid, "pid-agent-1")
        self.assertEqual(received.payload["task"], "analyze_logs")

    async def test_ipc_broadcast(self):
        self.bus.register_mailbox("pid-worker-1")
        self.bus.register_mailbox("pid-worker-2")
        self.bus.register_mailbox("pid-worker-3")

        bcast = IPCMessage(
            sender_pid="pid-leader",
            recipient_pid="*",
            msg_type=IPCMessageType.BROADCAST,
            payload={"announcement": "System entering standby in 5 minutes"}
        )

        sent = await self.bus.send(bcast)
        self.assertTrue(sent)
        self.assertTrue(self.bus.has_messages("pid-worker-1"))
        self.assertTrue(self.bus.has_messages("pid-worker-2"))
        self.assertTrue(self.bus.has_messages("pid-worker-3"))

    def test_shared_blackboard(self):
        updates_received = []

        def on_update(topic, key, value, author):
            updates_received.append((topic, key, value, author))

        self.blackboard.subscribe("system_health", on_update)
        self.blackboard.write("system_health", "cpu_load", 0.42, author_pid="monitor-1")

        self.assertEqual(len(updates_received), 1)
        self.assertEqual(updates_received[0], ("system_health", "cpu_load", 0.42, "monitor-1"))

        # Read back
        val = self.blackboard.read("system_health", "cpu_load")
        self.assertEqual(val, 0.42)

    def test_governor_fork_bomb_depth(self):
        pcb_root = ProcessControlBlock(name="root", depth=0)
        self.governor.check_spawn_permission(pcb_root)

        pcb_level1 = ProcessControlBlock(name="level1", depth=1)
        self.governor.check_spawn_permission(pcb_level1)

        # depth 2 is the maximum permitted depth
        pcb_level2 = ProcessControlBlock(name="level2", depth=2)
        with self.assertRaises(ForkBombPrevented):
            self.governor.check_spawn_permission(pcb_level2)

    def test_governor_max_children(self):
        pcb = ProcessControlBlock(name="parent", child_pids=["c1", "c2", "c3"])
        with self.assertRaises(ForkBombPrevented):
            self.governor.check_spawn_permission(pcb)

    async def test_parent_child_spawn_and_wait_cycle(self):
        kernel = Kernel(provider_name="mock")
        
        # Spawn parent
        parent = kernel.spawn_process(
            name="lead_coordinator",
            task_instruction="Coordinate child execution",
            priority=PriorityLevel.HIGH
        )

        # Spawn child under parent
        child = kernel.spawn_process(
            name="worker_child",
            task_instruction="Calculate sqrt(144) + 20",
            priority=PriorityLevel.NORMAL,
            parent_pid=parent.pid
        )

        self.assertEqual(child.depth, 1)
        self.assertEqual(child.parent_pid, parent.pid)

        # Run kernel until all idle
        await kernel.run_until_idle()

        # Check that both reached terminal state
        c_proc = kernel.scheduler.get_process(child.pid)
        p_proc = kernel.scheduler.get_process(parent.pid)
        self.assertEqual(c_proc.state, ProcessState.COMPLETED)
        self.assertEqual(p_proc.state, ProcessState.COMPLETED)

if __name__ == "__main__":
    unittest.main()
