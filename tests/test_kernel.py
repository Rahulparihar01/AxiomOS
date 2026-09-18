import asyncio
import unittest
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from kernel.governor import ResourceGovernor, StepLimitExceeded, TokenQuotaExceeded, UnauthorizedToolAccess
from kernel.scheduler import TaskScheduler
from kernel.event_loop import Kernel
from syscalls import SyscallRegistry
from syscalls.standard import SysCalc, SysFsRead

class TestAIOSKernel(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.governor = ResourceGovernor()
        self.scheduler = TaskScheduler()
        self.syscalls = SyscallRegistry()

    def test_pcb_lifecycle(self):
        pcb = ProcessControlBlock(name="unit_test_proc", token_budget=1000)
        self.assertEqual(pcb.state, ProcessState.CREATED)
        self.assertEqual(pcb.tokens_consumed, 0)
        self.assertEqual(pcb.current_step, 0)

        pcb.transition_to(ProcessState.READY)
        self.assertEqual(pcb.state, ProcessState.READY)

        pcb.increment_step()
        self.assertEqual(pcb.current_step, 1)

        pcb.consume_tokens(250)
        self.assertEqual(pcb.tokens_consumed, 250)

        pcb.transition_to(ProcessState.COMPLETED)
        self.assertEqual(pcb.state, ProcessState.COMPLETED)
        self.assertEqual(pcb.exit_code, 0)

    def test_governor_step_limit(self):
        pcb = ProcessControlBlock(name="loop_proc", max_steps=2)
        pcb.current_step = 2
        with self.assertRaises(StepLimitExceeded):
            self.governor.check_pre_step(pcb)
        self.assertEqual(pcb.state, ProcessState.FAILED)

    def test_governor_unauthorized_tool(self):
        pcb = ProcessControlBlock(name="restricted_proc", allocated_tools=["sys_calc"])
        # Authorized
        self.governor.check_tool_permission(pcb, "sys_calc")
        # Unauthorized
        with self.assertRaises(UnauthorizedToolAccess):
            self.governor.check_tool_permission(pcb, "sys_fs_delete")
        self.assertEqual(pcb.state, ProcessState.FAILED)

    async def test_scheduler_priority_ordering(self):
        p_bg = ProcessControlBlock(name="bg_proc", priority=PriorityLevel.BACKGROUND)
        p_norm = ProcessControlBlock(name="norm_proc", priority=PriorityLevel.NORMAL)
        p_high = ProcessControlBlock(name="high_proc", priority=PriorityLevel.HIGH)

        # Enqueue in reverse priority order
        self.scheduler.enqueue(p_bg)
        self.scheduler.enqueue(p_norm)
        self.scheduler.enqueue(p_high)

        # Dequeued order should be HIGH -> NORMAL -> BACKGROUND
        first = await self.scheduler.get_next_process()
        second = await self.scheduler.get_next_process()
        third = await self.scheduler.get_next_process()

        self.assertEqual(first.name, "high_proc")
        self.assertEqual(second.name, "norm_proc")
        self.assertEqual(third.name, "bg_proc")

    async def test_sys_calc(self):
        calc = SysCalc()
        pcb = ProcessControlBlock(name="math_proc")
        
        # Valid math expression
        res = await calc.execute(pcb, expression="2 * 10 + sqrt(100)")
        self.assertTrue(res.success)
        self.assertEqual(res.data["result"], 30.0)

        # Injection attempt
        malicious = await calc.execute(pcb, expression="__import__('os').system('dir')")
        self.assertFalse(malicious.success)

    async def test_sys_fs_sandbox(self):
        fs = SysFsRead()
        pcb = ProcessControlBlock(name="fs_proc")
        
        # Valid file
        valid = await fs.execute(pcb, filepath="requirements.txt")
        self.assertTrue(valid.success)
        self.assertIn("pydantic", valid.data["content"])

        # Directory traversal attempt
        traversal = await fs.execute(pcb, filepath="../../Windows/System32/drivers/etc/hosts")
        self.assertFalse(traversal.success)
        self.assertIn("Permission Denied", traversal.error)

    async def test_kernel_end_to_end(self):
        kernel = Kernel(provider_name="mock")
        p = kernel.spawn_process(
            name="integration_proc",
            task_instruction="Calculate sqrt(144) + 10",
            priority=PriorityLevel.HIGH,
            token_budget=10000,
            max_steps=5
        )

        await kernel.run_until_idle()

        updated_pcb = kernel.scheduler.get_process(p.pid)
        self.assertIsNotNone(updated_pcb)
        self.assertEqual(updated_pcb.state, ProcessState.COMPLETED)
        self.assertGreater(updated_pcb.tokens_consumed, 0)
        self.assertIsNotNone(updated_pcb.result)

if __name__ == "__main__":
    unittest.main()
