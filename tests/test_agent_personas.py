import asyncio
import unittest
from kernel.event_loop import Kernel
from kernel.process import PriorityLevel, ProcessControlBlock, ProcessState
from agents.planner import PlannerAgent
from agents.coder import CoderAgent
from agents.reviewer import ReviewerAgent
from agents.base_agent import BaseAgent

class TestAgentPersonas(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying specialized agent personas and role dispatching."""

    def test_planner_agent_initialization(self):
        pcb = ProcessControlBlock(name="lead_planner", priority=PriorityLevel.HIGH)
        planner = PlannerAgent(pcb=pcb)
        self.assertIn("Lead Planner Agent", planner.system_prompt)
        
        # Test subtask DAG registration
        sub = planner.register_subtask("task-1", "Design microservice architecture", dependencies=[])
        self.assertEqual(sub["id"], "task-1")
        self.assertEqual(sub["status"], "PENDING")
        self.assertEqual(len(planner.subtasks), 1)

    def test_coder_agent_initialization(self):
        pcb = ProcessControlBlock(name="algo_coder")
        coder = CoderAgent(pcb=pcb)
        self.assertIn("Coder Agent", coder.system_prompt)
        self.assertIn("sys_exec_python", coder.system_prompt)

    def test_reviewer_agent_initialization(self):
        pcb = ProcessControlBlock(name="security_auditor")
        reviewer = ReviewerAgent(pcb=pcb)
        self.assertIn("Reviewer and Auditor Agent", reviewer.system_prompt)
        verdict = reviewer.record_verdict("proc-test", True, "Artifact conforms to specifications.")
        self.assertEqual(verdict["target_pid"], "proc-test")
        self.assertTrue(verdict["approved"])
        self.assertEqual(len(reviewer.verdicts), 1)

    async def test_kernel_role_based_spawning(self):
        kernel = Kernel(provider_name="mock")
        
        # 1. Spawn planner via role
        p_planner = kernel.spawn_process(
            name="system_architect",
            task_instruction="Plan system components",
            role="planner"
        )
        agent_planner = kernel._active_agents[p_planner.pid]
        self.assertIsInstance(agent_planner, PlannerAgent)
        self.assertEqual(p_planner.role, "planner")

        # 2. Spawn coder via name heuristic
        p_coder = kernel.spawn_process(
            name="backend_coder",
            task_instruction="Write sorting algorithm"
        )
        agent_coder = kernel._active_agents[p_coder.pid]
        self.assertIsInstance(agent_coder, CoderAgent)
        self.assertEqual(p_coder.role, "coder")

        # 3. Spawn reviewer via role
        p_rev = kernel.spawn_process(
            name="qa_inspector",
            task_instruction="Review code output",
            role="reviewer"
        )
        agent_rev = kernel._active_agents[p_rev.pid]
        self.assertIsInstance(agent_rev, ReviewerAgent)
        self.assertEqual(p_rev.role, "reviewer")

        # 4. Spawn standard base agent
        p_base = kernel.spawn_process(
            name="general_helper",
            task_instruction="Help user"
        )
        agent_base = kernel._active_agents[p_base.pid]
        self.assertIsInstance(agent_base, BaseAgent)
        self.assertEqual(p_base.role, "base")

        # Execute all to completion
        await kernel.run_until_idle()
        self.assertEqual(kernel.scheduler.get_process(p_planner.pid).state, ProcessState.COMPLETED)
        self.assertEqual(kernel.scheduler.get_process(p_coder.pid).state, ProcessState.COMPLETED)
        self.assertEqual(kernel.scheduler.get_process(p_rev.pid).state, ProcessState.COMPLETED)

if __name__ == "__main__":
    unittest.main()
