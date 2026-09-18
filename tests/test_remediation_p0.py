import asyncio
import unittest
from pathlib import Path
import tempfile
import uuid

from kernel.event_loop import Kernel
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from memory.mmu import MemoryManagementUnit
from memory.l4_archival import L4ArchivalStore
from agents.planner import PlannerAgent
from agents.coder import CoderAgent
from agents.reviewer import ReviewerAgent
from agents.researcher import ResearchAgent
from agents.conflict_resolver import ConflictResolverAgent
from syscalls.persona import (
    SysPlanRegisterSubtask,
    SysAuditRecordVerdict,
    SysCodeRecordArtifact,
    SysResearchRecordFinding,
    SysConflictRecordResolution
)
from syscalls.process import SysProcKill

class TestRemediationP0(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying fixes for GAP-01, GAP-02, GAP-03, GAP-04, and GAP-06."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_p0_kernel.db"
        self.kernel = Kernel(provider_name="mock", db_path=self.db_path)

    async def asyncTearDown(self):
        self.kernel.shutdown()
        import gc
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass


    # --- GAP-03: Process Name vs. PID Bug in child_pids ---
    async def test_gap03_child_pids_contains_actual_pids_not_names(self):
        parent_proc = self.kernel.spawn_process(
            name="lead_coordinator",
            task_instruction="Coordinate child workers"
        )
        child_proc = self.kernel.spawn_process(
            name="sub_worker_alpha",
            task_instruction="Execute worker task",
            parent_pid=parent_proc.pid
        )

        # Verify child_pids contains the child's PID (UUID), not its human name
        self.assertIn(child_proc.pid, parent_proc.child_pids)
        self.assertNotIn("sub_worker_alpha", parent_proc.child_pids)
        
        # Verify scheduler lookup works using child_pids
        retrieved_child = self.kernel.scheduler.get_process(parent_proc.child_pids[0])
        self.assertIsNotNone(retrieved_child)
        self.assertEqual(retrieved_child.pid, child_proc.pid)

    # --- GAP-02: Cascading Process Kill and sys_proc_kill ---
    async def test_gap02_cascading_process_kill_terminates_all_descendants(self):
        parent = self.kernel.spawn_process(name="root_parent", task_instruction="Root task")
        child1 = self.kernel.spawn_process(name="child_1", task_instruction="Child 1", parent_pid=parent.pid)
        child2 = self.kernel.spawn_process(name="child_2", task_instruction="Child 2", parent_pid=parent.pid)
        grandchild = self.kernel.spawn_process(name="grandchild_1", task_instruction="Grandchild", parent_pid=child1.pid)

        # Verify all are in READY or RUNNING state
        self.assertEqual(parent.state, ProcessState.READY)
        self.assertEqual(child1.state, ProcessState.READY)
        self.assertEqual(child2.state, ProcessState.READY)
        self.assertEqual(grandchild.state, ProcessState.READY)

        # Kill parent with cascade=True (default)
        killed = self.kernel.kill_process(parent.pid, cascade=True)
        self.assertTrue(killed)

        # Verify all descendants are marked KILLED
        self.assertEqual(parent.state, ProcessState.KILLED)
        self.assertEqual(child1.state, ProcessState.KILLED)
        self.assertEqual(child2.state, ProcessState.KILLED)
        self.assertEqual(grandchild.state, ProcessState.KILLED)

    async def test_gap02_sys_proc_kill_syscall_execution(self):
        target = self.kernel.spawn_process(name="target_to_abort", task_instruction="Abort me")
        child = self.kernel.spawn_process(name="child_to_abort", task_instruction="Abort child", parent_pid=target.pid)

        caller = self.kernel.spawn_process(name="operator_agent", task_instruction="Manage system")
        
        # Call sys_proc_kill syscall
        result = await self.kernel.syscalls.dispatch(
            pcb=caller,
            name="sys_proc_kill",
            target_pid=target.pid,
            cascade=True
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["state"], "KILLED")
        self.assertEqual(target.state, ProcessState.KILLED)
        self.assertEqual(child.state, ProcessState.KILLED)

    # --- GAP-04: Timeout Protection in wait_for_children ---
    async def test_gap04_wait_for_children_times_out_cleanly_without_deadlock(self):
        parent = self.kernel.spawn_process(name="waiting_parent", task_instruction="Wait for slow child")
        # Spawn child that does not complete
        slow_child = self.kernel.spawn_process(name="slow_child", task_instruction="Never finishes", parent_pid=parent.pid)

        # Call wait_for_children with very short timeout
        results = await self.kernel.wait_for_children(parent.pid, target_pids=[slow_child.pid], timeout=0.1)
        
        # Verify parent is RUNNING (unblocked) and results indicate timeout
        self.assertEqual(parent.state, ProcessState.RUNNING)
        self.assertTrue(results.get("_timed_out"))
        self.assertIn(slow_child.pid, results)

    # --- GAP-01 & GAP-06: Persona Syscalls & L4 Conflict Resolution ---
    async def test_gap01_sys_plan_register_subtask(self):
        planner_pcb = self.kernel.spawn_process(
            name="chief_architect",
            task_instruction="Plan microservices DAG",
            role="planner"
        )
        planner_agent = self.kernel._active_agents[planner_pcb.pid]
        self.assertIsInstance(planner_agent, PlannerAgent)

        res = await self.kernel.syscalls.dispatch(
            pcb=planner_pcb,
            name="sys_plan_register_subtask",
            subtask_id="dag-task-01",
            description="Build auth gateway",
            dependencies=[]
        )
        self.assertTrue(res.success)
        self.assertEqual(res.data["id"], "dag-task-01")
        # Verify agent state updated
        self.assertEqual(len(planner_agent.subtasks), 1)
        self.assertEqual(planner_agent.subtasks[0]["id"], "dag-task-01")
        # Verify blackboard entry written
        bb_entry = self.kernel.blackboard.read("milestones", "dag-task-01")
        self.assertIsNotNone(bb_entry)
        self.assertEqual(bb_entry["description"], "Build auth gateway")

    async def test_gap01_sys_audit_record_verdict(self):
        reviewer_pcb = self.kernel.spawn_process(
            name="sec_auditor",
            task_instruction="Audit code outputs",
            role="reviewer"
        )
        reviewer_agent = self.kernel._active_agents[reviewer_pcb.pid]
        self.assertIsInstance(reviewer_agent, ReviewerAgent)

        res = await self.kernel.syscalls.dispatch(
            pcb=reviewer_pcb,
            name="sys_audit_record_verdict",
            target_pid="proc-target-123",
            approved=True,
            comments="Zero vulnerabilities detected"
        )
        self.assertTrue(res.success)
        self.assertEqual(len(reviewer_agent.verdicts), 1)
        self.assertTrue(reviewer_agent.verdicts[0]["approved"])
        bb_entry = self.kernel.blackboard.read("system_audit", "verdict_proc-target-123")
        self.assertIsNotNone(bb_entry)
        self.assertEqual(bb_entry["comments"], "Zero vulnerabilities detected")

    async def test_gap01_sys_code_record_artifact(self):
        coder_pcb = self.kernel.spawn_process(
            name="algo_dev",
            task_instruction="Synthesize quicksort",
            role="coder"
        )
        coder_agent = self.kernel._active_agents[coder_pcb.pid]
        self.assertIsInstance(coder_agent, CoderAgent)

        res = await self.kernel.syscalls.dispatch(
            pcb=coder_pcb,
            name="sys_code_record_artifact",
            filename="quicksort.py",
            code="def quicksort(arr): return arr"
        )
        self.assertTrue(res.success)
        self.assertEqual(len(coder_agent.artifacts), 1)
        bb_entry = self.kernel.blackboard.read("artifacts", "quicksort.py")
        self.assertIsNotNone(bb_entry)
        self.assertIn("quicksort", bb_entry["code"])

    async def test_gap01_sys_research_record_finding(self):
        research_pcb = self.kernel.spawn_process(
            name="fact_finder",
            task_instruction="Research quantum algorithms",
            role="researcher"
        )
        research_agent = self.kernel._active_agents[research_pcb.pid]
        self.assertIsInstance(research_agent, ResearchAgent)

        res = await self.kernel.syscalls.dispatch(
            pcb=research_pcb,
            name="sys_research_record_finding",
            source_url="https://arxiv.org/abs/quantum",
            topic="quantum_supremacy",
            content="53 qubits demonstrated polynomial speedup"
        )
        self.assertTrue(res.success)
        self.assertEqual(len(research_agent.findings), 1)
        # Verify L4 store received fact
        fact = self.kernel.mmu.l4_archival.get_fact("research.quantum_supremacy")
        self.assertIn("53 qubits", fact)

    async def test_gap06_sys_conflict_record_resolution_and_l4_clearing(self):
        # 1. Create an active conflict in L4 store
        l4 = self.kernel.mmu.l4_archival
        l4.store_versioned_fact(key="company.valuation", value="$1B", confidence=0.9)
        rec2, was_conflict = l4.store_versioned_fact(key="company.valuation", value="$2B", confidence=0.7)
        self.assertTrue(was_conflict)
        conflicts_before = l4.list_conflicts()
        self.assertTrue(any(c.key == "company.valuation" for c in conflicts_before))

        # 2. Spawn ConflictResolverAgent and resolve conflict via syscall
        resolver_pcb = self.kernel.spawn_process(
            name="board_arbitrator",
            task_instruction="Resolve valuation contradiction",
            role="conflict_resolver"
        )
        resolver_agent = self.kernel._active_agents[resolver_pcb.pid]
        self.assertIsInstance(resolver_agent, ConflictResolverAgent)

        res = await self.kernel.syscalls.dispatch(
            pcb=resolver_pcb,
            name="sys_conflict_record_resolution",
            key="company.valuation",
            chosen_value="$2B (Audited Series B)",
            rationale="Audited 10-K report supersedes preliminary report",
            conflicting_versions=[1, 2]
        )
        self.assertTrue(res.success)
        self.assertEqual(len(resolver_agent.resolutions), 1)

        # 3. Verify L4 store has cleared conflict flags
        conflicts_after = l4.list_conflicts()
        self.assertFalse(any(c.key == "company.valuation" for c in conflicts_after))

        # 4. Verify authoritative fact value is updated
        latest_fact = l4.get_fact("company.valuation")
        self.assertEqual(latest_fact, "$2B (Audited Series B)")

    async def test_autonomous_execution_with_mock_provider(self):
        """Verify autonomous end-to-end agent step loop invoking persona tools."""
        p_planner = self.kernel.spawn_process(
            name="planner_auto",
            task_instruction="plan architecture dag subtask",
            role="planner"
        )
        p_reviewer = self.kernel.spawn_process(
            name="reviewer_auto",
            task_instruction="issue audit verdict for worker",
            role="reviewer"
        )
        p_coder = self.kernel.spawn_process(
            name="coder_auto",
            task_instruction="synthesize artifact solution",
            role="coder"
        )

        # Run kernel until idle
        await self.kernel.run_until_idle()

        self.assertEqual(p_planner.state, ProcessState.COMPLETED)
        self.assertEqual(p_reviewer.state, ProcessState.COMPLETED)
        self.assertEqual(p_coder.state, ProcessState.COMPLETED)

        # Verify planner agent registered subtask autonomously
        agent_planner: PlannerAgent = self.kernel._active_agents[p_planner.pid]
        self.assertTrue(len(agent_planner.subtasks) >= 1)

        # Verify reviewer agent recorded verdict autonomously
        agent_reviewer: ReviewerAgent = self.kernel._active_agents[p_reviewer.pid]
        self.assertTrue(len(agent_reviewer.verdicts) >= 1)

        # Verify coder agent recorded artifact autonomously
        agent_coder: CoderAgent = self.kernel._active_agents[p_coder.pid]
        self.assertTrue(len(agent_coder.artifacts) >= 1)

if __name__ == "__main__":
    unittest.main()
