import json
from typing import Any, Dict, List, Optional
from kernel.process import ProcessControlBlock, PriorityLevel
from kernel.governor import ResourceGovernor
from syscalls import SyscallRegistry
from models.provider import BaseModelProvider
from memory.mmu import MemoryManagementUnit
from agents.base_agent import BaseAgent

DEFAULT_PLANNER_PROMPT = (
    "You are the Lead Planner Agent inside AI-OS. Your responsibility is to analyze complex goals, "
    "break them down into an ordered dependency Directed Acyclic Graph (DAG) of subtasks using the sys_plan_register_subtask syscall, "
    "spawn child worker processes (via sys_proc_spawn), coordinate their completion (via sys_proc_wait), and abort runaway workers (via sys_proc_kill). "
    "Always plan methodically, communicate milestones clearly, and verify child outputs."
)

class PlannerAgent(BaseAgent):
    """
    Specialized Planner Agent.
    Decomposes high-level instructions into executable subtasks, coordinates child workers,
    and publishes DAG milestones to the Shared Blackboard.
    """
    def __init__(
        self,
        pcb: ProcessControlBlock,
        system_prompt: Optional[str] = None,
        model_provider: Optional[BaseModelProvider] = None,
        syscall_registry: Optional[SyscallRegistry] = None,
        governor: Optional[ResourceGovernor] = None,
        mmu: Optional[MemoryManagementUnit] = None,
        model_router: Optional[Any] = None
    ):
        prompt = system_prompt or DEFAULT_PLANNER_PROMPT
        super().__init__(
            pcb=pcb,
            system_prompt=prompt,
            model_provider=model_provider,
            syscall_registry=syscall_registry,
            governor=governor,
            mmu=mmu,
            model_router=model_router
        )
        self.subtasks: List[Dict[str, Any]] = []

    def register_subtask(self, subtask_id: str, description: str, dependencies: Optional[List[str]] = None) -> Dict[str, Any]:
        """Register a DAG subtask node in the planner's local state and blackboard."""
        subtask = {
            "id": subtask_id,
            "description": description,
            "dependencies": dependencies or [],
            "status": "PENDING"
        }
        if not any(s.get("id") == subtask_id for s in self.subtasks):
            self.subtasks.append(subtask)

        if hasattr(self, "syscalls") and getattr(self.syscalls, "kernel", None):
            kernel = self.syscalls.kernel
            if hasattr(kernel, "blackboard"):
                kernel.blackboard.write("milestones", subtask_id, subtask, author_pid=self.pcb.pid)
        return subtask
