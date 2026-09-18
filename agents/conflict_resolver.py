from typing import Any, Dict, List, Optional
from kernel.process import ProcessControlBlock
from kernel.governor import ResourceGovernor
from syscalls import SyscallRegistry
from models.provider import BaseModelProvider
from memory.mmu import MemoryManagementUnit
from agents.base_agent import BaseAgent

DEFAULT_CONFLICT_RESOLVER_PROMPT = (
    "You are the Specialized Conflict Resolver Agent inside AI-OS. Your responsibility is to analyze "
    "detected contradictory statements or conflicting knowledge records in L4 archival memory, "
    "query versioned history and contextual sources using sys_mem_recall, arbitrate discrepancies "
    "using semantic arbitration rules (recency, authority, corroboration), and commit authoritative "
    "reconciled records using the sys_conflict_record_resolution syscall to clear conflict flags."
)

class ConflictResolverAgent(BaseAgent):
    """
    Specialized Conflict Resolver Agent.
    Arbitrates semantic contradictions and version conflicts in L4 memory,
    determines truth provenance, and stores authoritative resolutions.
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
        prompt = system_prompt or DEFAULT_CONFLICT_RESOLVER_PROMPT
        super().__init__(
            pcb=pcb,
            system_prompt=prompt,
            model_provider=model_provider,
            syscall_registry=syscall_registry,
            governor=governor,
            mmu=mmu,
            model_router=model_router
        )
        self.resolutions: List[Dict[str, Any]] = []

    def record_resolution(
        self,
        key: str,
        conflicting_versions: List[int],
        chosen_value: str,
        rationale: str
    ) -> Dict[str, Any]:
        """Record an arbitration decision in local agent state, L4 archival memory, and blackboard."""
        resolution = {
            "key": key,
            "conflicting_versions": conflicting_versions,
            "chosen_value": chosen_value,
            "rationale": rationale,
            "resolver_pid": self.pcb.pid
        }
        self.resolutions.append(resolution)
        if hasattr(self, "syscalls") and getattr(self.syscalls, "kernel", None):
            kernel = self.syscalls.kernel
            if getattr(kernel, "mmu", None) and getattr(kernel.mmu, "l4_archival", None):
                rec = kernel.mmu.l4_archival.resolve_conflict(
                    key=key,
                    chosen_value=chosen_value,
                    rationale=rationale,
                    resolved_by_pid=self.pcb.pid
                )
                resolution["resolved_fact_id"] = rec.fact_id
                resolution["version"] = rec.version
            if hasattr(kernel, "blackboard"):
                kernel.blackboard.write("conflict_resolutions", key, resolution, author_pid=self.pcb.pid)
        return resolution
