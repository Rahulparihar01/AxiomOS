from typing import Any, Dict, List, Optional
from kernel.process import ProcessControlBlock
from kernel.governor import ResourceGovernor
from syscalls import SyscallRegistry
from models.provider import BaseModelProvider
from memory.mmu import MemoryManagementUnit
from agents.base_agent import BaseAgent

DEFAULT_RESEARCHER_PROMPT = (
    "You are the Specialized Research Agent inside AI-OS. Your responsibility is to autonomously gather "
    "factual information, retrieve web documentation and public APIs using the sys_net_fetch syscall, "
    "query semantic memory using sys_mem_recall, synthesize comprehensive analytical answers, and permanently "
    "store verified findings using the sys_research_record_finding and sys_mem_store syscalls. "
    "Always cite sources and verify factual consistency."
)

class ResearchAgent(BaseAgent):
    """
    Specialized Research Agent.
    Executes web retrieval, queries historical vector memory, synthesizes analytical findings,
    and commits verified facts to permanent storage.
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
        prompt = system_prompt or DEFAULT_RESEARCHER_PROMPT
        super().__init__(
            pcb=pcb,
            system_prompt=prompt,
            model_provider=model_provider,
            syscall_registry=syscall_registry,
            governor=governor,
            mmu=mmu,
            model_router=model_router
        )
        self.findings: List[Dict[str, Any]] = []

    def record_finding(self, source_url: str, topic: str, content: str) -> Dict[str, Any]:
        """Record a verified research finding in local agent state, blackboard, and L4 memory."""
        finding = {
            "source_url": source_url,
            "topic": topic,
            "content": content,
            "researcher_pid": self.pcb.pid
        }
        self.findings.append(finding)
        if hasattr(self, "syscalls") and getattr(self.syscalls, "kernel", None):
            kernel = self.syscalls.kernel
            if hasattr(kernel, "blackboard"):
                kernel.blackboard.write("research", topic, finding, author_pid=self.pcb.pid)
            if getattr(kernel, "mmu", None) and getattr(kernel.mmu, "l4_archival", None):
                kernel.mmu.l4_archival.store_fact(f"research.{topic}", content, owner_pid=self.pcb.pid)
        return finding
