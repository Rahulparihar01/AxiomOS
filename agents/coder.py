from typing import Any, Dict, List, Optional
from kernel.process import ProcessControlBlock
from kernel.governor import ResourceGovernor
from syscalls import SyscallRegistry
from models.provider import BaseModelProvider
from memory.mmu import MemoryManagementUnit
from agents.base_agent import BaseAgent

DEFAULT_CODER_PROMPT = (
    "You are a specialized Coder Agent inside AI-OS. Your role is to implement algorithms, "
    "write clean, efficient, and secure code, execute isolated test scripts using the sys_exec_python sandbox syscall, "
    "record synthesized code artifacts via sys_code_record_artifact, and iteratively fix and refactor code until all tests pass."
)

class CoderAgent(BaseAgent):
    """
    Specialized Coder Agent.
    Synthesizes code, manages sandbox execution, detects runtime exceptions,
    and refactors solutions iteratively.
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
        prompt = system_prompt or DEFAULT_CODER_PROMPT
        super().__init__(
            pcb=pcb,
            system_prompt=prompt,
            model_provider=model_provider,
            syscall_registry=syscall_registry,
            governor=governor,
            mmu=mmu,
            model_router=model_router
        )
        self.artifacts: List[Dict[str, Any]] = []

    def record_artifact(self, filename: str, code: str) -> Dict[str, Any]:
        """Record a synthesized code artifact in the coder's local state and blackboard."""
        artifact = {
            "filename": filename,
            "code": code,
            "author_pid": self.pcb.pid
        }
        self.artifacts.append(artifact)
        if hasattr(self, "syscalls") and getattr(self.syscalls, "kernel", None):
            kernel = self.syscalls.kernel
            if hasattr(kernel, "blackboard"):
                kernel.blackboard.write("artifacts", filename, artifact, author_pid=self.pcb.pid)
        return artifact
