from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type
from pydantic import BaseModel, Field
from kernel.process import ProcessControlBlock

class SyscallResult(BaseModel):
    """Normalized result returned by a kernel syscall."""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    tokens_billed: int = 0

class SyscallBase(ABC):
    """
    Abstract Base Class for all AI-OS System Calls (Syscalls).
    Analogous to POSIX syscalls, this forms the hardware and external tool abstraction boundary.
    """
    name: str
    description: str
    is_mutating: bool = False
    requires_approval: bool = False
    input_schema: Optional[Type[BaseModel]] = None

    @abstractmethod
    async def execute(self, pcb: ProcessControlBlock, **kwargs) -> SyscallResult:
        """Execute the system call on behalf of the calling process."""
        pass

    def get_tool_definition(self) -> Dict[str, Any]:
        """Convert the syscall specification into a standard tool definition for LLMs."""
        schema = {}
        if self.input_schema:
            schema = self.input_schema.model_json_schema()
        return {
            "name": self.name,
            "description": self.description,
            "parameters": schema,
            "is_mutating": self.is_mutating
        }
