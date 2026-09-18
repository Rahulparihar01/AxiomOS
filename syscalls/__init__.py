from typing import Dict, List, Optional
from kernel.process import ProcessControlBlock
from syscalls.base import SyscallBase, SyscallResult
from syscalls.standard import SysFsRead, SysCalc, SysLog, SysNetFetch
from syscalls.memory import SysMemStore, SysMemRecall, SysMemStats
from syscalls.process import (
    SysProcSpawn,
    SysProcSendMsg,
    SysProcRecvMsg,
    SysProcWait,
    SysProcKill,
    SysBlackboardWrite,
    SysBlackboardRead,
    SysBlackboardAwait,
    SysCapRenew
)
from syscalls.sandbox import (
    SysExecPython,
    SysFsWrite,
    SysFsDelete
)
from syscalls.mcp import McpToolAdapter, McpClientRegistry, McpStdioTransport
from syscalls.mcp_server import AIOSMcpServer
from syscalls.persona import (
    SysPlanRegisterSubtask,
    SysAuditRecordVerdict,
    SysCodeRecordArtifact,
    SysResearchRecordFinding,
    SysConflictRecordResolution
)

class SyscallRegistry:
    """Central registry of kernel system calls."""
    def __init__(self, mmu=None, kernel=None):
        self.mmu = mmu
        self.kernel = kernel
        self._syscalls: Dict[str, SyscallBase] = {}
        self.mcp_client = McpClientRegistry(self)
        
        # 1. Standard Hardware/OS Syscalls (Ring 1)
        self.register(SysFsRead())
        self.register(SysCalc())
        self.register(SysLog())
        self.register(SysFsWrite())
        self.register(SysNetFetch())
        
        # 2. Memory Syscalls (if MMU is provided)
        if mmu:
            self.register(SysMemStore(mmu, kernel=kernel))
            self.register(SysMemRecall(mmu))
            self.register(SysMemStats(mmu))

        # 3. Process, IPC, and Sandboxed Syscalls (if Kernel is provided)
        if kernel:
            self.register(SysProcSpawn(kernel))
            self.register(SysProcSendMsg(kernel))
            self.register(SysProcRecvMsg(kernel))
            self.register(SysProcWait(kernel))
            self.register(SysProcKill(kernel))
            self.register(SysBlackboardWrite(kernel))
            self.register(SysBlackboardRead(kernel))
            self.register(SysBlackboardAwait(kernel))
            self.register(SysExecPython(kernel))
            self.register(SysFsDelete(kernel))
            self.register(SysCapRenew(kernel))
            # 4. Specialized Persona Syscalls (autonomous agent role actions)
            self.register(SysPlanRegisterSubtask(kernel))
            self.register(SysAuditRecordVerdict(kernel))
            self.register(SysCodeRecordArtifact(kernel))
            self.register(SysResearchRecordFinding(kernel))
            self.register(SysConflictRecordResolution(kernel))


    def register(self, syscall: SyscallBase):
        self._syscalls[syscall.name] = syscall

    def get(self, name: str) -> Optional[SyscallBase]:
        return self._syscalls.get(name)

    def list_tools(self) -> List[dict]:
        return [s.get_tool_definition() for s in self._syscalls.values()]

    async def dispatch(self, pcb: ProcessControlBlock, name: str, **kwargs) -> SyscallResult:
        # 1. Capability token verification (VULN-06)
        token = getattr(pcb, "capability_token", None)
        if isinstance(token, dict):
            try:
                from security.capability import CapabilityToken
                token = CapabilityToken.model_validate(token)
                pcb.capability_token = token
            except Exception:
                token = None
        if token:
            # Check expiration (TTL)
            if hasattr(token, "is_expired") and token.is_expired():
                return SyscallResult(
                    success=False,
                    error=f"Capability Denied: Capability token for PID '{pcb.pid}' has expired (TTL exceeded)."
                )
            # Check allowed syscalls
            if hasattr(token, "can_call_syscall") and not token.can_call_syscall(name):
                return SyscallResult(
                    success=False,
                    error=f"Capability Denied: Syscall '{name}' is not authorized by capability token."
                )
            # Check path scoping on filesystem syscalls
            if "filepath" in kwargs and hasattr(token, "can_access_path"):
                if not token.can_access_path(kwargs["filepath"]):
                    return SyscallResult(
                        success=False,
                        error=f"Capability Denied: Access to path '{kwargs['filepath']}' is outside authorized scope paths."
                    )

        syscall = self.get(name)
        if not syscall:
            return SyscallResult(success=False, error=f"Unknown Syscall: '{name}'")
        return await syscall.execute(pcb, **kwargs)

__all__ = [
    "SyscallBase",
    "SyscallResult",
    "SyscallRegistry",
    "SysFsRead",
    "SysCalc",
    "SysLog",
    "SysMemStore",
    "SysMemRecall",
    "SysMemStats",
    "SysProcSpawn",
    "SysProcSendMsg",
    "SysProcRecvMsg",
    "SysProcWait",
    "SysProcKill",
    "SysBlackboardWrite",
    "SysBlackboardRead",
    "SysBlackboardAwait",
    "SysCapRenew",
    "SysExecPython",
    "SysFsWrite",
    "SysFsDelete",
    "SysNetFetch",
    "SysPlanRegisterSubtask",
    "SysAuditRecordVerdict",
    "SysCodeRecordArtifact",
    "SysResearchRecordFinding",
    "SysConflictRecordResolution",
    "McpToolAdapter",
    "McpClientRegistry",
    "McpStdioTransport",
    "AIOSMcpServer"
]

