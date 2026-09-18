from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from config.settings import settings
from kernel.process import ProcessControlBlock, ProcessState
from syscalls.base import SyscallBase, SyscallResult
from security.rings import SecurityRing
from sandbox.runner import BaseCodeRunner, IsolatedCodeRunner, get_code_runner

class ExecPythonInput(BaseModel):
    code: str = Field(description="Python code snippet to execute inside the ephemeral sandbox.")
    timeout_seconds: Optional[float] = Field(default=10.0, description="Max execution timeout in seconds.")

class SysExecPython(SyscallBase):
    name = "sys_exec_python"
    description = "Execute arbitrary Python code in an isolated ephemeral sandbox (Requires HITL authorization)."
    is_mutating = True
    requires_approval = True
    security_ring = SecurityRing.RING_3_DESTRUCTIVE
    input_schema = ExecPythonInput

    def __init__(self, kernel, runner: Optional[BaseCodeRunner] = None):
        self.kernel = kernel
        self.runner = runner or get_code_runner()

    async def execute(self, pcb: ProcessControlBlock, code: str, timeout_seconds: Optional[float] = 10.0, **kwargs) -> SyscallResult:
        try:
            # 1. Human-in-the-Loop Authorization Check
            req = self.kernel.hitl_manager.create_request(
                pid=pcb.pid,
                syscall_name=self.name,
                arguments={"code": code[:200] + ("..." if len(code) > 200 else "")}
            )

            if not req.resolved:
                pcb.transition_to(ProcessState.BLOCKED)
                approved = await self.kernel.hitl_manager.wait_for_decision(req.request_id)
                pcb.transition_to(ProcessState.RUNNING)
            else:
                approved = bool(req.approved)

            if not approved:
                return SyscallResult(
                    success=False,
                    error=f"Permission Denied: Human operator rejected execution request ({req.request_id})."
                )

            # 2. Run inside Sandbox
            result = await self.runner.run_python(code=code, timeout=timeout_seconds)
            return SyscallResult(
                success=(result.exit_code == 0),
                data={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration_ms,
                    "timed_out": result.timed_out
                },
                error=result.stderr if result.exit_code != 0 else None
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_exec_python failed: {str(e)}")

class FsWriteInput(BaseModel):
    filepath: str = Field(description="Relative workspace path to write to.")
    content: str = Field(description="Textual content to write.")

class SysFsWrite(SyscallBase):
    name = "sys_fs_write"
    description = "Write textual content to a file within the workspace boundary."
    is_mutating = True
    security_ring = SecurityRing.RING_2_MUTATING
    input_schema = FsWriteInput

    async def execute(self, pcb: ProcessControlBlock, filepath: str, content: str, **kwargs) -> SyscallResult:
        try:
            workspace_root = settings.workspace_root.resolve()
            target_path = (workspace_root / filepath).resolve()

            # Sandboxing check: Prevent traversal
            if not str(target_path).startswith(str(workspace_root)):
                return SyscallResult(
                    success=False,
                    error=f"Permission Denied: Path '{filepath}' attempts directory traversal outside workspace."
                )

            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content, encoding="utf-8")
            return SyscallResult(
                success=True,
                data={"filepath": filepath, "bytes_written": len(content.encode('utf-8'))}
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_fs_write failed: {str(e)}")

class FsDeleteInput(BaseModel):
    filepath: str = Field(description="Relative workspace path of file to delete.")

class SysFsDelete(SyscallBase):
    name = "sys_fs_delete"
    description = "Delete a file from the workspace boundary (Requires HITL authorization)."
    is_mutating = True
    requires_approval = True
    security_ring = SecurityRing.RING_3_DESTRUCTIVE
    input_schema = FsDeleteInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, filepath: str, **kwargs) -> SyscallResult:
        try:
            # 1. Human-in-the-Loop Authorization Check
            req = self.kernel.hitl_manager.create_request(
                pid=pcb.pid,
                syscall_name=self.name,
                arguments={"filepath": filepath}
            )

            if not req.resolved:
                pcb.transition_to(ProcessState.BLOCKED)
                approved = await self.kernel.hitl_manager.wait_for_decision(req.request_id)
                pcb.transition_to(ProcessState.RUNNING)
            else:
                approved = bool(req.approved)

            if not approved:
                return SyscallResult(
                    success=False,
                    error=f"Permission Denied: Human operator rejected file deletion ({req.request_id})."
                )

            workspace_root = settings.workspace_root.resolve()
            target_path = (workspace_root / filepath).resolve()

            if not str(target_path).startswith(str(workspace_root)):
                return SyscallResult(
                    success=False,
                    error=f"Permission Denied: Path '{filepath}' attempts directory traversal outside workspace."
                )

            if not target_path.exists():
                return SyscallResult(success=False, error=f"File not found: '{filepath}'")

            target_path.unlink()
            return SyscallResult(success=True, data={"deleted_filepath": filepath})
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_fs_delete failed: {str(e)}")
