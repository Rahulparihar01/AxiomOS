from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from syscalls.base import SyscallBase, SyscallResult
from ipc.message import IPCMessage, IPCMessageType

class ProcSpawnInput(BaseModel):
    name: str = Field(description="Name/role for the child worker agent.")
    task_instruction: str = Field(description="Goal or instructions for the spawned child agent.")
    allocated_tools: Optional[List[str]] = Field(default=None, description="Subset of tools permitted for this child process.")
    priority: str = Field(default="NORMAL", description="Priority: CRITICAL, HIGH, NORMAL, BACKGROUND.")
    token_budget: Optional[int] = Field(default=20000, description="Token budget cap for child process.")
    role: Optional[str] = Field(default=None, description="Persona role: planner, coder, reviewer, researcher, conflict_resolver, base.")
    scope_paths: Optional[List[str]] = Field(default=None, description="Authorized filesystem paths for the spawned agent.")

class SysProcSpawn(SyscallBase):
    name = "sys_proc_spawn"
    description = "Spawn a child agent process to execute a delegated subtask in parallel."
    is_mutating = True
    input_schema = ProcSpawnInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        name: str,
        task_instruction: str,
        allocated_tools: Optional[List[str]] = None,
        priority: str = "NORMAL",
        token_budget: Optional[int] = 20000,
        role: Optional[str] = None,
        scope_paths: Optional[List[str]] = None,
        **kwargs
    ) -> SyscallResult:
        try:
            # Fork-bomb protection in governor
            self.kernel.governor.check_spawn_permission(pcb)

            priority_enum = getattr(PriorityLevel, priority.upper(), PriorityLevel.NORMAL)
            child_pcb = self.kernel.spawn_process(
                name=name,
                task_instruction=task_instruction,
                priority=priority_enum,
                token_budget=token_budget,
                allocated_tools=allocated_tools,
                parent_pid=pcb.pid,
                role=role,
                scope_paths=scope_paths
            )
            return SyscallResult(
                success=True,
                data={"child_pid": child_pcb.pid, "name": child_pcb.name, "state": child_pcb.state.value}
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_proc_spawn failed: {str(e)}")

class ProcSendMsgInput(BaseModel):
    recipient_pid: str = Field(description="Target agent PID or '*' for broadcast.")
    msg_type: str = Field(default="DIRECT_MESSAGE", description="Message type: DIRECT_MESSAGE, TASK_DELEGATION, TASK_RESULT.")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured message payload.")

class SysProcSendMsg(SyscallBase):
    name = "sys_proc_send_msg"
    description = "Send a structured IPC message to another agent or broadcast to all agents."
    is_mutating = True
    input_schema = ProcSendMsgInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        recipient_pid: str,
        msg_type: str = "DIRECT_MESSAGE",
        payload: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> SyscallResult:
        try:
            type_enum = getattr(IPCMessageType, msg_type.upper(), IPCMessageType.DIRECT_MESSAGE)
            msg = IPCMessage(
                sender_pid=pcb.pid,
                recipient_pid=recipient_pid,
                msg_type=type_enum,
                payload=payload or {}
            )
            delivered = await self.kernel.message_bus.send(msg)
            return SyscallResult(
                success=True,
                data={"message_id": msg.message_id, "delivered": delivered, "recipient": recipient_pid}
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_proc_send_msg failed: {str(e)}")

class ProcRecvMsgInput(BaseModel):
    timeout: Optional[float] = Field(default=0.0, description="Seconds to wait (0.0 for non-blocking poll).")

class SysProcRecvMsg(SyscallBase):
    name = "sys_proc_recv_msg"
    description = "Poll or receive pending messages from the agent's IPC inbox."
    is_mutating = False
    input_schema = ProcRecvMsgInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, timeout: Optional[float] = 0.0, **kwargs) -> SyscallResult:
        try:
            msg = await self.kernel.message_bus.receive(pcb.pid, timeout=timeout)
            if not msg:
                return SyscallResult(success=True, data={"message": None, "pending": False})
            return SyscallResult(
                success=True,
                data={"message": msg.model_dump(), "pending": True}
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_proc_recv_msg failed: {str(e)}")

class ProcWaitInput(BaseModel):
    child_pids: Optional[List[str]] = Field(default=None, description="Specific child PIDs to wait for, or None for all children.")
    mode: str = Field(default="wait_all", description="Wait mode: 'wait_all' (all must finish) or 'wait_any' (first to finish).")
    timeout: Optional[float] = Field(default=60.0, description="Max seconds to wait before timing out.")

class SysProcWait(SyscallBase):
    name = "sys_proc_wait"
    description = "Wait for child processes to finish execution and retrieve their results."
    is_mutating = False
    input_schema = ProcWaitInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, child_pids: Optional[List[str]] = None, mode: str = "wait_all", timeout: Optional[float] = 60.0, **kwargs) -> SyscallResult:
        try:
            results = await self.kernel.wait_for_children(pcb.pid, target_pids=child_pids, mode=mode, timeout=timeout)
            return SyscallResult(success=True, data={"children_results": results})
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_proc_wait failed: {str(e)}")

class ProcKillInput(BaseModel):
    target_pid: str = Field(description="PID of the process to terminate.")
    cascade: bool = Field(default=True, description="Whether to recursively terminate child and descendant processes.")

class SysProcKill(SyscallBase):
    name = "sys_proc_kill"
    description = "Terminate an active or blocked agent process and optionally its child processes."
    is_mutating = True
    input_schema = ProcKillInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, target_pid: str, cascade: bool = True, **kwargs) -> SyscallResult:
        try:
            success = self.kernel.kill_process(target_pid, cascade=cascade)
            if not success:
                return SyscallResult(success=False, error=f"Process '{target_pid}' not found or already in terminal state.")
            return SyscallResult(success=True, data={"pid": target_pid, "state": "KILLED", "cascade": cascade})
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_proc_kill failed: {str(e)}")


class BlackboardWriteInput(BaseModel):
    topic: str = Field(description="Category or channel on the blackboard.")
    key: str = Field(description="Entry key.")
    value: Any = Field(description="Value to publish.")

class SysBlackboardWrite(SyscallBase):
    name = "sys_bb_write"
    description = "Post or update shared state on the multi-agent blackboard."
    is_mutating = True
    input_schema = BlackboardWriteInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, topic: str, key: str, value: Any, **kwargs) -> SyscallResult:
        self.kernel.blackboard.write(topic=topic, key=key, value=value, author_pid=pcb.pid)
        return SyscallResult(success=True, data={"topic": topic, "key": key, "status": "written"})

class BlackboardReadInput(BaseModel):
    topic: str = Field(description="Category or channel on the blackboard.")
    key: Optional[str] = Field(default=None, description="Specific key to read, or None to read the entire topic.")

class SysBlackboardRead(SyscallBase):
    name = "sys_bb_read"
    description = "Read shared findings, status, or state from the multi-agent blackboard."
    is_mutating = False
    input_schema = BlackboardReadInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, topic: str, key: Optional[str] = None, **kwargs) -> SyscallResult:
        if key:
            val = self.kernel.blackboard.read(topic=topic, key=key)
            return SyscallResult(success=True, data={"topic": topic, "key": key, "value": val})
        else:
            all_entries = self.kernel.blackboard.read_topic(topic=topic)
            return SyscallResult(success=True, data={"topic": topic, "entries": all_entries})

class BlackboardAwaitInput(BaseModel):
    topic: str = Field(description="Category or channel on the blackboard.")
    key: str = Field(description="Specific key to asynchronously await.")
    timeout: float = Field(default=10.0, description="Maximum seconds to await before timing out.")

class SysBlackboardAwait(SyscallBase):
    name = "sys_bb_await"
    description = "Asynchronously wait for a key to appear or update on the blackboard without spin-polling."
    is_mutating = False
    input_schema = BlackboardAwaitInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, topic: str, key: str, timeout: float = 10.0, **kwargs) -> SyscallResult:
        val = await self.kernel.blackboard.wait_for_key(topic=topic, key=key, timeout=timeout)
        if val is None:
            return SyscallResult(success=False, error=f"Timeout awaiting key '{key}' under topic '{topic}' after {timeout}s.")
        return SyscallResult(success=True, data={"topic": topic, "key": key, "value": val})

class CapRenewInput(BaseModel):
    extension_seconds: Optional[int] = Field(default=120, description="Additional lease duration in seconds (default: 120).")

class SysCapRenew(SyscallBase):
    name = "sys_cap_renew"
    description = "Extend the capability security token lease for this process to continue long-running operations."
    is_mutating = False
    input_schema = CapRenewInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, extension_seconds: Optional[int] = 120, **kwargs) -> SyscallResult:
        try:
            success = self.kernel.renew_capability_lease(pcb.pid, extension_seconds=extension_seconds)
            token = getattr(pcb, "capability_token", None)
            if not success or not token:
                return SyscallResult(
                    success=False,
                    error=f"Capability lease renewal failed for PID '{pcb.pid}'. Token may be revoked or reached maximum renewals ({getattr(token, 'max_renewals', 10)})."
                )
            return SyscallResult(
                success=True,
                data={
                    "pid": pcb.pid,
                    "token_id": token.token_id,
                    "expires_at": str(token.expires_at),
                    "renewal_count": token.renewal_count,
                    "remaining_ttl_seconds": round(token.remaining_ttl(), 2)
                }
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_cap_renew failed: {str(e)}")
