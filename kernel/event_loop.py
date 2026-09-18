import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from config.settings import settings
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from kernel.scheduler import TaskScheduler
from kernel.governor import ResourceGovernor, RateLimitExceeded
from kernel.checkpoint import CheckpointManager
from kernel.cost_estimator import CostEstimator
from kernel.flight_recorder import FlightRecorder
from kernel.replay import TraceReplayEngine
from security.capability import CapabilityIssuer
from syscalls import SyscallRegistry
from models.provider import BaseModelProvider, get_provider
from models.router import AdaptiveModelRouter
from agents.base_agent import BaseAgent
from agents.planner import PlannerAgent
from agents.coder import CoderAgent
from agents.reviewer import ReviewerAgent
from agents.researcher import ResearchAgent
from agents.conflict_resolver import ConflictResolverAgent
from memory.mmu import MemoryManagementUnit
from ipc.bus import MessageBus
from ipc.blackboard import SharedBlackboard
from security.hitl import HITLManager
from security.firewall import PromptInjectionFirewall
from syscalls.mcp_server import AIOSMcpServer

class Kernel:
    """
    The central AI-OS Kernel orchestrator.
    Manages the deterministic control plane, scheduling, system calls, MMU,
    Inter-Process Communication (IPC), Sandboxing, Checkpoint Recovery, and HITL Security Gates.
    """
    def __init__(
        self,
        provider_name: Optional[str] = None,
        paging_threshold: float = 0.75,
        auto_approve_hitl: bool = False,
        db_path: Optional[Any] = None
    ):
        self.scheduler = TaskScheduler(max_concurrent=settings.default_workers)
        self.governor = ResourceGovernor()
        self.mmu = MemoryManagementUnit(paging_threshold=paging_threshold, db_path=db_path)
        self.cost_estimator = CostEstimator(l4_store=self.mmu.l4_archival)
        self.capability_issuer = CapabilityIssuer()
        self.flight_recorder = FlightRecorder(db_path=db_path)
        self.replay_engine = TraceReplayEngine(flight_recorder=self.flight_recorder)
        self.message_bus = MessageBus(db_path=db_path)
        self.blackboard = SharedBlackboard(db_path=db_path)
        self.hitl_manager = HITLManager(auto_approve_policy=auto_approve_hitl)
        self.firewall = PromptInjectionFirewall()
        self.checkpoint_mgr = CheckpointManager(db_path=db_path)
        self.syscalls = SyscallRegistry(mmu=self.mmu, kernel=self)
        self.mcp_server = AIOSMcpServer(kernel=self)
        
        provider_type = provider_name or settings.default_provider
        self.model_provider: BaseModelProvider = get_provider(provider_type, settings)
        self.model_router = AdaptiveModelRouter()
        
        self._active_agents: Dict[str, BaseAgent] = {}
        self._is_running = False
        self._worker_tasks: List[asyncio.Task] = []
        self._listeners: List[Callable[[ProcessControlBlock], None]] = []
        self._token_listeners: List[Callable[[str, str], None]] = []

    def add_process_listener(self, callback: Callable[[ProcessControlBlock], None]):
        """Subscribe to process state transition events (e.g. for UI rendering)."""
        self._listeners.append(callback)

    def add_token_listener(self, callback: Callable[[str, str], None]):
        """Subscribe to live incremental token stream deltas (pid: str, delta: str)."""
        self._token_listeners.append(callback)

    def notify_token(self, pid: str, delta: str):
        """Broadcast live token delta to registered token stream listeners."""
        for listener in self._token_listeners:
            try:
                listener(pid, delta)
            except Exception:
                pass

    def _notify(self, pcb: ProcessControlBlock):
        for listener in self._listeners:
            try:
                listener(pcb)
            except Exception:
                pass

    def _resolve_role(self, role: Optional[str] = None, name: str = "") -> str:
        """Deterministically map agent role and name hints to formal persona roles."""
        role_lower = (role or "").lower()
        name_lower = (name or "").lower()

        if role_lower in ("planner", "lead") or "planner" in name_lower or "architect" in name_lower:
            return "planner"
        elif role_lower in ("coder", "developer", "engineer") or "coder" in name_lower or "dev" in name_lower:
            return "coder"
        elif role_lower in ("reviewer", "auditor", "verifier") or "reviewer" in name_lower or "audit" in name_lower:
            return "reviewer"
        elif role_lower in ("researcher", "research", "analyst", "scout") or "research" in name_lower:
            return "researcher"
        elif role_lower in ("conflict_resolver", "resolver", "arbitrator") or "conflict" in name_lower or "resolver" in name_lower:
            return "conflict_resolver"
        return "base"

    def _create_agent_for_pcb(
        self,
        pcb: ProcessControlBlock,
        system_prompt: Optional[str] = None,
        role: Optional[str] = None
    ) -> BaseAgent:
        resolved_role = self._resolve_role(role or getattr(pcb, "role", None), pcb.name)
        pcb.role = resolved_role

        if resolved_role == "planner":
            agent_cls = PlannerAgent
        elif resolved_role == "coder":
            agent_cls = CoderAgent
        elif resolved_role == "reviewer":
            agent_cls = ReviewerAgent
        elif resolved_role == "researcher":
            agent_cls = ResearchAgent
        elif resolved_role == "conflict_resolver":
            agent_cls = ConflictResolverAgent
        else:
            agent_cls = BaseAgent

        agent = agent_cls(
            pcb=pcb,
            system_prompt=system_prompt,
            model_provider=self.model_provider,
            syscall_registry=self.syscalls,
            governor=self.governor,
            mmu=self.mmu,
            model_router=self.model_router
        )
        if self._token_listeners:
            agent.token_callback = lambda delta: self.notify_token(pcb.pid, delta)
        else:
            agent.token_callback = None
        return agent

    def spawn_process(
        self,
        name: str,
        task_instruction: str,
        system_prompt: Optional[str] = None,
        priority: PriorityLevel = PriorityLevel.NORMAL,
        token_budget: Optional[int] = None,
        max_steps: Optional[int] = None,
        allocated_tools: Optional[List[str]] = None,
        l1_capacity: Optional[int] = None,
        parent_pid: Optional[str] = None,
        role: Optional[str] = None,
        scope_paths: Optional[List[str]] = None,
        ttl_seconds: int = 120,
        workspace_id: str = "default",
        tenant_id: str = "default"
    ) -> ProcessControlBlock:
        """Create and queue a new agent process with virtual memory, IPC mailbox, and checkpointing."""
        depth = 0
        parent_pcb = None
        if parent_pid:
            parent_pcb = self.scheduler.get_process(parent_pid)
            if parent_pcb:
                depth = parent_pcb.depth + 1

        effective_role = self._resolve_role(role, name)
        assigned_budget = token_budget or settings.default_token_budget

        # 1. Predictive Cost Estimation & Admission Control
        cost_est = self.cost_estimator.estimate(role=effective_role, instruction=task_instruction)
        effective_priority = priority
        if cost_est.confidence >= 0.4 and cost_est.predicted_tokens_p90 > assigned_budget:
            effective_priority = PriorityLevel.BACKGROUND

        # Least-privilege defaults per role (Remediates GAP-11 wildcard bypass)
        effective_tools = allocated_tools if allocated_tools is not None else self.capability_issuer.get_default_syscalls(effective_role)
        effective_paths = scope_paths if scope_paths is not None else self.capability_issuer.get_default_paths(effective_role)

        pcb = ProcessControlBlock(
            name=name,
            role=effective_role,
            priority=effective_priority,
            token_budget=assigned_budget,
            max_steps=max_steps or settings.default_max_steps,
            allocated_tools=effective_tools,
            l1_capacity=l1_capacity or 4000,
            parent_pid=parent_pid,
            depth=depth,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            predicted_tokens_p90=cost_est.predicted_tokens_p90,
            cost_confidence=cost_est.confidence
        )

        if parent_pcb:
            parent_pcb.child_pids.append(pcb.pid)

        # 2. Issue Scoped Capability Token (VULN-06 & GAP-11)
        token = self.capability_issuer.issue_token(
            pid=pcb.pid,
            role=effective_role,
            scope_paths=effective_paths,
            allowed_syscalls=effective_tools,
            ttl_seconds=ttl_seconds
        )
        pcb.capability_token = token

        # Register IPC mailbox for this process
        self.message_bus.register_mailbox(pcb.pid)

        agent = self._create_agent_for_pcb(pcb, system_prompt=system_prompt, role=role)
        agent.set_task(task_instruction)

        self._active_agents[pcb.pid] = agent
        self.scheduler.enqueue(pcb)
        
        # Save initial checkpoint
        self.checkpoint_mgr.save_snapshot(pcb, agent.l1)
        
        self._notify(pcb)
        return pcb

    def recover_interrupted_processes(self) -> int:
        """
        Recover and re-enqueue in-flight processes from the SQLite checkpoint store after a crash.
        """
        snapshots = self.checkpoint_mgr.load_uncompleted_snapshots()
        recovered_count = 0

        for pcb, l1_dict in snapshots:
            if pcb.pid in self.scheduler.list_processes():
                continue

            # Restore IPC mailbox
            self.message_bus.register_mailbox(pcb.pid)

            # Ensure capability token is a valid CapabilityToken instance and renewed for recovery
            token = getattr(pcb, "capability_token", None)
            if isinstance(token, dict):
                try:
                    from security.capability import CapabilityToken
                    token = CapabilityToken.model_validate(token)
                    pcb.capability_token = token
                except Exception:
                    token = None
            if token and hasattr(token, "renew_lease"):
                token.renew_lease()
            elif not token:
                effective_role = self._resolve_role(pcb.role, pcb.name)
                token = self.capability_issuer.issue_token(
                    pid=pcb.pid,
                    role=effective_role,
                    allowed_syscalls=pcb.allocated_tools,
                    ttl_seconds=120
                )
                pcb.capability_token = token

            agent = self._create_agent_for_pcb(pcb, system_prompt=l1_dict.get("system_prompt"))

            # Restore L1 context history
            agent.l1.messages = l1_dict.get("messages", [])
            if l1_dict.get("summary"):
                agent.l1.set_compacted_summary(l1_dict["summary"])

            self._active_agents[pcb.pid] = agent
            self.scheduler.enqueue(pcb)
            recovered_count += 1
            self._notify(pcb)

        return recovered_count

    async def wait_for_children(
        self,
        parent_pid: str,
        target_pids: Optional[List[str]] = None,
        mode: str = "wait_all",
        timeout: Optional[float] = 60.0
    ) -> Dict[str, Any]:
        parent_pcb = self.scheduler.get_process(parent_pid)
        if not parent_pcb:
            raise ValueError(f"Unknown parent process: {parent_pid}")

        pids_to_wait = target_pids or [
            p.pid for p in self.scheduler.list_processes().values()
            if p.parent_pid == parent_pid
        ]

        if not pids_to_wait:
            return {}

        wait_event = self.scheduler.register_waiting_parent(parent_pid, pids_to_wait, mode=mode)
        parent_pcb.transition_to(ProcessState.BLOCKED)
        self._notify(parent_pcb)

        all_already_done = True
        for c_pid in pids_to_wait:
            c_proc = self.scheduler.get_process(c_pid)
            if not c_proc or c_proc.state not in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
                all_already_done = False
                break

        timed_out = False
        if not all_already_done:
            if timeout is not None:
                try:
                    await asyncio.wait_for(wait_event.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    self.scheduler.unregister_waiting_parent(parent_pid)
            else:
                await wait_event.wait()

        parent_pcb.transition_to(ProcessState.RUNNING)
        self._notify(parent_pcb)

        results = {}
        for c_pid in pids_to_wait:
            c_proc = self.scheduler.get_process(c_pid)
            if c_proc:
                results[c_pid] = {
                    "name": c_proc.name,
                    "state": c_proc.state.value,
                    "result": c_proc.result,
                    "error": c_proc.error_message
                }
        if timed_out:
            results["_timed_out"] = True
        return results

    async def _execute_process_step(self, pcb: ProcessControlBlock):
        """Execute a single reasoning/action step for a process."""
        agent = self._active_agents.get(pcb.pid)
        if not agent or pcb.state in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
            self._notify(pcb)
            return

        if self._token_listeners:
            agent.token_callback = lambda delta: self.notify_token(pcb.pid, delta)
        else:
            agent.token_callback = None

        self.scheduler.mark_process_running()
        try:
            # Proactive capability lease renewal for active processes near expiry (Remediates GAP-11)
            token = getattr(pcb, "capability_token", None)
            if isinstance(token, dict):
                try:
                    from security.capability import CapabilityToken
                    token = CapabilityToken.model_validate(token)
                    pcb.capability_token = token
                except Exception:
                    token = None
            if token and hasattr(token, "is_expired") and not token.is_expired():
                if hasattr(token, "remaining_ttl") and token.remaining_ttl() <= 30.0 and getattr(token, "renewal_count", 0) < getattr(token, "max_renewals", 10):
                    token.renew_lease()

            self._notify(pcb)
            done = await agent.step()
            self._notify(pcb)

            if done or pcb.state in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
                duration = max(0.01, (datetime.now(timezone.utc) - pcb.created_at).total_seconds())
                await self.mmu.l4_archival.log_task_cost_async(
                    role=pcb.role,
                    instruction=getattr(agent, "task_instruction", pcb.name),
                    tokens_consumed=pcb.tokens_consumed,
                    wall_time_seconds=duration
                )
                await self.checkpoint_mgr.delete_snapshot_async(pcb.pid)
                self.scheduler.notify_process_terminated(pcb)
                self._notify(pcb)
            else:
                # Checkpoint active intermediate state
                await self.checkpoint_mgr.save_snapshot_async(pcb, agent.l1)
                # Cooperative yield
                self.scheduler.enqueue(pcb)
                self._notify(pcb)

        except RateLimitExceeded as rle:
            pcb.transition_to(ProcessState.BLOCKED, error=str(rle))
            await self.checkpoint_mgr.save_snapshot_async(pcb, agent.l1)
            self._notify(pcb)
            # Re-enqueue asynchronously after brief backoff so other processes continue running
            async def delayed_re_enqueue(target_pcb):
                await asyncio.sleep(0.5)
                if target_pcb.state == ProcessState.BLOCKED:
                    self.scheduler.enqueue(target_pcb)
                    self._notify(target_pcb)
            asyncio.create_task(delayed_re_enqueue(pcb))
        except Exception as exc:
            pcb.transition_to(ProcessState.FAILED, error=str(exc))
            await self.checkpoint_mgr.delete_snapshot_async(pcb.pid)
            self.scheduler.notify_process_terminated(pcb)
            self._notify(pcb)
        finally:
            self.scheduler.mark_process_idle()

    async def _worker_loop(self, worker_id: int):
        """Persistent worker coroutine processing the scheduler ready queue."""
        while self._is_running:
            try:
                pcb = await self.scheduler.get_next_process()
                await self._execute_process_step(pcb)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.02)

    def start_daemon(self, num_workers: Optional[int] = None) -> List[asyncio.Task]:
        """Start persistent background scheduler worker pool (idempotent)."""
        if self._worker_tasks:
            return list(self._worker_tasks)
        self._is_running = True
        try:
            self.flight_recorder.prune_traces()
        except Exception:
            pass
        workers_count = num_workers or self.scheduler.max_concurrent
        for i in range(workers_count):
            task = asyncio.create_task(self._worker_loop(i))
            self._worker_tasks.append(task)
        return list(self._worker_tasks)

    def stop_daemon(self):
        """Stop background daemon workers."""
        self._is_running = False
        for t in self._worker_tasks:
            t.cancel()
        self._worker_tasks.clear()

    def kill_process(self, pid: str, cascade: bool = True) -> bool:
        """Terminate an active or blocked process by PID (sys_proc_kill) with optional cascading to children."""
        pcb = self.scheduler.get_process(pid)
        if not pcb or pcb.state in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
            return False

        target_pids = [pid]
        if cascade:
            # Recursively collect all descendant PIDs using child_pids and parent_pid relationships
            queue = [pid]
            all_procs = self.scheduler.list_processes()
            while queue:
                curr_pid = queue.pop(0)
                curr_pcb = all_procs.get(curr_pid)
                # Check registered child_pids
                if curr_pcb and curr_pcb.child_pids:
                    for child_id in curr_pcb.child_pids:
                        if child_id not in target_pids:
                            target_pids.append(child_id)
                            queue.append(child_id)
                # Also check parent_pid backlink across all known processes
                for candidate in all_procs.values():
                    if candidate.parent_pid == curr_pid and candidate.pid not in target_pids:
                        target_pids.append(candidate.pid)
                        queue.append(candidate.pid)

        # Terminate all target processes from leaves to root
        for target_id in reversed(target_pids):
            target_pcb = self.scheduler.get_process(target_id)
            if target_pcb and target_pcb.state not in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
                target_pcb.transition_to(
                    ProcessState.KILLED,
                    error="Terminated by operator signal (sys_proc_kill)" if target_id == pid else f"Cascading kill from parent '{pid}'"
                )
                self.checkpoint_mgr.delete_snapshot(target_id)
                self.scheduler.remove_from_ready(target_id)
                self.scheduler.notify_process_terminated(target_pcb)
                self._notify(target_pcb)
        return True

    def renew_capability_lease(self, pid: str, extension_seconds: Optional[int] = None) -> bool:
        """Extend the capability token lease for an active process (Remediates GAP-11)."""
        pcb = self.scheduler.get_process(pid)
        if not pcb or pcb.state in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
            return False
        token = getattr(pcb, "capability_token", None)
        if isinstance(token, dict):
            try:
                from security.capability import CapabilityToken
                token = CapabilityToken.model_validate(token)
                pcb.capability_token = token
            except Exception:
                token = None
        if not token or not hasattr(token, "renew_lease"):
            return False
        success = token.renew_lease(extension_seconds)
        if success:
            agent = self._active_agents.get(pid)
            if agent:
                self.checkpoint_mgr.save_snapshot(pcb, agent.l1)
            self._notify(pcb)
        return success

    async def run_until_idle(self):
        """
        Execute or wait until all queued processes reach a terminal state.
        """
        if self._worker_tasks:
            # Daemon mode: wait until both ready queue and active workers are idle
            while (self.scheduler.has_pending_tasks() or self.scheduler.has_active_running_tasks()) and self._is_running:
                await asyncio.sleep(0.05)
            return

        # Synchronous batch mode
        self._is_running = True
        while self.scheduler.has_pending_tasks() and self._is_running:
            pcb = await self.scheduler.get_next_process()
            await self._execute_process_step(pcb)
        self._is_running = False

    def shutdown(self):
        """Halt the kernel event loop and clean up resources."""
        self.stop_daemon()
        self._is_running = False
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                if hasattr(self.model_provider, "aclose"):
                    asyncio.create_task(self.model_provider.aclose())
                if hasattr(self.model_router, "aclose"):
                    asyncio.create_task(self.model_router.aclose())
        except Exception:
            pass

    async def aclose(self):
        """Asynchronously shutdown daemon and close all network resource pools."""
        self.shutdown()
        if hasattr(self.model_provider, "aclose"):
            await self.model_provider.aclose()
        if hasattr(self.model_router, "aclose"):
            await self.model_router.aclose()

