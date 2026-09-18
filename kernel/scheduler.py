import asyncio
from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel

@dataclass
class ReadyQueueEntry:
    """Queue entry with dynamic wait credit tracking for anti-starvation aging."""
    pcb: ProcessControlBlock
    wait_ticks: int = 0
    enqueued_order: int = 0
    enqueued_time: float = field(default_factory=time.time)

    def effective_score(self, aging_rate: float = 1.0) -> float:
        """Calculate dynamic effective priority: base priority points + wait credits."""
        base_priority = int(self.pcb.priority) * 10.0
        aging_credit = self.wait_ticks * aging_rate
        return base_priority + aging_credit

class TaskScheduler:
    """
    Priority-based task scheduler for AxiomOS agent processes.
    Enforces fair scheduling, process queues, concurrency limits,
    dynamic priority aging for starvation defense (GAP-09),
    and process hierarchy wake-ups (parent-child wait/signal).
    """
    def __init__(self, max_concurrent: int = 4, aging_rate: float = 1.0):
        self.max_concurrent = max_concurrent
        self.aging_rate = aging_rate
        self._ready_list: List[ReadyQueueEntry] = []
        self._ready_event = asyncio.Event()
        self._processes: Dict[str, ProcessControlBlock] = {}
        self._waiting_parents: Dict[str, Dict[str, Any]] = {}
        self._counter = 0
        self._active_running_count = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _safe_set_event(self, event: asyncio.Event):
        """Thread-safe and cross-loop safe event trigger."""
        try:
            target_loop = getattr(self, "_loop", None) or getattr(event, "_loop", None)
            if target_loop and target_loop.is_running():
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None
                if current_loop is target_loop:
                    event.set()
                else:
                    target_loop.call_soon_threadsafe(event.set)
            else:
                event.set()
        except Exception:
            try:
                event.set()
            except Exception:
                pass

    def _safe_clear_event(self, event: asyncio.Event):
        """Thread-safe and cross-loop safe event clear."""
        try:
            target_loop = getattr(self, "_loop", None) or getattr(event, "_loop", None)
            if target_loop and target_loop.is_running():
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None
                if current_loop is target_loop:
                    event.clear()
                else:
                    target_loop.call_soon_threadsafe(event.clear)
            else:
                event.clear()
        except Exception:
            try:
                event.clear()
            except Exception:
                pass

    def register_process(self, pcb: ProcessControlBlock):
        """Register a new process with the scheduler."""
        self._processes[pcb.pid] = pcb

    def enqueue(self, pcb: ProcessControlBlock):
        """Place a process onto the ready queue with aging tracking."""
        self.register_process(pcb)
        pcb.transition_to(ProcessState.READY)
        self._counter += 1

        existing = next((e for e in self._ready_list if e.pcb.pid == pcb.pid), None)
        if existing:
            existing.pcb = pcb
        else:
            self._ready_list.append(ReadyQueueEntry(pcb=pcb, wait_ticks=0, enqueued_order=self._counter))

        self._safe_set_event(self._ready_event)

    def remove_from_ready(self, pid: str) -> bool:
        """Remove a process from the ready queue if present (e.g. on kill/abort)."""
        idx = next((i for i, e in enumerate(self._ready_list) if e.pcb.pid == pid), None)
        if idx is not None:
            self._ready_list.pop(idx)
            if not self._ready_list:
                self._safe_clear_event(self._ready_event)
            return True
        return False

    async def get_next_process(self) -> ProcessControlBlock:
        """
        Dequeue the process with the highest dynamic effective priority.
        Increments wait_ticks for all other waiting processes to prevent starvation (Remediates GAP-09).
        """
        self._loop = asyncio.get_running_loop()
        while not self._ready_list:
            self._safe_clear_event(self._ready_event)
            await self._ready_event.wait()

        # Find candidate with highest effective score; tie-break with lowest enqueued_order (FIFO)
        best_idx = 0
        best_entry = self._ready_list[0]
        best_score = best_entry.effective_score(self.aging_rate)

        for i in range(1, len(self._ready_list)):
            entry = self._ready_list[i]
            score = entry.effective_score(self.aging_rate)
            if (score > best_score) or (score == best_score and entry.enqueued_order < best_entry.enqueued_order):
                best_score = score
                best_entry = entry
                best_idx = i

        chosen = self._ready_list.pop(best_idx)
        if not self._ready_list:
            self._safe_clear_event(self._ready_event)

        # Age all remaining waiting tasks: increment wait_ticks
        for entry in self._ready_list:
            entry.wait_ticks += 1

        return chosen.pcb

    def mark_process_running(self):
        """Record an active worker executing a process step."""
        self._active_running_count += 1

    def mark_process_idle(self):
        """Record that a worker has finished a process step."""
        if self._active_running_count > 0:
            self._active_running_count -= 1

    def has_active_running_tasks(self) -> bool:
        """Check if any worker is currently executing a process step."""
        return self._active_running_count > 0

    def has_pending_tasks(self) -> bool:
        """Check if any processes are waiting to run."""
        return len(self._ready_list) > 0

    def get_process(self, pid: str) -> Optional[ProcessControlBlock]:
        """Look up a PCB by PID."""
        return self._processes.get(pid)

    def list_processes(self) -> Dict[str, ProcessControlBlock]:
        """Return all tracked processes."""
        return dict(self._processes)

    def register_waiting_parent(self, parent_pid: str, target_pids: List[str], mode: str = "wait_all") -> asyncio.Event:
        """Register a parent process waiting for its child processes to terminate."""
        event = asyncio.Event()
        self._waiting_parents[parent_pid] = {
            "target_pids": set(target_pids),
            "mode": mode,
            "event": event
        }
        return event

    def unregister_waiting_parent(self, parent_pid: str):
        """Unregister a parent process from the waiting list (e.g. on timeout or cancellation)."""
        self._waiting_parents.pop(parent_pid, None)


    def notify_process_terminated(self, terminated_pcb: ProcessControlBlock):
        """
        Notify the scheduler that a process reached a terminal state.
        Checks if a waiting parent process can be unblocked.
        """
        parent_pid = terminated_pcb.parent_pid
        if not parent_pid or parent_pid not in self._waiting_parents:
            return

        wait_info = self._waiting_parents[parent_pid]
        target_pids: Set[str] = wait_info["target_pids"]
        mode: str = wait_info["mode"]
        event: asyncio.Event = wait_info["event"]

        if terminated_pcb.pid in target_pids:
            if mode == "wait_any":
                self._safe_set_event(event)
                self._waiting_parents.pop(parent_pid, None)
            elif mode == "wait_all":
                # Check if all target children have reached terminal state
                all_done = True
                for c_pid in target_pids:
                    c_proc = self.get_process(c_pid)
                    if not c_proc or c_proc.state not in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
                        all_done = False
                        break
                if all_done:
                    self._safe_set_event(event)
                    self._waiting_parents.pop(parent_pid, None)
