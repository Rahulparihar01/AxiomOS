import fnmatch
import time
from collections import deque
from typing import Dict, List, Optional
from kernel.process import ProcessControlBlock, ProcessState

class GovernorViolation(Exception):
    """Base exception for kernel resource quota violations."""
    pass

class TokenQuotaExceeded(GovernorViolation):
    """Raised when an agent process attempts to consume tokens beyond its budget."""
    pass

class RateLimitExceeded(GovernorViolation):
    """Raised when process or kernel exceeds sliding-window requests or tokens per minute."""
    pass

class StepLimitExceeded(GovernorViolation):
    """Raised when an agent process exceeds its maximum reasoning steps (infinite loop protection)."""
    pass

class UnauthorizedToolAccess(GovernorViolation):
    """Raised when an agent process attempts to invoke a syscall not in its capability list."""
    pass

class ForkBombPrevented(GovernorViolation):
    """Raised when an agent process attempts to exceed maximum spawn recursion depth."""
    pass

class SlidingWindowRateLimiter:
    """Sliding-window request and token rate limiter for API cost containment."""
    def __init__(self, window_seconds: float = 60.0, max_requests: int = 60, max_tokens: int = 100000):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        # pid -> deque of (timestamp, tokens)
        self._history: Dict[str, deque] = {}

    def record_and_check(self, pid: str, tokens: int = 0) -> bool:
        """Returns True if within rate limits, False if rate limit breached."""
        now = time.time()
        if pid not in self._history:
            self._history[pid] = deque()

        q = self._history[pid]
        # Purge entries outside window
        while q and (now - q[0][0]) > self.window_seconds:
            q.popleft()

        total_requests = len(q) + 1
        total_tokens = sum(entry[1] for entry in q) + tokens

        if total_requests > self.max_requests or total_tokens > self.max_tokens:
            return False

        q.append((now, tokens))
        return True

class ResourceGovernor:
    """
    Kernel subsystem that enforces security boundaries, resource quotas,
    and circuit breakers to prevent runaway loops and uncontrolled API spending.
    """
    def __init__(
        self,
        max_process_depth: int = 3,
        max_children_per_parent: int = 5,
        max_requests_per_minute: int = 60,
        max_tokens_per_minute: int = 100000
    ):
        self.max_process_depth = max_process_depth
        self.max_children_per_parent = max_children_per_parent
        self.rate_limiter = SlidingWindowRateLimiter(
            max_requests=max_requests_per_minute,
            max_tokens=max_tokens_per_minute
        )

    def check_spawn_permission(self, pcb: ProcessControlBlock):
        """Guard against fork bombs and runaway process trees."""
        if pcb.depth >= self.max_process_depth:
            err = f"Fork-bomb prevented: Process {pcb.pid} (depth {pcb.depth}) reached max process tree depth of {self.max_process_depth}"
            raise ForkBombPrevented(err)
        
        if len(pcb.child_pids) >= self.max_children_per_parent:
            err = f"Process limit reached: Process {pcb.pid} reached maximum child processes limit ({self.max_children_per_parent})"
            raise ForkBombPrevented(err)

    def check_pre_step(self, pcb: ProcessControlBlock):
        """Pre-execution validation before an agent reasoning cycle begins."""
        if pcb.state in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
            raise GovernorViolation(f"Cannot execute process {pcb.pid} in terminal state {pcb.state}")

        if pcb.current_step >= pcb.max_steps:
            pcb.transition_to(
                ProcessState.FAILED,
                error=f"Exceeded maximum reasoning steps ({pcb.max_steps}). Loop halted by Governor."
            )
            raise StepLimitExceeded(pcb.error_message)

        if pcb.tokens_consumed >= pcb.token_budget:
            pcb.transition_to(
                ProcessState.FAILED,
                error=f"Exceeded token budget ({pcb.tokens_consumed}/{pcb.token_budget}). Halted by Governor."
            )
            raise TokenQuotaExceeded(pcb.error_message)

    def check_token_consumption(self, pcb: ProcessControlBlock, tokens: int):
        """Verify if process has sufficient remaining token budget."""
        if (pcb.tokens_consumed + tokens) > pcb.token_budget:
            pcb.transition_to(
                ProcessState.FAILED,
                error=f"Token consumption would exceed budget ({pcb.tokens_consumed + tokens} > {pcb.token_budget})."
            )
            raise TokenQuotaExceeded(pcb.error_message)

    def check_tool_permission(self, pcb: ProcessControlBlock, tool_name: str):
        """Enforce capability-based access control on syscalls."""
        # If allocated_tools is empty or contains "*", all tools are authorized
        if pcb.allocated_tools and ("*" not in pcb.allocated_tools):
            allowed = any(tool_name == pat or fnmatch.fnmatch(tool_name, pat) for pat in pcb.allocated_tools)
            if not allowed:
                err = f"Security Violation: Process {pcb.pid} is not authorized to invoke syscall '{tool_name}'"
                pcb.transition_to(ProcessState.FAILED, error=err)
                raise UnauthorizedToolAccess(err)

    def check_rate_limit(self, pcb: ProcessControlBlock, estimated_tokens: int = 0):
        """Enforce sliding-window rate limits before LLM dispatch."""
        if not self.rate_limiter.record_and_check(pcb.pid, tokens=estimated_tokens):
            err = f"Rate Limit Breached: Process {pcb.pid} exceeded request or token rate limits."
            pcb.transition_to(ProcessState.BLOCKED, error=err)
            raise RateLimitExceeded(err)
