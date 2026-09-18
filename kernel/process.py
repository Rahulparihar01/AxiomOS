from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import uuid

class ProcessState(str, Enum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"         # Waiting on I/O, tool response, or human approval
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"

class PriorityLevel(int, Enum):
    BACKGROUND = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

class ProcessControlBlock(BaseModel):
    """
    Process Control Block (PCB) representing an isolated execution context for an AI agent.
    Maintains process identity, execution state, resource accounting, and security boundaries.
    """
    pid: str = Field(default_factory=lambda: f"proc-{uuid.uuid4().hex[:8]}")
    tenant_id: str = "default"
    workspace_id: str = "default"
    parent_pid: Optional[str] = None
    depth: int = 0
    child_pids: List[str] = Field(default_factory=list)
    name: str
    role: str = "base"
    state: ProcessState = ProcessState.CREATED
    priority: PriorityLevel = PriorityLevel.NORMAL
    
    # Resource quotas and accounting
    token_budget: int = 50000
    tokens_consumed: int = 0
    max_steps: int = 15
    current_step: int = 0
    predicted_tokens_p90: Optional[int] = None
    cost_confidence: float = 0.0

    # Memory Subsystem Telemetry
    l1_token_count: int = 0
    l1_capacity: int = 4000
    l1_utilization_pct: float = 0.0
    paged_chunks_count: int = 0
    
    # Security & Tool permissions
    allocated_tools: List[str] = Field(default_factory=list)
    environment_vars: Dict[str, str] = Field(default_factory=dict)
    capability_token: Optional[Any] = None

    @field_validator("capability_token", mode="before")
    @classmethod
    def _deserialize_capability_token(cls, v):
        if isinstance(v, dict):
            try:
                from security.capability import CapabilityToken
                return CapabilityToken.model_validate(v)
            except Exception:
                return v
        return v
    
    # Execution tracing & Output
    trace_id: str = Field(default_factory=lambda: f"trace-{uuid.uuid4().hex[:8]}")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    exit_code: Optional[int] = None
    error_message: Optional[str] = None
    result: Optional[Any] = None

    def transition_to(self, new_state: ProcessState, error: Optional[str] = None):
        """Transition process state with timestamp update and optional error logging."""
        self.state = new_state
        self.updated_at = datetime.now(timezone.utc)
        if error:
            self.error_message = error
            self.exit_code = 1
        elif new_state == ProcessState.COMPLETED:
            self.exit_code = 0

    def consume_tokens(self, amount: int):
        """Account for tokens consumed by this process."""
        self.tokens_consumed += amount
        self.updated_at = datetime.now(timezone.utc)

    def increment_step(self) -> int:
        """Advance the execution step counter."""
        self.current_step += 1
        self.updated_at = datetime.now(timezone.utc)
        return self.current_step
