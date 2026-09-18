from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
import uuid

class IPCMessageType(str, Enum):
    TASK_DELEGATION = "TASK_DELEGATION"    # Parent assigning subtask to child
    TASK_RESULT = "TASK_RESULT"            # Worker returning completed output
    DIRECT_MESSAGE = "DIRECT_MESSAGE"      # Peer-to-peer communication
    BROADCAST = "BROADCAST"                # System-wide announcement
    SIGNAL_HALT = "SIGNAL_HALT"            # Termination or interrupt signal
    MEMORY_CONFLICT = "MEMORY_CONFLICT"    # Notification of contradictory facts in memory

class IPCMessage(BaseModel):
    """
    Structured A2A (Agent-to-Agent) IPC message envelope.
    Ensures validated schemas, distributed trace correlation, and auditability.
    """
    message_id: str = Field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:8]}")
    trace_id: str = Field(default_factory=lambda: f"trace-{uuid.uuid4().hex[:8]}")
    sender_pid: str
    recipient_pid: str  # PID of target process or '*' for broadcast
    msg_type: IPCMessageType = IPCMessageType.DIRECT_MESSAGE
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

def create_conflict_message(
    sender_pid: str,
    key: str,
    existing_value: Any,
    incoming_value: Any,
    existing_written_by: Optional[str] = None,
    incoming_written_by: Optional[str] = None,
    trace_id: Optional[str] = None
) -> IPCMessage:
    """Helper to construct a standard MEMORY_CONFLICT IPCMessage."""
    return IPCMessage(
        trace_id=trace_id or f"trace-{uuid.uuid4().hex[:8]}",
        sender_pid=sender_pid,
        recipient_pid="*",
        msg_type=IPCMessageType.MEMORY_CONFLICT,
        payload={
            "key": key,
            "existing_value": existing_value,
            "existing_written_by": existing_written_by,
            "incoming_value": incoming_value,
            "incoming_written_by": incoming_written_by,
            "resolution": "PENDING"
        }
    )
