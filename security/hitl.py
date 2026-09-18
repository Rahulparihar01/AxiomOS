import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field
import uuid

class ApprovalRequest(BaseModel):
    """Structured request for Human-in-the-Loop authorization."""
    request_id: str = Field(default_factory=lambda: f"hitl-{uuid.uuid4().hex[:8]}")
    pid: str
    syscall_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str = "RING_3_DESTRUCTIVE"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    approved: Optional[bool] = None
    resolver: Optional[str] = None

class HITLManager:
    """
    Human-in-the-Loop (HITL) Authorization Manager.
    Intercepts Ring 3 destructive syscalls, suspends agent execution,
    and requires explicit human operator confirmation.
    """
    def __init__(self, auto_approve_policy: bool = False):
        self.auto_approve_policy = auto_approve_policy
        self._pending: Dict[str, Tuple[ApprovalRequest, asyncio.Event]] = {}
        self._history: List[ApprovalRequest] = []
        self._listeners: List[Any] = []

    def add_listener(self, callback: Any):
        """Register a callback invoked when an approval request is created or resolved."""
        self._listeners.append(callback)

    def _notify(self, event_type: str, req: ApprovalRequest):
        for cb in list(self._listeners):
            try:
                cb(event_type, req)
            except Exception:
                pass

    def create_request(self, pid: str, syscall_name: str, arguments: Dict[str, Any]) -> ApprovalRequest:
        """Register a new pending approval request."""
        req = ApprovalRequest(
            pid=pid,
            syscall_name=syscall_name,
            arguments=arguments,
            risk_level="RING_3_DESTRUCTIVE"
        )
        
        event = asyncio.Event()
        if self.auto_approve_policy:
            req.resolved = True
            req.approved = True
            req.resolver = "AUTO_POLICY_OVERRIDE"
            event.set()
            self._history.append(req)
        else:
            self._pending[req.request_id] = (req, event)
            self._notify("hitl_requested", req)
            
        return req

    async def wait_for_decision(self, request_id: str, timeout: Optional[float] = None) -> bool:
        """Wait asynchronously until human operator approves or rejects the request."""
        if self.auto_approve_policy:
            return True

        item = self._pending.get(request_id)
        if not item:
            # Check history
            for h in self._history:
                if h.request_id == request_id:
                    return bool(h.approved)
            return False

        req, event = item
        try:
            if timeout:
                await asyncio.wait_for(event.wait(), timeout=timeout)
            else:
                await event.wait()
            return bool(req.approved)
        except asyncio.TimeoutError:
            # Reject on timeout
            self.resolve_request(request_id, approved=False, resolver="TIMEOUT_AUTO_REJECT")
            return False

    def resolve_request(self, request_id: str, approved: bool, resolver: str = "HUMAN_OPERATOR") -> bool:
        """Resolve a pending request and signal waiting agent."""
        item = self._pending.pop(request_id, None)
        if not item:
            return False

        req, event = item
        req.resolved = True
        req.approved = approved
        req.resolver = resolver
        self._history.append(req)
        event.set()
        self._notify("hitl_resolved", req)
        return True

    def list_pending(self) -> List[ApprovalRequest]:
        """Return list of all currently unresolved approval requests."""
        return [req for req, _ in self._pending.values()]

    def get_history(self) -> List[ApprovalRequest]:
        return list(self._history)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "pending_count": len(self._pending),
            "total_resolved": len(self._history),
            "approved_count": sum(1 for r in self._history if r.approved),
            "rejected_count": sum(1 for r in self._history if not r.approved)
        }
