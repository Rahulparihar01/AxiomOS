"""
AI-OS Remote Client SDK.
Provides an ergonomic Python interface for communicating with an AI-OS Kernel
runtime over HTTP/REST and WebSockets.
"""

from typing import Any, Dict, List, Optional
import httpx


class AIOSClient:
    """
    Official Python client for commanding an AI-OS Kernel instance.
    Supports process orchestration, HITL resolutions, deterministic trace replays,
    and BYOK dynamic key management.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_token: Optional[str] = None,
        timeout: float = 30.0,
        http_client: Optional[Any] = None
    ):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.api_token = api_token
        self.timeout = timeout
        self._is_external_client = http_client is not None
        self._client = http_client or httpx.Client(base_url=self.base_url, timeout=self.timeout)

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        if getattr(self._client, "base_url", None) and str(self._client.base_url).strip("/"):
            return path
        return f"{self.base_url}{path}"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["X-AIOS-Token"] = self.api_token
        return headers

    def close(self):
        """Close underlying HTTP client connection pool if locally created."""
        if not self._is_external_client and hasattr(self._client, "close"):
            try:
                self._client.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # --- System & Observability ---

    def health(self) -> Dict[str, Any]:
        """Check container liveness and scheduler status."""
        resp = self._client.get(self._url("/api/health"))
        resp.raise_for_status()
        return resp.json()

    def status(self) -> Dict[str, Any]:
        """Fetch kernel status, active tokens, and memory metrics."""
        resp = self._client.get(self._url("/api/status"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    def system_info(self) -> Dict[str, Any]:
        """Fetch complete subsystem telemetry."""
        resp = self._client.get(self._url("/api/system/info"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    # --- Process Orchestration ---

    def spawn(
        self,
        name: str,
        task_instruction: str,
        priority: str = "NORMAL",
        role: Optional[str] = None,
        token_budget: Optional[int] = None,
        allocated_tools: Optional[List[str]] = None,
        workspace_id: str = "default",
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """Spawn and enqueue a new autonomous agent process."""
        payload = {
            "name": name,
            "task_instruction": task_instruction,
            "priority": priority.upper(),
            "role": role,
            "token_budget": token_budget,
            "allocated_tools": allocated_tools,
            "workspace_id": workspace_id,
            "tenant_id": tenant_id
        }
        resp = self._client.post(
            self._url("/api/processes/spawn"),
            json=payload,
            headers=self._get_headers()
        )
        resp.raise_for_status()
        return resp.json()

    def list_processes(
        self,
        limit: int = 100,
        offset: int = 0,
        workspace_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List active and historical kernel processes."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if workspace_id:
            params["workspace_id"] = workspace_id
        resp = self._client.get(
            self._url("/api/processes"),
            params=params,
            headers=self._get_headers()
        )
        resp.raise_for_status()
        return resp.json()

    def get_process(self, pid: str) -> Dict[str, Any]:
        """Inspect a specific process PCB and working memory."""
        resp = self._client.get(self._url(f"/api/processes/{pid}"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    def kill(self, pid: str) -> bool:
        """Terminate a process and all its descendants."""
        resp = self._client.delete(self._url(f"/api/processes/{pid}"), headers=self._get_headers())
        if resp.status_code == 200:
            return True
        return False

    # --- Human-in-the-Loop (HITL) ---

    def list_hitl(self) -> List[Dict[str, Any]]:
        """List all pending destructive syscall approval requests."""
        resp = self._client.get(self._url("/api/hitl/pending"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    def resolve_hitl(self, request_id: str, approved: bool = True) -> bool:
        """Approve or reject a pending agent operation."""
        resp = self._client.post(
            self._url("/api/hitl/resolve"),
            json={"request_id": request_id, "approved": approved},
            headers=self._get_headers()
        )
        if resp.status_code == 200:
            return True
        return False

    # --- Trace Replay & Compliance Export ---

    def list_traces(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List flight recorder execution traces."""
        resp = self._client.get(self._url("/api/traces"), params={"limit": limit}, headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Get step-by-step history of a trace."""
        resp = self._client.get(self._url(f"/api/traces/{trace_id}"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    def replay_trace(self, trace_id: str) -> Dict[str, Any]:
        """Replay a trace offline deterministically with zero live API calls."""
        resp = self._client.post(self._url(f"/api/traces/{trace_id}/replay"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    def export_trace(self, trace_id: str) -> Dict[str, Any]:
        """Export an audit-ready compliance package for a trace."""
        resp = self._client.get(self._url(f"/api/traces/{trace_id}/export"), headers=self._get_headers())
        resp.raise_for_status()
        return resp.json()

    # --- Dynamic BYOK Secrets Vault ---

    def set_key(self, workspace_id: str, provider: str, api_key: str) -> Dict[str, Any]:
        """Register a provider API key for a specific workspace."""
        resp = self._client.post(
            self._url(f"/api/workspaces/{workspace_id}/keys"),
            json={"provider": provider, "api_key": api_key},
            headers=self._get_headers()
        )
        resp.raise_for_status()
        return resp.json()

    def list_keys(self, workspace_id: str) -> Dict[str, Any]:
        """List configured providers and masked keys for a workspace."""
        resp = self._client.get(
            self._url(f"/api/workspaces/{workspace_id}/keys"),
            headers=self._get_headers()
        )
        resp.raise_for_status()
        return resp.json()

    def delete_key(self, workspace_id: str, provider: str) -> bool:
        """Delete a stored provider API key from a workspace."""
        resp = self._client.delete(
            self._url(f"/api/workspaces/{workspace_id}/keys/{provider}"),
            headers=self._get_headers()
        )
        if resp.status_code == 200:
            return True
        return False
