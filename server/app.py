import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field

from config.settings import settings
from kernel.process import PriorityLevel, ProcessControlBlock

class SpawnRequest(BaseModel):
    name: str
    task_instruction: str
    priority: str = "NORMAL"
    token_budget: Optional[int] = None
    allocated_tools: Optional[List[str]] = None
    role: Optional[str] = None
    workspace_id: str = "default"
    tenant_id: str = "default"

class HITLResolutionRequest(BaseModel):
    request_id: str
    approved: bool

class CostEstimateRequest(BaseModel):
    role: str
    instruction: str

class SetVaultKeyRequest(BaseModel):
    provider: str
    api_key: str

from security.vault import SecretsVault
from contextlib import asynccontextmanager

API_KEY_HEADER = APIKeyHeader(name="X-AIOS-Token", auto_error=False)

def verify_admin_token(token: Optional[str] = Depends(API_KEY_HEADER)):
    """Enforce API token authentication when AIOS_ADMIN_TOKEN is configured."""
    if settings.admin_token:
        if not token or token != settings.admin_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Missing or invalid X-AIOS-Token header."
            )
    return token

def create_app(kernel) -> FastAPI:
    """Factory function creating the FastAPI Web Control Center bound to a Kernel instance."""
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: Run persistent background worker pool
        kernel.start_daemon()
        yield
        # Shutdown: Stop worker pool and release pooled connections
        if hasattr(kernel, "aclose"):
            await kernel.aclose()
        else:
            kernel.stop_daemon()

    app = FastAPI(title="AI-OS Control Center", version=settings.version, lifespan=lifespan)

    # Configure CORS protection
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    static_dir = Path(__file__).resolve().parent / "static"
    active_queues: List[asyncio.Queue] = []

    @app.get("/", response_class=HTMLResponse)
    async def get_dashboard():
        index_path = static_dir / "index.html"
        if not index_path.exists():
            return HTMLResponse("<h1>AI-OS Control Center UI missing</h1>", status_code=404)
        return FileResponse(index_path)

    @app.websocket("/ws/stream")
    async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
        """Bidirectional WebSocket streaming real-time process updates and telemetry."""
        # Enforce authentication on WebSocket connection if admin token configured
        if settings.admin_token and token != settings.admin_token:
            await websocket.close(code=1008, reason="Unauthorized: Missing or invalid token")
            return

        await websocket.accept()
        queue: asyncio.Queue = asyncio.Queue()
        active_queues.append(queue)

        async def sender():
            try:
                while True:
                    data = await queue.get()
                    await websocket.send_text(data)
            except Exception:
                pass

        sender_task = asyncio.create_task(sender())

        try:
            while True:
                # Keepalive / ping
                msg = await websocket.receive_text()
                if msg == "ping":
                    await queue.put(json.dumps({"type": "pong"}))
        except WebSocketDisconnect:
            pass
        finally:
            sender_task.cancel()
            if queue in active_queues:
                active_queues.remove(queue)

    process_stream_buffers: Dict[str, str] = {}

    def broadcast_process_event(pcb: ProcessControlBlock):
        """Kernel listener pushing process telemetry to connected WebSockets."""
        if not active_queues:
            return
        payload = json.dumps({
            "type": "process_update",
            "process": pcb.model_dump()
        }, default=str)
        
        for q in list(active_queues):
            try:
                q.put_nowait(payload)
            except Exception:
                pass

    kernel.add_process_listener(broadcast_process_event)

    def broadcast_token_chunk(pid: str, delta: str):
        """Kernel listener pushing live token stream deltas to connected WebSockets and buffering recent stream content."""
        if pid not in process_stream_buffers:
            process_stream_buffers[pid] = ""
        if len(process_stream_buffers[pid]) < 100000:
            process_stream_buffers[pid] += delta

        if not active_queues:
            return
        payload = json.dumps({
            "type": "token_chunk",
            "pid": pid,
            "delta": delta
        })
        for q in list(active_queues):
            try:
                q.put_nowait(payload)
            except Exception:
                pass

    if hasattr(kernel, "add_token_listener"):
        kernel.add_token_listener(broadcast_token_chunk)

    def broadcast_hitl_event(event_type: str, req: Any):
        """Kernel listener pushing HITL request/resolution events to connected WebSockets."""
        if not active_queues:
            return
        payload = json.dumps({
            "type": event_type,
            "request": req.model_dump() if hasattr(req, "model_dump") else req
        }, default=str)
        for q in list(active_queues):
            try:
                q.put_nowait(payload)
            except Exception:
                pass

    if hasattr(kernel.hitl_manager, "add_listener"):
        kernel.hitl_manager.add_listener(broadcast_hitl_event)

    boot_time = time.time()

    @app.get("/api/health")
    async def get_health() -> Dict[str, Any]:
        """Standard liveness/readiness probe for container orchestration."""
        return {
            "status": "healthy",
            "os_name": settings.os_name,
            "version": settings.version,
            "uptime_seconds": round(time.time() - boot_time, 2),
            "scheduler_active": kernel.scheduler is not None,
            "daemon_running": getattr(kernel, "_daemon_running", False)
        }

    @app.get("/api/system/info")
    async def get_system_info() -> Dict[str, Any]:
        """Enterprise observability endpoint for system status and subsystem telemetry."""
        processes = kernel.scheduler.list_processes()
        return {
            "os_name": settings.os_name,
            "version": settings.version,
            "uptime_seconds": round(time.time() - boot_time, 2),
            "subsystems": {
                "scheduler": {
                    "total_processes": len(processes),
                    "workers": settings.default_workers,
                    "daemon_running": getattr(kernel, "_daemon_running", False)
                },
                "security": {
                    "sandbox_backend": settings.sandbox_backend,
                    "auth_enabled": bool(settings.admin_token)
                },
                "memory": {
                    "embedding_provider": settings.embedding_provider,
                    "stats": kernel.mmu.get_memory_stats()
                },
                "ipc": kernel.message_bus.get_stats(),
                "hitl": kernel.hitl_manager.get_stats()
            }
        }

    @app.get("/api/status")
    async def get_status() -> Dict[str, Any]:
        processes = kernel.scheduler.list_processes()
        total_tokens = sum(p.tokens_consumed for p in processes.values())
        return {
            "os_name": settings.os_name,
            "version": settings.version,
            "active_processes": len(processes),
            "total_tokens_consumed": total_tokens,
            "memory": kernel.mmu.get_memory_stats(),
            "ipc": kernel.message_bus.get_stats(),
            "hitl": kernel.hitl_manager.get_stats(),
            "config": {
                "sandbox_backend": settings.sandbox_backend,
                "embedding_provider": settings.embedding_provider,
                "default_provider": settings.default_provider,
                "workers": settings.default_workers,
                "http_pool_keepalive": settings.http_pool_max_keepalive
            }
        }

    @app.get("/api/processes")
    async def list_processes(limit: int = 100, offset: int = 0, workspace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        processes = kernel.scheduler.list_processes()
        if workspace_id:
            all_procs = [p.model_dump() for p in processes.values() if getattr(p, "workspace_id", "default") == workspace_id]
        else:
            all_procs = [p.model_dump() for p in processes.values()]
        return all_procs[offset: offset + limit]

    @app.get("/api/processes/{pid}")
    async def get_process_detail(pid: str) -> Dict[str, Any]:
        pcb = kernel.scheduler.get_process(pid)
        if not pcb:
            raise HTTPException(status_code=404, detail=f"Process '{pid}' not found")
        l1 = kernel.mmu.get_l1(pid)
        streamed = process_stream_buffers.get(pid)
        if not streamed:
            if pcb.result:
                streamed = pcb.result
            elif l1 and l1.messages:
                for m in reversed(l1.messages):
                    if m.get("role") == "assistant" and m.get("content"):
                        streamed = m.get("content")
                        break
        return {
            "process": pcb.model_dump(),
            "messages": l1.messages if l1 else [],
            "summary": l1._summary_context if l1 else None,
            "recalled": l1._recalled_context if l1 else [],
            "streamed_content": streamed or ""
        }

    @app.delete("/api/processes/{pid}", dependencies=[Depends(verify_admin_token)])
    async def terminate_process(pid: str) -> Dict[str, Any]:
        success = kernel.kill_process(pid)
        if not success:
            raise HTTPException(status_code=404, detail=f"Process '{pid}' not found or already terminated")
        return {"success": True, "pid": pid, "state": "KILLED"}

    @app.post("/api/processes/spawn", dependencies=[Depends(verify_admin_token)])
    async def spawn_process(req: SpawnRequest) -> Dict[str, Any]:
        priority_enum = getattr(PriorityLevel, req.priority.upper(), PriorityLevel.NORMAL)
        pcb = kernel.spawn_process(
            name=req.name,
            task_instruction=req.task_instruction,
            priority=priority_enum,
            token_budget=req.token_budget,
            allocated_tools=req.allocated_tools,
            role=req.role,
            workspace_id=req.workspace_id,
            tenant_id=req.tenant_id
        )
        return {
            "success": True,
            "pid": pcb.pid,
            "name": pcb.name,
            "state": pcb.state.value,
            "workspace_id": pcb.workspace_id,
            "tenant_id": pcb.tenant_id
        }

    @app.get("/api/hitl/pending")
    async def list_pending_hitl() -> List[Dict[str, Any]]:
        return [r.model_dump() for r in kernel.hitl_manager.list_pending()]

    @app.post("/api/hitl/resolve", dependencies=[Depends(verify_admin_token)])
    async def resolve_hitl(req: HITLResolutionRequest) -> Dict[str, Any]:
        success = kernel.hitl_manager.resolve_request(
            request_id=req.request_id,
            approved=req.approved,
            resolver="WEB_CONTROL_CENTER"
        )
        if not success:
            raise HTTPException(status_code=404, detail="Request ID not found or already resolved")
        return {"success": True, "request_id": req.request_id, "approved": req.approved}

    @app.get("/api/blackboard")
    async def get_blackboard() -> Dict[str, Any]:
        topics = kernel.blackboard.list_topics()
        return {topic: kernel.blackboard.read_topic(topic) for topic in topics}

    # --- Replay & Trace Endpoints ---
    @app.get("/api/traces")
    @app.get("/api/replay/traces")
    async def list_traces(limit: int = 50) -> List[Dict[str, Any]]:
        return kernel.flight_recorder.list_traces(limit=limit)

    @app.get("/api/traces/{trace_id}")
    @app.get("/api/replay/traces/{trace_id}/records")
    async def get_trace_records(trace_id: str) -> List[Dict[str, Any]]:
        records = kernel.flight_recorder.get_trace(trace_id)
        if not records:
            raise HTTPException(status_code=404, detail=f"Trace '{trace_id}' not found")
        return [r.model_dump() for r in records]

    @app.post("/api/traces/{trace_id}/replay")
    @app.get("/api/replay/traces/{trace_id}")
    async def replay_trace(trace_id: str) -> Dict[str, Any]:
        trace = kernel.flight_recorder.get_trace(trace_id)
        if not trace:
            raise HTTPException(status_code=404, detail=f"Trace '{trace_id}' not found")
        result = await kernel.replay_engine.replay_trace_async(trace_id)
        return result.model_dump()

    # --- Memory & Conflict Endpoints (EGAP-03) ---
    @app.get("/api/memory/facts")
    async def list_memory_facts() -> Dict[str, Any]:
        return {
            "facts": kernel.mmu.l4_archival.list_facts(),
            "versioned": [f.model_dump() for f in kernel.mmu.l4_archival.list_versioned_facts()]
        }

    @app.get("/api/memory/conflicts")
    async def list_memory_conflicts() -> List[Dict[str, Any]]:
        return [c.model_dump() for c in kernel.mmu.l4_archival.list_conflicts()]

    # --- Cost Estimation & History Endpoints ---
    @app.get("/api/costs/history")
    async def get_costs_history(role: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        return kernel.mmu.l4_archival.get_task_cost_history(role=role, limit=limit)

    @app.post("/api/costs/estimate")
    async def estimate_task_cost(req: CostEstimateRequest) -> Dict[str, Any]:
        est = kernel.cost_estimator.estimate(role=req.role, instruction=req.instruction)
        return est.model_dump()

    # --- Model Context Protocol (MCP) JSON-RPC Endpoint (GAP-13) ---
    @app.post("/api/mcp")
    async def mcp_json_rpc_endpoint(request: Request) -> Dict[str, Any]:
        """
        Model Context Protocol (MCP) JSON-RPC 2.0 HTTP transport endpoint.
        Exposes AI-OS kernel tools, processes, and memory to external MCP clients.
        """
        try:
            body = await request.json()
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(exc)}"}
            }

        response = await kernel.mcp_server.handle_json_rpc(body)
        if response is None:
            return {}
        return response

    # --- BYOK Secrets Vault Endpoints ---
    vault = SecretsVault()

    @app.post("/api/workspaces/{workspace_id}/keys", dependencies=[Depends(verify_admin_token)])
    async def set_workspace_key(workspace_id: str, req: SetVaultKeyRequest) -> Dict[str, Any]:
        vault.set_key(workspace_id, req.provider, req.api_key)
        return {
            "success": True,
            "workspace_id": workspace_id,
            "provider": req.provider.strip().lower(),
            "masked_key": vault.mask_key(req.api_key)
        }

    @app.get("/api/workspaces/{workspace_id}/keys", dependencies=[Depends(verify_admin_token)])
    async def list_workspace_keys(workspace_id: str) -> Dict[str, Any]:
        keys = vault.list_keys(workspace_id)
        return {"workspace_id": workspace_id, "keys": keys}

    @app.delete("/api/workspaces/{workspace_id}/keys/{provider}", dependencies=[Depends(verify_admin_token)])
    async def delete_workspace_key(workspace_id: str, provider: str) -> Dict[str, Any]:
        deleted = vault.delete_key(workspace_id, provider)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"No key found for provider '{provider}' in workspace '{workspace_id}'")
        return {"success": True, "workspace_id": workspace_id, "provider": provider}

    # --- Trace Compliance Export Endpoint ---
    @app.get("/api/traces/{trace_id}/export")
    async def export_trace(trace_id: str) -> Dict[str, Any]:
        records = kernel.flight_recorder.get_trace(trace_id)
        if not records:
            raise HTTPException(status_code=404, detail=f"Trace '{trace_id}' not found")
        
        replay_result = await kernel.replay_engine.replay_trace_async(trace_id)
        model_calls = [r for r in records if r.record_type == "model_call"]
        syscalls = [r for r in records if r.record_type == "syscall"]

        return {
            "export_schema_version": "1.0.0",
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": trace_id,
            "audit_summary": {
                "total_records": len(records),
                "model_calls_count": len(model_calls),
                "syscalls_count": len(syscalls),
                "deterministic_reproducibility": replay_result.is_reproducible,
                "divergence_step": replay_result.divergence_step,
                "error": replay_result.error
            },
            "records": [r.model_dump() for r in records]
        }

    return app
