import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field
from config.settings import settings

class TraceRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"rec-{uuid.uuid4().hex[:8]}")
    trace_id: str
    step_seq: int
    record_type: str # "model_call" or "syscall"
    prompt_hash: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class FlightRecorder:
    """
    Flight Recorder subsystem for deterministic replay and auditability.
    Appends execution steps (model calls and syscall invocations) into SQLite WAL,
    allowing reproduction of production failures offline.
    """
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (settings.workspace_root / "aios_memory.db")
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Context manager providing a SQLite connection that is guaranteed to close."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flight_recorder_traces (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    step_seq INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    prompt_hash TEXT,
                    payload_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_traces_trace_step ON flight_recorder_traces(trace_id, step_seq ASC);
            """)
            conn.commit()

    def record_model_call(
        self,
        trace_id: str,
        step_seq: int,
        prompt: Any,
        response_content: Optional[str],
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
        seed: Optional[int] = 42
    ) -> str:
        """Record an LLM generation interaction."""
        prompt_str = json.dumps(prompt, default=str)
        prompt_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()[:16]
        rec_id = f"rec-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()

        payload = {
            "prompt": prompt,
            "response_content": response_content,
            "tool_calls": tool_calls or [],
            "temperature": temperature,
            "seed": seed
        }

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO flight_recorder_traces (id, trace_id, step_seq, record_type, prompt_hash, payload_json, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rec_id, trace_id, step_seq, "model_call", prompt_hash, json.dumps(payload), now_str)
            )
            conn.commit()
        return rec_id

    async def record_model_call_async(
        self,
        trace_id: str,
        step_seq: int,
        prompt: Any,
        response_content: Optional[str],
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
        seed: Optional[int] = 42
    ) -> str:
        """Asynchronously record an LLM generation interaction without blocking the event loop."""
        return await asyncio.to_thread(
            self.record_model_call,
            trace_id,
            step_seq,
            prompt,
            response_content,
            tool_calls,
            temperature,
            seed
        )

    def record_syscall(
        self,
        trace_id: str,
        step_seq: int,
        syscall_name: str,
        input_kwargs: Dict[str, Any],
        success: bool,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        duration_ms: float = 0.0
    ) -> str:
        """Record a system call execution."""
        rec_id = f"rec-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()

        payload = {
            "syscall_name": syscall_name,
            "input_kwargs": input_kwargs,
            "success": success,
            "data": data,
            "error": error,
            "duration_ms": duration_ms
        }

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO flight_recorder_traces (id, trace_id, step_seq, record_type, prompt_hash, payload_json, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rec_id, trace_id, step_seq, "syscall", None, json.dumps(payload), now_str)
            )
            conn.commit()
        return rec_id

    async def record_syscall_async(
        self,
        trace_id: str,
        step_seq: int,
        syscall_name: str,
        input_kwargs: Dict[str, Any],
        success: bool,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        duration_ms: float = 0.0
    ) -> str:
        """Asynchronously record a system call execution without blocking the event loop."""
        return await asyncio.to_thread(
            self.record_syscall,
            trace_id,
            step_seq,
            syscall_name,
            input_kwargs,
            success,
            data,
            error,
            duration_ms
        )

    def get_trace(self, trace_id: str) -> List[TraceRecord]:
        """Load all sequential trace records for a given trace ID."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT id, trace_id, step_seq, record_type, prompt_hash, payload_json, timestamp "
                "FROM flight_recorder_traces WHERE trace_id = ? ORDER BY step_seq ASC, timestamp ASC",
                (trace_id,)
            )
            records = []
            for r in cur.fetchall():
                try:
                    payload = json.loads(r[5]) if r[5] else {}
                except Exception:
                    payload = {}
                records.append(TraceRecord(
                    id=r[0],
                    trace_id=r[1],
                    step_seq=r[2],
                    record_type=r[3],
                    prompt_hash=r[4],
                    payload=payload,
                    timestamp=r[6]
                ))
            return records

    async def get_trace_async(self, trace_id: str) -> List[TraceRecord]:
        """Asynchronously load all sequential trace records without blocking the event loop."""
        return await asyncio.to_thread(self.get_trace, trace_id)

    def list_traces(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List distinct available trace IDs with their summary stats."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT trace_id, count(*), min(timestamp), max(timestamp) "
                "FROM flight_recorder_traces GROUP BY trace_id ORDER BY max(timestamp) DESC LIMIT ?",
                (limit,)
            )
            return [
                {
                    "trace_id": row[0],
                    "records_count": row[1],
                    "started_at": row[2],
                    "ended_at": row[3]
                }
                for row in cur.fetchall()
            ]

    async def list_traces_async(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Asynchronously list traces without blocking the event loop."""
        return await asyncio.to_thread(self.list_traces, limit)

    def prune_traces(self, retention_days: Optional[int] = None) -> int:
        """
        Prune trace records older than retention_days.
        Defaults to settings.trace_retention_days if not specified.
        Returns the number of pruned trace rows.
        """
        days = retention_days if retention_days is not None else settings.trace_retention_days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM flight_recorder_traces WHERE timestamp < ?",
                (cutoff,)
            )
            conn.commit()
            return cur.rowcount

    async def prune_traces_async(self, retention_days: Optional[int] = None) -> int:
        """Asynchronously prune old trace records without blocking the event loop."""
        return await asyncio.to_thread(self.prune_traces, retention_days)

    def clear(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM flight_recorder_traces")
            conn.commit()

    async def clear_async(self):
        await asyncio.to_thread(self.clear)
