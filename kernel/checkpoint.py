import asyncio
from contextlib import contextmanager
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from config.settings import settings
from kernel.process import ProcessControlBlock, ProcessState, PriorityLevel
from memory.l1_context import L1ContextManager
from pydantic import BaseModel, Field

class L1SnapshotData(BaseModel):
    """Strict schema for serialized working memory context."""
    system_prompt: str = ""
    max_capacity_tokens: int = 16000
    messages: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Optional[str] = None

class ProcessSnapshot:
    def __init__(self, pid: str, pcb_dict: Dict[str, Any], l1_dict: Dict[str, Any], updated_at: str):
        self.pid = pid
        self.pcb_dict = pcb_dict
        self.l1_dict = l1_dict
        self.updated_at = updated_at

class CheckpointManager:
    """
    Durable Execution & State Checkpoint Manager.
    Persists process execution state and L1 working memory to SQLite,
    enabling automatic crash recovery and fault tolerance across OS reboots.
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
                CREATE TABLE IF NOT EXISTS process_checkpoints (
                    pid TEXT PRIMARY KEY,
                    pcb_json TEXT NOT NULL,
                    l1_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.commit()

    def save_snapshot(self, pcb: ProcessControlBlock, l1: Optional[L1ContextManager] = None):
        """Persist a live snapshot of a process and its working memory."""
        # Only checkpoint active (non-terminal) processes
        if pcb.state in (ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.KILLED):
            self.delete_snapshot(pcb.pid)
            return

        pcb_json = pcb.model_dump_json()
        l1_dict = {}
        if l1:
            l1_dict = {
                "system_prompt": l1.system_prompt,
                "max_capacity_tokens": l1.max_capacity_tokens,
                "messages": l1.messages,
                "summary": l1._summary_context
            }
        l1_json = json.dumps(l1_dict)
        now_str = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO process_checkpoints (pid, pcb_json, l1_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(pid) DO UPDATE SET pcb_json=excluded.pcb_json, l1_json=excluded.l1_json, updated_at=excluded.updated_at",
                (pcb.pid, pcb_json, l1_json, now_str)
            )
            conn.commit()

    async def save_snapshot_async(self, pcb: ProcessControlBlock, l1: Optional[L1ContextManager] = None):
        """Asynchronously persist a process snapshot without blocking the asyncio event loop."""
        await asyncio.to_thread(self.save_snapshot, pcb, l1)

    def delete_snapshot(self, pid: str):
        """Remove checkpoint when process cleanly terminates."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM process_checkpoints WHERE pid = ?", (pid,))
            conn.commit()

    async def delete_snapshot_async(self, pid: str):
        """Asynchronously remove a checkpoint without blocking the asyncio event loop."""
        await asyncio.to_thread(self.delete_snapshot, pid)

    def load_uncompleted_snapshots(self) -> List[Tuple[ProcessControlBlock, Dict[str, Any]]]:
        """Query all uncompleted process snapshots awaiting recovery with strict schema validation."""
        results = []
        with self._get_connection() as conn:
            cur = conn.execute("SELECT pid, pcb_json, l1_json FROM process_checkpoints")
            for row in cur.fetchall():
                try:
                    pcb = ProcessControlBlock.model_validate_json(row[1])
                    l1_data = L1SnapshotData.model_validate_json(row[2])
                    results.append((pcb, l1_data.model_dump()))
                except Exception:
                    continue
        return results

    async def load_uncompleted_snapshots_async(self) -> List[Tuple[ProcessControlBlock, Dict[str, Any]]]:
        """Asynchronously query uncompleted snapshots without blocking the asyncio event loop."""
        return await asyncio.to_thread(self.load_uncompleted_snapshots)

    def clear_all(self):
        """Purge all checkpoints (used for clean-boot testing)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM process_checkpoints")
            conn.commit()

    async def clear_all_async(self):
        """Asynchronously purge all checkpoints without blocking the asyncio event loop."""
        await asyncio.to_thread(self.clear_all)
