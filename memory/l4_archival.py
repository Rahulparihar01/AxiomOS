import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import uuid
from pydantic import BaseModel, Field
from config.settings import settings
from memory.base import BaseMemoryStore, MemoryEntry, MemoryTier

class ArchivalEntryRecord(BaseModel):
    """Schema for validating deserialized archival memory records from SQLite."""
    id: str
    tier: str
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

class VersionedFactRecord(BaseModel):
    """Schema for versioned facts stored in L4 with conflict detection metadata."""
    fact_id: str
    key: str
    value: str
    written_by_pid: Optional[str] = None
    confidence: float = 1.0
    version: int = 1
    superseded_fact_id: Optional[str] = None
    conflict_flag: bool = False
    timestamp: str

class L4ArchivalStore(BaseMemoryStore):
    """
    L4 Archival Store: Persistent relational storage powered by SQLite.
    Stores durable facts, structured key-values, and permanent audit logs.
    Analogous to NVMe Secondary Storage / Hard Disk.
    """
    def __init__(self, db_path: Optional[Path] = None):
        self.tier = MemoryTier.L4_ARCHIVAL
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
        """Initialize database schema with WAL mode for high concurrency."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS archival_memories (
                    id TEXT PRIMARY KEY,
                    tier TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT,
                    tags_json TEXT,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS key_value_facts (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    owner_pid TEXT,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS versioned_facts (
                    fact_id TEXT PRIMARY KEY,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    written_by_pid TEXT,
                    confidence REAL NOT NULL,
                    version INTEGER NOT NULL,
                    superseded_fact_id TEXT,
                    conflict_flag INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_versioned_facts_key_ver ON versioned_facts(key, version DESC);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS task_cost_history (
                    id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    instruction TEXT NOT NULL,
                    tokens_consumed INTEGER NOT NULL,
                    wall_time_seconds REAL NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_task_cost_role ON task_cost_history(role);
            """)
            conn.commit()

    async def add(self, content: str, metadata: Optional[Dict[str, Any]] = None, tags: Optional[List[str]] = None) -> MemoryEntry:
        """Asynchronously insert an archival memory chunk without blocking the asyncio event loop."""
        entry = MemoryEntry(
            tier=self.tier,
            content=content,
            metadata=metadata or {},
            tags=tags or []
        )
        def _write():
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO archival_memories (id, tier, content, metadata_json, tags_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        entry.id,
                        entry.tier.value,
                        entry.content,
                        json.dumps(entry.metadata),
                        json.dumps(entry.tags),
                        entry.created_at.isoformat()
                    )
                )
                conn.commit()
        await asyncio.to_thread(_write)
        return entry

    async def get(self, memory_id: str) -> Optional[MemoryEntry]:
        """Asynchronously retrieve an archival memory record without blocking the asyncio event loop."""
        def _read():
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT id, tier, content, metadata_json, tags_json, created_at FROM archival_memories WHERE id = ?",
                    (memory_id,)
                )
                row = cur.fetchone()
                if not row:
                    return None
                try:
                    raw_meta = json.loads(row[3]) if row[3] else {}
                    raw_tags = json.loads(row[4]) if row[4] else []
                    record = ArchivalEntryRecord(
                        id=row[0],
                        tier=row[1],
                        content=row[2],
                        metadata=raw_meta if isinstance(raw_meta, dict) else {},
                        tags=raw_tags if isinstance(raw_tags, list) else []
                    )
                    return MemoryEntry(
                        id=record.id,
                        tier=MemoryTier(record.tier),
                        content=record.content,
                        metadata=record.metadata,
                        tags=record.tags
                    )
                except Exception:
                    return None
        return await asyncio.to_thread(_read)

    def store_versioned_fact(
        self,
        key: str,
        value: str,
        written_by_pid: Optional[str] = None,
        confidence: float = 1.0
    ) -> Tuple[VersionedFactRecord, bool]:
        """
        Store a persistent, versioned fact with contradiction detection.
        Returns a tuple of (VersionedFactRecord, was_conflict: bool).
        """
        now_str = datetime.now(timezone.utc).isoformat()
        was_conflict = False

        with self._get_connection() as conn:
            # 1. Fetch latest version of this key if one exists
            cur = conn.execute(
                "SELECT fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp "
                "FROM versioned_facts WHERE key = ? ORDER BY version DESC LIMIT 1",
                (key,)
            )
            latest_row = cur.fetchone()

            if latest_row:
                latest_fact = VersionedFactRecord(
                    fact_id=latest_row[0],
                    key=latest_row[1],
                    value=latest_row[2],
                    written_by_pid=latest_row[3],
                    confidence=latest_row[4],
                    version=latest_row[5],
                    superseded_fact_id=latest_row[6],
                    conflict_flag=bool(latest_row[7]),
                    timestamp=latest_row[8]
                )
                new_version = latest_fact.version + 1
                superseded_id = latest_fact.fact_id

                # Contradiction detection: values differ
                if latest_fact.value != value:
                    # If incoming is not an explicit 1.0 override or prior was confident, flag conflict
                    if confidence < 1.0 or latest_fact.confidence >= 0.8:
                        was_conflict = True
            else:
                new_version = 1
                superseded_id = None

            fact_id = f"fact-{uuid.uuid4().hex[:8]}"
            record = VersionedFactRecord(
                fact_id=fact_id,
                key=key,
                value=value,
                written_by_pid=written_by_pid,
                confidence=confidence,
                version=new_version,
                superseded_fact_id=superseded_id,
                conflict_flag=was_conflict,
                timestamp=now_str
            )

            # Insert versioned fact
            conn.execute(
                "INSERT INTO versioned_facts (fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.fact_id,
                    record.key,
                    record.value,
                    record.written_by_pid,
                    record.confidence,
                    record.version,
                    record.superseded_fact_id,
                    1 if record.conflict_flag else 0,
                    record.timestamp
                )
            )

            # Also maintain legacy key_value_facts for fast O(1) lookup
            conn.execute(
                "INSERT INTO key_value_facts (key, value, owner_pid, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, owner_pid=excluded.owner_pid, updated_at=excluded.updated_at",
                (key, value, written_by_pid, now_str)
            )
            conn.commit()

        return record, was_conflict

    def get_latest_fact(self, key: str) -> Optional[VersionedFactRecord]:
        """Retrieve the latest versioned fact record for a key."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp "
                "FROM versioned_facts WHERE key = ? ORDER BY version DESC LIMIT 1",
                (key,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return VersionedFactRecord(
                fact_id=row[0],
                key=row[1],
                value=row[2],
                written_by_pid=row[3],
                confidence=row[4],
                version=row[5],
                superseded_fact_id=row[6],
                conflict_flag=bool(row[7]),
                timestamp=row[8]
            )

    def get_fact_history(self, key: str) -> List[VersionedFactRecord]:
        """Retrieve all historical versions of a fact for a key."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp "
                "FROM versioned_facts WHERE key = ? ORDER BY version ASC",
                (key,)
            )
            return [
                VersionedFactRecord(
                    fact_id=row[0],
                    key=row[1],
                    value=row[2],
                    written_by_pid=row[3],
                    confidence=row[4],
                    version=row[5],
                    superseded_fact_id=row[6],
                    conflict_flag=bool(row[7]),
                    timestamp=row[8]
                )
                for row in cur.fetchall()
            ]

    def store_fact(self, key: str, value: str, owner_pid: Optional[str] = None):
        """Set a persistent fact or variable (maintains backward compatibility)."""
        self.store_versioned_fact(key=key, value=value, written_by_pid=owner_pid, confidence=1.0)

    def get_fact(self, key: str) -> Optional[str]:
        """Retrieve a persistent fact by key."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT value FROM key_value_facts WHERE key = ?", (key,))
            row = cur.fetchone()
            return row[0] if row else None

    def list_facts(self) -> Dict[str, str]:
        """Return all persistent key-value facts."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT key, value FROM key_value_facts")
            return {row[0]: row[1] for row in cur.fetchall()}

    def list_conflicts(self) -> List[VersionedFactRecord]:
        """Return all versioned fact records that have been flagged as conflicting."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp "
                "FROM versioned_facts WHERE conflict_flag = 1 ORDER BY timestamp DESC"
            )
            return [
                VersionedFactRecord(
                    fact_id=row[0],
                    key=row[1],
                    value=row[2],
                    written_by_pid=row[3],
                    confidence=row[4],
                    version=row[5],
                    superseded_fact_id=row[6],
                    conflict_flag=bool(row[7]),
                    timestamp=row[8]
                )
                for row in cur.fetchall()
            ]

    def resolve_conflict(
        self,
        key: str,
        chosen_value: str,
        rationale: str = "",
        resolved_by_pid: Optional[str] = None
    ) -> VersionedFactRecord:
        """
        Resolve a detected conflict on a key by clearing conflict flags on all historical
        records and appending an authoritative, conflict-free version.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            # 1. Clear conflict flags on all existing records for this key
            conn.execute("UPDATE versioned_facts SET conflict_flag = 0 WHERE key = ?", (key,))

            # 2. Get latest version number
            cur = conn.execute("SELECT max(version), fact_id FROM versioned_facts WHERE key = ?", (key,))
            row = cur.fetchone()
            latest_ver = row[0] if (row and row[0] is not None) else 0
            superseded_id = row[1] if (row and row[1] is not None) else None
            next_ver = latest_ver + 1

            fact_id = f"fact-{uuid.uuid4().hex[:8]}"
            record = VersionedFactRecord(
                fact_id=fact_id,
                key=key,
                value=chosen_value,
                written_by_pid=resolved_by_pid,
                confidence=1.0,
                version=next_ver,
                superseded_fact_id=superseded_id,
                conflict_flag=False,
                timestamp=now_str
            )

            conn.execute(
                "INSERT INTO versioned_facts (fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    record.fact_id,
                    record.key,
                    record.value,
                    record.written_by_pid,
                    record.confidence,
                    record.version,
                    record.superseded_fact_id,
                    record.timestamp
                )
            )

            # 3. Update legacy key_value_facts for O(1) reads
            conn.execute(
                "INSERT INTO key_value_facts (key, value, owner_pid, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, owner_pid=excluded.owner_pid, updated_at=excluded.updated_at",
                (key, chosen_value, resolved_by_pid, now_str)
            )
            conn.commit()
            return record


    def list_versioned_facts(self, limit: int = 100) -> List[VersionedFactRecord]:
        """Return recent versioned facts."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT fact_id, key, value, written_by_pid, confidence, version, superseded_fact_id, conflict_flag, timestamp "
                "FROM versioned_facts ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [
                VersionedFactRecord(
                    fact_id=row[0],
                    key=row[1],
                    value=row[2],
                    written_by_pid=row[3],
                    confidence=row[4],
                    version=row[5],
                    superseded_fact_id=row[6],
                    conflict_flag=bool(row[7]),
                    timestamp=row[8]
                )
                for row in cur.fetchall()
            ]

    def log_task_cost(
        self,
        role: str,
        instruction: str,
        tokens_consumed: int,
        wall_time_seconds: float
    ) -> str:
        """Log completed task execution resource telemetry to L4 cost history."""
        cost_id = f"cost-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO task_cost_history (id, role, instruction, tokens_consumed, wall_time_seconds, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cost_id, role, instruction, tokens_consumed, wall_time_seconds, now_str)
            )
            conn.commit()
        return cost_id

    def get_task_cost_history(self, role: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Query historical task cost records."""
        with self._get_connection() as conn:
            if role:
                cur = conn.execute(
                    "SELECT id, role, instruction, tokens_consumed, wall_time_seconds, timestamp "
                    "FROM task_cost_history WHERE role = ? ORDER BY timestamp DESC LIMIT ?",
                    (role, limit)
                )
            else:
                cur = conn.execute(
                    "SELECT id, role, instruction, tokens_consumed, wall_time_seconds, timestamp "
                    "FROM task_cost_history ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
            rows = cur.fetchall()
            return [
                {
                    "id": r[0],
                    "role": r[1],
                    "instruction": r[2],
                    "tokens_consumed": r[3],
                    "wall_time_seconds": r[4],
                    "timestamp": r[5]
                }
                for r in rows
            ]

    async def clear(self):
        """Asynchronously purge all archival memories and tables without blocking the event loop."""
        def _clear():
            with self._get_connection() as conn:
                conn.execute("DELETE FROM archival_memories")
                conn.execute("DELETE FROM key_value_facts")
                conn.execute("DELETE FROM versioned_facts")
                conn.execute("DELETE FROM task_cost_history")
                conn.commit()
        await asyncio.to_thread(_clear)

    async def store_fact_async(self, key: str, value: str, owner_pid: Optional[str] = None):
        """Asynchronous non-blocking wrapper for store_fact."""
        return await asyncio.to_thread(self.store_fact, key, value, owner_pid)

    async def get_fact_async(self, key: str) -> Optional[str]:
        """Asynchronous non-blocking wrapper for get_fact."""
        return await asyncio.to_thread(self.get_fact, key)

    async def list_facts_async(self) -> Dict[str, str]:
        """Asynchronous non-blocking wrapper for list_facts."""
        return await asyncio.to_thread(self.list_facts)

    async def store_versioned_fact_async(
        self,
        key: str,
        value: str,
        written_by_pid: Optional[str] = None,
        confidence: float = 1.0
    ) -> Tuple[VersionedFactRecord, bool]:
        """Asynchronous non-blocking wrapper for store_versioned_fact."""
        return await asyncio.to_thread(self.store_versioned_fact, key, value, written_by_pid, confidence)

    async def get_latest_fact_async(self, key: str) -> Optional[VersionedFactRecord]:
        """Asynchronous non-blocking wrapper for get_latest_fact."""
        return await asyncio.to_thread(self.get_latest_fact, key)

    async def get_fact_history_async(self, key: str) -> List[VersionedFactRecord]:
        """Asynchronous non-blocking wrapper for get_fact_history."""
        return await asyncio.to_thread(self.get_fact_history, key)

    async def list_conflicts_async(self) -> List[VersionedFactRecord]:
        """Asynchronous non-blocking wrapper for list_conflicts."""
        return await asyncio.to_thread(self.list_conflicts)

    async def resolve_conflict_async(
        self,
        key: str,
        authoritative_value: str,
        resolved_by_pid: str,
        reasoning: str = ""
    ) -> Optional[VersionedFactRecord]:
        """Asynchronous non-blocking wrapper for resolve_conflict."""
        return await asyncio.to_thread(self.resolve_conflict, key, authoritative_value, resolved_by_pid, reasoning)

    async def list_versioned_facts_async(self, limit: int = 100) -> List[VersionedFactRecord]:
        """Asynchronous non-blocking wrapper for list_versioned_facts."""
        return await asyncio.to_thread(self.list_versioned_facts, limit)

    async def log_task_cost_async(
        self,
        role: str,
        instruction: str,
        tokens_consumed: int,
        wall_time_seconds: float
    ) -> str:
        """Asynchronous non-blocking wrapper for log_task_cost."""
        return await asyncio.to_thread(self.log_task_cost, role, instruction, tokens_consumed, wall_time_seconds)

    async def get_task_cost_history_async(self, role: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Asynchronous non-blocking wrapper for get_task_cost_history."""
        return await asyncio.to_thread(self.get_task_cost_history, role, limit)
