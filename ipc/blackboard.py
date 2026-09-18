import asyncio
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

class BlackboardEntry:
    def __init__(self, key: str, value: Any, author_pid: str, updated_at: Optional[datetime] = None):
        self.key = key
        self.value = value
        self.author_pid = author_pid
        self.updated_at = updated_at or datetime.now(timezone.utc)

class SharedBlackboard:
    """
    Shared Blackboard Architecture for collaborative multi-agent problem solving.
    Enables decoupled agents to write state, post intermediate findings,
    subscribe to topics, and asynchronously await specific keys without spin-polling.
    Optionally backed by SQLite WAL storage for durability across kernel reboots and crashes.
    """
    def __init__(self, db_path: Optional[Any] = None):
        # topic -> {key -> BlackboardEntry}
        self._topics: Dict[str, Dict[str, BlackboardEntry]] = {}
        self._subscribers: Dict[str, List[Callable[[str, str, Any, str], None]]] = {}
        # (topic, key) -> List[asyncio.Event]
        self._waiters: Dict[Tuple[str, str], List[asyncio.Event]] = {}
        self.db_path = str(db_path) if db_path is not None else None
        if self.db_path:
            self._init_db()
            self._load_from_db()

    @contextmanager
    def _get_connection(self):
        """Context manager providing a SQLite connection that is guaranteed to close."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initialize durable blackboard table and WAL journal mode."""
        if not self.db_path:
            return
        try:
            with self._get_connection() as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS durable_blackboard_entries (
                        topic TEXT NOT NULL,
                        key TEXT NOT NULL,
                        value_json TEXT NOT NULL,
                        author_pid TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (topic, key)
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_blackboard_topic 
                    ON durable_blackboard_entries(topic);
                """)
                conn.commit()
        except Exception:
            pass

    def _load_from_db(self):
        """Hydrate in-memory topics from SQLite durable table."""
        if not self.db_path:
            return
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT topic, key, value_json, author_pid, updated_at FROM durable_blackboard_entries")
                rows = cursor.fetchall()
                for topic, key, value_json, author_pid, updated_at_str in rows:
                    try:
                        value = json.loads(value_json)
                    except Exception:
                        value = value_json
                    try:
                        dt = datetime.fromisoformat(updated_at_str)
                    except Exception:
                        dt = datetime.now(timezone.utc)

                    if topic not in self._topics:
                        self._topics[topic] = {}
                    self._topics[topic][key] = BlackboardEntry(
                        key=key,
                        value=value,
                        author_pid=author_pid,
                        updated_at=dt
                    )
        except Exception:
            pass

    def _persist_entry(self, topic: str, key: str, value: Any, author_pid: str, updated_at: datetime):
        """Upsert a single blackboard entry to SQLite."""
        if not self.db_path:
            return
        try:
            val_str = json.dumps(value)
        except (TypeError, ValueError):
            val_str = json.dumps(str(value))
        
        updated_str = updated_at.isoformat()
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO durable_blackboard_entries 
                    (topic, key, value_json, author_pid, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (topic, key, val_str, author_pid, updated_str))
                conn.commit()
        except Exception:
            pass

    def write(self, topic: str, key: str, value: Any, author_pid: str):
        """Write or update an entry on the shared blackboard."""
        if topic not in self._topics:
            self._topics[topic] = {}
        
        entry = BlackboardEntry(key=key, value=value, author_pid=author_pid)
        self._topics[topic][key] = entry

        if self.db_path:
            self._persist_entry(topic, key, value, author_pid, entry.updated_at)

        # Notify subscribers
        for callback in self._subscribers.get(topic, []):
            try:
                callback(topic, key, value, author_pid)
            except Exception:
                pass

        # Wake up any coroutines waiting for this specific key
        waiter_key = (topic, key)
        if waiter_key in self._waiters:
            for event in self._waiters[waiter_key]:
                event.set()
            del self._waiters[waiter_key]

    async def write_async(self, topic: str, key: str, value: Any, author_pid: str):
        """Asynchronously write or update an entry on the shared blackboard without blocking the event loop."""
        if topic not in self._topics:
            self._topics[topic] = {}
        
        entry = BlackboardEntry(key=key, value=value, author_pid=author_pid)
        self._topics[topic][key] = entry

        if self.db_path:
            await asyncio.to_thread(self._persist_entry, topic, key, value, author_pid, entry.updated_at)

        # Notify subscribers
        for callback in self._subscribers.get(topic, []):
            try:
                callback(topic, key, value, author_pid)
            except Exception:
                pass

        # Wake up any coroutines waiting for this specific key
        waiter_key = (topic, key)
        if waiter_key in self._waiters:
            for event in self._waiters[waiter_key]:
                event.set()
            del self._waiters[waiter_key]

    def read(self, topic: str, key: str) -> Optional[Any]:
        """Read a single value from the blackboard."""
        topic_entries = self._topics.get(topic)
        if not topic_entries:
            return None
        entry = topic_entries.get(key)
        return entry.value if entry else None

    def get_entry(self, topic: str, key: str) -> Optional[BlackboardEntry]:
        """Get the full BlackboardEntry object including author_pid and timestamp."""
        topic_entries = self._topics.get(topic)
        if not topic_entries:
            return None
        return topic_entries.get(key)

    async def wait_for_key(self, topic: str, key: str, timeout: float = 10.0) -> Optional[Any]:
        """Asynchronously await a blackboard key to be written, avoiding spin-polling."""
        existing = self.read(topic, key)
        if existing is not None:
            return existing

        waiter_key = (topic, key)
        event = asyncio.Event()
        if waiter_key not in self._waiters:
            self._waiters[waiter_key] = []
        self._waiters[waiter_key].append(event)

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self.read(topic, key)
        except asyncio.TimeoutError:
            return None
        finally:
            if waiter_key in self._waiters and event in self._waiters[waiter_key]:
                self._waiters[waiter_key].remove(event)
                if not self._waiters[waiter_key]:
                    del self._waiters[waiter_key]

    def read_topic(self, topic: str) -> Dict[str, Any]:
        """Read all key-values under a specific topic."""
        topic_entries = self._topics.get(topic, {})
        return {k: entry.value for k, entry in topic_entries.items()}

    def subscribe(self, topic: str, callback: Callable[[str, str, Any, str], None]):
        """Subscribe to updates on a specific blackboard topic."""
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)

    def list_topics(self) -> List[str]:
        return list(self._topics.keys())

    def delete_entry(self, topic: str, key: str) -> bool:
        """Delete a single key from a topic in both memory and durable storage."""
        found = False
        if topic in self._topics and key in self._topics[topic]:
            del self._topics[topic][key]
            found = True
            if not self._topics[topic]:
                del self._topics[topic]
        
        if self.db_path:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        "DELETE FROM durable_blackboard_entries WHERE topic = ? AND key = ?",
                        (topic, key)
                    )
                    conn.commit()
            except Exception:
                pass
        return found

    async def delete_entry_async(self, topic: str, key: str) -> bool:
        """Asynchronously delete a key without blocking the event loop."""
        return await asyncio.to_thread(self.delete_entry, topic, key)

    def clear(self, topic: Optional[str] = None):
        """Clear all entries, or clear a specific topic."""
        if topic is None:
            self._topics.clear()
            self._subscribers.clear()
            self._waiters.clear()
            if self.db_path:
                try:
                    with self._get_connection() as conn:
                        conn.execute("DELETE FROM durable_blackboard_entries")
                        conn.commit()
                except Exception:
                    pass
        else:
            self._topics.pop(topic, None)
            self._subscribers.pop(topic, None)
            # clear waiters for topic
            waiter_keys = [k for k in self._waiters if k[0] == topic]
            for k in waiter_keys:
                del self._waiters[k]
            if self.db_path:
                try:
                    with self._get_connection() as conn:
                        conn.execute("DELETE FROM durable_blackboard_entries WHERE topic = ?", (topic,))
                        conn.commit()
                except Exception:
                    pass

    async def clear_async(self, topic: Optional[str] = None):
        """Asynchronously clear entries without blocking the event loop."""
        await asyncio.to_thread(self.clear, topic)
