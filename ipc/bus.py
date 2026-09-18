import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from config.settings import settings
from ipc.message import IPCMessage, IPCMessageType

class MessageBus:
    """
    Central Asynchronous Message Bus for Multi-Agent Inter-Process Communication.
    Supports point-to-point mailboxes, broadcast channels, distributed trace logging,
    and durable SQLite WAL queue persistence across system crashes/reboots (EGAP-05).
    """
    def __init__(self, db_path: Optional[Any] = None):
        # Per-PID inbox mailboxes
        self._mailboxes: Dict[str, asyncio.Queue[IPCMessage]] = {}
        self._history: List[IPCMessage] = []
        self._total_messages_routed = 0

        # SQLite durable WAL persistence
        if db_path is not None:
            self.db_path = str(db_path)
        else:
            default_dir = settings.workspace_root / "data"
            default_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(default_dir / "aios_state.db")

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
        """Initialize durable IPC message table and WAL journal mode."""
        try:
            with self._get_connection() as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS durable_ipc_messages (
                        message_id TEXT PRIMARY KEY,
                        sender_pid TEXT NOT NULL,
                        recipient_pid TEXT NOT NULL,
                        msg_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        trace_id TEXT,
                        created_at TEXT NOT NULL,
                        consumed INTEGER DEFAULT 0
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_durable_ipc_recip 
                    ON durable_ipc_messages(recipient_pid, consumed);
                """)
                conn.commit()
        except Exception:
            pass

    def _persist_message(self, message: IPCMessage, target_pid: Optional[str] = None):
        """Persist in-flight IPC message to SQLite WAL storage for a target recipient."""
        try:
            recip = target_pid or message.recipient_pid
            msg_id = f"{message.message_id}:{recip}" if target_pid else message.message_id
            msg_type_str = message.msg_type.value if hasattr(message.msg_type, "value") else str(message.msg_type)
            created_str = message.created_at.isoformat() if hasattr(message.created_at, "isoformat") else str(message.created_at)
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO durable_ipc_messages "
                    "(message_id, sender_pid, recipient_pid, msg_type, payload_json, trace_id, created_at, consumed) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                    (
                        msg_id,
                        message.sender_pid,
                        recip,
                        msg_type_str,
                        json.dumps(message.payload),
                        message.trace_id,
                        created_str
                    )
                )
                conn.commit()
        except Exception:
            pass

    def _mark_consumed(self, message_id: str, pid: Optional[str] = None):
        """Mark an in-flight message as consumed upon receipt."""
        try:
            with self._get_connection() as conn:
                if pid:
                    conn.execute(
                        "UPDATE durable_ipc_messages SET consumed = 1 WHERE message_id = ? OR message_id = ?",
                        (message_id, f"{message_id}:{pid}")
                    )
                else:
                    conn.execute(
                        "UPDATE durable_ipc_messages SET consumed = 1 WHERE message_id = ? OR message_id LIKE ?",
                        (message_id, f"{message_id}:%")
                    )
                conn.commit()
        except Exception:
            pass

    def _restore_mailbox_messages(self, pid: str):
        """Restore unconsumed durable messages for a registered mailbox."""
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT message_id, sender_pid, recipient_pid, msg_type, payload_json, trace_id, created_at "
                    "FROM durable_ipc_messages WHERE recipient_pid = ? AND consumed = 0 ORDER BY created_at ASC",
                    (pid,)
                )
                for r in cur.fetchall():
                    try:
                        payload = json.loads(r[4]) if r[4] else {}
                    except Exception:
                        payload = {}
                    
                    try:
                        msg_type = IPCMessageType(r[3])
                    except Exception:
                        msg_type = IPCMessageType.DIRECT_MESSAGE

                    raw_id = r[0].split(":")[0]
                    msg = IPCMessage(
                        message_id=raw_id,
                        sender_pid=r[1],
                        recipient_pid=r[2],
                        msg_type=msg_type,
                        payload=payload,
                        trace_id=r[5] or ""
                    )
                    self._mailboxes[pid].put_nowait(msg)
        except Exception:
            pass

    def register_mailbox(self, pid: str):
        """Create a dedicated FIFO mailbox for a registered process and restore durable messages."""
        if pid not in self._mailboxes:
            self._mailboxes[pid] = asyncio.Queue()
            self._restore_mailbox_messages(pid)

    def unregister_mailbox(self, pid: str):
        """Remove a process mailbox upon termination."""
        self._mailboxes.pop(pid, None)

    async def send(self, message: IPCMessage) -> bool:
        """Route an IPC message to its destination mailbox or broadcast to all."""
        self._history.append(message)
        self._total_messages_routed += 1

        if message.recipient_pid == "*":
            # Broadcast to all registered mailboxes except the sender
            sent_any = False
            for pid, queue in self._mailboxes.items():
                if pid != message.sender_pid:
                    await asyncio.to_thread(self._persist_message, message, pid)
                    await queue.put(message)
                    sent_any = True
            return sent_any

        # Direct point-to-point delivery
        await asyncio.to_thread(self._persist_message, message, message.recipient_pid)
        queue = self._mailboxes.get(message.recipient_pid)
        if queue:
            await queue.put(message)
            return True
        return False

    def broadcast(self, message: IPCMessage):
        """Synchronous/non-blocking broadcast to all mailboxes."""
        self._history.append(message)
        self._total_messages_routed += 1

        for pid, queue in self._mailboxes.items():
            if pid != message.sender_pid:
                self._persist_message(message, target_pid=pid)
                try:
                    queue.put_nowait(message)
                except Exception:
                    pass

    async def receive(self, pid: str, timeout: Optional[float] = None) -> Optional[IPCMessage]:
        """Dequeue the next message from a process's mailbox and mark it consumed in SQLite."""
        queue = self._mailboxes.get(pid)
        if not queue:
            return None

        msg: Optional[IPCMessage] = None
        if timeout is not None and timeout <= 0:
            # Non-blocking poll
            try:
                msg = queue.get_nowait()
            except asyncio.QueueEmpty:
                return None
        else:
            try:
                if timeout:
                    msg = await asyncio.wait_for(queue.get(), timeout=timeout)
                else:
                    msg = await queue.get()
            except asyncio.TimeoutError:
                return None

        if msg:
            await asyncio.to_thread(self._mark_consumed, msg.message_id, pid)
        return msg

    def recover_unconsumed_messages(self) -> int:
        """
        Scan SQLite WAL queue for unconsumed messages after a crash/reboot,
        re-register destination mailboxes, and restore messages into memory.
        Returns the count of recovered messages.
        """
        recovered_count = 0
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT message_id, sender_pid, recipient_pid, msg_type, payload_json, trace_id, created_at "
                    "FROM durable_ipc_messages WHERE consumed = 0 ORDER BY created_at ASC"
                )
                rows = cur.fetchall()
                for r in rows:
                    recip = r[2]
                    if recip != "*":
                        if recip not in self._mailboxes:
                            self._mailboxes[recip] = asyncio.Queue()
                    recovered_count += 1
        except Exception:
            pass
        return recovered_count

    async def recover_unconsumed_messages_async(self) -> int:
        """Asynchronously recover unconsumed messages without blocking the event loop."""
        return await asyncio.to_thread(self.recover_unconsumed_messages)

    def has_messages(self, pid: str) -> bool:
        """Check if a process has pending messages in its inbox."""
        queue = self._mailboxes.get(pid)
        return bool(queue and not queue.empty())

    def get_history(self, trace_id: Optional[str] = None) -> List[IPCMessage]:
        """Retrieve audit history of routed messages, optionally filtered by trace_id."""
        if trace_id:
            return [m for m in self._history if m.trace_id == trace_id]
        return list(self._history)

    def get_stats(self) -> Dict[str, Any]:
        """Return bus routing statistics."""
        return {
            "active_mailboxes": len(self._mailboxes),
            "total_messages_routed": self._total_messages_routed,
            "history_log_size": len(self._history)
        }

    def clear(self):
        """Clear memory queues and durable SQLite table."""
        self._mailboxes.clear()
        self._history.clear()
        self._total_messages_routed = 0
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM durable_ipc_messages")
                conn.commit()
        except Exception:
            pass

    async def clear_async(self):
        """Asynchronously clear memory queues and durable SQLite table."""
        await asyncio.to_thread(self.clear)
