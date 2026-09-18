import asyncio
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ipc.blackboard import SharedBlackboard, BlackboardEntry
from kernel.event_loop import Kernel

class TestDurableBlackboard(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_blackboard.db"

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_in_memory_mode_backwards_compatible(self):
        """Verify blackboard works completely in-memory when db_path is None."""
        bb = SharedBlackboard()
        self.assertIsNone(bb.db_path)
        bb.write("milestones", "task-1", {"status": "ok"}, author_pid="test-p1")
        self.assertEqual(bb.read("milestones", "task-1"), {"status": "ok"})
        self.assertIn("milestones", bb.list_topics())
        bb.clear()
        self.assertEqual(len(bb.list_topics()), 0)

    def test_durable_persistence_and_recovery(self):
        """Verify entries are persisted in SQLite WAL and recovered across instances."""
        bb1 = SharedBlackboard(db_path=self.db_path)
        self.assertTrue(self.db_path.exists())

        # Write diverse structured values
        bb1.write("milestones", "dag-task-01", {"status": "completed", "steps": [1, 2, 3]}, author_pid="planner-1")
        bb1.write("artifacts", "quicksort.py", "def quicksort(arr): return arr", author_pid="coder-2")
        bb1.write("metrics", "accuracy_score", 0.9875, author_pid="reviewer-3")
        bb1.write("config", "max_retries", 5, author_pid="kernel-0")

        # Verify SQLite table contents directly
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT topic, key, author_pid FROM durable_blackboard_entries ORDER BY topic, key")
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 4)
            self.assertEqual(rows[0], ("artifacts", "quicksort.py", "coder-2"))
            self.assertEqual(rows[1], ("config", "max_retries", "kernel-0"))
            self.assertEqual(rows[2], ("metrics", "accuracy_score", "reviewer-3"))
            self.assertEqual(rows[3], ("milestones", "dag-task-01", "planner-1"))
        finally:
            conn.close()

        del bb1

        # Simulate crash/reboot: instantiate a brand new blackboard on the same DB file
        bb2 = SharedBlackboard(db_path=self.db_path)

        # Verify full hydration
        self.assertEqual(
            bb2.read("milestones", "dag-task-01"),
            {"status": "completed", "steps": [1, 2, 3]}
        )
        self.assertEqual(
            bb2.read("artifacts", "quicksort.py"),
            "def quicksort(arr): return arr"
        )
        self.assertEqual(bb2.read("metrics", "accuracy_score"), 0.9875)
        self.assertEqual(bb2.read("config", "max_retries"), 5)

        # Verify metadata restoration
        entry = bb2.get_entry("milestones", "dag-task-01")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.author_pid, "planner-1")
        self.assertIsNotNone(entry.updated_at)

    def test_durable_upsert_overwrite(self):
        """Verify updating existing keys updates both in-memory and SQLite records."""
        bb = SharedBlackboard(db_path=self.db_path)
        bb.write("metrics", "cpu_load", 0.25, author_pid="mon-1")
        self.assertEqual(bb.read("metrics", "cpu_load"), 0.25)

        # Overwrite with new value and author
        bb.write("metrics", "cpu_load", 0.88, author_pid="mon-2")
        self.assertEqual(bb.read("metrics", "cpu_load"), 0.88)

        # Restart and verify authoritative persistence
        bb_reloaded = SharedBlackboard(db_path=self.db_path)
        self.assertEqual(bb_reloaded.read("metrics", "cpu_load"), 0.88)
        self.assertEqual(bb_reloaded.get_entry("metrics", "cpu_load").author_pid, "mon-2")

    def test_durable_delete_entry(self):
        """Verify selective key deletion removes entry in memory and SQLite."""
        bb = SharedBlackboard(db_path=self.db_path)
        bb.write("cache", "k1", "v1", author_pid="p1")
        bb.write("cache", "k2", "v2", author_pid="p1")

        deleted = bb.delete_entry("cache", "k1")
        self.assertTrue(deleted)
        self.assertIsNone(bb.read("cache", "k1"))
        self.assertEqual(bb.read("cache", "k2"), "v2")

        # Verify deleted in new instance
        bb_reloaded = SharedBlackboard(db_path=self.db_path)
        self.assertIsNone(bb_reloaded.read("cache", "k1"))
        self.assertEqual(bb_reloaded.read("cache", "k2"), "v2")

    def test_durable_topic_clear_and_full_clear(self):
        """Verify topic-scoped clear and global clear persist to SQLite."""
        bb = SharedBlackboard(db_path=self.db_path)
        bb.write("topicA", "key1", "val1", author_pid="p1")
        bb.write("topicA", "key2", "val2", author_pid="p1")
        bb.write("topicB", "key3", "val3", author_pid="p1")

        # Clear topicA only
        bb.clear(topic="topicA")
        self.assertNotIn("topicA", bb.list_topics())
        self.assertIn("topicB", bb.list_topics())

        # Check DB reflects topicA deletion
        bb2 = SharedBlackboard(db_path=self.db_path)
        self.assertNotIn("topicA", bb2.list_topics())
        self.assertEqual(bb2.read("topicB", "key3"), "val3")

        # Global clear
        bb2.clear()
        self.assertEqual(len(bb2.list_topics()), 0)

        # Check DB is completely empty
        bb3 = SharedBlackboard(db_path=self.db_path)
        self.assertEqual(len(bb3.list_topics()), 0)

    async def test_async_wait_for_key_durable(self):
        """Verify wait_for_key works seamlessly with durable persistence."""
        bb = SharedBlackboard(db_path=self.db_path)

        async def writer():
            await asyncio.sleep(0.05)
            bb.write("coordination", "step_done", True, author_pid="agent-worker")

        writer_task = asyncio.create_task(writer())
        res = await bb.wait_for_key("coordination", "step_done", timeout=2.0)
        await writer_task

        self.assertTrue(res)

        # Verify it was also persisted
        bb_check = SharedBlackboard(db_path=self.db_path)
        self.assertTrue(bb_check.read("coordination", "step_done"))

    def test_kernel_integration_with_durable_blackboard(self):
        """Verify Kernel initializes SharedBlackboard with its db_path and state survives kernel reboot."""
        kernel1 = Kernel(db_path=self.db_path)
        self.assertEqual(kernel1.blackboard.db_path, str(self.db_path))

        kernel1.blackboard.write("artifacts", "solution.py", "print('hello')", author_pid="coder-proc")
        
        # Verify persistence across Kernel instances
        kernel2 = Kernel(db_path=self.db_path)
        restored = kernel2.blackboard.read("artifacts", "solution.py")
        self.assertEqual(restored, "print('hello')")
        entry = kernel2.blackboard.get_entry("artifacts", "solution.py")
        self.assertEqual(entry.author_pid, "coder-proc")

if __name__ == "__main__":
    unittest.main()
