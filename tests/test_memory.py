import asyncio
import os
from pathlib import Path
import unittest
from memory.base import MemoryTier
from memory.l1_context import L1ContextManager
from memory.l2_session import L2SessionBuffer
from memory.l3_semantic import L3SemanticStore
from memory.l4_archival import L4ArchivalStore
from memory.mmu import MemoryManagementUnit
from kernel.process import ProcessControlBlock
from syscalls.memory import SysMemStore, SysMemRecall, SysMemStats

class TestAIOSMemory(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.test_db = Path("./test_aios_memory.db")
        if self.test_db.exists():
            try:
                os.remove(self.test_db)
            except Exception:
                pass
        self.mmu = MemoryManagementUnit(paging_threshold=0.70)
        self.mmu.l4_archival = L4ArchivalStore(db_path=self.test_db)

    async def asyncTearDown(self):
        if self.test_db.exists():
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def test_l1_context_token_tracking(self):
        l1 = L1ContextManager(system_prompt="System prompt test", max_capacity_tokens=200)
        self.assertGreater(l1.get_token_count(), 0)
        self.assertLess(l1.utilization_ratio, 0.5)

        # Add messages
        l1.add_message("user", "Hello world, this is a test prompt to consume tokens.")
        l1.add_message("assistant", "This is an assistant response with additional text.")
        initial_tokens = l1.get_token_count()

        # Evict oldest
        evicted = l1.extract_oldest_turns(count=1)
        self.assertEqual(len(evicted), 1)
        self.assertLess(l1.get_token_count(), initial_tokens)

    async def test_l2_session_buffer(self):
        l2 = L2SessionBuffer(capacity=3)
        await l2.add("turn 1")
        await l2.add("turn 2")
        await l2.add("turn 3")
        self.assertEqual(len(l2), 3)

        # 4th item should evict oldest (turn 1)
        await l2.add("turn 4")
        self.assertEqual(len(l2), 3)
        recent = l2.get_recent(limit=3)
        self.assertEqual([e.content for e in recent], ["turn 2", "turn 3", "turn 4"])

    async def test_l3_semantic_recall(self):
        l3 = L3SemanticStore()
        await l3.add("The capital of France is Paris, famous for the Eiffel Tower.", tags=["geography"])
        await l3.add("Python is an interpreted, high-level, general-purpose programming language.", tags=["coding"])
        await l3.add("Quantum computing utilizes superposition and quantum entanglement.", tags=["physics"])

        # Search for programming topic
        results = await l3.search("programming language python development", top_k=1)
        self.assertEqual(len(results), 1)
        self.assertIn("Python", results[0].entry.content)
        self.assertGreater(results[0].relevance_score, 0.2)

        # Search for geography topic
        geo_results = await l3.search("Eiffel tower in France", top_k=1)
        self.assertEqual(len(geo_results), 1)
        self.assertIn("Paris", geo_results[0].entry.content)

    async def test_l4_archival_sqlite(self):
        l4 = self.mmu.l4_archival
        # Store persistent key-value fact
        l4.store_fact("user_timezone", "UTC+5:30", owner_pid="proc-101")
        val = l4.get_fact("user_timezone")
        self.assertEqual(val, "UTC+5:30")

        # Add structured archival memory
        entry = await l4.add("Critical system configuration update executed", metadata={"version": "1.0"})
        retrieved = await l4.get(entry.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.content, "Critical system configuration update executed")

    async def test_mmu_automated_paging(self):
        pid = "proc-test-mmu"
        l1 = self.mmu.allocate_process_memory(pid=pid, system_prompt="Sys", max_capacity_tokens=100)
        # Add messages that will easily exceed 70% of 100 tokens
        l1.add_message("user", "Can you explain the detailed history of operating systems from early mainframes like Multics and UNIX through to modern Linux kernels and microkernels?")
        l1.add_message("assistant", "UNIX was originally developed at Bell Telephone Laboratories in the late 1960s by Ken Thompson, Dennis Ritchie, and Douglas McIlroy, establishing foundational OS concepts like pipes and hierarchical file systems.")
        l1.add_message("user", "Now contrast monolithic kernels with microkernels like seL4 and hybrid kernels like Windows NT.")

        self.assertGreaterEqual(l1.utilization_ratio, 0.70)

        # Trigger MMU check_and_page
        event = await self.mmu.check_and_page(pid)
        self.assertIsNotNone(event)
        self.assertGreater(event["turns_evicted"], 0)
        self.assertGreater(event["tokens_freed"], 0)

        # Check that evicted context was paged into L3 and L4
        self.assertGreaterEqual(len(self.mmu.l3_semantic), 1)
        
        # Check that L1 now contains the compacted summary
        compiled = l1.compile_messages()
        has_summary = any("SYSTEM MEMORY SUMMARY" in m.get("content", "") for m in compiled)
        self.assertTrue(has_summary)

    async def test_memory_syscalls(self):
        pcb = ProcessControlBlock(name="mem_agent")
        self.mmu.allocate_process_memory(pid=pcb.pid, max_capacity_tokens=1000)

        store_call = SysMemStore(self.mmu)
        recall_call = SysMemRecall(self.mmu)
        stats_call = SysMemStats(self.mmu)

        # 1. Store fact syscall
        store_res = await store_call.execute(pcb, key="default_theme", value="dark_mode")
        self.assertTrue(store_res.success)

        # 2. Recall fact syscall
        recall_res = await recall_call.execute(pcb, query="default_theme")
        self.assertTrue(recall_res.success)
        self.assertEqual(recall_res.data["exact_fact"], "dark_mode")

        # 3. Stats syscall
        stats_res = await stats_call.execute(pcb)
        self.assertTrue(stats_res.success)
        self.assertIn("l1_tokens", stats_res.data)
        self.assertIn("l4_facts_count", stats_res.data)

if __name__ == "__main__":
    unittest.main()
