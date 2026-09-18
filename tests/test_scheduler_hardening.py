import asyncio
import gc
import shutil
import tempfile
import unittest

from kernel.cost_estimator import CostEstimator
from kernel.process import PriorityLevel, ProcessControlBlock, ProcessState
from kernel.scheduler import TaskScheduler
from memory.l4_archival import L4ArchivalStore

class TestSchedulerHardening(unittest.IsolatedAsyncioTestCase):
    """
    Test suite for GAP-08 and GAP-09:
    - GAP-08: Similarity-weighted task cost prediction percentiles (eliminating percentile skew).
    - GAP-09: Dynamic priority aging and anti-starvation defense in the scheduler queue.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = f"{self.tmp_dir}/test_scheduler.db"
        self.l4_store = L4ArchivalStore(db_path=self.db_path)
        self.estimator = CostEstimator(l4_store=self.l4_store)
        self.scheduler = TaskScheduler(max_concurrent=4, aging_rate=1.0)

    def tearDown(self):
        gc.collect()
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass

    def test_similarity_weighted_percentiles_gap08(self):
        """Verify that historical heavy tasks do not distort predictions for simple tasks."""
        # 1. Seed database with 10 heavy compiler tasks (50,000 tokens each)
        for i in range(10):
            self.l4_store.log_task_cost(
                role="coder",
                instruction=f"Compile Linux kernel submodule driver component architecture part {i}",
                tokens_consumed=50000,
                wall_time_seconds=25.0
            )

        # 2. Seed database with 1 simple math task (100 tokens)
        self.l4_store.log_task_cost(
            role="coder",
            instruction="Calculate math sum of two integers: 5 + 7",
            tokens_consumed=100,
            wall_time_seconds=0.1
        )

        # 3. Query with a math instruction
        math_estimate = self.estimator.estimate(
            role="coder",
            instruction="Calculate math sum of two integers: 12 + 8"
        )

        # In unweighted mode, p90 would be 50,000 tokens.
        # In similarity-weighted mode (GAP-08), the close math match dominates the distribution.
        self.assertEqual(math_estimate.sample_size, 11)
        self.assertEqual(math_estimate.predicted_tokens_p50, 100)
        self.assertEqual(math_estimate.predicted_tokens_p90, 100)
        self.assertGreaterEqual(math_estimate.confidence, 0.6)

        # 4. Query with a heavy compiler instruction
        compiler_estimate = self.estimator.estimate(
            role="coder",
            instruction="Compile Linux kernel submodule driver component architecture part 99"
        )
        self.assertEqual(compiler_estimate.predicted_tokens_p50, 50000)
        self.assertEqual(compiler_estimate.predicted_tokens_p90, 50000)
        self.assertGreaterEqual(compiler_estimate.confidence, 0.6)

    def test_cost_estimator_cold_start_gap08(self):
        """Verify fallback to safe defaults on cold start."""
        empty_l4 = L4ArchivalStore(db_path=f"{self.tmp_dir}/empty.db")
        est = CostEstimator(l4_store=empty_l4)
        result = est.estimate("reviewer", "Review security of smart contract")

        self.assertEqual(result.sample_size, 0)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.predicted_tokens_p50, 2500)
        self.assertEqual(result.predicted_tokens_p90, 6000)

    async def test_scheduler_immediate_priority_ordering_gap09(self):
        """Verify strict priority ordering when processes arrive simultaneously."""
        p_bg = ProcessControlBlock(name="bg", priority=PriorityLevel.BACKGROUND)
        p_norm = ProcessControlBlock(name="norm", priority=PriorityLevel.NORMAL)
        p_high = ProcessControlBlock(name="high", priority=PriorityLevel.HIGH)
        p_crit = ProcessControlBlock(name="crit", priority=PriorityLevel.CRITICAL)

        # Enqueue in reverse order
        self.scheduler.enqueue(p_bg)
        self.scheduler.enqueue(p_norm)
        self.scheduler.enqueue(p_high)
        self.scheduler.enqueue(p_crit)

        d1 = await self.scheduler.get_next_process()
        d2 = await self.scheduler.get_next_process()
        d3 = await self.scheduler.get_next_process()
        d4 = await self.scheduler.get_next_process()

        self.assertEqual(d1.name, "crit")
        self.assertEqual(d2.name, "high")
        self.assertEqual(d3.name, "norm")
        self.assertEqual(d4.name, "bg")

    async def test_scheduler_anti_starvation_aging_gap09(self):
        """Verify background task accumulates wait credits and is dequeued under continuous high load."""
        scheduler = TaskScheduler(aging_rate=1.0)

        # Enqueue a BACKGROUND process (base score = 0)
        p_bg = ProcessControlBlock(name="starved_background_job", priority=PriorityLevel.BACKGROUND)
        scheduler.enqueue(p_bg)

        # Saturated high-priority stream: enqueue and dequeue HIGH tasks (base score = 20)
        # Each cycle, p_bg wait_ticks increments by 1.
        # At cycle 21, p_bg effective score = 0 + 21*1.0 = 21 > 20 (HIGH base score).
        # Therefore, by cycle 25 at most, p_bg MUST be dequeued before a newly arrived HIGH task.
        dequeued_names = []
        bg_dequeued = False

        for i in range(30):
            p_high = ProcessControlBlock(name=f"high_stream_{i}", priority=PriorityLevel.HIGH)
            scheduler.enqueue(p_high)

            next_proc = await scheduler.get_next_process()
            dequeued_names.append(next_proc.name)
            if next_proc.name == "starved_background_job":
                bg_dequeued = True
                break

        self.assertTrue(bg_dequeued, "Background task was starved and never dequeued under continuous high priority load.")
        # Background task was dequeued around cycle 21
        self.assertLessEqual(len(dequeued_names), 25)
        self.assertEqual(dequeued_names[-1], "starved_background_job")

    def test_scheduler_remove_from_ready(self):
        """Verify removing a cancelled/killed process from the ready queue."""
        p1 = ProcessControlBlock(name="task_to_cancel", priority=PriorityLevel.NORMAL)
        self.scheduler.enqueue(p1)
        self.assertTrue(self.scheduler.has_pending_tasks())

        removed = self.scheduler.remove_from_ready(p1.pid)
        self.assertTrue(removed)
        self.assertFalse(self.scheduler.has_pending_tasks())

if __name__ == "__main__":
    unittest.main()
