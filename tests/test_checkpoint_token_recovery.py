import tempfile
import unittest
from pathlib import Path

from kernel import Kernel, ProcessControlBlock, PriorityLevel
from kernel.checkpoint import CheckpointManager
from security.capability import CapabilityIssuer, CapabilityToken


class TestCheckpointTokenRecovery(unittest.TestCase):
    """Verify that ProcessControlBlock and CheckpointManager correctly restore capability tokens."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_checkpoints.db"
        self.checkpoint_mgr = CheckpointManager(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_checkpoint_roundtrip_restores_capability_token_instance(self):
        token = CapabilityIssuer.issue_token(
            pid="proc-roundtrip-01",
            role="coder",
            allowed_syscalls=["sys_fs_read", "sys_fs_write"],
            ttl_seconds=120
        )
        pcb = ProcessControlBlock(
            pid="proc-roundtrip-01",
            name="worker",
            role="coder",
            capability_token=token
        )

        # Save to database
        self.checkpoint_mgr.save_snapshot(pcb)

        # Load back from database
        snapshots = self.checkpoint_mgr.load_uncompleted_snapshots()
        self.assertEqual(len(snapshots), 1)
        recovered_pcb, l1_data = snapshots[0]

        # Verify capability_token is a CapabilityToken and has is_expired
        self.assertIsNotNone(recovered_pcb.capability_token)
        self.assertIsInstance(recovered_pcb.capability_token, CapabilityToken)
        self.assertFalse(recovered_pcb.capability_token.is_expired())
        self.assertTrue(hasattr(recovered_pcb.capability_token, "is_expired"))
        self.assertTrue(hasattr(recovered_pcb.capability_token, "renew_lease"))

    def test_raw_dict_validation_in_pcb(self):
        token = CapabilityIssuer.issue_token(pid="proc-dict-test", role="planner")
        token_dict = token.model_dump()

        # Instantiate PCB with a raw dict
        pcb = ProcessControlBlock(
            pid="proc-dict-test",
            name="planner_proc",
            role="planner",
            capability_token=token_dict
        )

    async def async_kernel_recovery_test(self):
        kernel = Kernel(provider_name="mock", auto_approve_hitl=True)
        kernel.checkpoint_mgr = self.checkpoint_mgr

        # Save an interrupted process whose capability_token in the DB is a raw dictionary
        token = CapabilityIssuer.issue_token(pid="proc-recovered-01", role="coder", ttl_seconds=120)
        pcb = ProcessControlBlock(
            pid="proc-recovered-01",
            name="recovered_coder",
            role="coder",
            capability_token=token.model_dump()  # raw dict
        )
        self.checkpoint_mgr.save_snapshot(pcb)

        # Recover processes in the kernel
        recovered_count = kernel.recover_interrupted_processes()
        self.assertEqual(recovered_count, 1)

        # Execute a step to verify no 'dict' object has no attribute 'is_expired' error
        recovered_pcb = kernel.scheduler.get_process("proc-recovered-01")
        self.assertIsNotNone(recovered_pcb)
        self.assertIsInstance(recovered_pcb.capability_token, CapabilityToken)
        self.assertTrue(hasattr(recovered_pcb.capability_token, "is_expired"))

        await kernel.run_until_idle()
        kernel.shutdown()

    def test_kernel_recovery_and_step_execution(self):
        import asyncio
        asyncio.run(self.async_kernel_recovery_test())


if __name__ == "__main__":
    unittest.main()
