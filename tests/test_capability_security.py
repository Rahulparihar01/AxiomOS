import asyncio
from datetime import datetime, timedelta, timezone
import gc
import shutil
import tempfile
import unittest

from kernel.event_loop import Kernel
from kernel.process import PriorityLevel, ProcessControlBlock, ProcessState
from security.capability import CapabilityIssuer, CapabilityToken
from syscalls import SyscallRegistry

class TestCapabilitySecurity(unittest.IsolatedAsyncioTestCase):
    """
    Comprehensive test suite for GAP-11:
    - Remediating wildcard bypass with least-privilege role defaults
    - Enforcing sensitive file & path traversal protection
    - Dynamic capability lease renewal and auto-extension
    - Enforcement on syscall dispatch
    """

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.kernel = Kernel(provider_name="mock", db_path=f"{self.tmp_dir}/test_aios.db")

    async def asyncTearDown(self):
        try:
            self.kernel.shutdown()
            await self.kernel.aclose()
        except Exception:
            pass
        gc.collect()
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass

    def test_role_based_least_privilege_defaults(self):
        """Verify spawn_process assigns bounded role scopes instead of wildcard ['*'] bypass."""
        # 1. Planner
        p_planner = self.kernel.spawn_process("lead_planner", "Coordinate architecture", role="planner")
        tok_planner: CapabilityToken = p_planner.capability_token
        self.assertNotIn("*", tok_planner.allowed_syscalls)
        self.assertTrue(tok_planner.can_call_syscall("sys_plan_register_subtask"))
        self.assertTrue(tok_planner.can_call_syscall("sys_proc_spawn"))
        self.assertTrue(tok_planner.can_call_syscall("sys_fs_read"))
        self.assertFalse(tok_planner.can_call_syscall("sys_exec_python"))
        self.assertFalse(tok_planner.can_call_syscall("sys_fs_write"))
        self.assertFalse(tok_planner.can_call_syscall("sys_fs_delete"))

        # 2. Coder
        p_coder = self.kernel.spawn_process("backend_coder", "Implement service", role="coder")
        tok_coder: CapabilityToken = p_coder.capability_token
        self.assertNotIn("*", tok_coder.allowed_syscalls)
        self.assertTrue(tok_coder.can_call_syscall("sys_code_record_artifact"))
        self.assertTrue(tok_coder.can_call_syscall("sys_exec_python"))
        self.assertTrue(tok_coder.can_call_syscall("sys_fs_write"))
        self.assertTrue(tok_coder.can_call_syscall("sys_fs_read"))
        self.assertFalse(tok_coder.can_call_syscall("sys_plan_register_subtask"))

        # 3. Reviewer
        p_rev = self.kernel.spawn_process("security_auditor", "Audit codebase", role="reviewer")
        tok_rev: CapabilityToken = p_rev.capability_token
        self.assertNotIn("*", tok_rev.allowed_syscalls)
        self.assertTrue(tok_rev.can_call_syscall("sys_audit_record_verdict"))
        self.assertTrue(tok_rev.can_call_syscall("sys_fs_read"))
        self.assertFalse(tok_rev.can_call_syscall("sys_exec_python"))
        self.assertFalse(tok_rev.can_call_syscall("sys_fs_write"))

        # 4. Researcher
        p_res = self.kernel.spawn_process("market_scout", "Retrieve docs", role="researcher")
        tok_res: CapabilityToken = p_res.capability_token
        self.assertNotIn("*", tok_res.allowed_syscalls)
        self.assertTrue(tok_res.can_call_syscall("sys_research_record_finding"))
        self.assertTrue(tok_res.can_call_syscall("sys_net_fetch"))
        self.assertFalse(tok_res.can_call_syscall("sys_exec_python"))
        self.assertFalse(tok_res.can_call_syscall("sys_fs_write"))

        # 5. Conflict Resolver
        p_resolver = self.kernel.spawn_process("fact_arbitrator", "Arbitrate discrepancies", role="conflict_resolver")
        tok_resolver: CapabilityToken = p_resolver.capability_token
        self.assertNotIn("*", tok_resolver.allowed_syscalls)
        self.assertTrue(tok_resolver.can_call_syscall("sys_conflict_record_resolution"))
        self.assertFalse(tok_resolver.can_call_syscall("sys_exec_python"))
        self.assertFalse(tok_resolver.can_call_syscall("sys_fs_write"))

        # 6. Base / Generic worker
        p_base = self.kernel.spawn_process("generic_worker", "Perform calculation", role="base")
        tok_base: CapabilityToken = p_base.capability_token
        self.assertNotIn("*", tok_base.allowed_syscalls)
        self.assertTrue(tok_base.can_call_syscall("sys_calc"))
        self.assertTrue(tok_base.can_call_syscall("sys_log"))
        self.assertFalse(tok_base.can_call_syscall("sys_exec_python"))
        self.assertFalse(tok_base.can_call_syscall("sys_fs_delete"))

    def test_sensitive_file_and_traversal_protection(self):
        """Verify sensitive credentials (.env, secrets) and traversal (..) are blocked."""
        # Create token with broad wildcard permissions
        token = CapabilityIssuer.issue_token(pid="test-proc", role="base", scope_paths=["*"])

        # Path traversal must be blocked
        self.assertFalse(token.can_access_path("../../etc/passwd"))
        self.assertFalse(token.can_access_path("sandbox/../../../secret.env"))

        # Sensitive files must be blocked even when wildcard is present
        self.assertFalse(token.can_access_path(".env"))
        self.assertFalse(token.can_access_path("config/secrets.env"))
        self.assertFalse(token.can_access_path("keys/private_key.pem"))
        self.assertFalse(token.can_access_path("credentials.json.secret"))

        # Normal workspace files must be allowed
        self.assertTrue(token.can_access_path("workspace/main.py"))
        self.assertTrue(token.can_access_path("sandbox/scratch/temp.txt"))
        self.assertTrue(token.can_access_path("requirements.txt"))

        # Explicitly targeted sensitive file is allowed if specifically granted
        explicit_token = CapabilityIssuer.issue_token(
            pid="admin-proc",
            role="base",
            scope_paths=[".env", "config/secrets.env"]
        )
        self.assertTrue(explicit_token.can_access_path(".env"))
        self.assertTrue(explicit_token.can_access_path("config/secrets.env"))
        self.assertFalse(explicit_token.can_access_path("other_secret.env"))

    def test_capability_lease_renewal_lifecycle(self):
        """Verify CapabilityToken renewal mechanism, quota limits, and revocation."""
        token = CapabilityToken(pid="proc-test", ttl_seconds=60, max_renewals=3)
        self.assertFalse(token.is_expired())
        self.assertAlmostEqual(token.remaining_ttl(), 60.0, delta=2.0)
        self.assertEqual(token.renewal_count, 0)

        # 1. First renewal
        initial_expires = token.expires_at
        renew_ok = token.renew_lease(extension_seconds=90)
        self.assertTrue(renew_ok)
        self.assertEqual(token.renewal_count, 1)
        self.assertGreater(token.expires_at, initial_expires)

        # 2. Second and third renewals
        self.assertTrue(token.renew_lease(60))
        self.assertEqual(token.renewal_count, 2)
        self.assertTrue(token.renew_lease(60))
        self.assertEqual(token.renewal_count, 3)

        # 3. Exceeded max renewals quota (3)
        renew_fail = token.renew_lease(60)
        self.assertFalse(renew_fail)
        self.assertEqual(token.renewal_count, 3)

        # 4. Revocation
        token.revoke()
        self.assertTrue(token.is_expired())
        self.assertFalse(token.renew_lease(60))
        self.assertEqual(token.remaining_ttl(), 0.0)

    def test_kernel_renew_capability_lease_method(self):
        """Verify Kernel.renew_capability_lease extends active process token."""
        pcb = self.kernel.spawn_process("long_task", "Execute long batch job", role="base", ttl_seconds=60)
        token = pcb.capability_token
        orig_expiry = token.expires_at

        # Renew lease via kernel
        ok = self.kernel.renew_capability_lease(pcb.pid, extension_seconds=300)
        self.assertTrue(ok)
        self.assertEqual(token.renewal_count, 1)
        self.assertGreater(token.expires_at, orig_expiry)

        # Non-existent process returns False
        self.assertFalse(self.kernel.renew_capability_lease("non-existent-pid"))

        # Terminal process cannot be renewed
        pcb.transition_to(ProcessState.COMPLETED)
        self.assertFalse(self.kernel.renew_capability_lease(pcb.pid))

    async def test_sys_cap_renew_syscall_dispatch(self):
        """Verify sys_cap_renew syscall executes and updates capability lease."""
        pcb = self.kernel.spawn_process("worker", "Execute job", role="base", ttl_seconds=60)
        token = pcb.capability_token
        initial_count = token.renewal_count

        res = await self.kernel.syscalls.dispatch(pcb, "sys_cap_renew", extension_seconds=180)
        self.assertTrue(res.success)
        self.assertEqual(res.data["pid"], pcb.pid)
        self.assertEqual(res.data["renewal_count"], initial_count + 1)
        self.assertGreater(res.data["remaining_ttl_seconds"], 170.0)

    async def test_syscall_dispatch_enforcement_by_role(self):
        """Verify dispatch rejects unauthorized syscalls and unauthorized paths per role."""
        planner_pcb = self.kernel.spawn_process("planner_agent", "Plan migration", role="planner")
        reviewer_pcb = self.kernel.spawn_process("auditor_agent", "Review artifacts", role="reviewer")

        # Planner attempting code execution -> Denied
        plan_exec_res = await self.kernel.syscalls.dispatch(planner_pcb, "sys_exec_python", code="print('hack')")
        self.assertFalse(plan_exec_res.success)
        self.assertIn("Capability Denied: Syscall 'sys_exec_python' is not authorized", plan_exec_res.error)

        # Reviewer attempting file write -> Denied
        rev_write_res = await self.kernel.syscalls.dispatch(
            reviewer_pcb, "sys_fs_write", filepath="malicious.txt", content="payload"
        )
        self.assertFalse(rev_write_res.success)
        self.assertIn("Capability Denied: Syscall 'sys_fs_write' is not authorized", rev_write_res.error)

    async def test_proactive_auto_renewal_in_event_loop(self):
        """Verify Kernel._execute_process_step auto-renews token when nearing TTL expiration."""
        pcb = self.kernel.spawn_process("step_worker", "Compute sum", role="base", ttl_seconds=120)
        token: CapabilityToken = pcb.capability_token

        # Set token close to expiration (10 seconds remaining, <= 30 threshold)
        token.expires_at = datetime.now(timezone.utc) + timedelta(seconds=10)
        self.assertLessEqual(token.remaining_ttl(), 15.0)
        initial_renewals = token.renewal_count

        # Execute one step via kernel
        await self.kernel._execute_process_step(pcb)

        # Token should have been proactively renewed
        self.assertGreater(token.renewal_count, initial_renewals)
        self.assertGreater(token.remaining_ttl(), 60.0)

if __name__ == "__main__":
    unittest.main()
