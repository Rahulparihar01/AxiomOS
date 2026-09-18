import asyncio
import unittest
from unittest.mock import AsyncMock, patch
from kernel.process import ProcessControlBlock
from sandbox.runner import IsolatedCodeRunner, DockerIsolatedRunner
from syscalls.standard import SysNetFetch
from syscalls import SyscallRegistry

class TestASTSandboxAndNetFetch(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying AST-level static sandbox safety and web fetch syscall."""

    def setUp(self):
        self.runner = IsolatedCodeRunner(timeout_seconds=2.0)
        self.pcb = ProcessControlBlock(name="security_tester")

    async def test_ast_safety_blocks_dynamic_imports(self):
        # 1. Block __import__
        code_dynamic_import = "__import__('os').system('dir')"
        res = await self.runner.run_python(code_dynamic_import)
        self.assertEqual(res.exit_code, -1)
        self.assertIn("Static Safety Guard", res.stderr)
        self.assertIn("__import__", res.stderr)

    async def test_ast_safety_blocks_reflection_attack(self):
        # 2. Block obfuscated getattr rmtree
        code_reflection = "getattr(shutil, 'rm' + 'tree')('/')"
        res = await self.runner.run_python(code_reflection)
        self.assertEqual(res.exit_code, -1)
        self.assertIn("Static Safety Guard", res.stderr)

    async def test_ast_safety_blocks_importlib(self):
        # 3. Block importlib.import_module
        code_importlib = "import importlib\nimportlib.import_module('os')"
        res = await self.runner.run_python(code_importlib)
        self.assertEqual(res.exit_code, -1)
        self.assertIn("Static Safety Guard", res.stderr)

    async def test_ast_safety_allows_safe_code(self):
        # 4. Allow clean calculations
        safe_code = "print(sum([x * 2 for x in range(5)]))"
        res = await self.runner.run_python(safe_code)
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.stdout.strip(), "20")

    async def test_docker_runner_graceful_fallback(self):
        docker_runner = DockerIsolatedRunner(timeout_seconds=2.0)
        code = "print('Docker or Isolated Runner active')"
        res = await docker_runner.run_python(code)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("active", res.stdout)

    async def test_sys_net_fetch_protocol_validation(self):
        fetcher = SysNetFetch()

        # 1. Reject disallowed protocol scheme
        res_file = await fetcher.execute(self.pcb, url="file:///etc/passwd")
        self.assertFalse(res_file.success)
        self.assertIn("Disallowed protocol scheme", res_file.error)

        # 2. Reject loopback SSRF attempt
        res_loopback = await fetcher.execute(self.pcb, url="http://127.0.0.1:8000/api/status")
        self.assertFalse(res_loopback.success)
        self.assertIn("SSRF Protection", res_loopback.error)

        # 3. Reject localhost SSRF attempt
        res_localhost = await fetcher.execute(self.pcb, url="http://localhost:5000/admin")
        self.assertFalse(res_localhost.success)
        self.assertIn("SSRF Protection", res_localhost.error)

        # 4. Reject AWS/cloud metadata address
        res_meta = await fetcher.execute(self.pcb, url="http://169.254.169.254/latest/meta-data")
        self.assertFalse(res_meta.success)
        self.assertIn("SSRF Protection", res_meta.error)

    async def test_sys_net_fetch_mock_successful_get(self):
        fetcher = SysNetFetch()
        
        # Mock httpx GET
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.url = "https://api.example.com/data"
        mock_response.headers = {"content-type": "application/json"}
        mock_response.text = '{"status": "ok", "items": [1, 2, 3]}'

        with patch("httpx.AsyncClient.get", return_value=mock_response):
            res = await fetcher.execute(self.pcb, url="https://api.example.com/data")
            self.assertTrue(res.success)
            self.assertEqual(res.data["status_code"], 200)
            self.assertIn('"status": "ok"', res.data["content"])

if __name__ == "__main__":
    unittest.main()
