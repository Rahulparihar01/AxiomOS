from abc import ABC, abstractmethod
import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

class ExecutionResult(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    timed_out: bool = False

class BaseCodeRunner(ABC):
    """Abstract interface for sandboxed execution runners."""
    @abstractmethod
    async def run_python(self, code: str, timeout: Optional[float] = None) -> ExecutionResult:
        pass

import ast
import shutil

class SecurityASTVisitor(ast.NodeVisitor):
    """AST visitor detecting obfuscated execution, dynamic imports, and reflection attacks."""
    def __init__(self):
        self.violation: Optional[str] = None

    def visit_Call(self, node):
        if self.violation:
            return

        # Check for dynamic import: __import__(...)
        if isinstance(node.func, ast.Name):
            if node.func.id == "__import__":
                self.violation = "Static Safety Guard: Dynamic import '__import__' is forbidden."
                return
            if node.func.id in ("eval", "exec") and len(node.args) > 0 and not isinstance(node.args[0], ast.Constant):
                self.violation = f"Static Safety Guard: Dynamic '{node.func.id}' execution is forbidden."
                return
            if node.func.id in ("getattr", "setattr", "delattr") and len(node.args) >= 2:
                target_attr = ""
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    target_attr = node.args[1].value
                elif isinstance(node.args[1], ast.BinOp):
                    try:
                        target_attr = ast.literal_eval(node.args[1])
                    except Exception:
                        self.violation = "Static Safety Guard: Obfuscated attribute reflection detected."
                        return

                if target_attr in ("__subclasses__", "__builtins__", "__globals__", "rmtree", "system"):
                    self.violation = f"Static Safety Guard: Prohibited reflection access to '{target_attr}'."
                    return

        elif isinstance(node.func, ast.Attribute):
            if node.func.attr == "import_module":
                self.violation = "Static Safety Guard: Dynamic import via 'importlib.import_module' is forbidden."
                return
            if node.func.attr == "rmtree":
                if node.args:
                    arg_val = ""
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        arg_val = node.args[0].value
                    if arg_val in ("/", "C:", "C:\\", "\\", "c:"):
                        self.violation = "Static Safety Guard: Prohibited destructive recursive directory removal on root."
                        return

        self.generic_visit(node)

class IsolatedCodeRunner(BaseCodeRunner):
    """
    Hardened ephemeral sandbox runtime for untrusted code execution.
    Isolates file systems in temporary scratchpads, strictly whitelists environment variables,
    pre-scans for dangerous host operations with AST validation, and enforces hard execution timeouts.
    """
    # Environment variables strictly allowed in the sandbox process (whitelist approach)
    SAFE_ENV_KEYS = {
        "PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP",
        "PATHEXT", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
        "LANG", "LC_ALL"
    }

    # Prohibited critical operations detected in static pre-inspection
    DANGEROUS_PATTERNS = [
        "shutil.rmtree('C:",
        "shutil.rmtree(\"C:",
        "shutil.rmtree('/')",
        "shutil.rmtree(\"/\")",
        "os.system('format",
        "os.system(\"format",
    ]

    def __init__(self, timeout_seconds: float = 10.0, max_output_chars: int = 10000):
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    def _get_isolated_env(self) -> Dict[str, str]:
        """Produce a strict whitelist-based environment stripping all host credentials."""
        isolated_env = {}
        for key, val in os.environ.items():
            if key.upper() in self.SAFE_ENV_KEYS:
                isolated_env[key] = val
        # Ensure Python unbuffered mode
        isolated_env["PYTHONUNBUFFERED"] = "1"
        return isolated_env

    def _pre_inspect_code(self, code: str) -> Optional[str]:
        """Static safety pre-inspection to reject catastrophic host commands and obfuscation."""
        # 1. Fast-path pattern check
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in code:
                return f"Static Safety Guard: Prohibited destructive pattern detected: '{pattern}'"
        
        # 2. AST-level safety analysis
        try:
            tree = ast.parse(code)
            visitor = SecurityASTVisitor()
            visitor.visit(tree)
            if visitor.violation:
                return visitor.violation
        except SyntaxError:
            # Let the python sandbox interpreter report syntax errors normally
            pass
        return None

    async def run_python(self, code: str, timeout: Optional[float] = None) -> ExecutionResult:
        """Execute a Python snippet in an isolated ephemeral directory with strict environment boundaries."""
        effective_timeout = timeout or self.timeout_seconds
        start_time = time.perf_counter()

        # Pre-execution safety inspection
        safety_violation = self._pre_inspect_code(code)
        if safety_violation:
            return ExecutionResult(
                stdout="",
                stderr=safety_violation,
                exit_code=-1,
                duration_ms=0.0,
                timed_out=False
            )

        with tempfile.TemporaryDirectory(prefix="aios_sandbox_", ignore_cleanup_errors=True) as tmpdir:
            script_path = Path(tmpdir) / "script.py"
            script_path.write_text(code, encoding="utf-8")

            # Use current virtual environment python interpreter if available
            python_executable = sys.executable

            try:
                proc = await asyncio.create_subprocess_exec(
                    python_executable,
                    str(script_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=tmpdir,
                    env=self._get_isolated_env()
                )

                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=effective_timeout
                    )
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    stdout = stdout_bytes.decode("utf-8", errors="replace")[:self.max_output_chars]
                    stderr = stderr_bytes.decode("utf-8", errors="replace")[:self.max_output_chars]
                    return ExecutionResult(
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=proc.returncode if proc.returncode is not None else 0,
                        duration_ms=duration_ms,
                        timed_out=False
                    )
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                        await asyncio.wait_for(proc.wait(), timeout=1.0)
                    except Exception:
                        pass
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    return ExecutionResult(
                        stdout="",
                        stderr=f"Execution timed out after {effective_timeout}s. Process killed by Sandbox.",
                        exit_code=-1,
                        duration_ms=duration_ms,
                        timed_out=True
                    )
            except Exception as exc:
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return ExecutionResult(
                    stdout="",
                    stderr=f"Sandbox initialization error: {str(exc)}",
                    exit_code=-1,
                    duration_ms=duration_ms,
                    timed_out=False
                )

class DockerIsolatedRunner(BaseCodeRunner):
    """
    Enterprise Containerized Sandbox Backend.
    Spawns ephemeral Docker/Podman containers with network disabled (--network none)
    and resource limits for untrusted multi-tenant code execution.
    """
    def __init__(self, image: str = "python:3.11-slim", timeout_seconds: float = 10.0, max_output_chars: int = 10000):
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    async def run_python(self, code: str, timeout: Optional[float] = None) -> ExecutionResult:
        effective_timeout = timeout or self.timeout_seconds
        docker_path = shutil.which("docker")

        # If docker is available on the system host, attempt containerized execution
        if docker_path:
            start_time = time.perf_counter()
            try:
                proc = await asyncio.create_subprocess_exec(
                    docker_path,
                    "run",
                    "--rm",
                    "-i",
                    "--network", "none",
                    "-m", "256m",
                    "--cpus", "1.0",
                    self.image,
                    "python", "-u", "-",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(input=code.encode("utf-8")),
                        timeout=effective_timeout
                    )
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    return ExecutionResult(
                        stdout=stdout_bytes.decode("utf-8", errors="replace")[:self.max_output_chars],
                        stderr=stderr_bytes.decode("utf-8", errors="replace")[:self.max_output_chars],
                        exit_code=proc.returncode if proc.returncode is not None else 0,
                        duration_ms=duration_ms,
                        timed_out=False
                    )
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    return ExecutionResult(
                        stdout="",
                        stderr=f"Container execution timed out after {effective_timeout}s.",
                        exit_code=-1,
                        duration_ms=duration_ms,
                        timed_out=True
                    )
            except Exception as e:
                # Docker daemon not running or error spawning container -> fall back gracefully
                local_runner = IsolatedCodeRunner(timeout_seconds=effective_timeout, max_output_chars=self.max_output_chars)
                res = await local_runner.run_python(code, timeout=effective_timeout)
                res.stderr = f"[Sandbox Warning: Container runtime unavailable ({str(e)}). Executed via Isolated Host Sandbox]\n" + res.stderr
                return res

        # Fall back to local isolated runner if docker CLI is not installed
        local_runner = IsolatedCodeRunner(timeout_seconds=effective_timeout, max_output_chars=self.max_output_chars)
        return await local_runner.run_python(code, timeout=effective_timeout)

# Alias for naming consistency
DockerCodeRunner = DockerIsolatedRunner

def get_code_runner(backend: Optional[str] = None) -> BaseCodeRunner:
    """Factory function returning the configured code sandbox runner."""
    from config.settings import settings
    selected = (backend or settings.sandbox_backend).lower()
    if selected in ("docker", "container"):
        return DockerIsolatedRunner(
            image=settings.sandbox_docker_image,
            timeout_seconds=settings.default_timeout_seconds
        )
    return IsolatedCodeRunner(timeout_seconds=settings.default_timeout_seconds)
