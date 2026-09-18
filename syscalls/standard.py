import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from pydantic import BaseModel, Field
from config.settings import settings
from kernel.process import ProcessControlBlock
from syscalls.base import SyscallBase, SyscallResult

class FsReadInput(BaseModel):
    filepath: str = Field(description="Relative path of the file to read within the workspace.")

class SysFsRead(SyscallBase):
    name = "sys_fs_read"
    description = "Read the textual content of a file within the permitted workspace directory."
    is_mutating = False
    input_schema = FsReadInput

    async def execute(self, pcb: ProcessControlBlock, filepath: str, **kwargs) -> SyscallResult:
        try:
            workspace_root = settings.workspace_root.resolve()
            target_path = (workspace_root / filepath).resolve()

            # Sandboxing check: Prevent directory traversal outside of workspace root
            if not str(target_path).startswith(str(workspace_root)):
                return SyscallResult(
                    success=False,
                    error=f"Permission Denied: Path '{filepath}' attempts directory traversal outside workspace."
                )

            if not target_path.exists():
                return SyscallResult(success=False, error=f"File not found: '{filepath}'")

            if not target_path.is_file():
                return SyscallResult(success=False, error=f"Path is not a regular file: '{filepath}'")

            content = target_path.read_text(encoding="utf-8", errors="replace")
            # Truncate if excessively large to protect context window
            if len(content) > 10000:
                content = content[:10000] + "\n... [Content truncated by Kernel Syscall: >10,000 chars]"

            return SyscallResult(success=True, data={"content": content, "size_bytes": len(content)})
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_fs_read failed: {str(e)}")

import ast
import operator

class SafeMathEvaluator:
    """Deterministic AST-based math evaluator preventing arbitrary code execution."""
    ALLOWED_OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    ALLOWED_UNARY = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }
    ALLOWED_FUNCTIONS = {
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
        "pow": pow,
        "sqrt": math.sqrt,
        "sin": math.sin,
        "cos": math.cos,
        "tan": math.tan,
        "log": math.log,
        "exp": math.exp,
    }
    ALLOWED_CONSTANTS = {
        "pi": math.pi,
        "e": math.e,
    }

    @classmethod
    def evaluate(cls, expression: str) -> float:
        parsed = ast.parse(expression.strip(), mode="eval")
        return cls._eval_node(parsed.body)

    @classmethod
    def _eval_node(cls, node: ast.AST):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError(f"Disallowed literal type: {type(node.value).__name__}")
        elif isinstance(node, ast.BinOp):
            op_type = type(node.op)
            if op_type not in cls.ALLOWED_OPERATORS:
                raise ValueError(f"Unsupported binary operator: {op_type.__name__}")
            left = cls._eval_node(node.left)
            right = cls._eval_node(node.right)
            # Guard against excessive exponential computations (ReDoS/DoS)
            if op_type is ast.Pow and (right > 1000 or (left > 10 and right > 100)):
                raise ValueError("Exponentiation exceeds safe magnitude limit.")
            return cls.ALLOWED_OPERATORS[op_type](left, right)
        elif isinstance(node, ast.UnaryOp):
            op_type = type(node.op)
            if op_type not in cls.ALLOWED_UNARY:
                raise ValueError(f"Unsupported unary operator: {op_type.__name__}")
            return cls.ALLOWED_UNARY[op_type](cls._eval_node(node.operand))
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ValueError("Dynamic or nested function calls are forbidden.")
            func_name = node.func.id
            if func_name not in cls.ALLOWED_FUNCTIONS:
                raise ValueError(f"Disallowed function '{func_name}'. Whitelist: {list(cls.ALLOWED_FUNCTIONS.keys())}")
            args = [cls._eval_node(arg) for arg in node.args]
            return cls.ALLOWED_FUNCTIONS[func_name](*args)
        elif isinstance(node, ast.Name):
            name = node.id
            if name in cls.ALLOWED_CONSTANTS:
                return cls.ALLOWED_CONSTANTS[name]
            raise ValueError(f"Undefined or forbidden identifier '{name}'.")
        else:
            raise ValueError(f"Forbidden syntax construct '{type(node).__name__}'.")

class CalcInput(BaseModel):
    expression: str = Field(description="Mathematical expression to evaluate, e.g., 'sqrt(144) + 25 * 3'.")

class SysCalc(SyscallBase):
    name = "sys_calc"
    description = "Safely evaluate a mathematical expression deterministically without executing arbitrary code."
    is_mutating = False
    input_schema = CalcInput

    async def execute(self, pcb: ProcessControlBlock, expression: str, **kwargs) -> SyscallResult:
        try:
            result = SafeMathEvaluator.evaluate(expression)
            return SyscallResult(success=True, data={"result": result})
        except Exception as e:
            return SyscallResult(success=False, error=f"Evaluation error: {str(e)}")

class LogInput(BaseModel):
    message: str = Field(description="Audit message to append to kernel event logs.")
    level: str = Field(default="INFO", description="Log severity level: DEBUG, INFO, WARNING, ERROR.")

class SysLog(SyscallBase):
    name = "sys_log"
    description = "Append a structured diagnostic message to the kernel audit log."
    is_mutating = True
    input_schema = LogInput

    async def execute(self, pcb: ProcessControlBlock, message: str, level: str = "INFO", **kwargs) -> SyscallResult:
        timestamp = datetime.now(timezone.utc).isoformat()
        formatted_entry = f"[{timestamp}] [PID:{pcb.pid}] [{level.upper()}] {message}"
        return SyscallResult(success=True, data={"log_entry": formatted_entry})

import httpx
from urllib.parse import urlparse

class NetFetchInput(BaseModel):
    url: str = Field(description="HTTP/HTTPS URL to retrieve (read-only GET request).")
    timeout_seconds: float = Field(default=10.0, description="Request timeout in seconds.")
    max_chars: int = Field(default=10000, description="Maximum characters of response content to return.")

class SysNetFetch(SyscallBase):
    name = "sys_net_fetch"
    description = "Perform a read-only HTTP/HTTPS GET request to fetch web pages, documentation, or public API data."
    is_mutating = False
    input_schema = NetFetchInput

    BLOCKED_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "[::1]"}

    async def execute(self, pcb: ProcessControlBlock, url: str, timeout_seconds: float = 10.0, max_chars: int = 10000, **kwargs) -> SyscallResult:
        try:
            parsed = urlparse(url)
            if parsed.scheme.lower() not in ("http", "https"):
                return SyscallResult(
                    success=False,
                    error=f"Disallowed protocol scheme: '{parsed.scheme}'. Only 'http' and 'https' are permitted."
                )

            hostname = (parsed.hostname or "").lower()
            if hostname in self.BLOCKED_HOSTS or hostname.startswith("127.") or hostname.startswith("10.") or hostname.startswith("192.168."):
                return SyscallResult(
                    success=False,
                    error=f"SSRF Protection: Access to private or loopback host '{hostname}' is forbidden."
                )

            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
                headers = {"User-Agent": f"AI-OS/{settings.version} (Autonomous-Agent-Kernel)"}
                resp = await client.get(url, headers=headers)
                content = resp.text
                if len(content) > max_chars:
                    content = content[:max_chars] + f"\n... [Content truncated by SysNetFetch: >{max_chars} chars]"

                return SyscallResult(
                    success=True,
                    data={
                        "status_code": resp.status_code,
                        "url": str(resp.url),
                        "content_type": resp.headers.get("content-type", ""),
                        "content": content,
                        "size_bytes": len(content)
                    }
                )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_net_fetch failed: {str(e)}")
