from datetime import datetime, timedelta, timezone
import fnmatch
from pathlib import Path
from typing import Dict, List, Optional
import uuid
from pydantic import BaseModel, Field, model_validator

class CapabilityToken(BaseModel):
    """
    Short-lived, capability-scoped access token issued per agent process/task.
    Enforces least privilege by bounding syscall access to specific filesystem paths,
    authorized syscall functions, role definitions, and a strict Time-To-Live (TTL) lease.
    Remediates VULN-06 and GAP-11.
    """
    token_id: str = Field(default_factory=lambda: f"cap-{uuid.uuid4().hex[:8]}")
    pid: str
    role: str = "base"
    scope_paths: List[str] = Field(default_factory=lambda: ["*"])
    allowed_syscalls: List[str] = Field(default_factory=lambda: ["*"])
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    ttl_seconds: int = 120
    renewal_count: int = 0
    max_renewals: int = 10
    requires_hitl: bool = False
    revoked: bool = False

    @model_validator(mode="after")
    def align_expiry(self) -> "CapabilityToken":
        if self.expires_at is None:
            self.expires_at = self.issued_at + timedelta(seconds=self.ttl_seconds)
        return self

    def is_expired(self) -> bool:
        """Check if the capability token has expired its Time-To-Live or been revoked."""
        if self.revoked:
            return True
        return datetime.now(timezone.utc) > self.expires_at

    def remaining_ttl(self) -> float:
        """Return remaining seconds before token lease expiration (or 0.0 if expired)."""
        if self.is_expired():
            return 0.0
        return max(0.0, (self.expires_at - datetime.now(timezone.utc)).total_seconds())

    def renew_lease(self, extension_seconds: Optional[int] = None) -> bool:
        """
        Extend capability token lease if eligible.
        Returns True if successfully renewed, False if max renewals reached or revoked.
        """
        if self.revoked or self.renewal_count >= self.max_renewals:
            return False
        seconds = extension_seconds if extension_seconds is not None else self.ttl_seconds
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        self.renewal_count += 1
        return True

    def revoke(self) -> None:
        """Immediately invalidate this capability token."""
        self.revoked = True

    def can_access_path(self, target_path: str) -> bool:
        """
        Verify if target file path falls within the token's scope_paths glob patterns.
        Rejects directory traversal outside the workspace and protects sensitive files.
        """
        if self.is_expired() or self.revoked:
            return False

        normalized_target = str(Path(target_path)).replace("\\", "/")

        # 1. Guard against directory traversal outside workspace
        target_parts = [p for p in normalized_target.split("/") if p]
        if ".." in target_parts:
            return False

        # 2. Sensitive credential & system file protection (.env, secrets, keys)
        target_name = Path(normalized_target).name.lower()
        sensitive_patterns = [".env", ".env.*", "*.env", "*secrets*", "*secret*", "*private_key*", "*id_rsa*"]
        is_sensitive = any(
            fnmatch.fnmatch(target_name, sp) or fnmatch.fnmatch(normalized_target.lower(), sp)
            for sp in sensitive_patterns
        )
        if is_sensitive:
            # Only permit access if explicitly and specifically named in scope_paths
            explicit_match = any(
                (pat == normalized_target or pat == target_name)
                for pat in self.scope_paths
            )
            if not explicit_match:
                return False

        # 3. Check for wildcard permission
        if "*" in self.scope_paths or "**" in self.scope_paths:
            return True

        # 4. Pattern matching on normalized relative paths and basenames
        for pattern in self.scope_paths:
            normalized_pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(normalized_target, normalized_pattern):
                return True
            if fnmatch.fnmatch(target_name, normalized_pattern):
                return True
            # Subpath prefix check for directory trees (e.g. "sandbox/**" or "scratch/*")
            if normalized_pattern.endswith("/**"):
                base_dir = normalized_pattern[:-3]
                if normalized_target.startswith(base_dir) or normalized_target.startswith(f"./{base_dir}"):
                    return True
            elif normalized_pattern.endswith("/*"):
                base_dir = normalized_pattern[:-2]
                if normalized_target.startswith(base_dir) or normalized_target.startswith(f"./{base_dir}"):
                    return True

        return False

    def can_call_syscall(self, syscall_name: str) -> bool:
        """Check if the specific syscall is authorized by this token."""
        if self.is_expired() or self.revoked:
            return False
        if "*" in self.allowed_syscalls:
            return True
        for allowed in self.allowed_syscalls:
            if allowed == syscall_name or fnmatch.fnmatch(syscall_name, allowed):
                return True
        return False

class CapabilityIssuer:
    """
    Kernel space token authority responsible for issuing scoped capability tokens
    at process spawn time. Enforces least-privilege defaults per agent persona.
    """

    ROLE_DEFAULT_PATHS: Dict[str, List[str]] = {
        "planner": [
            "workspace/**",
            "docs/**",
            "sandbox/**",
            "*.md",
            "*.json",
            "*.txt"
        ],
        "coder": [
            "workspace/**",
            "sandbox/**",
            "scratch/**",
            "tmp/**",
            "tests/**",
            "src/**",
            "*.py",
            "*.json",
            "*.txt",
            "*.md"
        ],
        "reviewer": [
            "workspace/**",
            "sandbox/**",
            "scratch/**",
            "docs/**",
            "tests/**",
            "*.py",
            "*.json",
            "*.md",
            "*.txt"
        ],
        "researcher": [
            "workspace/**",
            "docs/**",
            "research/**",
            "sandbox/**",
            "*.md",
            "*.txt",
            "*.json"
        ],
        "conflict_resolver": [
            "workspace/**",
            "memory/**",
            "docs/**",
            "*.json",
            "*.md"
        ],
        "base": [
            "workspace/**",
            "sandbox/**",
            "scratch/**",
            "tmp/**",
            "*.txt",
            "*.json",
            "*.md",
            "*.py"
        ]
    }

    ROLE_DEFAULT_SYSCALLS: Dict[str, List[str]] = {
        "planner": [
            "sys_plan_register_subtask",
            "sys_proc_spawn",
            "sys_proc_wait",
            "sys_proc_kill",
            "sys_proc_send_msg",
            "sys_proc_recv_msg",
            "sys_blackboard_read",
            "sys_blackboard_write",
            "sys_blackboard_await",
            "sys_mem_recall",
            "sys_mem_stats",
            "sys_log",
            "sys_calc",
            "sys_fs_read",
            "sys_cap_renew",
            "mcp_*"
        ],
        "coder": [
            "sys_code_record_artifact",
            "sys_fs_read",
            "sys_fs_write",
            "sys_fs_delete",
            "sys_exec_python",
            "sys_calc",
            "sys_log",
            "sys_mem_recall",
            "sys_mem_store",
            "sys_mem_stats",
            "sys_blackboard_read",
            "sys_blackboard_write",
            "sys_blackboard_await",
            "sys_cap_renew",
            "mcp_*"
        ],
        "reviewer": [
            "sys_audit_record_verdict",
            "sys_fs_read",
            "sys_log",
            "sys_calc",
            "sys_mem_recall",
            "sys_mem_stats",
            "sys_blackboard_read",
            "sys_blackboard_write",
            "sys_blackboard_await",
            "sys_cap_renew",
            "mcp_*"
        ],
        "researcher": [
            "sys_research_record_finding",
            "sys_net_fetch",
            "sys_mem_recall",
            "sys_mem_store",
            "sys_mem_stats",
            "sys_log",
            "sys_calc",
            "sys_blackboard_read",
            "sys_blackboard_write",
            "sys_blackboard_await",
            "sys_fs_read",
            "sys_cap_renew",
            "mcp_*"
        ],
        "conflict_resolver": [
            "sys_conflict_record_resolution",
            "sys_mem_recall",
            "sys_mem_store",
            "sys_mem_stats",
            "sys_log",
            "sys_calc",
            "sys_blackboard_read",
            "sys_blackboard_write",
            "sys_blackboard_await",
            "sys_cap_renew",
            "mcp_*"
        ],
        "base": [
            "sys_calc",
            "sys_log",
            "sys_mem_recall",
            "sys_mem_store",
            "sys_mem_stats",
            "sys_fs_read",
            "sys_fs_write",
            "sys_proc_spawn",
            "sys_proc_wait",
            "sys_proc_kill",
            "sys_proc_send_msg",
            "sys_proc_recv_msg",
            "sys_blackboard_read",
            "sys_blackboard_write",
            "sys_blackboard_await",
            "sys_cap_renew",
            "mcp_*"
        ]
    }

    @classmethod
    def get_default_paths(cls, role: str) -> List[str]:
        """Retrieve default authorized path scopes for a persona role."""
        return list(cls.ROLE_DEFAULT_PATHS.get((role or "base").lower(), cls.ROLE_DEFAULT_PATHS["base"]))

    @classmethod
    def get_default_syscalls(cls, role: str) -> List[str]:
        """Retrieve default authorized syscalls for a persona role."""
        return list(cls.ROLE_DEFAULT_SYSCALLS.get((role or "base").lower(), cls.ROLE_DEFAULT_SYSCALLS["base"]))

    @classmethod
    def issue_token(
        cls,
        pid: str,
        role: str = "base",
        scope_paths: Optional[List[str]] = None,
        allowed_syscalls: Optional[List[str]] = None,
        ttl_seconds: int = 120,
        requires_hitl: bool = False
    ) -> CapabilityToken:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)

        effective_role = (role or "base").lower()
        paths = scope_paths if scope_paths is not None else cls.get_default_paths(effective_role)
        syscalls = allowed_syscalls if allowed_syscalls is not None else cls.get_default_syscalls(effective_role)

        return CapabilityToken(
            pid=pid,
            role=effective_role,
            scope_paths=paths,
            allowed_syscalls=syscalls,
            issued_at=now,
            expires_at=expires,
            ttl_seconds=ttl_seconds,
            requires_hitl=requires_hitl
        )

    @classmethod
    def renew_token(cls, token: CapabilityToken, extension_seconds: Optional[int] = None) -> bool:
        """Renew capability lease for a valid token."""
        return token.renew_lease(extension_seconds)
