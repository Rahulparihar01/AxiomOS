"""
Enterprise BYOK (Bring-Your-Own-Key) Secrets Vault for AI-OS.
Allows workspaces to dynamically store, rotate, and securely access their own
LLM model provider credentials with token masking.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from config.settings import settings


class SecretsVault:
    """
    Durable, multi-tenant secrets store.
    Persists API credentials per workspace into SQLite with automated key masking.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (settings.workspace_root / "aios_memory.db")
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS workspace_vault_keys (
                    workspace_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    api_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (workspace_id, provider)
                );
            """)
            conn.commit()

    @staticmethod
    def mask_key(key: str) -> str:
        """Mask an API key for safe presentation (e.g. 'sk-12...abcd')."""
        if not key:
            return ""
        if len(key) <= 8:
            return "****"
        return f"{key[:4]}...{key[-4:]}"

    def set_key(self, workspace_id: str, provider: str, api_key: str) -> None:
        """Store or update a provider API key for a given workspace."""
        now = datetime.now(timezone.utc).isoformat()
        normalized_provider = provider.strip().lower()
        clean_key = api_key.strip()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO workspace_vault_keys (workspace_id, provider, api_key, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, provider) DO UPDATE SET
                    api_key=excluded.api_key,
                    updated_at=excluded.updated_at
            """, (workspace_id, normalized_provider, clean_key, now, now))
            conn.commit()

    def get_key(self, workspace_id: str, provider: str) -> Optional[str]:
        """Retrieve raw API key for a workspace and provider."""
        normalized_provider = provider.strip().lower()
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT api_key FROM workspace_vault_keys WHERE workspace_id = ? AND provider = ?",
                (workspace_id, normalized_provider)
            )
            row = cur.fetchone()
            if row:
                return row["api_key"]
        return None

    def list_keys(self, workspace_id: str) -> Dict[str, Dict[str, Any]]:
        """List configured providers and their masked keys for a workspace."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT provider, api_key, updated_at FROM workspace_vault_keys WHERE workspace_id = ?",
                (workspace_id,)
            )
            result = {}
            for row in cur.fetchall():
                p = row["provider"]
                k = row["api_key"]
                result[p] = {
                    "provider": p,
                    "masked_key": self.mask_key(k),
                    "updated_at": row["updated_at"]
                }
            return result

    def delete_key(self, workspace_id: str, provider: str) -> bool:
        """Delete an API key for a given workspace and provider."""
        normalized_provider = provider.strip().lower()
        with self._get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM workspace_vault_keys WHERE workspace_id = ? AND provider = ?",
                (workspace_id, normalized_provider)
            )
            conn.commit()
            return cur.rowcount > 0
