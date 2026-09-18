from abc import ABC, abstractmethod
import hashlib
import json
import logging
import math
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import httpx
from config.settings import settings
from memory.base import BaseMemoryStore, MemoryEntry, MemorySearchResult, MemoryTier

logger = logging.getLogger(__name__)

class BaseTextVectorizer(ABC):
    """Abstract interface for text vectorizers and embedding adapters."""

    @abstractmethod
    def vectorize(self, text: str) -> List[float]:
        """Synchronously vectorize input text into a normalized embedding vector."""
        pass

    async def avectorize(self, text: str) -> List[float]:
        """Asynchronously vectorize input text."""
        return self.vectorize(text)

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        """Compute cosine similarity between two unit-normalized vectors."""
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        return sum(a * b for a, b in zip(v1, v2))


class HashTextVectorizer(BaseTextVectorizer):
    """
    Deterministic text vectorizer using subword hashing and cosine normalization.
    Uses MD5 cryptographic hashing rather than process-seeded hash() to guarantee
    identical vector coordinates across different Python execution sessions.
    """
    def __init__(self, dimensions: int = 128):
        self.dimensions = dimensions

    def _hash(self, token: str) -> int:
        return int(hashlib.md5(token.encode("utf-8")).hexdigest()[:8], 16) % self.dimensions

    def vectorize(self, text: str) -> List[float]:
        tokens = re.findall(r"\b\w+\b", text.lower())
        if not tokens:
            return [0.0] * self.dimensions

        vec = [0.0] * self.dimensions
        for token in tokens:
            idx = self._hash(token)
            vec[idx] += 1.0

        # Also add character 3-grams for semantic subword fuzzy matching
        for i in range(len(text) - 2):
            trigram = text[i:i+3].lower()
            idx = self._hash(trigram)
            vec[idx] += 0.5

        # Normalize vector to unit length (L2 norm)
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec


# Legacy alias
TextVectorizer = HashTextVectorizer


class DenseEmbeddingVectorizer(BaseTextVectorizer):
    """
    Pluggable dense vector embedding adapter for OpenAI or Gemini embedding endpoints.
    Features automatic graceful degradation to HashTextVectorizer on failure or missing API keys.
    """
    def __init__(
        self,
        provider: str = "openai",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        dimensions: int = 128
    ):
        self.provider = provider.lower()
        self.dimensions = dimensions
        self.api_key = api_key or (settings.openai_api_key if self.provider == "openai" else settings.gemini_api_key)
        self.model = model or settings.embedding_model
        self._fallback = HashTextVectorizer(dimensions=dimensions)

    def vectorize(self, text: str) -> List[float]:
        """Synchronous vectorization fallback using hash vectorizer."""
        return self._fallback.vectorize(text)

    async def avectorize(self, text: str) -> List[float]:
        """Asynchronously call remote embedding API with fallback."""
        if not self.api_key:
            return self._fallback.vectorize(text)

        try:
            if self.provider == "openai":
                url = "https://api.openai.com/v1/embeddings"
                headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
                payload = {"input": text, "model": self.model}
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    raw_vec = data["data"][0]["embedding"]
            elif self.provider == "gemini":
                model_name = self.model or "text-embedding-004"
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:embedContent?key={self.api_key}"
                payload = {"content": {"parts": [{"text": text}]}}
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    raw_vec = data["embedding"]["values"]
            else:
                return self._fallback.vectorize(text)

            # Reduce or project to desired dimensions if needed
            if len(raw_vec) > self.dimensions:
                raw_vec = raw_vec[:self.dimensions]
            elif len(raw_vec) < self.dimensions:
                raw_vec = raw_vec + [0.0] * (self.dimensions - len(raw_vec))

            norm = math.sqrt(sum(x * x for x in raw_vec))
            if norm > 0:
                raw_vec = [x / norm for x in raw_vec]
            return raw_vec
        except Exception as exc:
            logger.warning(f"Dense embedding call failed ({exc}); falling back to HashTextVectorizer.")
            return self._fallback.vectorize(text)


def get_vectorizer(provider_type: Optional[str] = None, dimensions: int = 128) -> BaseTextVectorizer:
    """Factory function returning the configured text vectorizer."""
    prov = (provider_type or settings.embedding_provider).lower()
    if prov in ("openai", "gemini"):
        return DenseEmbeddingVectorizer(provider=prov, dimensions=dimensions)
    return HashTextVectorizer(dimensions=dimensions)


class L3SemanticStore(BaseMemoryStore):
    """
    L3 Semantic Recall Store: Vector database tier storing paged-out context
    chunks, learned procedures, and documents. Supports top-k cosine similarity recall.
    Persists vectors to SQLite for durable cross-reboot recall.
    """
    def __init__(
        self,
        dimensions: int = 128,
        db_path: Optional[Path] = None,
        vectorizer: Optional[BaseTextVectorizer] = None
    ):
        self.tier = MemoryTier.L3_SEMANTIC
        self.vectorizer = vectorizer or get_vectorizer(dimensions=dimensions)
        self._entries: Dict[str, Tuple[MemoryEntry, List[float]]] = {}
        self.db_path = db_path or (settings.workspace_root / "aios_memory.db")
        self._init_db()
        self._load_from_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS l3_semantic_vectors (
                    id TEXT PRIMARY KEY,
                    tier TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT,
                    tags_json TEXT,
                    vector_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.commit()

    def _load_from_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT id, tier, content, metadata_json, tags_json, vector_json, created_at FROM l3_semantic_vectors")
            for row in cur.fetchall():
                try:
                    entry = MemoryEntry(
                        id=row[0],
                        tier=MemoryTier(row[1]),
                        content=row[2],
                        metadata=json.loads(row[3]) if row[3] else {},
                        tags=json.loads(row[4]) if row[4] else []
                    )
                    vec = json.loads(row[5])
                    self._entries[entry.id] = (entry, vec)
                except Exception:
                    continue

    async def add(self, content: str, metadata: Optional[Dict[str, Any]] = None, tags: Optional[List[str]] = None) -> MemoryEntry:
        entry = MemoryEntry(
            tier=self.tier,
            content=content,
            metadata=metadata or {},
            tags=tags or []
        )
        if hasattr(self.vectorizer, "avectorize"):
            vector = await self.vectorizer.avectorize(content)
        else:
            vector = self.vectorizer.vectorize(content)
        self._entries[entry.id] = (entry, vector)

        # Persist to SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO l3_semantic_vectors (id, tier, content, metadata_json, tags_json, vector_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET content=excluded.content, vector_json=excluded.vector_json",
                (
                    entry.id,
                    entry.tier.value,
                    entry.content,
                    json.dumps(entry.metadata),
                    json.dumps(entry.tags),
                    json.dumps(vector),
                    entry.created_at.isoformat()
                )
            )
            conn.commit()

        return entry

    async def get(self, memory_id: str) -> Optional[MemoryEntry]:
        item = self._entries.get(memory_id)
        return item[0] if item else None

    async def search(self, query: str, top_k: int = 3, min_score: float = 0.05) -> List[MemorySearchResult]:
        """Perform semantic similarity search over stored memory vectors."""
        if hasattr(self.vectorizer, "avectorize"):
            query_vec = await self.vectorizer.avectorize(query)
        else:
            query_vec = self.vectorizer.vectorize(query)
        scored: List[Tuple[MemoryEntry, float]] = []

        for entry, vec in self._entries.values():
            score = self.vectorizer.cosine_similarity(query_vec, vec)
            if score >= min_score:
                scored.append((entry, score))

        # Sort descending by cosine similarity score
        scored.sort(key=lambda x: x[1], reverse=True)
        return [MemorySearchResult(entry=e, relevance_score=round(s, 4)) for e, s in scored[:top_k]]

    async def clear(self):
        self._entries.clear()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM l3_semantic_vectors")
            conn.commit()

    def __len__(self) -> int:
        return len(self._entries)
