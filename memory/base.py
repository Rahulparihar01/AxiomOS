from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid

class MemoryTier(str, Enum):
    L1_ACTIVE = "L1_ACTIVE"        # Working prompt context in LLM window
    L2_SESSION = "L2_SESSION"      # Ephemeral dialogue turn cache
    L3_SEMANTIC = "L3_SEMANTIC"    # Vector embedding recall store
    L4_ARCHIVAL = "L4_ARCHIVAL"    # Persistent relational key-value/audit store

class MemoryEntry(BaseModel):
    """Normalized unit of memory across any tier."""
    id: str = Field(default_factory=lambda: f"mem-{uuid.uuid4().hex[:8]}")
    tier: MemoryTier
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MemorySearchResult(BaseModel):
    """Result returned by semantic search or recall."""
    entry: MemoryEntry
    relevance_score: float

class BaseMemoryStore(ABC):
    """Abstract interface for a memory tier store."""

    @abstractmethod
    async def add(self, content: str, metadata: Optional[Dict[str, Any]] = None, tags: Optional[List[str]] = None) -> MemoryEntry:
        pass

    @abstractmethod
    async def get(self, memory_id: str) -> Optional[MemoryEntry]:
        pass

    @abstractmethod
    async def clear(self):
        pass
