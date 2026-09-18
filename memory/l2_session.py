from collections import deque
from typing import Any, Dict, List, Optional
from memory.base import BaseMemoryStore, MemoryEntry, MemoryTier

class L2SessionBuffer(BaseMemoryStore):
    """
    L2 Session Buffer: High-speed ephemeral in-memory cache retaining recent dialogue
    turns and intermediate agent outputs. Analogous to L2 CPU Cache / In-Memory RAM.
    """
    def __init__(self, capacity: int = 50):
        self.tier = MemoryTier.L2_SESSION
        self.capacity = capacity
        self._entries: deque[MemoryEntry] = deque(maxlen=capacity)
        self._lookup: Dict[str, MemoryEntry] = {}

    async def add(self, content: str, metadata: Optional[Dict[str, Any]] = None, tags: Optional[List[str]] = None) -> MemoryEntry:
        entry = MemoryEntry(
            tier=self.tier,
            content=content,
            metadata=metadata or {},
            tags=tags or []
        )
        if len(self._entries) == self.capacity:
            # Drop oldest from lookup table
            oldest = self._entries[0]
            self._lookup.pop(oldest.id, None)
            
        self._entries.append(entry)
        self._lookup[entry.id] = entry
        return entry

    async def get(self, memory_id: str) -> Optional[MemoryEntry]:
        return self._lookup.get(memory_id)

    def get_recent(self, limit: int = 10) -> List[MemoryEntry]:
        """Return the N most recent session entries in chronological order."""
        items = list(self._entries)
        return items[-limit:]

    async def clear(self):
        self._entries.clear()
        self._lookup.clear()

    def __len__(self) -> int:
        return len(self._entries)
