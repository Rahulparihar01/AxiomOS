import asyncio
from typing import Any, Dict, List, Optional
from memory.base import MemorySearchResult
from memory.l1_context import L1ContextManager
from memory.l2_session import L2SessionBuffer
from memory.l3_semantic import L3SemanticStore
from memory.l4_archival import L4ArchivalStore

class PageEvent(BaseException if False else object):
    def __init__(self, pid: str, turns_evicted: int, tokens_freed: int, new_utilization: float):
        self.pid = pid
        self.turns_evicted = turns_evicted
        self.tokens_freed = tokens_freed
        self.new_utilization = new_utilization

class MemoryManagementUnit:
    """
    The Memory Management Unit (MMU) of the AI-OS.
    Manages virtual context memory, automatic paging, historical compaction,
    and demand paging across L1, L2, L3, and L4 tiers.
    """
    def __init__(self, paging_threshold: float = 0.75, db_path: Optional[Any] = None):
        self.paging_threshold = paging_threshold
        # Per-process L1 working memory
        self._l1_spaces: Dict[str, L1ContextManager] = {}
        # Shared memory tiers
        self.l2_session = L2SessionBuffer()
        self.l3_semantic = L3SemanticStore(db_path=db_path)
        self.l4_archival = L4ArchivalStore(db_path=db_path)
        # Telemetry & Paging history
        self.paging_events: List[Dict[str, Any]] = []

    def allocate_process_memory(self, pid: str, system_prompt: str = "", max_capacity_tokens: int = 4000) -> L1ContextManager:
        """Create and bind an L1 working context to a specific agent process."""
        l1 = L1ContextManager(system_prompt=system_prompt, max_capacity_tokens=max_capacity_tokens)
        self._l1_spaces[pid] = l1
        return l1

    def get_l1(self, pid: str) -> Optional[L1ContextManager]:
        return self._l1_spaces.get(pid)

    async def check_and_page(self, pid: str) -> Optional[Dict[str, Any]]:
        """
        Check active context utilization. If utilization >= paging_threshold,
        trigger automated page-out and compaction to L3/L4.
        """
        l1 = self.get_l1(pid)
        if not l1:
            return None

        if l1.utilization_ratio < self.paging_threshold:
            return None

        # Context limit reached! Trigger Page-Out
        initial_tokens = l1.get_token_count()
        # Evict oldest turns (e.g. 2 turns at a time)
        evicted_turns = l1.extract_oldest_turns(count=2)
        if not evicted_turns:
            return None

        # Format evicted turns into an archival text chunk
        evicted_text_lines = []
        for turn in evicted_turns:
            role = turn.get("role", "unknown")
            content = str(turn.get("content", ""))
            evicted_text_lines.append(f"{role.upper()}: {content}")
        evicted_chunk = "\n".join(evicted_text_lines)

        # 1. Page to L2 session buffer
        await self.l2_session.add(
            content=evicted_chunk,
            metadata={"pid": pid, "type": "paged_dialogue_turns"},
            tags=["paged", pid]
        )

        # 2. Vectorize and page to L3 semantic store for future recall
        await self.l3_semantic.add(
            content=evicted_chunk,
            metadata={"pid": pid, "original_turn_count": len(evicted_turns)},
            tags=["paged_context", pid]
        )

        # 3. Save to L4 archival permanent storage
        await self.l4_archival.add(
            content=evicted_chunk,
            metadata={"pid": pid, "source": "mmu_page_out"},
            tags=["archived_context", pid]
        )

        # 4. Generate a concise compacted summary and inject into L1
        first_line = evicted_text_lines[0].split("\n")[0][:40]
        compacted_summary = f"[Archived {len(evicted_turns)} turns: '{first_line}...']"
        l1.set_compacted_summary(compacted_summary)

        tokens_freed = initial_tokens - l1.get_token_count()
        event_data = {
            "pid": pid,
            "turns_evicted": len(evicted_turns),
            "tokens_freed": tokens_freed,
            "new_utilization": round(l1.utilization_ratio, 3)
        }
        self.paging_events.append(event_data)
        return event_data

    async def recall_memory(self, pid: str, query: str, top_k: int = 3) -> List[MemorySearchResult]:
        """
        Demand Paging: Query L3 semantic store and inject relevant historical context
        directly into the process's L1 working context.
        """
        results = await self.l3_semantic.search(query=query, top_k=top_k)
        l1 = self.get_l1(pid)
        if l1 and results:
            for r in results:
                snippet = f"Relevant Past Memory (Score: {r.relevance_score}): {r.entry.content}"
                l1.inject_recalled_memory(snippet)
        return results

    def get_memory_stats(self, pid: Optional[str] = None) -> Dict[str, Any]:
        """Return system-wide and per-process memory statistics across all tiers."""
        stats = {
            "l2_session_entries": len(self.l2_session),
            "l3_semantic_vectors": len(self.l3_semantic),
            "l4_facts_count": len(self.l4_archival.list_facts()),
            "total_page_outs": len(self.paging_events)
        }
        if pid and pid in self._l1_spaces:
            l1 = self._l1_spaces[pid]
            stats["pid"] = pid
            stats["l1_tokens"] = l1.get_token_count()
            stats["l1_capacity"] = l1.max_capacity_tokens
            stats["l1_utilization_pct"] = round(l1.utilization_ratio * 100, 1)
        return stats
