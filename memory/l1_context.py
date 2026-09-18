from typing import Any, Dict, List, Optional
from memory.base import MemoryTier

def estimate_tokens(text: str) -> int:
    """Fast, reliable heuristic token counter (avg ~4 characters per token)."""
    if not text:
        return 0
    return max(1, len(text) // 4 + 1)

class L1ContextManager:
    """
    L1 Working Memory: Manages the active prompt context window passed directly to the LLM.
    Acts as the CPU L1 Cache of the AI-OS.
    """
    def __init__(self, system_prompt: str = "", max_capacity_tokens: int = 4000):
        self.tier = MemoryTier.L1_ACTIVE
        self.system_prompt = system_prompt
        self.max_capacity_tokens = max_capacity_tokens
        self.messages: List[Dict[str, Any]] = []
        self._summary_context: Optional[str] = None
        self._recalled_context: List[str] = []

    def set_system_prompt(self, prompt: str):
        self.system_prompt = prompt

    def add_message(self, role: str, content: str, **kwargs) -> Dict[str, Any]:
        msg = {"role": role, "content": content, **kwargs}
        self.messages.append(msg)
        return msg

    def set_compacted_summary(self, summary: str):
        """Set or update the compacted historical summary."""
        self._summary_context = summary

    def inject_recalled_memory(self, content: str):
        """Inject demand-paged memory into the active context."""
        self._recalled_context.append(content)

    def clear_recalled_memory(self):
        self._recalled_context.clear()

    def get_token_count(self) -> int:
        """Estimate the total tokens in the active context window."""
        total = estimate_tokens(self.system_prompt)
        if self._summary_context:
            total += estimate_tokens(self._summary_context)
        for recalled in self._recalled_context:
            total += estimate_tokens(recalled)
        for m in self.messages:
            total += estimate_tokens(str(m.get("content", "")))
        return total

    @property
    def utilization_ratio(self) -> float:
        """Returns current utilization between 0.0 and 1.0+."""
        return self.get_token_count() / max(1, self.max_capacity_tokens)

    def extract_oldest_turns(self, count: int) -> List[Dict[str, Any]]:
        """
        Extract the oldest conversational turns for eviction/paging,
        leaving at least the most recent turn, ensuring assistant tool_calls
        and their matching tool response turns are kept as atomic groups.
        """
        if len(self.messages) <= 1:
            return []
        extract_count = min(count, len(self.messages) - 1)

        # Expand extract_count to include all matching tool response messages so we don't leave orphaned tool turns
        while extract_count < len(self.messages) - 1 and self.messages[extract_count].get("role") == "tool":
            extract_count += 1

        # If extract_count-1 is an assistant turn declaring tool_calls, pull in its subsequent tool responses
        if (
            extract_count < len(self.messages) - 1
            and self.messages[extract_count - 1].get("role") == "assistant"
            and self.messages[extract_count - 1].get("tool_calls")
        ):
            while extract_count < len(self.messages) - 1 and self.messages[extract_count].get("role") == "tool":
                extract_count += 1

        evicted = self.messages[:extract_count]
        self.messages = self.messages[extract_count:]
        return evicted

    def compile_messages(self) -> List[Dict[str, Any]]:
        """
        Assemble the full prompt messages array ready for LLM consumption,
        integrating compacted summary and any recalled memory.
        """
        compiled: List[Dict[str, Any]] = []
        
        # Inject compacted summary if present
        if self._summary_context:
            compiled.append({
                "role": "system",
                "content": f"[SYSTEM MEMORY SUMMARY OF PREVIOUS STEPS]:\n{self._summary_context}"
            })
            
        # Inject recalled long-term memories if present
        if self._recalled_context:
            recalled_text = "\n---\n".join(self._recalled_context)
            compiled.append({
                "role": "system",
                "content": f"[RECALLED HISTORICAL CONTEXT FROM L3/L4 MEMORY]:\n{recalled_text}"
            })

        compiled.extend(self.messages)
        return compiled
