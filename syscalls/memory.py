from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from kernel.process import ProcessControlBlock
from syscalls.base import SyscallBase, SyscallResult
from memory.mmu import MemoryManagementUnit

from ipc.message import create_conflict_message

class MemStoreInput(BaseModel):
    key: str = Field(description="Unique key or topic for the fact/memory.")
    value: str = Field(description="Content or value of the fact to store permanently.")
    confidence: float = Field(default=1.0, description="Confidence score for this fact (0.0 to 1.0).")

class SysMemStore(SyscallBase):
    name = "sys_mem_store"
    description = "Store a persistent fact, variable, or learned information into L4 archival memory."
    is_mutating = True
    input_schema = MemStoreInput

    def __init__(self, mmu: MemoryManagementUnit, kernel: Optional[Any] = None):
        self.mmu = mmu
        self.kernel = kernel

    async def execute(self, pcb: ProcessControlBlock, key: str, value: str, confidence: float = 1.0, **kwargs) -> SyscallResult:
        try:
            record, was_conflict = self.mmu.l4_archival.store_versioned_fact(
                key=key,
                value=value,
                written_by_pid=pcb.pid,
                confidence=confidence
            )

            # If conflict detected and kernel message bus is accessible, broadcast MEMORY_CONFLICT event
            if was_conflict and self.kernel and getattr(self.kernel, "message_bus", None):
                history = self.mmu.l4_archival.get_fact_history(key)
                prev_record = history[-2] if len(history) >= 2 else None
                conflict_msg = create_conflict_message(
                    sender_pid=pcb.pid,
                    key=key,
                    existing_value=prev_record.value if prev_record else "unknown",
                    incoming_value=value,
                    existing_written_by=prev_record.written_by_pid if prev_record else None,
                    incoming_written_by=pcb.pid,
                    trace_id=getattr(pcb, "trace_id", None)
                )
                self.kernel.message_bus.broadcast(conflict_msg)

            # Also index in L3 vector memory for semantic recall
            await self.mmu.l3_semantic.add(
                content=f"Fact '{key}': {value}",
                metadata={"key": key, "owner_pid": pcb.pid, "version": record.version, "conflict": was_conflict},
                tags=["fact", pcb.pid]
            )

            return SyscallResult(
                success=True,
                data={
                    "stored_key": key,
                    "fact_id": record.fact_id,
                    "version": record.version,
                    "conflict_flag": record.conflict_flag,
                    "status": "persisted_with_conflict" if was_conflict else "persisted"
                }
            )
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_mem_store failed: {str(e)}")

class MemRecallInput(BaseModel):
    query: str = Field(description="Search query or topic to retrieve relevant historical memories for.")
    top_k: int = Field(default=3, description="Maximum number of relevant past memories to return.")

class SysMemRecall(SyscallBase):
    name = "sys_mem_recall"
    description = "Perform semantic recall across L3 vector memory to retrieve past conversation contexts and facts."
    is_mutating = False
    input_schema = MemRecallInput

    def __init__(self, mmu: MemoryManagementUnit):
        self.mmu = mmu

    async def execute(self, pcb: ProcessControlBlock, query: str, top_k: int = 3, **kwargs) -> SyscallResult:
        try:
            # Check L4 exact fact match first
            exact_fact = self.mmu.l4_archival.get_fact(query)
            results = await self.mmu.recall_memory(pid=pcb.pid, query=query, top_k=top_k)

            formatted_results = [
                {"content": r.entry.content, "score": r.relevance_score, "tags": r.entry.tags}
                for r in results
            ]
            
            data: Dict[str, Any] = {"matches": formatted_results, "total_found": len(formatted_results)}
            if exact_fact:
                data["exact_fact"] = exact_fact

            return SyscallResult(success=True, data=data)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_mem_recall failed: {str(e)}")

class SysMemStats(SyscallBase):
    name = "sys_mem_stats"
    description = "Retrieve current memory telemetry and utilization across L1, L2, L3, and L4 tiers."
    is_mutating = False

    def __init__(self, mmu: MemoryManagementUnit):
        self.mmu = mmu

    async def execute(self, pcb: ProcessControlBlock, **kwargs) -> SyscallResult:
        try:
            stats = self.mmu.get_memory_stats(pid=pcb.pid)
            return SyscallResult(success=True, data=stats)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_mem_stats failed: {str(e)}")
