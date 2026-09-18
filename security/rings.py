from enum import IntEnum

class SecurityRing(IntEnum):
    """
    Hierarchical Security Rings for AI-OS Syscalls.
    Analogous to x86 CPU Protection Rings (Ring 0 to Ring 3).
    """
    RING_0_KERNEL = 0      # Core Kernel & Scheduler internal operations
    RING_1_SAFE = 1        # Read-only, deterministic tools (No external side-effects)
    RING_2_MUTATING = 2    # Modifies internal agent/memory/workspace state
    RING_3_DESTRUCTIVE = 3 # High-risk operations (Code execution, deletion) requiring HITL approval
