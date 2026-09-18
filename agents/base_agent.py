import fnmatch
import json
from typing import Any, Callable, Dict, List, Optional
from kernel.process import ProcessControlBlock, ProcessState
from kernel.governor import ResourceGovernor
from syscalls import SyscallRegistry
from models.provider import BaseModelProvider
from memory.mmu import MemoryManagementUnit
from memory.l1_context import L1ContextManager

class BaseAgent:
    """
    Standard AI-OS Agent process worker.
    Runs a goal-driven reasoning and action cycle governed by the Kernel and MMU.
    """
    def __init__(
        self,
        pcb: ProcessControlBlock,
        system_prompt: str,
        model_provider: BaseModelProvider,
        syscall_registry: SyscallRegistry,
        governor: ResourceGovernor,
        mmu: Optional[MemoryManagementUnit] = None,
        model_router: Optional[Any] = None,
        token_callback: Optional[Callable[[str], Any]] = None
    ):
        self.pcb = pcb
        self.system_prompt = system_prompt
        self.model_router = model_router
        self.model = model_router.route(pcb) if model_router else model_provider
        self.syscalls = syscall_registry
        self.governor = governor
        self.mmu = mmu
        self.token_callback = token_callback
        
        # Initialize L1 context manager from MMU if available, else local instance
        if self.mmu:
            self.l1: L1ContextManager = self.mmu.allocate_process_memory(
                pid=pcb.pid,
                system_prompt=system_prompt,
                max_capacity_tokens=pcb.l1_capacity
            )
        else:
            self.l1 = L1ContextManager(
                system_prompt=system_prompt,
                max_capacity_tokens=pcb.l1_capacity
            )

    def set_task(self, task_instruction: str):
        """Initialize the agent's task."""
        self.task_instruction = task_instruction
        self.l1.add_message("user", task_instruction)
        self._update_memory_telemetry()

    def _update_memory_telemetry(self):
        """Update PCB memory accounting fields."""
        self.pcb.l1_token_count = self.l1.get_token_count()
        self.pcb.l1_capacity = self.l1.max_capacity_tokens
        self.pcb.l1_utilization_pct = round(self.l1.utilization_ratio * 100, 1)

    async def step(self) -> bool:
        """
        Execute a single reasoning/action cycle.
        Returns True if process has completed or terminated, False if more steps are needed.
        """
        # 1. Kernel Governor Pre-Check (step budget, token budget, state, rate limits)
        self.governor.check_pre_step(self.pcb)
        self.governor.check_rate_limit(self.pcb)
        
        self.pcb.transition_to(ProcessState.RUNNING)
        step_num = self.pcb.increment_step()

        # 2. MMU Automated Paging Check (Virtual Memory Manager)
        if self.mmu:
            page_event = await self.mmu.check_and_page(self.pcb.pid)
            if page_event:
                self.pcb.paged_chunks_count += 1

        self._update_memory_telemetry()

        # 3. Get available tools filtered by process allocation
        available_tools = self.syscalls.list_tools()
        if self.pcb.allocated_tools and ("*" not in self.pcb.allocated_tools):
            available_tools = [
                t for t in available_tools
                if any(t["name"] == pat or fnmatch.fnmatch(t["name"], pat) for pat in self.pcb.allocated_tools)
            ]

        # 4. Compile Active L1 Working Context
        compiled_messages = self.l1.compile_messages()

        # 5. Model Inference (LLM Compute with Circuit Breaker Failover)
        if self.model_router and hasattr(self.model_router, "generate_with_fallback"):
            resp = await self.model_router.generate_with_fallback(
                pcb=self.pcb,
                system_prompt=self.system_prompt,
                messages=compiled_messages,
                tools=available_tools,
                on_token=self.token_callback
            )
        else:
            if self.token_callback is not None:
                try:
                    resp = await self.model.generate(
                        system_prompt=self.system_prompt,
                        messages=compiled_messages,
                        tools=available_tools,
                        on_token=self.token_callback
                    )
                except TypeError:
                    resp = await self.model.generate(
                        system_prompt=self.system_prompt,
                        messages=compiled_messages,
                        tools=available_tools
                    )
            else:
                resp = await self.model.generate(
                    system_prompt=self.system_prompt,
                    messages=compiled_messages,
                    tools=available_tools
                )

        # Record model interaction in flight recorder if enabled
        if hasattr(self.syscalls, "kernel") and getattr(self.syscalls.kernel, "flight_recorder", None):
            fr = self.syscalls.kernel.flight_recorder
            if hasattr(fr, "record_model_call_async"):
                await fr.record_model_call_async(
                    trace_id=self.pcb.trace_id,
                    step_seq=step_num,
                    prompt=compiled_messages,
                    response_content=resp.content,
                    tool_calls=[tc.model_dump() for tc in resp.tool_calls] if resp.tool_calls else []
                )
            else:
                fr.record_model_call(
                    trace_id=self.pcb.trace_id,
                    step_seq=step_num,
                    prompt=compiled_messages,
                    response_content=resp.content,
                    tool_calls=[tc.model_dump() for tc in resp.tool_calls] if resp.tool_calls else []
                )

        # 6. Account for token consumption and enforce budget quota
        self.pcb.consume_tokens(resp.total_tokens)
        if self.pcb.tokens_consumed > self.pcb.token_budget:
            self.pcb.transition_to(
                ProcessState.FAILED,
                error=f"Halted by Governor: Token budget exceeded ({self.pcb.tokens_consumed}/{self.pcb.token_budget})"
            )
            return True  # Terminal state reached

        # 7. Handle Tool Calls if any
        if resp.tool_calls:
            # First append the assistant turn declaring tool_calls to preserve OpenAI/Gemini message ordering
            self.l1.add_message(
                role="assistant",
                content=resp.content or "",
                tool_calls=[tc.model_dump() for tc in resp.tool_calls]
            )

            for tool_call in resp.tool_calls:
                # Security boundary check
                self.governor.check_tool_permission(self.pcb, tool_call.name)
                
                # Transition to BLOCKED (waiting on I/O)
                self.pcb.transition_to(ProcessState.BLOCKED)
                
                # Dispatch syscall
                result = await self.syscalls.dispatch(
                    self.pcb,
                    tool_call.name,
                    **tool_call.arguments
                )

                # Record syscall in flight recorder if enabled
                if hasattr(self.syscalls, "kernel") and getattr(self.syscalls.kernel, "flight_recorder", None):
                    fr = self.syscalls.kernel.flight_recorder
                    dur = getattr(result, "duration_ms", 0.0)
                    if hasattr(fr, "record_syscall_async"):
                        await fr.record_syscall_async(
                            trace_id=self.pcb.trace_id,
                            step_seq=step_num,
                            syscall_name=tool_call.name,
                            input_kwargs=tool_call.arguments,
                            success=result.success,
                            data=result.data,
                            error=result.error,
                            duration_ms=dur
                        )
                    else:
                        fr.record_syscall(
                            trace_id=self.pcb.trace_id,
                            step_seq=step_num,
                            syscall_name=tool_call.name,
                            input_kwargs=tool_call.arguments,
                            success=result.success,
                            data=result.data,
                            error=result.error,
                            duration_ms=dur
                        )
                
                # Append tool execution result into L1 working context
                tool_output_str = json.dumps(result.data) if result.success else f"Error: {result.error}"
                self.l1.add_message(
                    role="tool",
                    content=tool_output_str,
                    tool_call_id=tool_call.id,
                    name=tool_call.name
                )
            
            self._update_memory_telemetry()
            # Re-enter RUNNING state for the next reasoning cycle
            self.pcb.transition_to(ProcessState.RUNNING)
            return False

        # 8. If no tool calls, agent has produced the final answer
        self.pcb.result = resp.content
        if resp.content:
            self.l1.add_message("assistant", resp.content)
        self._update_memory_telemetry()
        self.pcb.transition_to(ProcessState.COMPLETED)
        return True
