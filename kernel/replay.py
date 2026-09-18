import asyncio
import concurrent.futures
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from kernel.flight_recorder import FlightRecorder, TraceRecord
from kernel.process import ProcessControlBlock, ProcessState
from kernel.governor import ResourceGovernor
from agents.base_agent import BaseAgent
from models.provider import BaseModelProvider, ModelResponse, ToolCallRequest
from syscalls.base import SyscallResult

class ReplayStepSummary(BaseModel):
    step_seq: int
    record_type: str
    details: Dict[str, Any]
    matched: bool = True
    divergence_reason: Optional[str] = None

class ReplayReport(BaseModel):
    trace_id: str
    total_records: int
    model_calls_count: int
    syscalls_count: int
    is_reproducible: bool
    steps: List[ReplayStepSummary] = Field(default_factory=list)
    divergence_step: Optional[int] = None
    error: Optional[str] = None

class ReplayModelProvider(BaseModelProvider):
    """
    Model provider for deterministic offline replay.
    Feeds recorded model responses back into the agent reasoning cycle
    while verifying prompt hash integrity and catching divergences.
    """
    def __init__(self, model_records: List[TraceRecord]):
        self.model_records = sorted(model_records, key=lambda r: r.step_seq)
        self.current_idx = 0
        self.divergences: List[Dict[str, Any]] = []

    async def generate(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        on_token: Optional[Any] = None,
        **kwargs: Any
    ) -> ModelResponse:
        if self.current_idx >= len(self.model_records):
            reason = f"Extra model call invoked beyond {len(self.model_records)} recorded steps"
            self.divergences.append({
                "step_seq": self.current_idx + 1,
                "reason": reason,
                "rec_id": None
            })
            return ModelResponse(content=None, tool_calls=[])

        rec = self.model_records[self.current_idx]
        self.current_idx += 1

        prompt_str = json.dumps(messages, default=str)
        computed_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()[:16]

        if rec.prompt_hash and computed_hash != rec.prompt_hash:
            reason = (
                f"Prompt hash mismatch at step {rec.step_seq}: "
                f"expected '{rec.prompt_hash}', got '{computed_hash}'"
            )
            self.divergences.append({
                "step_seq": rec.step_seq,
                "reason": reason,
                "rec_id": rec.id
            })

        raw_tool_calls = rec.payload.get("tool_calls") or []
        tool_calls = [
            ToolCallRequest(
                id=tc.get("id", f"call_{i}"),
                name=tc["name"],
                arguments=tc.get("arguments", {})
            )
            for i, tc in enumerate(raw_tool_calls)
        ]

        content = rec.payload.get("response_content")
        p_tokens = len(prompt_str) // 4
        c_tokens = len(content or "") // 4

        if on_token and content:
            for w in content.split(" "):
                chunk = w + " "
                try:
                    res = on_token(chunk)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    pass

        return ModelResponse(
            content=content,
            tool_calls=tool_calls,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=p_tokens + c_tokens
        )

class ReplaySyscallInterceptor:
    """
    Isolated syscall interceptor for deterministic offline replay.
    Matches agent-requested syscalls and arguments against recorded flight trace
    and returns recorded results without performing live side-effects (no real FS, net, proc, etc.).
    """
    def __init__(self, syscall_records: List[TraceRecord]):
        self.syscall_records = list(sorted(syscall_records, key=lambda r: (r.step_seq, r.timestamp)))
        self.current_idx = 0
        self.divergences: List[Dict[str, Any]] = []
        self.executed_calls: List[Dict[str, Any]] = []

    def list_tools(self) -> List[Dict[str, Any]]:
        return []

    def get_all_tool_schemas(self) -> List[Dict[str, Any]]:
        return []

    async def dispatch(self, pcb: ProcessControlBlock, name: str, **kwargs) -> SyscallResult:
        if self.current_idx >= len(self.syscall_records):
            reason = f"Unexpected syscall '{name}' invoked when no recorded syscall remained"
            self.divergences.append({
                "step_seq": pcb.step_count,
                "reason": reason,
                "rec_id": None
            })
            return SyscallResult(success=False, error=reason)

        rec = self.syscall_records[self.current_idx]
        self.current_idx += 1

        recorded_name = rec.payload.get("syscall_name")
        recorded_kwargs = rec.payload.get("input_kwargs") or {}

        if name != recorded_name:
            reason = (
                f"Syscall name mismatch at step {rec.step_seq}: "
                f"expected '{recorded_name}', got '{name}'"
            )
            self.divergences.append({
                "step_seq": rec.step_seq,
                "reason": reason,
                "rec_id": rec.id
            })
            return SyscallResult(success=False, error=reason)

        if kwargs != recorded_kwargs:
            reason = (
                f"Syscall argument mismatch for '{name}' at step {rec.step_seq}: "
                f"expected {recorded_kwargs}, got {kwargs}"
            )
            self.divergences.append({
                "step_seq": rec.step_seq,
                "reason": reason,
                "rec_id": rec.id
            })
            return SyscallResult(success=False, error=reason)

        self.executed_calls.append({
            "step_seq": rec.step_seq,
            "name": name,
            "kwargs": kwargs
        })

        return SyscallResult(
            success=rec.payload.get("success", True),
            data=rec.payload.get("data"),
            error=rec.payload.get("error")
        )

class TraceReplayEngine:
    """
    Deterministic Trace Replay Engine.
    Loads recorded model and syscall telemetry from FlightRecorder and verifies
    exact state transitions deterministically without invoking live LLMs or live tools.
    """
    def __init__(self, flight_recorder: Optional[FlightRecorder] = None):
        self.flight_recorder = flight_recorder or FlightRecorder()

    async def replay_trace_async(self, trace_id: str, verify_simulation: bool = True) -> ReplayReport:
        """
        Reconstruct and verify execution flow from a historical trace asynchronously.
        Executes an offline simulation of agent reasoning loops using recorded LLM and syscall outputs.
        """
        records = self.flight_recorder.get_trace(trace_id)
        if not records:
            return ReplayReport(
                trace_id=trace_id,
                total_records=0,
                model_calls_count=0,
                syscalls_count=0,
                is_reproducible=False,
                error=f"No trace records found for trace_id '{trace_id}'"
            )

        model_records = [r for r in records if r.record_type == "model_call"]
        syscall_records = [r for r in records if r.record_type == "syscall"]

        step_summaries: List[ReplayStepSummary] = []
        simulation_divergences: List[Dict[str, Any]] = []

        # 1. Baseline Integrity Check on Records
        for rec in records:
            step_matched = True
            step_divergence = None

            if rec.record_type == "model_call":
                details = {
                    "prompt_hash": rec.prompt_hash,
                    "response_content": (rec.payload.get("response_content") or "")[:150],
                    "tool_calls_count": len(rec.payload.get("tool_calls", []))
                }
                # Check recorded hash integrity
                prompt_data = rec.payload.get("prompt")
                if prompt_data is not None:
                    prompt_str = json.dumps(prompt_data, default=str)
                    computed_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()[:16]
                    if rec.prompt_hash and rec.prompt_hash != computed_hash:
                        step_matched = False
                        step_divergence = (
                            f"Integrity check failed: prompt_hash '{rec.prompt_hash}' "
                            f"does not match payload hash '{computed_hash}'"
                        )
                        simulation_divergences.append({
                            "step_seq": rec.step_seq,
                            "reason": step_divergence,
                            "rec_id": rec.id
                        })
            elif rec.record_type == "syscall":
                details = {
                    "syscall_name": rec.payload.get("syscall_name"),
                    "input_kwargs": rec.payload.get("input_kwargs"),
                    "success": rec.payload.get("success"),
                    "has_error": bool(rec.payload.get("error"))
                }
            else:
                details = rec.payload

            step_summaries.append(ReplayStepSummary(
                step_seq=rec.step_seq,
                record_type=rec.record_type,
                details=details,
                matched=step_matched,
                divergence_reason=step_divergence
            ))

        # 2. Active Offline Simulation (Re-run reasoning step loop with Replay providers)
        if verify_simulation and model_records:
            try:
                replay_model = ReplayModelProvider(model_records)
                replay_syscalls = ReplaySyscallInterceptor(syscall_records)
                pcb = ProcessControlBlock(
                    name=f"replay_{trace_id}",
                    task_instruction="",
                    allocated_tools=["*"],
                    trace_id=trace_id,
                    token_budget=1000000
                )
                agent = BaseAgent(
                    pcb=pcb,
                    system_prompt="",
                    model_provider=replay_model,
                    syscall_registry=replay_syscalls,
                    governor=ResourceGovernor()
                )

                # Initialize agent L1 context with initial messages
                first_prompt = model_records[0].payload.get("prompt", [])
                for msg in first_prompt:
                    agent.l1.add_message(msg.get("role", "user"), msg.get("content", ""))

                step_count = 0
                max_steps = len(model_records) + 5
                done = False
                while not done and step_count < max_steps:
                    step_count += 1
                    done = await agent.step()

                simulation_divergences.extend(replay_model.divergences)
                simulation_divergences.extend(replay_syscalls.divergences)

                if not done and step_count >= max_steps:
                    simulation_divergences.append({
                        "step_seq": step_count,
                        "reason": "Agent did not complete within expected number of trace steps",
                        "rec_id": None
                    })
            except Exception as ex:
                simulation_divergences.append({
                    "step_seq": 1,
                    "reason": f"Simulation runtime exception: {str(ex)}",
                    "rec_id": None
                })

        # 3. Consolidate Divergences onto Step Summaries
        for div in simulation_divergences:
            rec_id = div.get("rec_id")
            step_seq = div.get("step_seq")
            reason = div.get("reason", "Simulation divergence")

            # Match by rec_id or step_seq
            matched_summary = None
            if rec_id:
                for s, r in zip(step_summaries, records):
                    if r.id == rec_id:
                        matched_summary = s
                        break
            if not matched_summary and step_seq:
                for s in step_summaries:
                    if s.step_seq == step_seq:
                        matched_summary = s
                        break

            if matched_summary:
                matched_summary.matched = False
                if not matched_summary.divergence_reason:
                    matched_summary.divergence_reason = reason
            else:
                # If no direct match, mark first step as divergent
                if step_summaries:
                    step_summaries[0].matched = False
                    if not step_summaries[0].divergence_reason:
                        step_summaries[0].divergence_reason = reason

        is_reproducible = all(s.matched for s in step_summaries)
        first_divergent_step = None
        error_msg = None

        if not is_reproducible:
            divergent = next((s for s in step_summaries if not s.matched), None)
            if divergent:
                first_divergent_step = divergent.step_seq
                error_msg = divergent.divergence_reason or f"Divergence detected at step {divergent.step_seq}"

        return ReplayReport(
            trace_id=trace_id,
            total_records=len(records),
            model_calls_count=len(model_records),
            syscalls_count=len(syscall_records),
            is_reproducible=is_reproducible,
            steps=step_summaries,
            divergence_step=first_divergent_step,
            error=error_msg
        )

    def replay_trace(self, trace_id: str, verify_simulation: bool = True) -> ReplayReport:
        """
        Synchronous wrapper for replay_trace_async.
        Safe for use both from synchronous contexts (CLI) and inside running event loops (async tests).
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    asyncio.run,
                    self.replay_trace_async(trace_id, verify_simulation=verify_simulation)
                )
                return future.result()
        else:
            return asyncio.run(self.replay_trace_async(trace_id, verify_simulation=verify_simulation))
