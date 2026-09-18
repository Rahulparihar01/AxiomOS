from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from kernel.process import ProcessControlBlock
from syscalls.base import SyscallBase, SyscallResult

# --- 1. Planner Syscall ---
class PlanRegisterSubtaskInput(BaseModel):
    subtask_id: str = Field(description="Unique identifier for this DAG subtask node.")
    description: str = Field(description="Actionable goal or description of the subtask.")
    dependencies: Optional[List[str]] = Field(default=None, description="List of subtask IDs that must complete before this subtask.")

class SysPlanRegisterSubtask(SyscallBase):
    name = "sys_plan_register_subtask"
    description = "Register an ordered DAG subtask node and publish it to the shared blackboard for coordination."
    is_mutating = True
    input_schema = PlanRegisterSubtaskInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        subtask_id: str,
        description: str,
        dependencies: Optional[List[str]] = None,
        **kwargs
    ) -> SyscallResult:
        try:
            deps = dependencies or []
            subtask_data = {
                "id": subtask_id,
                "description": description,
                "dependencies": deps,
                "status": "PENDING"
            }

            # Update active planner agent state if matched
            if self.kernel and hasattr(self.kernel, "_active_agents"):
                agent = self.kernel._active_agents.get(pcb.pid)
                if agent and hasattr(agent, "subtasks"):
                    # Avoid duplicate id
                    if not any(s.get("id") == subtask_id for s in agent.subtasks):
                        agent.subtasks.append(subtask_data)

            # Publish to shared blackboard under topic 'milestones'
            if self.kernel and hasattr(self.kernel, "blackboard"):
                self.kernel.blackboard.write(
                    topic="milestones",
                    key=subtask_id,
                    value=subtask_data,
                    author_pid=pcb.pid
                )

            return SyscallResult(success=True, data=subtask_data)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_plan_register_subtask failed: {str(e)}")


# --- 2. Reviewer / Auditor Syscall ---
class AuditRecordVerdictInput(BaseModel):
    target_pid: str = Field(description="PID of the agent process whose output was audited.")
    approved: bool = Field(description="Whether the output conforms to specifications (True) or is rejected (False).")
    comments: str = Field(description="Detailed verification feedback, test results, or regression notes.")

class SysAuditRecordVerdict(SyscallBase):
    name = "sys_audit_record_verdict"
    description = "Record a formal verification approval or rejection verdict for an agent's output."
    is_mutating = True
    input_schema = AuditRecordVerdictInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        target_pid: str,
        approved: bool,
        comments: str,
        **kwargs
    ) -> SyscallResult:
        try:
            verdict_data = {
                "target_pid": target_pid,
                "approved": approved,
                "comments": comments,
                "auditor_pid": pcb.pid
            }

            # Update active reviewer agent state if matched
            if self.kernel and hasattr(self.kernel, "_active_agents"):
                agent = self.kernel._active_agents.get(pcb.pid)
                if agent and hasattr(agent, "verdicts"):
                    agent.verdicts.append(verdict_data)

            # Publish to shared blackboard under topic 'system_audit'
            if self.kernel and hasattr(self.kernel, "blackboard"):
                self.kernel.blackboard.write(
                    topic="system_audit",
                    key=f"verdict_{target_pid}",
                    value=verdict_data,
                    author_pid=pcb.pid
                )

            return SyscallResult(success=True, data=verdict_data)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_audit_record_verdict failed: {str(e)}")


# --- 3. Coder Syscall ---
class CodeRecordArtifactInput(BaseModel):
    filename: str = Field(description="Relative filepath or identifier for the code artifact.")
    code: str = Field(description="Synthesized source code or script content.")

class SysCodeRecordArtifact(SyscallBase):
    name = "sys_code_record_artifact"
    description = "Record a synthesized code artifact in the coder manifest and publish to the shared blackboard."
    is_mutating = True
    input_schema = CodeRecordArtifactInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        filename: str,
        code: str,
        **kwargs
    ) -> SyscallResult:
        try:
            artifact_data = {
                "filename": filename,
                "code": code,
                "author_pid": pcb.pid
            }

            # Update active coder agent state if matched
            if self.kernel and hasattr(self.kernel, "_active_agents"):
                agent = self.kernel._active_agents.get(pcb.pid)
                if agent and hasattr(agent, "artifacts"):
                    agent.artifacts.append(artifact_data)

            # Publish to shared blackboard under topic 'artifacts'
            if self.kernel and hasattr(self.kernel, "blackboard"):
                self.kernel.blackboard.write(
                    topic="artifacts",
                    key=filename,
                    value=artifact_data,
                    author_pid=pcb.pid
                )

            return SyscallResult(success=True, data=artifact_data)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_code_record_artifact failed: {str(e)}")


# --- 4. Researcher Syscall ---
class ResearchRecordFindingInput(BaseModel):
    source_url: str = Field(description="Source URL, document path, or reference origin for the finding.")
    topic: str = Field(description="Category, entity, or search topic of the research finding.")
    content: str = Field(description="Verified analytical facts and findings.")

class SysResearchRecordFinding(SyscallBase):
    name = "sys_research_record_finding"
    description = "Record a verified research finding, publish to shared blackboard, and persist to L4 archival memory."
    is_mutating = True
    input_schema = ResearchRecordFindingInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        source_url: str,
        topic: str,
        content: str,
        **kwargs
    ) -> SyscallResult:
        try:
            finding_data = {
                "source_url": source_url,
                "topic": topic,
                "content": content,
                "researcher_pid": pcb.pid
            }

            # Update active research agent state if matched
            if self.kernel and hasattr(self.kernel, "_active_agents"):
                agent = self.kernel._active_agents.get(pcb.pid)
                if agent and hasattr(agent, "findings"):
                    agent.findings.append(finding_data)

            # Publish to shared blackboard under topic 'research'
            if self.kernel and hasattr(self.kernel, "blackboard"):
                self.kernel.blackboard.write(
                    topic="research",
                    key=topic,
                    value=finding_data,
                    author_pid=pcb.pid
                )

            # Persist fact to L4 archival memory if MMU available
            if self.kernel and getattr(self.kernel, "mmu", None) and getattr(self.kernel.mmu, "l4_archival", None):
                fact_key = f"research.{topic}"
                self.kernel.mmu.l4_archival.store_fact(key=fact_key, value=content, owner_pid=pcb.pid)

            return SyscallResult(success=True, data=finding_data)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_research_record_finding failed: {str(e)}")


# --- 5. Conflict Resolver Syscall ---
class ConflictRecordResolutionInput(BaseModel):
    key: str = Field(description="Memory fact key that experienced contradiction/conflict.")
    chosen_value: str = Field(description="Authoritative resolved fact value.")
    rationale: str = Field(description="Arbitration rationale (e.g. source authority, recency, cross-validation).")
    conflicting_versions: Optional[List[int]] = Field(default=None, description="Version numbers that were superseded or conflicting.")

class SysConflictRecordResolution(SyscallBase):
    name = "sys_conflict_record_resolution"
    description = "Commit authoritative arbitration on conflicting knowledge in L4 memory, clearing conflict flags."
    is_mutating = True
    input_schema = ConflictRecordResolutionInput

    def __init__(self, kernel):
        self.kernel = kernel

    async def execute(
        self,
        pcb: ProcessControlBlock,
        key: str,
        chosen_value: str,
        rationale: str,
        conflicting_versions: Optional[List[int]] = None,
        **kwargs
    ) -> SyscallResult:
        try:
            resolution_data = {
                "key": key,
                "chosen_value": chosen_value,
                "rationale": rationale,
                "conflicting_versions": conflicting_versions or [],
                "resolver_pid": pcb.pid
            }

            # Update active conflict resolver agent state if matched
            if self.kernel and hasattr(self.kernel, "_active_agents"):
                agent = self.kernel._active_agents.get(pcb.pid)
                if agent and hasattr(agent, "resolutions"):
                    agent.resolutions.append(resolution_data)

            # Clear conflict flags and persist authoritative fact in L4 archival memory
            resolved_record = None
            if self.kernel and getattr(self.kernel, "mmu", None) and getattr(self.kernel.mmu, "l4_archival", None):
                resolved_record = self.kernel.mmu.l4_archival.resolve_conflict(
                    key=key,
                    chosen_value=chosen_value,
                    rationale=rationale,
                    resolved_by_pid=pcb.pid
                )
                resolution_data["resolved_fact_id"] = resolved_record.fact_id
                resolution_data["version"] = resolved_record.version

            # Publish resolution to blackboard under topic 'conflict_resolutions'
            if self.kernel and hasattr(self.kernel, "blackboard"):
                self.kernel.blackboard.write(
                    topic="conflict_resolutions",
                    key=key,
                    value=resolution_data,
                    author_pid=pcb.pid
                )

            return SyscallResult(success=True, data=resolution_data)
        except Exception as e:
            return SyscallResult(success=False, error=f"sys_conflict_record_resolution failed: {str(e)}")
