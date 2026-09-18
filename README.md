# AxiomOS — The Deterministic Control Plane for Autonomous Agents

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)]()
[![Tests](https://img.shields.io/badge/Tests-157%2F157%20Passing%20(100%25)-brightgreen.svg)]()
[![MCP Server](https://img.shields.io/badge/MCP%20Server-JSON--RPC%202.0-blueviolet.svg)]()
[![Architecture Audit](https://img.shields.io/badge/Architecture%20Audit-13%2F13%20Gaps%20Remediated-success.svg)](CODEBASE_GAP_REPORT.md)

> **"The intelligence of an AI Operating System stems from the entire system architecture—the microkernel, priority scheduling, virtualized memory hierarchy, capability security, and deterministic safety controls—not merely the underlying model."**

---

## The Meaning & Philosophy of AxiomOS

### 1. Etymology: Why "Axiom"?
In formal logic, mathematics, and philosophy, an **Axiom** (from Ancient Greek *ἀξίωμα* / *axíōma*, meaning *"that which is deemed worthy, self-evident truth, undeniable foundation"*) is a premise so foundational, demonstrable, and verifiable that it serves as the starting point for all further reasoning.

### 2. The Production Agent Crisis
Today’s enterprise AI agent landscape faces a crippling paradox: **probabilistic chaos**.
* **The Script-Based Trap:** Mainstream frameworks treat autonomous agents as unconstrained Python scripts. When agents execute in production, they suffer from runaway loops, task starvation, resource exhaustion, and catastrophic hallucinations.
* **The "Black Box" Liability:** In regulated enterprise environments (Finance, Healthcare, Legal, Defense), non-deterministic failures are unacceptable. When a rogue agent executes an unintended file deletion or submits a faulty API call, engineers have no mechanism to reproduce, audit, or formally verify what went wrong.

### 3. The AxiomOS Solution
**AxiomOS** was engineered to establish an **indisputable, deterministic bedrock** beneath non-deterministic machine intelligence:
* **Mathematical Reproducibility:** Every execution step, model token delta, and system call is cryptographically hashed and captured by the Flight Recorder. Past executions can be re-simulated offline with **0 live API calls and 0 side effects**, proving deterministic integrity.
* **Microkernel Process Isolation:** Agents execute as sandboxed **Process Control Blocks (PCBs)** governed by hard token quotas, anti-starvation priority aging queues, and cascading parent-child termination.
* **Zero-Trust Capability Security (CapBAC):** Privilege is never ambient. Every agent operates within strict Ring 0–3 privilege boundaries, receiving short-lived capability tokens with finite TTLs and proactive runtime lease renewal.
* **Hardware-Analogous Context MMU:** Instead of context window overflow and memory amnesia, AxiomOS virtualizes memory across four distinct tiers: L1 Working Memory, L2 Session Buffers, L3 Semantic Vector Recall, and L4 Archival SQLite Fact Storage with automated contradiction resolution.

**AxiomOS transforms autonomous AI agents from experimental scripts into hardened, audit-ready enterprise infrastructure.**

---

## 1. System Architecture & Privilege Rings

AxiomOS enforces strict privilege ring separation between trusted kernel control logic and untrusted, non-deterministic agent compute:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        WEB CONTROL CENTER, API & PROTOCOLS                             │
│    REST Endpoints (Token Auth)  │  Real-Time Token WebSocket  │  MCP JSON-RPC 2.0      │
└───────────────────────────────────┬────────────────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────────────────────┐
│                      RING 0: AXIOMOS MICROKERNEL & CONTROL PLANE                       │
│  ┌─────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────────┐  │
│  │ Anti-Starvation Aging   │  │ Process Control Block │  │ Token Governor, Quotas   │  │
│  │ Priority Task Scheduler │  │ Lifecycle & Cascading │  │ & Rate Limiter           │  │
│  └─────────────────────────┘  └───────────────────────┘  └──────────────────────────┘  │
│  ┌─────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────────┐  │
│  │ Context MMU (Paging)    │  │ Durable State & WAL   │  │ Capability Security      │  │
│  │ L1 - L4 Tiered Memory   │  │ Snapshot Manager      │  │ Dynamic Lease Renewal    │  │
│  └─────────────────────────┘  └───────────────────────┘  └──────────────────────────┘  │
│  ┌─────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────────┐  │
│  │ Similarity-Weighted     │  │ Asynchronous Threaded │  │ Flight Recorder & True   │  │
│  │ P90 Cost Estimator      │  │ SQLite Storage Engine │  │ Deterministic Replay     │  │
│  └─────────────────────────┘  └───────────────────────┘  └──────────────────────────┘  │
└───────────────────┬───────────────────────────────────┬────────────────────────────────┘
                    │                                   │
┌───────────────────▼─────────────────┐   ┌─────────────▼────────────────────────────────┐
│    RING 1: MULTI-AGENT RUNTIME      │   │          RING 1: MEMORY HIERARCHY            │
│  - Specialized Agent Personas:      │   │  L1: Active Context (Tokens & Messages)      │
│    Planner, Coder, Reviewer,        │   │  L2: Session History Buffer (LRU / FIFO)     │
│    Researcher, Conflict Resolver    │   │  L3: Semantic Vector DB & Cosine Recall      │
│  - Durable Shared Blackboard (WAL)  │   │  L4: Archival SQLite Facts, Contradictions   │
│  - Point-to-Point A2A IPC Mailboxes │   │      & Authoritative Resolution Workflow     │
└───────────────────┬─────────────────┘   └──────────────────────────────────────────────┘
                    │
┌───────────────────▼────────────────────────────────────────────────────────────────────┐
│                    RING 2 & RING 3: SYSCALL & TOOL EXECUTION                           │
│  - Ring 2 (Safe): sys_fs_read, sys_calc (AST Evaluator), sys_bb_read, sys_log          │
│  - Ring 3 (Destructive): sys_fs_write, sys_fs_delete, sys_exec_python, sys_proc_kill   │
│  - Persona Syscalls: sys_plan_register_subtask, sys_audit_record_verdict,              │
│    sys_code_record_artifact, sys_research_record_finding, sys_conflict_record_resol. │
│  - Sandboxing: Ephemeral Scratchpad, Whitelist Env, Destructive Pre-Check, Docker      │
│  - Protocols: Model Context Protocol (MCP) Server (Stdio & HTTP Transports)            │
│  - Safety Gate: Human-in-the-Loop (HITL) Interactive Suspension & Authorizations       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems & Technical Capabilities

### 1. Deterministic Microkernel & Anti-Starvation Scheduler
* Written in 100% deterministic Python `asyncio` with thread-safe cross-loop signaling.
* Processes are tracked with **Process Control Blocks (PCB)** across finite states: `CREATED`, `READY`, `RUNNING`, `BLOCKED`, `COMPLETED`, `FAILED`, `KILLED`.
* **Anti-Starvation Priority Aging:** Implements dynamic scoring:
  $$\text{Effective Priority} = (\text{Priority} \times 10.0) + (\text{Wait Ticks} \times \text{Aging Rate})$$
  Ensures lower-priority background tasks cannot be starved by continuous high-priority arrivals.
* **Cascading Process Tree Termination:** `Kernel.kill_process` and `sys_proc_kill` traverse child hierarchies to abort descendant trees without leaving orphaned processes.
* **Deadlock Defense:** Process synchronization via `wait_for_children` enforces configurable timeouts (default 60s) with automatic parent unregistration.

### 2. Tiered Virtual Memory Manager (MMU) & Conflict Arbitration
* **L1 Working Memory:** Active context window with real-time token tracking, atomic tool-turn preservation, and automated paging triggers.
* **L2 Session Memory:** Ephemeral FIFO / LRU conversation buffer.
* **L3 Semantic Memory:** Pluggable vectorizer architecture (`BaseTextVectorizer`) supporting offline deterministic subword hashing (`HashTextVectorizer`) and dense embedding adapters (`DenseEmbeddingVectorizer` for OpenAI/Gemini) with cosine similarity recall.
* **L4 Archival Memory:** Relational SQLite WAL storage for long-term knowledge facts, versioned updates, and semantic conflict tracking.
* **Authoritative Conflict Resolution:** First-class resolution workflow (`resolve_conflict()`, `sys_conflict_record_resolution`) to resolve contradictory memory records.
* **Automated Paging Daemon:** Compresses and pages out older context to cold storage when L1 hits 75% capacity.

### 3. Multi-Agent IPC & Durable Shared Blackboard
* **Durable Shared Blackboard in SQLite WAL:** Multi-agent collaborative blackboard persisted in SQLite WAL mode (`durable_blackboard_entries`), surviving kernel crashes and restarts with instant startup hydration.
* **Point-to-Point Mailboxes:** Structured IPC message envelopes with atomic delivery and crash-safe storage.
* **Non-Blocking Await:** Conditional asynchronous subscriptions (`sys_bb_await`), eliminating CPU-intensive spin-polling.

### 4. Specialized Agent Personas as Native Syscalls
Agent personas interact with the OS through formal, capability-checked system calls:
* **Planner Agent:** `sys_plan_register_subtask` to register ordered DAG subtasks and publish milestones.
* **Reviewer Agent:** `sys_audit_record_verdict` to audit child process artifacts and record binding verdicts.
* **Coder Agent:** `sys_code_record_artifact` to register synthesized code modules and artifacts.
* **Research Agent:** `sys_research_record_finding` to record empirical findings into L4 archival memory.
* **Conflict Resolver Agent:** `sys_conflict_record_resolution` to resolve contradictory knowledge facts.

### 5. Capability-Based Security & Lease Renewal
* **Least-Privilege Role Scoping:** Role-based allowlists for all agent personas, replacing wildcard privileges with least-privilege tokens.
* **Path Traversal Protection:** Canonical path validation preventing directory escapes (`../`, `..\\`) and restricting access to sensitive configuration files (`.env`, `config/secrets.env`).
* **Dynamic Lease Renewal:** Capability security tokens have finite TTLs with runtime renewal (`sys_cap_renew`, `kernel.renew_capability_lease`). Proactive event loop renewal prevents task interruption while strictly bounding stale permissions.

### 6. Similarity-Weighted Predictive Cost Estimator
* Task cost prediction using semantic task clustering and similarity-weighted cumulative distribution functions ($w = (\text{sim} + 0.05)^2$).
* Prevents heavy historical tasks (e.g. compilers) from distorting predictions for simple tasks and causing unwarranted priority downgrades.

### 7. Non-Blocking Asynchronous Storage Concurrency
* All SQLite I/O operations across L4 Archival Store, Checkpoint Manager, Flight Recorder, Message Bus, and Shared Blackboard are offloaded to worker threads via `asyncio.to_thread`.
* Guarantees zero event-loop micro-freezes or scheduling latency jitter during heavy concurrent disk I/O.
* Context-managed connections eliminate Windows file-locking leaks.

### 8. True Deterministic Offline Replay Engine
* Virtual simulation engine (`TraceReplayEngine`) driven by `ReplayModelProvider` and `ReplaySyscallInterceptor`.
* Re-executes recorded flight traces step-by-step with **0 live API calls and 0 side effects** (no file system writes, network requests, or process spawning).
* Verifies prompt hash integrity, model call sequence, and syscall arguments, flagging execution divergences automatically.

### 9. Model Context Protocol (MCP) Server
* Native dual-transport MCP Server conforming to the official specification (`protocolVersion: "2024-11-05"`).
* Exposes 10 core AxiomOS tools over standard I/O (`axiom mcp-server`) and HTTP (`POST /api/mcp`) for external LLM orchestrators (Claude Desktop, Cursor, Cline, IDEs).

### 10. Real-Time Incremental Token Streaming over WebSockets
* Streaming generation interface (`generate_stream()`) implemented across Mock, OpenAI, and Gemini providers.
* Web Control Center broadcasts token chunks (`{"type": "token_chunk", "pid": pid, "delta": text}`) over `/ws/stream` via thread-safe, non-blocking per-connection queues.
* Interactive web terminal renders live incremental token generation with autoscrolling and glowing indicator badges.

### 11. Multi-Tenant BYOK Secrets Vaulting
* Workspace-scoped credential vault (`security/vault.py`) storing encrypted/masked API keys dynamically with zero environment restarts.
* Secure REST API (`POST/GET/DELETE /api/workspaces/{workspace_id}/keys`) and automatic key masking (`sk-p...cdef`) preventing raw credential exposure in logs or UI.

### 12. Remote Client SDK & Enterprise Compliance Trace Export
* First-class client library (`from axiom import AxiomClient` or `from aios import AIOSClient`) with full REST and WebSocket abstractions for microservice and multi-tenant architectures.
* Audit-ready compliance export endpoint (`GET /api/traces/{trace_id}/export`) packaging step manifests, cryptographic prompt hashes, and deterministic reproducibility reports.

---

## 3. Quickstart

### Prerequisites
* Python 3.11+
* Virtual Environment (recommended)

### Installation
```powershell
# 1. Clone repository & enter directory
git clone https://github.com/your-org/axiomos.git
cd axiomos

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

# 4. Install package and dependencies
pip install -r requirements.txt
pip install -e .

# 5. Run Interactive Showcase Demo (Zero external API keys needed)
python demo.py
```

### Configuration
Copy `.env.example` to `.env`:
```powershell
cp .env.example .env
```
Configure settings in `.env`:
```ini
AIOS_LOG_LEVEL=INFO
DEFAULT_PROVIDER=mock
MODEL_NAME=gemini-1.5-flash

# Security token for Web Management API & WebSockets
AIOS_ADMIN_TOKEN=your-secure-token-here

# API Keys (Optional - only needed if not using mock provider)
GEMINI_API_KEY=
OPENAI_API_KEY=
```

---

## 4. Usage & CLI

AxiomOS provides the global `axiom` CLI command (with `axiomos` and `aios` aliases):

### 1. Boot Kernel with Web Control Center
```powershell
# Headless server mode (default)
axiom start --web --port 8000

# Automatically open Web Control Center in default browser
axiom start --web --open-browser
```
Access **`http://127.0.0.1:8000`** to view the real-time interactive dashboard featuring live process inspection, memory hierarchy visualization, and streaming token output.

### 2. Python SDK Quickstart
AxiomOS provides both an **in-process embedded microkernel** and a **remote microservice client SDK**:

#### A. In-Process Embedded Kernel
```python
import asyncio
from axiom import Kernel, PriorityLevel

async def main():
    kernel = Kernel(provider_name="mock")
    kernel.start_daemon()

    pcb = kernel.spawn_process(
        name="research_worker",
        task_instruction="Synthesize architecture notes",
        priority=PriorityLevel.HIGH,
        role="coder",
        workspace_id="default"
    )
    await kernel.run_until_idle()
    kernel.shutdown()

asyncio.run(main())
```

#### B. Remote Microservice Client (`AxiomClient`)
```python
from axiom import AxiomClient

client = AxiomClient(base_url="http://127.0.0.1:8000", api_token="your-token")

# Check system health
health = client.health()
print(f"System status: {health['status']}")

# Set workspace BYOK secrets dynamically
client.set_key(workspace_id="team_data", provider="openai", api_key="sk-proj-...")

# Spawn agent process in a tenant workspace
proc = client.spawn(
    name="data_pipeline",
    task_instruction="Audit database schema",
    role="coder",
    workspace_id="team_data"
)
print(f"Agent spawned PID: {proc['pid']}")

# Export compliance audit package
traces = client.list_traces()
if traces:
    compliance_pkg = client.export_trace(traces[0]["trace_id"])
    print("Deterministic Audit Passed:", compliance_pkg["audit_summary"]["deterministic_reproducibility"])
```

### 3. Run an Ad-Hoc Task with Specialized Personas
```powershell
# Run task as Planner
axiom run "Decompose microservice refactor into subtasks" --role planner --priority HIGH

# Run task as Coder
axiom run "Write an async HTTP connection pool test" --role coder

# Run task as Researcher
axiom run "Analyze microkernel capability security models" --role researcher
```

### 4. Launch as a Model Context Protocol (MCP) Server
```powershell
# Launch over standard I/O for Claude Desktop / Cursor / Cline
axiom mcp-server
```

### 5. Deterministic Offline Replay Verification
```powershell
# List recorded execution traces
axiom replay --list

# Replay a trace deterministically without live side effects
axiom replay --trace-id <trace_id>
```

### 6. Inspect Process Control Blocks & Checkpoints
```powershell
# View active / uncompleted processes
axiom ps

# Inspect recoverable processes from checkpoint store
axiom recover
```

---

## 5. Security & Threat Model

The AxiomOS kernel enforces multi-layered defense-in-depth:

| Threat / Vulnerability | Kernel Defense Mechanism | Status |
| :--- | :--- | :---: |
| **Arbitrary Code Execution** | Replaced `eval()` with `SafeMathEvaluator` AST visitor parsing only approved math nodes. | **HARDENED** |
| **Sandbox Host Escape** | Ephemeral scratchpads, strict environment variable scrubbing, and pluggable Docker runner. | **HARDENED** |
| **Path Traversal & Secret Leaks** | Canonical path validation blocking `..` and protecting `.env` and `config/secrets.env`. | **HARDENED** |
| **Unauthenticated API Access** | Mandatory `X-AIOS-Token` on mutating REST routes and WebSocket connection upgrade queries. | **HARDENED** |
| **Prompt Injection & Evasion** | Pre-normalization pipeline: Base64 extraction, URL decoding, and zero-width Unicode stripping. | **HARDENED** |
| **Capability Over-Privilege** | Least-privilege persona allowlists with finite TTLs and dynamic lease renewal (`sys_cap_renew`). | **HARDENED** |
| **Task Starvation Under Load** | Dynamic priority aging credit algorithm guaranteeing bounded wait times for background tasks. | **HARDENED** |

---

## 6. Testing & Quality Assurance

The codebase includes an extensive automated test suite covering unit isolation, microkernel scheduling, capability security, async database concurrency, deterministic replay, and WebSocket streaming.

Run all tests:
```powershell
.\.venv\Scripts\python -m unittest discover -s tests -p "test_*.py" -v
```

### Execution Results:
```
Ran 157 tests in 34.846s

OK (100% Pass Rate - 157/157 Tests)
```

| Test Module | Tests | Result | Focus Area |
| :--- | :---: | :---: | :--- |
| `test_checkpoint_token_recovery.py` | 3 | **PASS** | CapBAC deserialization from JSON & crash recovery lease renewal |
| `test_client_and_vault.py` | 6 | **PASS** | BYOK SecretsVault, remote AxiomClient SDK, trace export |
| `test_enterprise_product.py` | 3 | **PASS** | Multi-tenant workspace scoping, trace APIs & HITL events |
| `test_productization.py` | 4 | **PASS** | Top-level SDK, CLI flags, /api/health probes |
| `test_token_streaming.py` | 6 | **PASS** | GAP-12: Real-time incremental token streaming over WebSockets |
| `test_async_storage_concurrency.py` | 5 | **PASS** | GAP-10: Non-blocking threaded SQLite storage & zero event loop jitter |
| `test_durable_blackboard.py` | 7 | **PASS** | GAP-07: Durable Shared Blackboard SQLite WAL persistence |
| `test_scheduler_hardening.py` | 5 | **PASS** | GAP-08: Similarity percentiles & GAP-09: Anti-starvation aging |
| `test_capability_security.py` | 7 | **PASS** | GAP-11: Least-privilege role scoping & lease renewal |
| `test_mcp_server.py` | 8 | **PASS** | GAP-13: AxiomOS Model Context Protocol (MCP) Server |
| `test_deterministic_replay.py` | 6 | **PASS** | GAP-05: True Offline Deterministic Replay Engine |
| `test_remediation_p0.py` | 10 | **PASS** | GAP-01, GAP-02, GAP-03, GAP-04, GAP-06 Remediation |
| `test_agent_personas.py` | 4 | **PASS** | Agent Persona instantiation & role mapping |
| `test_ast_sandbox_and_netfetch.py` | 4 | **PASS** | AST math sandbox & safe netfetch |
| `test_daemon_concurrency.py` | 3 | **PASS** | Multi-worker background concurrency |
| `test_e2e_scenarios.py` | 5 | **PASS** | Multi-agent collaboration, HITL, checkpointing, MCP dynamic tools |
| `test_enterprise_gaps.py` | 6 | **PASS** | Enterprise hardening features (EGAP-01..06) |
| `test_ipc.py` | 6 | **PASS** | Durable SQLite IPC bus & mailboxes |
| `test_kernel.py` | 7 | **PASS** | Process lifecycle, priority queues, syscalls |
| `test_memory.py` | 6 | **PASS** | L1–L4 MMU hierarchy & automated paging |
| `test_production_features.py` | 4 | **PASS** | Circuit breaker router, WebSocket streaming |
| `test_real_model_protocols.py` | 3 | **PASS** | Real OpenAI & Gemini JSON payload formatting |
| `test_scalability_enhancements.py` | 11 | **PASS** | HTTP connection pooling, pluggable vectorizer, Docker sandbox |
| `test_security_and_gaps.py` | 13 | **PASS** | AST sandbox security, path traversal, capabilities |
| `test_security_sandbox.py` | 7 | **PASS** | Prompt injection firewall & capability token scopes |
| `test_v2_features.py` | 8 | **PASS** | Predictive scheduler, conflict detection, flight recorder |
| **TOTAL** | **157** | **100% PASS** | **Zero regressions across entire codebase** |

---

## 7. Documentation Directory

* **[CODEBASE_GAP_REPORT.md](CODEBASE_GAP_REPORT.md):** In-depth architectural audit and systematic remediation report detailing the resolution of all 13 production gaps.
* **[planning_for_ai(os).md](planning_for_ai(os).md):** Architectural specification, design philosophy, operating system analogies, and phased engineering roadmap.
* **[SECURITY_AND_GAP_AUDIT.md](SECURITY_AND_GAP_AUDIT.md):** Formal security audit report, threat models, privilege ring definitions, and remediation blueprints.
* **[TEST_REPORT.md](TEST_REPORT.md):** Quality assurance specifications, coverage matrices, and subsystem benchmarks.

---

## License

MIT License. Designed and engineered for secure, deterministic AI agent orchestration.
