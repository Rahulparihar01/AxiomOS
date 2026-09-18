import argparse
import asyncio
import sys
from typing import Optional
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from config.settings import settings
from kernel import Kernel, PriorityLevel, ProcessControlBlock, ProcessState
from ipc.message import IPCMessage, IPCMessageType
from server.app import create_app

console = Console(force_terminal=True)

def render_process_table(processes: dict[str, ProcessControlBlock], kernel: Optional[Kernel] = None):
    term_width = getattr(console, "width", 100) or 100
    is_wide = term_width >= 118

    table = Table(box=box.ROUNDED, header_style="bold cyan", expand=is_wide)
    table.add_column("PID", style="dim")
    table.add_column("Process Hierarchy", style="bold white")
    table.add_column("Persona", justify="center")
    if is_wide:
        table.add_column("Priority", justify="center")
    table.add_column("State", justify="center")
    if is_wide:
        table.add_column("Step", justify="center")
    table.add_column("Tokens", justify="right")
    table.add_column("L1 Memory", justify="center")
    if is_wide:
        table.add_column("Result / Diagnostic", style="italic")

    for pid, pcb in processes.items():
        state_color = {
            ProcessState.CREATED: "white",
            ProcessState.READY: "yellow",
            ProcessState.RUNNING: "bold blue",
            ProcessState.BLOCKED: "magenta",
            ProcessState.COMPLETED: "bold green",
            ProcessState.FAILED: "bold red",
            ProcessState.KILLED: "red"
        }.get(pcb.state, "white")

        p_state = f"[{state_color}]{pcb.state.value}[/{state_color}]"
        pid_display = pcb.pid if is_wide else pcb.pid.replace("proc-", "")
        
        if is_wide:
            tokens_str = f"{pcb.tokens_consumed:,} / {pcb.token_budget:,}"
            mem_str = f"{pcb.l1_token_count}/{pcb.l1_capacity} tok ({pcb.l1_utilization_pct}%)"
        else:
            tokens_str = (
                f"{pcb.tokens_consumed} / {pcb.token_budget // 1000}k"
                if pcb.token_budget >= 1000
                else f"{pcb.tokens_consumed} / {pcb.token_budget}"
            )
            mem_str = (
                f"{pcb.l1_token_count}/{pcb.l1_capacity // 1000}k ({int(pcb.l1_utilization_pct)}%)"
                if pcb.l1_capacity >= 1000
                else f"{pcb.l1_token_count}/{pcb.l1_capacity} ({int(pcb.l1_utilization_pct)}%)"
            )
            
        if pcb.paged_chunks_count > 0:
            mem_str += f" [yellow][+{pcb.paged_chunks_count}p][/yellow]"
        
        info = ""
        if pcb.error_message:
            info = f"[bold red]{pcb.error_message}[/bold red]"
        elif pcb.result:
            info = f"[green]{str(pcb.result)[:45]}...[/green]" if len(str(pcb.result)) > 45 else f"[green]{pcb.result}[/green]"
        else:
            info = "[dim]Processing...[/dim]"

        # Format process tree hierarchy display
        name_display = pcb.name
        if pcb.depth > 0:
            name_display = f"[dim]{'  ' * pcb.depth}└─[/dim] [cyan]{pcb.name}[/cyan]"
        if not is_wide and pcb.error_message:
            name_display += f"\n  [dim red]↳ {pcb.error_message[:50]}[/dim red]"

        # Format persona badge
        role = (getattr(pcb, "role", None) or "base").lower()
        if kernel and pcb.pid in kernel._active_agents:
            agent_inst = kernel._active_agents[pcb.pid]
            agent_type = agent_inst.__class__.__name__
            if "Planner" in agent_type:
                persona_badge = "[bold magenta]Planner[/bold magenta]"
            elif "Coder" in agent_type:
                persona_badge = "[bold cyan]Coder[/bold cyan]"
            elif "Reviewer" in agent_type:
                persona_badge = "[bold yellow]Reviewer[/bold yellow]"
            else:
                persona_badge = "[dim]Base[/dim]"
        elif role == "planner":
            persona_badge = "[bold magenta]Planner[/bold magenta]"
        elif role == "coder":
            persona_badge = "[bold cyan]Coder[/bold cyan]"
        elif role == "reviewer":
            persona_badge = "[bold yellow]Reviewer[/bold yellow]"
        else:
            persona_badge = "[dim]Base[/dim]"

        # Format priority with styling
        pri_style = {
            PriorityLevel.CRITICAL: "bold red",
            PriorityLevel.HIGH: "bold yellow",
            PriorityLevel.NORMAL: "cyan",
            PriorityLevel.BACKGROUND: "dim"
        }.get(pcb.priority, "white")
        pri_display = f"[{pri_style}]{pcb.priority.name[:4]}[/{pri_style}]"

        row_items = [
            pid_display,
            name_display,
            persona_badge
        ]
        if is_wide:
            row_items.append(pri_display)
        row_items.append(p_state)
        if is_wide:
            row_items.append(f"{pcb.current_step}/{pcb.max_steps}")
        row_items.extend([tokens_str, mem_str])
        if is_wide:
            row_items.append(info)

        table.add_row(*row_items)

    return table

def render_telemetry_panels(mem_stats: dict, ipc_stats: dict, bb_topics: list, hitl_stats: dict):
    # Memory Panel
    mem_table = Table(box=box.SIMPLE, show_header=False, expand=True)
    mem_table.add_column("Metric", style="cyan", width=30)
    mem_table.add_column("Value", style="bold green")
    mem_table.add_row("L1 Context Virtualization", "Active (Per-Process Window)")
    mem_table.add_row("L2 Session Buffer Entries", f"{mem_stats.get('l2_session_entries', 0)} in-memory cached turns")
    mem_table.add_row("L3 Semantic Vector Indices", f"{mem_stats.get('l3_semantic_vectors', 0)} vectors indexed")
    mem_table.add_row("L4 Archival Facts Persisted", f"{mem_stats.get('l4_facts_count', 0)} facts in SQLite")
    mem_table.add_row("Automated Context Paging", f"{mem_stats.get('total_page_outs', 0)} eviction/compaction events")

    mem_panel = Panel(mem_table, title="[bold magenta]Memory Management Unit (MMU)[/bold magenta]", border_style="magenta", box=box.ROUNDED)

    # IPC Panel
    ipc_table = Table(box=box.SIMPLE, show_header=False, expand=True)
    ipc_table.add_column("Metric", style="cyan", width=30)
    ipc_table.add_column("Value", style="bold green")
    ipc_table.add_row("Active Process Mailboxes", f"{ipc_stats.get('active_mailboxes', 0)} registered queues")
    ipc_table.add_row("Total Messages Routed", f"{ipc_stats.get('total_messages_routed', 0)} A2A envelopes")
    ipc_table.add_row("Message Audit Log Depth", f"{ipc_stats.get('history_log_size', 0)} entries")
    ipc_table.add_row("Shared Blackboard Channels", f"{len(bb_topics)} active channels ({', '.join(bb_topics) if bb_topics else 'None'})")

    ipc_panel = Panel(ipc_table, title="[bold yellow]Multi-Agent IPC & Blackboard Bus[/bold yellow]", border_style="yellow", box=box.ROUNDED)

    # Security Panel
    sec_table = Table(box=box.SIMPLE, show_header=False, expand=True)
    sec_table.add_column("Security Metric", style="cyan", width=30)
    sec_table.add_column("Status", style="bold green")
    sec_table.add_row("Protection Rings Enforced", "Ring 0 (Kernel) to Ring 3 (Destructive)")
    sec_table.add_row("Ephemeral Code Sandbox", "Active (10s timeout, isolated env)")
    sec_table.add_row("Prompt Injection Firewall", "Armed (Pattern neutralizing & XML boundaries)")
    sec_table.add_row("HITL Security Approvals", f"{hitl_stats.get('approved_count', 0)} approved, {hitl_stats.get('pending_count', 0)} pending")

    sec_panel = Panel(sec_table, title="[bold red]Security Rings & Sandboxing[/bold red]", border_style="red", box=box.ROUNDED)

    return mem_panel, ipc_panel, sec_panel

async def run_web_server(app, port: int = 8000):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()

async def main():
    parser = argparse.ArgumentParser(description="AI Operating System (AI-OS) - Kernel Boot")
    parser.add_argument("--provider", type=str, default=None, help="LLM Provider: mock, gemini, openai, ollama")
    parser.add_argument("--dry-run", action="store_true", help="Run in zero-cost deterministic mock mode")
    parser.add_argument("--web", action="store_true", help="Launch the interactive Web Control Center dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Web Control Center port (default: 8000)")
    parser.add_argument("--auto-approve", action="store_true", help="Auto-approve Ring 3 destructive operations")
    args = parser.parse_args()

    provider = "mock" if args.dry_run else (args.provider or settings.default_provider)
    auto_approve = args.auto_approve or args.dry_run

    banner = Panel(
        Text.from_markup(
            f"[bold cyan]AI OPERATING SYSTEM (AI-OS)[/bold cyan] [white]v{settings.version}[/white]\n"
            f"[dim]Deterministic Kernel Control Plane | Multi-Agent IPC Bus | Tiered MMU | Ring 0-3 Security[/dim]\n"
            f"[yellow]Active Compute Backend:[/yellow] [bold green]{provider.upper()}[/bold green] "
            f"| [red]HITL Security Gate:[/red] [bold yellow]{'AUTO-PERMISSIVE' if auto_approve else 'ENFORCED'}[/bold yellow]"
        ),
        box=box.DOUBLE,
        border_style="bright_blue"
    )
    console.print(banner)

    console.print("\n[bold green][*] Initializing Kernel & Subsystems...[/bold green]")
    kernel = Kernel(provider_name=provider, auto_approve_hitl=auto_approve)
    console.print("  [cyan][+][/cyan] Task Scheduler: Initialized (Priority Queue & Parent-Child Wait Synchronization)")
    console.print("  [cyan][+][/cyan] Resource Governor: Initialized (Token caps, fork-bomb recursion guards armed)")
    console.print("  [cyan][+][/cyan] Memory Management Unit (MMU): Initialized (L1-L4 Tiered Hierarchy)")
    console.print("  [cyan][+][/cyan] Inter-Process Communication (IPC): Initialized (A2A Message Bus & Shared Blackboard)")
    console.print("  [cyan][+][/cyan] Security & Sandbox: Initialized (Ring 0-3, Ephemeral Code Runner, Injection Firewall)")
    console.print("  [cyan][+][/cyan] Syscall Registry: Initialized (Hardware, Memory, Process, and Sandbox Syscalls)")
    console.print("  [cyan][+][/cyan] Model Interface: Initialized\n")

    # Launch Web Control Center if requested
    if args.web:
        web_app = create_app(kernel)
        asyncio.create_task(run_web_server(web_app, port=args.port))
        console.print(f"[bold green]► Interactive Web Control Center launched at: [underline cyan]http://127.0.0.1:{args.port}[/underline cyan][/bold green]\n")

    console.print("[bold yellow][*] Spawning Coordinated Multi-Agent Process Hierarchy...[/bold yellow]")

    # 1. Root Process: Lead Architect (Planner Persona)
    lead = kernel.spawn_process(
        name="lead_architect",
        task_instruction="Coordinate system audit evaluation across workers.",
        priority=PriorityLevel.HIGH,
        token_budget=40000,
        max_steps=5,
        allocated_tools=["sys_proc_spawn", "sys_proc_send_msg", "sys_proc_wait", "sys_bb_write", "sys_bb_read", "sys_log"],
        role="planner"
    )
    console.print(f"  - Spawned Root Process [{lead.priority.name}] [bold cyan]{lead.name}[/bold cyan] (PID: {lead.pid}) [dim](Persona: PlannerAgent)[/dim]")

    # 2. Child Process: Math Analyst (Spawned under Lead Architect)
    p_math = kernel.spawn_process(
        name="math_worker",
        task_instruction="Calculate sqrt(144) + 25 * 3 for financial audit.",
        priority=PriorityLevel.NORMAL,
        token_budget=20000,
        max_steps=5,
        allocated_tools=["sys_calc", "sys_proc_send_msg", "sys_log"],
        parent_pid=lead.pid
    )
    console.print(f"    └─ Spawned Child Worker [NORMAL] [cyan]{p_math.name}[/cyan] (PID: {p_math.pid})")

    # 3. Child Process: Document Auditor (Spawned under Lead Architect)
    p_doc = kernel.spawn_process(
        name="doc_inspector",
        task_instruction="Read the requirements.txt configuration file.",
        priority=PriorityLevel.NORMAL,
        token_budget=15000,
        max_steps=5,
        allocated_tools=["sys_fs_read", "sys_proc_send_msg", "sys_log"],
        parent_pid=lead.pid
    )
    console.print(f"    └─ Spawned Child Worker [NORMAL] [cyan]{p_doc.name}[/cyan] (PID: {p_doc.pid})")

    # 4. Child Process: Code & Output Auditor (Spawned under Lead Architect, Reviewer Persona)
    p_rev = kernel.spawn_process(
        name="code_reviewer",
        task_instruction="Audit calculation and document inspection outputs, verifying compliance against specifications.",
        priority=PriorityLevel.NORMAL,
        token_budget=20000,
        max_steps=5,
        allocated_tools=["sys_fs_read", "sys_bb_read", "sys_bb_write", "sys_proc_send_msg", "sys_log"],
        parent_pid=lead.pid,
        role="reviewer"
    )
    console.print(f"    └─ Spawned Child Reviewer [NORMAL] [cyan]{p_rev.name}[/cyan] (PID: {p_rev.pid}) [dim](Persona: ReviewerAgent)[/dim]")

    # 5. Independent Memory Archivist
    p_mem = kernel.spawn_process(
        name="memory_archivist",
        task_instruction="Persist system parameters and audit configuration.",
        priority=PriorityLevel.NORMAL,
        token_budget=25000,
        max_steps=5,
        allocated_tools=["sys_mem_store", "sys_mem_recall", "sys_mem_stats", "sys_log"],
        l1_capacity=2000
    )
    console.print(f"  - Spawned Independent Agent [NORMAL] [cyan]{p_mem.name}[/cyan] (PID: {p_mem.pid})")

    # 6. Sandboxed Python Code Execution Agent (Coder Persona, Ring 3 Destructive with HITL)
    p_sand = kernel.spawn_process(
        name="sandbox_runner",
        task_instruction="Execute isolated python calculation in sandbox.",
        priority=PriorityLevel.NORMAL,
        token_budget=30000,
        max_steps=5,
        allocated_tools=["sys_exec_python", "sys_log"],
        role="coder"
    )
    console.print(f"  - Spawned Sandbox Agent [NORMAL] [cyan]{p_sand.name}[/cyan] (PID: {p_sand.pid}) [dim](Persona: CoderAgent, Ring 3 HITL enabled)[/dim]")

    # 7. Circuit Breaker Test
    p_quota = kernel.spawn_process(
        name="quota_tester",
        task_instruction="Attempt heavy compute beyond budget.",
        priority=PriorityLevel.BACKGROUND,
        token_budget=50,
        max_steps=5,
        allocated_tools=["sys_calc"]
    )
    console.print(f"  - Spawned Circuit-Breaker Test [BACKGROUND] [cyan]{p_quota.name}[/cyan] (PID: {p_quota.pid}) [dim](Budget: 50 tokens)[/dim]")

    # Publish initial coordination state to Shared Blackboard
    kernel.blackboard.write(
        topic="system_audit",
        key="audit_status",
        value={"phase": "ACTIVE_DISPATCH", "workers_assigned": 4},
        author_pid=lead.pid
    )

    console.print("\n[bold magenta][*] Dispatching Kernel Multi-Worker Execution Loop...[/bold magenta]\n")
    
    # Start persistent concurrent daemon workers
    kernel.start_daemon()

    # Run the kernel dispatch loop until queues are idle
    await kernel.run_until_idle()

    console.print("\n[bold green][*] All Process Queues Idle. Final Process Control Table:[/bold green]\n")
    all_processes = kernel.scheduler.list_processes()
    console.print(render_process_table(all_processes, kernel=kernel))
    
    console.print()
    mem_stats = kernel.mmu.get_memory_stats()
    ipc_stats = kernel.message_bus.get_stats()
    bb_topics = kernel.blackboard.list_topics()
    hitl_stats = kernel.hitl_manager.get_stats()
    
    mem_panel, ipc_panel, sec_panel = render_telemetry_panels(mem_stats, ipc_stats, bb_topics, hitl_stats)
    console.print(mem_panel)
    console.print(ipc_panel)
    console.print(sec_panel)

    console.print("\n[bold cyan]Kernel Execution Cycle Completed Successfully.[/bold cyan]")

    if args.web:
        console.print("[yellow]Web Control Center is still running. Background workers active for new processes. Press Ctrl+C to stop.[/yellow]")
        while True:
            await asyncio.sleep(1)
    else:
        kernel.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Shutdown signal received. Exiting AI-OS.[/dim]")
