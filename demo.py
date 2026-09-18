"""
AI-OS Interactive Showcase & Demo
Demonstrates the AI-OS Deterministic Kernel, Process Scheduler, Capability Security,
Tiered Memory Hierarchy, and Trace Recording using the Python SDK.
"""

import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# Ensure UTF-8 console output on Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from aios import Kernel, PriorityLevel, CapabilityIssuer, __version__
from config.settings import settings

console = Console(force_terminal=True)


async def run_showcase():
    # 1. Welcome Banner
    banner = Panel(
        f"[bold cyan]AxiomOS Interactive Showcase[/bold cyan] (v{__version__})\n"
        f"[dim]The Deterministic Control Plane for Autonomous Agents | Zero External API Keys Needed[/dim]",
        box=box.ROUNDED,
        border_style="cyan"
    )
    console.print(banner)

    # 2. Kernel Initialization
    console.print("\n[bold yellow]Step 1: Booting AI-OS Microkernel...[/bold yellow]")
    kernel = Kernel(provider_name="mock", auto_approve_hitl=True)
    kernel.start_daemon()
    console.print("[green][OK] Kernel worker daemon initialized.[/green]")

    # 3. Capability Token Issuance (CapBAC Security)
    console.print("\n[bold yellow]Step 2: Issuing Scoped Capability Token (CapBAC Security)...[/bold yellow]")
    token = CapabilityIssuer.issue_token(pid="proc-demo-01", role="coder")
    
    cap_table = Table(title="Capability Token Metadata", box=box.SIMPLE_HEAVY)
    cap_table.add_column("Token ID", style="cyan")
    cap_table.add_column("Assigned Role", style="magenta")
    cap_table.add_column("Allowed Syscalls", style="green")
    cap_table.add_column("Filesystem Scopes", style="yellow")
    cap_table.add_column("TTL", style="blue")

    cap_table.add_row(
        token.token_id,
        token.role,
        ", ".join(token.allowed_syscalls[:4]) + "...",
        ", ".join(token.scope_paths[:3]) + "...",
        f"{token.ttl_seconds}s"
    )
    console.print(cap_table)

    # 4. Process Spawning & Anti-Starvation Scheduler
    console.print("\n[bold yellow]Step 3: Dispatching Autonomous Agent Process...[/bold yellow]")
    instruction = "Read system logs, compute performance benchmarks, and summarize results."
    pcb = kernel.spawn_process(
        name="benchmarking_agent",
        task_instruction=instruction,
        priority=PriorityLevel.HIGH,
        role="coder"
    )
    console.print(f"[cyan]>> Spawned Process PID:[/cyan] [bold]{pcb.pid}[/bold]")
    console.print(f"[cyan]>> Trace ID:[/cyan] [dim]{pcb.trace_id}[/dim]")
    console.print(f"[cyan]>> Priority:[/cyan] {pcb.priority.name}")

    # 5. Run Execution Loop until Idle
    console.print("\n[bold yellow]Step 4: Executing Deterministic Agent Reasoning Loop...[/bold yellow]")
    await kernel.run_until_idle()

    # 6. Process State Verification
    finished_pcb = kernel.scheduler.get_process(pcb.pid)
    status_style = "bold green" if finished_pcb.state.value == "completed" else "bold yellow"
    console.print(f"[bold]Process State:[/bold] [{status_style}]{finished_pcb.state.value.upper()}[/{status_style}]")
    console.print(f"[bold]Tokens Consumed:[/bold] {finished_pcb.tokens_consumed}")
    console.print(f"[bold]Execution Steps:[/bold] {finished_pcb.current_step}")

    # 7. Subsystem Telemetry & Tiered Memory
    console.print("\n[bold yellow]Step 5: Inspecting Memory Hierarchy & Subsystem Telemetry...[/bold yellow]")
    mem_stats = kernel.mmu.get_memory_stats()
    ipc_stats = kernel.message_bus.get_stats()

    stats_table = Table(title="AI-OS Subsystem Runtime State", box=box.ROUNDED)
    stats_table.add_column("Subsystem", style="cyan bold")
    stats_table.add_column("Metric / Status", style="white")

    stats_table.add_row("L1 Working Memory", f"{mem_stats.get('l1_active_contexts', 0)} active context(s)")
    stats_table.add_row("L2 Heap Buffers", f"{mem_stats.get('l2_cached_messages', 0)} cached messages")
    stats_table.add_row("L3 Vector Store", f"{mem_stats.get('l3_stored_vectors', 0)} semantic vectors")
    stats_table.add_row("IPC Message Bus", f"{ipc_stats.get('total_messages_routed', 0)} routed messages")
    stats_table.add_row("Scheduler Workers", f"{settings.default_workers} active workers")

    console.print(stats_table)

    # 8. Deterministic Replay / Flight Recorder
    console.print("\n[bold yellow]Step 6: Verifying Offline Deterministic Replay Records...[/bold yellow]")
    records = kernel.flight_recorder.get_trace(pcb.trace_id)
    console.print(f"[green][OK] Flight Recorder captured {len(records)} deterministic audit records for Trace '{pcb.trace_id}'.[/green]")
    console.print(f"[dim]Run `axiom replay --trace-id {pcb.trace_id}` to replay this execution offline with 0 live API calls.[/dim]")

    # Shutdown Kernel
    kernel.shutdown()
    console.print("\n[bold green][OK] AxiomOS Showcase Completed Successfully![/bold green]\n")


def main():
    try:
        asyncio.run(run_showcase())
    except KeyboardInterrupt:
        console.print("\n[dim]Showcase cancelled by user.[/dim]")


if __name__ == "__main__":
    main()
