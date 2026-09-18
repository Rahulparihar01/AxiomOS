import argparse
import asyncio
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# Ensure UTF-8 console output on Windows
if sys.platform == "win32" and sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from config.settings import settings
from kernel import Kernel, PriorityLevel, ProcessControlBlock, ProcessState
from kernel.checkpoint import CheckpointManager
from syscalls.mcp_server import AIOSMcpServer
from server.app import create_app
import uvicorn

console = Console(force_terminal=True)

async def cmd_start(args):
    """Boot the AxiomOS Kernel."""
    banner = Panel(
        f"[bold cyan]AxiomOS Kernel Boot[/bold cyan] (v{settings.version})\n"
        f"[dim]The Deterministic Control Plane for Autonomous Agents | Checkpointed Fault Tolerance | WebSockets[/dim]",
        box=box.ROUNDED,
        border_style="cyan"
    )
    console.print(banner)

    if getattr(args, "sandbox", None):
        settings.sandbox_backend = args.sandbox
    if getattr(args, "embedding", None):
        settings.embedding_provider = args.embedding

    kernel = Kernel(provider_name=args.provider, auto_approve_hitl=args.auto_approve)

    if args.clean:
        console.print("[yellow][*] Clean boot: Purging previous crash snapshots...[/yellow]")
        kernel.checkpoint_mgr.clear_all()
    else:
        # Check for crash recovery
        recovered = kernel.recover_interrupted_processes()
        if recovered > 0:
            console.print(f"[bold green][*] Fault Tolerance: Successfully restored {recovered} interrupted process(es) from checkpoint store![/bold green]")

    if args.web:
        web_app = create_app(kernel)
        config = uvicorn.Config(web_app, host="127.0.0.1", port=args.port, log_level="warning")
        server = uvicorn.Server(config)
        console.print(f"[bold green]► Web Control Center live at: [underline cyan]http://127.0.0.1:{args.port}[/underline cyan][/bold green]")
        if settings.admin_token:
            console.print(f"[bold green]  [Auth] X-AIOS-Token authentication is ACTIVE.[/bold green]")
        else:
            console.print(f"[dim yellow]  [Auth] Note: Running without AIOS_ADMIN_TOKEN (Development Mode).[/dim yellow]")
        
        asyncio.create_task(server.serve())
        if getattr(args, "open_browser", False):
            try:
                import webbrowser
                webbrowser.open(f"http://127.0.0.1:{args.port}")
            except Exception:
                pass

    # Start kernel worker pool
    kernel.start_daemon()

    console.print("\n[bold green][*] Kernel is running. Waiting for process completion...[/bold green]")
    await kernel.run_until_idle()
    console.print("[bold cyan][*] Kernel dispatch queue is idle.[/bold cyan]")

    if args.web:
        console.print("[dim]Web server is still active with daemon workers listening. Press Ctrl+C to exit.[/dim]")
        while True:
            await asyncio.sleep(1)
    else:
        kernel.shutdown()

async def cmd_run(args):
    """Run a single ad-hoc task in the AI-OS."""
    if getattr(args, "sandbox", None):
        settings.sandbox_backend = args.sandbox
    if getattr(args, "embedding", None):
        settings.embedding_provider = args.embedding

    kernel = Kernel(provider_name=args.provider, auto_approve_hitl=args.auto_approve)
    kernel.start_daemon()
    priority_enum = getattr(PriorityLevel, args.priority.upper(), PriorityLevel.NORMAL)

    pcb = kernel.spawn_process(
        name=args.name or "cli_worker",
        task_instruction=args.instruction,
        priority=priority_enum,
        role=args.role
    )
    console.print(f"[bold cyan][*] Spawning task (PID: {pcb.pid}, Trace ID: {pcb.trace_id}):[/bold cyan] {args.instruction}")

    await kernel.run_until_idle()
    kernel.shutdown()

    updated = kernel.scheduler.get_process(pcb.pid)
    if updated and updated.state == ProcessState.COMPLETED:
        console.print(f"\n[bold green]► Result:[/bold green]\n{updated.result}")
        console.print(f"[dim]Trace recorded. Replay offline with: python cli.py replay --trace-id {pcb.trace_id}[/dim]")
    else:
        console.print(f"\n[bold red]► Process Failed:[/bold red] {updated.error_message if updated else 'Unknown error'}")

def cmd_ps(args):
    """Display process status from checkpoint storage."""
    mgr = CheckpointManager()
    snapshots = mgr.load_uncompleted_snapshots()

    table = Table(box=box.ROUNDED, header_style="bold cyan", expand=True)
    table.add_column("PID", style="dim", width=15)
    table.add_column("Process Name", style="bold white", width=20)
    table.add_column("Priority", justify="center", width=12)
    table.add_column("State", justify="center", width=12)
    table.add_column("Tokens Consumed", justify="right", width=18)
    table.add_column("Last Checkpoint", style="italic")

    if not snapshots:
        console.print("[dim]No uncompleted processes in checkpoint store.[/dim]")
        return

    for pcb, l1 in snapshots:
        table.add_row(
            pcb.pid,
            pcb.name,
            pcb.priority.name,
            f"[yellow]{pcb.state.value}[/yellow]",
            f"{pcb.tokens_consumed:,} / {pcb.token_budget:,}",
            pcb.updated_at.strftime("%Y-%m-%d %H:%M:%S")
        )
    console.print(table)

def cmd_recover(args):
    """Inspect and report recoverable processes."""
    mgr = CheckpointManager()
    snapshots = mgr.load_uncompleted_snapshots()
    console.print(f"[bold cyan][*] Recoverable processes found:[/bold cyan] {len(snapshots)}")
    for pcb, _ in snapshots:
        console.print(f"  - PID: [cyan]{pcb.pid}[/cyan] ({pcb.name}) in state [yellow]{pcb.state.value}[/yellow]")

def cmd_replay(args):
    """Deterministically replay a recorded execution trace offline."""
    from kernel.flight_recorder import FlightRecorder
    from kernel.replay import TraceReplayEngine

    recorder = FlightRecorder()
    if getattr(args, "list", False) or not args.trace_id:
        traces = recorder.list_traces()
        if not traces:
            console.print("[dim]No execution traces available in flight recorder.[/dim]")
            return
        table = Table(title="Available Execution Traces", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Trace ID", style="bold cyan")
        table.add_column("Records", justify="right")
        table.add_column("Started At")
        table.add_column("Ended At")
        for t in traces:
            table.add_row(t["trace_id"], str(t["records_count"]), t["started_at"], t["ended_at"])
        console.print(table)
        return

    engine = TraceReplayEngine(flight_recorder=recorder)
    console.print(f"[bold cyan][*] Deterministic Flight Replay:[/bold cyan] {args.trace_id}")
    report = engine.replay_trace(args.trace_id)

    if not report.is_reproducible:
        console.print(f"[bold red]► Replay Divergence Detected (Step {report.divergence_step}):[/bold red] {report.error}")
        table = Table(box=box.ROUNDED, header_style="bold red")
        table.add_column("Step", justify="center", width=8)
        table.add_column("Type", width=15)
        table.add_column("Details", style="italic")
        table.add_column("Status", justify="center", width=20)
        for s in report.steps:
            status = "[bold green]MATCHED[/bold green]" if s.matched else f"[bold red]DIVERGED[/bold red]"
            table.add_row(str(s.step_seq), f"[cyan]{s.record_type}[/cyan]", str(s.details), status)
        console.print(table)
        return

    table = Table(box=box.ROUNDED, header_style="bold green")
    table.add_column("Step", justify="center", width=8)
    table.add_column("Type", width=15)
    table.add_column("Details", style="italic")
    table.add_column("Deterministic", justify="center", width=15)

    for s in report.steps:
        table.add_row(
            str(s.step_seq),
            f"[cyan]{s.record_type}[/cyan]",
            str(s.details),
            "[bold green]VERIFIED[/bold green]"
        )

    console.print(table)
    console.print(
        Panel(
            f"[bold green]✓ Trace Replay Success[/bold green]\n"
            f"Total Records: {report.total_records} | Model Calls: {report.model_calls_count} | Syscalls: {report.syscalls_count}\n"
            f"[dim]Deterministic execution verified offline with 0 live API calls or side-effects.[/dim]",
            box=box.ROUNDED,
            border_style="green"
        )
    )

async def cmd_mcp_server(args):
    """Launch AI-OS as a Model Context Protocol (MCP) Server over stdio."""
    kernel = Kernel(provider_name=args.provider, auto_approve_hitl=args.auto_approve)
    mcp_server = AIOSMcpServer(kernel=kernel)
    await mcp_server.run_stdio_server()

def main():
    parser = argparse.ArgumentParser(prog="axiom", description="AxiomOS: The Deterministic Control Plane for Autonomous Agents")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # start
    p_start = subparsers.add_parser("start", help="Boot AxiomOS Kernel")
    p_start.add_argument("--web", action="store_true", help="Launch Web Control Center")
    p_start.add_argument("--open-browser", "--open", dest="open_browser", action="store_true", default=False, help="Open Web Control Center in default browser")
    p_start.add_argument("--port", type=int, default=8000, help="Web port (default: 8000)")
    p_start.add_argument("--provider", type=str, default="mock", help="Model provider (mock, gemini, openai, ollama)")
    p_start.add_argument("--clean", action="store_true", help="Discard previous checkpoint snapshots")
    p_start.add_argument("--auto-approve", action="store_true", help="Auto-approve HITL operations")
    p_start.add_argument("--sandbox", type=str, choices=["local", "docker"], default=None, help="Sandbox isolation backend (local, docker)")
    p_start.add_argument("--embedding", type=str, choices=["hash", "openai", "gemini"], default=None, help="L3 memory embedding provider (hash, openai, gemini)")

    # run
    p_run = subparsers.add_parser("run", help="Run a single ad-hoc agent task")
    p_run.add_argument("instruction", type=str, help="Instruction for the agent")
    p_run.add_argument("--name", type=str, default=None, help="Agent process name")
    p_run.add_argument("--priority", type=str, default="NORMAL", help="Process priority")
    p_run.add_argument("--provider", type=str, default="mock", help="Model provider")
    p_run.add_argument("--role", type=str, default=None, choices=["base", "planner", "coder", "reviewer", "researcher", "conflict_resolver"], help="Specialized agent persona/role")
    p_run.add_argument("--auto-approve", action="store_true", help="Auto-approve HITL operations")
    p_run.add_argument("--sandbox", type=str, choices=["local", "docker"], default=None, help="Sandbox isolation backend (local, docker)")
    p_run.add_argument("--embedding", type=str, choices=["hash", "openai", "gemini"], default=None, help="L3 memory embedding provider (hash, openai, gemini)")

    # ps
    subparsers.add_parser("ps", help="List processes in checkpoint store")

    # recover
    subparsers.add_parser("recover", help="Inspect recoverable checkpoints")

    # replay
    p_replay = subparsers.add_parser("replay", help="Deterministically replay a recorded trace")
    p_replay.add_argument("--trace-id", type=str, default=None, help="Trace ID to replay")
    p_replay.add_argument("--list", action="store_true", help="List all available traces")

    # mcp-server (GAP-13)
    p_mcp = subparsers.add_parser("mcp-server", help="Launch AI-OS as a Model Context Protocol (MCP) stdio server")
    p_mcp.add_argument("--provider", type=str, default="mock", help="Model provider (mock, gemini, openai, ollama)")
    p_mcp.add_argument("--auto-approve", action="store_true", help="Auto-approve HITL operations")

    args = parser.parse_args()

    if args.command == "start":
        asyncio.run(cmd_start(args))
    elif args.command == "run":
        asyncio.run(cmd_run(args))
    elif args.command == "ps":
        cmd_ps(args)
    elif args.command == "recover":
        cmd_recover(args)
    elif args.command == "replay":
        cmd_replay(args)
    elif args.command == "mcp-server":
        asyncio.run(cmd_mcp_server(args))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]AI-OS terminated by user.[/dim]")
