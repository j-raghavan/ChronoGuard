#!/usr/bin/env python3
"""
ChronoGuard Demo: Interactive Audit Log Viewer
===============================================

Live view of audit logs as they're created.
Shows real-time monitoring of browser automation activity.
"""

import os
import sys
import time
from datetime import datetime, timedelta, UTC

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
except ImportError:
    print("❌ Missing dependencies!")
    print("Run: pip install requests rich")
    sys.exit(1)

console = Console()
API_BASE_URL = os.getenv("CHRONOGUARD_API_URL", "http://localhost:8000").rstrip("/")


def fetch_recent_audit_logs(minutes=5):
    """Fetch recent audit logs from the API."""
    try:
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(minutes=minutes)

        response = requests.get(
            f"{API_BASE_URL}/api/v1/audit/analytics",
            params={
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
            timeout=5,
        )

        if response.status_code == 200:
            data = response.json()
            return data.get("entries", [])
        else:
            return []
    except Exception:
        return []


def create_audit_table(entries):
    """Create a rich table with audit log entries."""
    table = Table(title="ChronoGuard Audit Log (Last 5 minutes)", show_header=True, header_style="bold magenta")

    table.add_column("Time", style="cyan", width=12)
    table.add_column("Agent", style="blue", width=15)
    table.add_column("Domain", style="yellow", width=25)
    table.add_column("Decision", width=10)
    table.add_column("Method", width=8)
    table.add_column("Path", width=20)

    if not entries:
        table.add_row("-", "-", "-", "-", "-", "-")
        return table

    for entry in entries[-20:]:  # Show last 20
        timestamp = entry.get("timestamp", "")
        if timestamp:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            time_str = dt.strftime("%H:%M:%S")
        else:
            time_str = "-"

        agent_id = entry.get("agent_id", "-")[:12] + "..."
        domain = entry.get("domain", "-")
        decision = entry.get("decision", "-")
        method = entry.get("request_method", "-")
        path = entry.get("request_path", "-")[:18]

        # Color code the decision
        if decision == "ALLOW":
            decision_styled = f"[green]✅ {decision}[/green]"
        else:
            decision_styled = f"[red]❌ {decision}[/red]"

        table.add_row(time_str, agent_id, domain, decision_styled, method, path)

    return table


def create_stats_panel(entries):
    """Create a panel with statistics."""
    total = len(entries)
    allowed = sum(1 for e in entries if e.get("decision") == "ALLOW")
    denied = total - allowed

    stats_text = f"""
[bold]Total Requests:[/bold] {total}
[green]✅ Allowed:[/green] {allowed}
[red]❌ Denied:[/red] {denied}

[bold cyan]Live monitoring ChronoGuard activity...[/bold cyan]
[dim]Updates every 2 seconds[/dim]
    """

    return Panel(stats_text, title="Statistics", border_style="green")


def main():
    """Run the interactive audit log viewer."""
    console.clear()
    console.print("\n[bold blue]ChronoGuard Interactive Audit Viewer[/bold blue]", justify="center")
    console.print("[dim]Press Ctrl+C to exit[/dim]\n", justify="center")

    # Check if backend is accessible
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=2)
        if response.status_code != 200:
            console.print("[red]❌ Backend not accessible![/red]")
            console.print("Make sure ChronoGuard is running: docker compose up")
            sys.exit(1)
    except Exception:
        console.print("[red]❌ Cannot connect to ChronoGuard API![/red]")
        console.print(f"Make sure backend is running on {API_BASE_URL}")
        sys.exit(1)

    console.print("[green]✅ Connected to ChronoGuard API[/green]\n")

    try:
        while True:
            entries = fetch_recent_audit_logs(minutes=60)

            # Create layout
            layout = Layout()
            layout.split_column(
                Layout(create_stats_panel(entries), size=10),
                Layout(create_audit_table(entries))
            )

            console.clear()
            console.print(layout)

            console.print(f"\n[dim]Last updated: {datetime.now().strftime('%H:%M:%S')} | Ctrl+C to exit[/dim]")

            time.sleep(2)

    except KeyboardInterrupt:
        console.print("\n\n[yellow]👋 Exiting audit viewer. Thanks for trying ChronoGuard![/yellow]\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
