"""
ui/dashboard.py
---------------
Live, non-blocking terminal dashboard powered by Rich.

Layout (three panels)
─────────────────────
┌──────────────────────────────────────┐
│  SYSTEM STATUS                       │
│  Queue depth | Engine status | Stats │
├──────────────────────────────────────┤
│  LIVE LOG                            │
│  Scrolling scan events (latest last) │
├──────────────────────────────────────┤
│  THREAT ALERTS                       │
│  Quarantined files in red            │
└──────────────────────────────────────┘

The dashboard is run via `start()` which launches a background thread
that calls `rich.live.Live.refresh()` at ~4 Hz.  All public mutator
methods are thread-safe.
"""

import os
import queue
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_LOG_LINES    = 50   # scrolling log keeps this many lines
REFRESH_PER_SEC  = 4    # Live refresh rate
BANNER = "[bold cyan]⚡ HybridShield Endpoint Threat Detection[/bold cyan]"


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class Dashboard:
    """
    Thread-safe live terminal dashboard.

    Usage
    -----
    dash = Dashboard(file_queue)
    dash.start()
    ...
    dash.stop()
    """

    def __init__(self, file_queue: queue.Queue):
        self._queue     = file_queue
        self._console   = Console()
        self._lock      = threading.Lock()

        # Shared state updated by worker threads
        self._log_lines: deque[str] = deque(maxlen=MAX_LOG_LINES)
        self._alerts:    list[dict] = []
        self._engine_status: str    = "Idle"
        self._start_time: datetime  = datetime.now()
        self._files_scanned: int    = 0
        self._threats_found: int    = 0

        # Background refresh thread
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._live: Optional[Live] = None

        # Worker thread references (injected after creation)
        self.workers: list = []

    # ------------------------------------------------------------------
    # Thread-safe mutators called by worker/watcher threads
    # ------------------------------------------------------------------

    def log_event(self, message: str) -> None:
        """Append a Rich-markup message to the scrolling log."""
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._log_lines.append(f"[dim]{ts}[/dim]  {message}")

    def set_engine_status(self, status: str) -> None:
        with self._lock:
            self._engine_status = status

    def add_threat_alert(
        self,
        filepath: str,
        score: int,
        reasons: list[str],
        quarantined: bool,
        quarantined_path: str = "",
    ) -> None:
        with self._lock:
            self._alerts.append({
                "time":        datetime.now().strftime("%H:%M:%S"),
                "filepath":    filepath,
                "score":       score,
                "reasons":     reasons,
                "quarantined": quarantined,
                "dest":        quarantined_path,
            })
            self._threats_found += 1

    # ------------------------------------------------------------------
    # Renderable builders
    # ------------------------------------------------------------------

    def _build_status_panel(self) -> Panel:
        """Top panel: queue depth, engine state, uptime, counters."""
        uptime = str(datetime.now() - self._start_time).split(".")[0]

        with self._lock:
            queue_depth    = self._queue.qsize()
            engine_status  = self._engine_status
            threats_found  = self._threats_found

        # Aggregate per-worker stats
        total_scanned = sum(
            getattr(w, "files_scanned", 0) for w in self.workers
        )

        # Build a simple grid
        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(justify="left",  min_width=28)
        grid.add_column(justify="left",  min_width=28)
        grid.add_column(justify="right", min_width=20)

        engine_color = "green" if engine_status == "Idle" else "yellow"

        grid.add_row(
            f"[bold]Queue Depth:[/bold]  "
            f"[cyan]{queue_depth}[/cyan] file(s)",

            f"[bold]Engine:[/bold]  "
            f"[{engine_color}]{engine_status}[/{engine_color}]",

            f"[bold]Uptime:[/bold] [white]{uptime}[/white]",
        )
        grid.add_row(
            f"[bold]Files Scanned:[/bold]  "
            f"[white]{total_scanned}[/white]",

            f"[bold]Threats Found:[/bold]  "
            f"[{'red' if threats_found else 'green'}]{threats_found}[/]",

            f"[bold]Workers:[/bold] [white]{len(self.workers)}[/white]",
        )

        return Panel(
            grid,
            title=f"[bold white]◈ SYSTEM STATUS[/bold white]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _build_log_panel(self) -> Panel:
        """Middle panel: scrolling event log."""
        with self._lock:
            lines = list(self._log_lines)

        log_text = Text.from_markup(
            "\n".join(lines) if lines else "[dim]Waiting for files…[/dim]"
        )

        return Panel(
            log_text,
            title="[bold white]◈ LIVE SCAN LOG[/bold white]",
            border_style="blue",
            padding=(0, 1),
        )

    def _build_alerts_panel(self) -> Panel:
        """Bottom panel: quarantine alerts table."""
        with self._lock:
            alerts = list(self._alerts)

        if not alerts:
            content = Text.from_markup(
                "[dim green]  No threats detected. System is clean.[/dim green]"
            )
            return Panel(
                content,
                title="[bold white]◈ THREAT ALERTS[/bold white]",
                border_style="green",
                padding=(0, 1),
            )

        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold red",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Time",       style="dim",         width=10)
        table.add_column("File",       style="bold red",    min_width=24, no_wrap=True)
        table.add_column("Score",      style="bold yellow", width=7, justify="right")
        table.add_column("Triggers",   style="white",       min_width=30)
        table.add_column("Status",     style="cyan",        width=12)

        for a in reversed(alerts):          # newest first
            fname    = os.path.basename(a["filepath"])
            triggers = " | ".join(a["reasons"])[:80]
            status   = "[green]Quarantined[/green]" if a["quarantined"] \
                       else "[red]Move failed[/red]"
            table.add_row(
                a["time"],
                fname,
                str(a["score"]),
                triggers,
                status,
            )

        return Panel(
            table,
            title=f"[bold white]◈ THREAT ALERTS  "
                  f"([bold red]{len(alerts)} DETECTED[/bold red])[/bold white]",
            border_style="red",
            padding=(0, 1),
        )

    def _build_layout(self) -> Layout:
        """Compose the three panels into a full-terminal layout."""
        layout = Layout(name="root")
        layout.split_column(
            Layout(self._build_status_panel(), name="status",  ratio=2),
            Layout(self._build_log_panel(),    name="log",     ratio=5),
            Layout(self._build_alerts_panel(), name="alerts",  ratio=3),
        )
        return layout

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Launch the background refresh thread and open the Live context."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_live,
            daemon=True,
            name="DashboardRefresh",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the refresh thread to exit cleanly."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run_live(self) -> None:
        """
        Main loop for the refresh thread.
        Uses rich.live.Live to redraw the full layout at REFRESH_PER_SEC.
        screen=False keeps the dashboard in the normal scroll buffer so
        it remains visible after Ctrl+C (no alternate screen teardown).
        """
        interval = 1.0 / REFRESH_PER_SEC
        # Print a one-time startup banner BEFORE Live takes over stdout
        self._console.rule(BANNER)
        self._console.print(
            "  [dim]Drop files into [cyan]monitored_zone/[/cyan] in a "
            "[bold]second terminal[/bold] to trigger scans.  "
            "Press [bold]Ctrl+C[/bold] to stop.[/dim]"
        )
        self._console.rule()
        try:
            with Live(
                self._build_layout(),
                console=self._console,
                refresh_per_second=REFRESH_PER_SEC,
                screen=False,          # stay in normal scroll buffer
                transient=False,
                vertical_overflow="visible",
            ) as live:
                self._live = live
                while not self._stop_event.is_set():
                    live.update(self._build_layout())
                    time.sleep(interval)
        except Exception:
            pass   # swallow errors so the dashboard never crashes the system
        finally:
            self._live = None

    # ------------------------------------------------------------------
    # Convenience: print a final summary after stopping
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        total_scanned = sum(
            getattr(w, "files_scanned", 0) for w in self.workers
        )
        self._console.print()
        self._console.rule("[bold cyan]Session Summary[/bold cyan]")
        self._console.print(
            f"  Files scanned : [white]{total_scanned}[/white]\n"
            f"  Threats found : [red]{self._threats_found}[/red]\n"
            f"  Duration      : "
            f"[white]{str(datetime.now() - self._start_time).split('.')[0]}[/white]"
        )
        self._console.rule()
