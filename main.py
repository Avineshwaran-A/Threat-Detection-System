"""
main.py
-------
HybridShield – Offline Endpoint Threat Detection System
========================================================

Entry point that wires every subsystem together:
  • Creates required directories
  • Initialises the shared work queue
  • Builds the YARA engine (compiled once, shared across workers)
  • Starts the Watchdog filesystem observer
  • Launches configurable AnalyzerWorker threads
  • Runs the Rich live dashboard on the main thread
  • Handles SIGINT / SIGTERM for a clean shutdown
"""

import os
import sys
import signal
import queue
import logging
import argparse
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap logging BEFORE importing project modules so that any import-time
# warnings are captured.
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("hybridshield.log", encoding="utf-8"),
        # Do NOT add a StreamHandler here – Rich owns stdout/stderr
    ],
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Project imports (after logging is configured)
# ---------------------------------------------------------------------------
from core.watcher         import FileSystemWatcher
from engines.analyzer     import AnalyzerWorker, YaraEngine
from ui.dashboard         import Dashboard

# ---------------------------------------------------------------------------
# Default paths (relative to project root)
# ---------------------------------------------------------------------------
DEFAULT_MONITOR_DIR    = "./monitored_zone"
DEFAULT_QUARANTINE_DIR = "./quarantine_zone"
DEFAULT_RULES_DIR      = "./rules"
DEFAULT_WORKERS        = 2


# ---------------------------------------------------------------------------
# Directory initialisation
# ---------------------------------------------------------------------------

def ensure_directories(*dirs: str) -> None:
    """Create all required directories if they do not already exist."""
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
        logger.info("Directory ready: %s", os.path.abspath(d))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hybridshield",
        description="Hybrid Endpoint Threat Detection System (fully offline)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--monitor-dir",
        default=DEFAULT_MONITOR_DIR,
        help="Directory to watch for new / modified files.",
    )
    parser.add_argument(
        "--quarantine-dir",
        default=DEFAULT_QUARANTINE_DIR,
        help="Destination for quarantined files.",
    )
    parser.add_argument(
        "--rules-dir",
        default=DEFAULT_RULES_DIR,
        help="Directory containing .yar YARA rule files.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of parallel analyzer worker threads.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="File log level.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Shutdown coordinator
# ---------------------------------------------------------------------------

class ShutdownCoordinator:
    """
    Centralises cleanup so that SIGINT, SIGTERM, and normal exit paths
    all run the same teardown sequence exactly once.
    """

    def __init__(self):
        self._triggered = threading.Event()
        self._components: list = []   # (name, callable)

    def register(self, name: str, stop_fn) -> None:
        self._components.append((name, stop_fn))

    def trigger(self) -> None:
        if self._triggered.is_set():
            return
        self._triggered.set()
        logger.info("Shutdown triggered – stopping components …")
        for name, fn in reversed(self._components):   # LIFO order
            try:
                logger.info("Stopping: %s", name)
                fn()
            except Exception as exc:
                logger.error("Error stopping %s: %s", name, exc)

    @property
    def is_triggered(self) -> bool:
        return self._triggered.is_set()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()

    # Adjust log level from CLI
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # ---- Directories -------------------------------------------------------
    ensure_directories(
        args.monitor_dir,
        args.quarantine_dir,
        args.rules_dir,
    )

    # ---- Shared work queue -------------------------------------------------
    file_queue: queue.Queue = queue.Queue()

    # ---- Dashboard (started before workers so it's ready for log_event) ---
    dashboard = Dashboard(file_queue=file_queue)
    dashboard.start()

    logger.info("Dashboard started.")

    # ---- Shutdown coordinator -----------------------------------------------
    coordinator = ShutdownCoordinator()

    def _handle_signal(signum, frame):
        dashboard.log_event(
            f"[bold red]Shutdown signal received ({signum}). Stopping…[/bold red]"
        )
        coordinator.trigger()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # ---- YARA Engine (shared instance) -------------------------------------
    dashboard.log_event("[cyan]Compiling YARA rules…[/cyan]")
    yara_engine = YaraEngine(rules_dir=args.rules_dir)
    dashboard.log_event("[green]YARA engine ready.[/green]")

    # ---- Analyzer workers --------------------------------------------------
    workers: list[AnalyzerWorker] = []
    for i in range(args.workers):
        worker = AnalyzerWorker(
            file_queue    = file_queue,
            yara_engine   = yara_engine,
            dashboard     = dashboard,
            quarantine_dir= args.quarantine_dir,
            worker_id     = i,
        )
        worker.start()
        workers.append(worker)
        coordinator.register(f"AnalyzerWorker-{i}", worker.stop)

    # Expose workers to the dashboard so it can aggregate stats
    dashboard.workers = workers
    dashboard.log_event(
        f"[green]{args.workers} analyzer worker(s) started.[/green]"
    )

    # ---- Watchdog observer -------------------------------------------------
    watcher = FileSystemWatcher(
        watch_dir  = args.monitor_dir,
        file_queue = file_queue,
        dashboard  = dashboard,
    )
    watcher.start()
    coordinator.register("FileSystemWatcher", watcher.stop)

    dashboard.log_event(
        f"[bold green]HybridShield is ACTIVE.[/bold green]  "
        f"Drop files into [cyan]{os.path.abspath(args.monitor_dir)}[/cyan]"
    )

    # Register dashboard last so it stops after everything else
    coordinator.register("Dashboard", dashboard.stop)

    # ---- Block main thread until shutdown -----------------------------------
    try:
        while not coordinator.is_triggered:
            # Keep the watcher alive; restart if it dies unexpectedly
            if not watcher.is_alive:
                logger.warning("Watcher died unexpectedly – restarting.")
                dashboard.log_event("[red]Watcher died – restarting…[/red]")
                watcher.start()
            import time; time.sleep(1)
    except KeyboardInterrupt:
        coordinator.trigger()

    # Drain remaining queue items (give workers up to 10 s to finish)
    dashboard.log_event("[yellow]Draining scan queue…[/yellow]")
    try:
        file_queue.join()
    except Exception:
        pass

    # Final teardown
    coordinator.trigger()

    # Print session summary to a fresh console (after Live closes)
    import time; time.sleep(0.5)
    dashboard.print_summary()

    return 0


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
