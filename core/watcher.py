"""
core/watcher.py
---------------
Filesystem observer using Watchdog.

Monitors a target directory for new/modified files and pushes
their absolute paths into a thread-safe queue for the analyzer
workers to consume.
"""

import os
import queue
import logging
import threading
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
)

logger = logging.getLogger(__name__)


class ThreatEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that filters FileCreated / FileModified events
    and places valid file paths onto the shared work queue.
    """

    # Prefixes and suffixes that indicate transient / temp OS files
    IGNORED_PREFIXES = (".", "~", "#")
    IGNORED_SUFFIXES = (".tmp", ".part", ".crdownload", ".swp", ".swx")

    def __init__(self, file_queue: queue.Queue, dashboard=None):
        super().__init__()
        self._queue = file_queue
        self._dashboard = dashboard  # optional rich dashboard reference
        # Track paths already enqueued to avoid duplicate work
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_ignored(self, path: str) -> bool:
        """Return True if this path should be silently ignored."""
        name = os.path.basename(path)
        if name.startswith(self.IGNORED_PREFIXES):
            return True
        if name.endswith(self.IGNORED_SUFFIXES):
            return True
        # Skip directories
        if os.path.isdir(path):
            return True
        return False

    # Seconds before the same path can be re-enqueued (debounce window)
    DEDUP_TTL = 2.0

    def _enqueue(self, path: str) -> None:
        """
        Place *path* on the work queue, logging the action.
        De-duplicates within DEDUP_TTL seconds so rapid save events
        (e.g. editor writes) don't spawn multiple scan jobs.
        After DEDUP_TTL the path is removed from _seen so future
        modifications to the same file are picked up again.
        """
        abs_path = os.path.abspath(path)

        if self._is_ignored(abs_path):
            logger.debug("Ignoring transient file: %s", abs_path)
            return

        with self._lock:
            if abs_path in self._seen:
                logger.debug("Duplicate event skipped: %s", abs_path)
                return
            self._seen.add(abs_path)

        # Schedule automatic removal from _seen after the debounce window
        threading.Timer(self.DEDUP_TTL, self._clear_seen, args=(abs_path,)).start()

        # Notify the dashboard if one is attached
        if self._dashboard:
            self._dashboard.log_event(f"[cyan]Detected:[/] {abs_path}")

        logger.info("Enqueuing file for analysis: %s", abs_path)
        self._queue.put(abs_path)

    def _clear_seen(self, path: str) -> None:
        """
        Remove *path* from the de-duplication set after it has been
        enqueued so the same file can be re-scanned on future events.
        """
        with self._lock:
            self._seen.discard(os.path.abspath(path))

    # ------------------------------------------------------------------
    # Watchdog event callbacks
    # ------------------------------------------------------------------

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            self._enqueue(event.src_path)

    def on_modified(self, event):
        if isinstance(event, FileModifiedEvent):
            self._enqueue(event.src_path)


class FileSystemWatcher:
    """
    High-level wrapper around the Watchdog Observer.

    Usage
    -----
    watcher = FileSystemWatcher(watch_dir, file_queue, dashboard)
    watcher.start()
    ...
    watcher.stop()
    """

    def __init__(
        self,
        watch_dir: str,
        file_queue: queue.Queue,
        dashboard=None,
    ):
        self._watch_dir = os.path.abspath(watch_dir)
        self._queue = file_queue
        self._dashboard = dashboard
        self._observer: Observer | None = None
        self._handler = ThreatEventHandler(file_queue, dashboard)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spin up the background observer thread and scan pre-existing files."""
        Path(self._watch_dir).mkdir(parents=True, exist_ok=True)

        self._observer = Observer()
        self._observer.schedule(
            self._handler,
            path=self._watch_dir,
            recursive=True,  # watch sub-directories too
        )
        self._observer.start()
        logger.info("Watcher started on: %s", self._watch_dir)

        if self._dashboard:
            self._dashboard.log_event(
                f"[green]Watcher active:[/] {self._watch_dir}"
            )

        # Enqueue files that already existed before the watcher started
        self._scan_existing_files()

    def _scan_existing_files(self) -> None:
        """
        Walk the watched directory and enqueue every file that was already
        present when the watcher started.  This catches files dropped before
        startup and files that were missed during a previous run.
        """
        count = 0
        for root, _dirs, files in os.walk(self._watch_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                self._handler._enqueue(fpath)
                count += 1

        if count and self._dashboard:
            self._dashboard.log_event(
                f"[cyan]Startup scan:[/] enqueued {count} pre-existing file(s)"
            )
        elif self._dashboard:
            self._dashboard.log_event(
                "[dim]Startup scan: monitored_zone is empty.[/dim]"
            )

    def stop(self) -> None:
        """Gracefully stop the observer thread."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
            logger.info("Watcher stopped.")

    @property
    def watch_dir(self) -> str:
        return self._watch_dir

    @property
    def is_alive(self) -> bool:
        return self._observer is not None and self._observer.is_alive()
