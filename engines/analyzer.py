"""
engines/analyzer.py
-------------------
Multi-engine analysis pipeline.

Pulls file paths off a shared queue and runs them sequentially through
three offline detection engines:
  1. ClamAV  – signature-based via a local clamd daemon
  2. YARA    – rule-based pattern matching
  3. Heuristics – entropy + MIME/extension spoofing

Results are forwarded to the risk scorer / quarantine module.
"""

import os
import glob
import queue
import logging
import threading
import time
from pathlib import Path
from typing import Optional

import yara

from engines.heuristics import run_heuristics
from remediation.quarantine import score_and_quarantine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")

# Seconds to wait for clamd before giving up
CLAMAV_TIMEOUT = 10

# Seconds a worker sleeps when the queue is empty
IDLE_SLEEP = 0.25


# ---------------------------------------------------------------------------
# ClamAV Engine
# ---------------------------------------------------------------------------

def run_clamav(filepath: str) -> dict:
    """
    Scan *filepath* using a locally running clamd daemon via pyclamd.

    Returns:
        {
            "available":  bool,   # False if clamd is unreachable
            "malicious":  bool,
            "threat_name": str | None,
        }
    """
    result = {"available": False, "malicious": False, "threat_name": None}

    try:
        import pyclamd  # lazy import – not needed if clamd absent

        # Try Unix socket first (faster), fall back to TCP
        cd = None
        try:
            cd = pyclamd.ClamdUnixSocket()
            cd.ping()
            result["available"] = True
        except Exception:
            pass

        if not result["available"]:
            try:
                cd = pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=3310,
                                                timeout=CLAMAV_TIMEOUT)
                cd.ping()
                result["available"] = True
            except Exception:
                logger.warning("ClamAV daemon unreachable – skipping engine.")
                return result

        scan_result = cd.scan_file(filepath)
        if scan_result is None:
            # scan_file returns None on clean
            result["malicious"] = False
        else:
            status, threat = scan_result.get(filepath, ("OK", None))
            if status == "FOUND":
                result["malicious"] = True
                result["threat_name"] = threat
                logger.warning("ClamAV FOUND '%s' in %s", threat, filepath)

    except ImportError:
        logger.warning("pyclamd not installed – ClamAV engine disabled.")
    except (OSError, PermissionError) as exc:
        logger.error("ClamAV scan error for %s: %s", filepath, exc)

    return result


# ---------------------------------------------------------------------------
# YARA Engine
# ---------------------------------------------------------------------------

class YaraEngine:
    """
    Compiles YARA rules from the rules/ directory once and caches the
    compiled ruleset.  Thread-safe – use a single instance shared across
    all worker threads.
    """

    def __init__(self, rules_dir: str):
        self._rules_dir = os.path.abspath(rules_dir)
        self._rules: Optional[yara.Rules] = None
        self._lock = threading.Lock()
        self._compile()

    def _compile(self) -> None:
        """(Re-)compile all .yar / .yara files in rules_dir."""
        yar_files = glob.glob(os.path.join(self._rules_dir, "**", "*.yar"),
                              recursive=True)
        yar_files += glob.glob(os.path.join(self._rules_dir, "**", "*.yara"),
                               recursive=True)

        if not yar_files:
            logger.info("No YARA rules found in %s – engine will be passive.",
                        self._rules_dir)
            self._rules = None
            return

        filepaths = {Path(f).stem: f for f in yar_files}
        try:
            with self._lock:
                self._rules = yara.compile(filepaths=filepaths)
            logger.info("YARA: compiled %d rule file(s).", len(filepaths))
        except yara.SyntaxError as exc:
            logger.error("YARA compilation error: %s", exc)
            self._rules = None

    def reload(self) -> None:
        """Hot-reload rules (call after adding new .yar files)."""
        self._compile()

    def scan(self, filepath: str) -> dict:
        """
        Scan *filepath* against compiled rules.

        Returns:
            {
                "available":   bool,
                "matches":     list[str],   # matched rule names
                "malicious":   bool,
            }
        """
        result = {"available": False, "matches": [], "malicious": False}

        with self._lock:
            if self._rules is None:
                return result
            result["available"] = True

        try:
            matches = self._rules.match(filepath, timeout=30)
            rule_names = [m.rule for m in matches]
            result["matches"] = rule_names
            result["malicious"] = len(rule_names) > 0
            if rule_names:
                logger.warning("YARA matched rules %s on %s",
                               rule_names, filepath)
        except yara.TimeoutError:
            logger.error("YARA scan timed out on %s", filepath)
        except (OSError, PermissionError) as exc:
            logger.error("YARA scan IO error on %s: %s", filepath, exc)
        except yara.Error as exc:
            logger.error("YARA scan error on %s: %s", filepath, exc)

        return result


# ---------------------------------------------------------------------------
# Analyzer Worker
# ---------------------------------------------------------------------------

class AnalyzerWorker(threading.Thread):
    """
    Background thread that consumes file paths from *file_queue*,
    runs the three-engine pipeline, then forwards results to the
    risk scorer / quarantine module.
    """

    def __init__(
        self,
        file_queue: queue.Queue,
        yara_engine: YaraEngine,
        dashboard=None,
        quarantine_dir: str = "./quarantine_zone",
        worker_id: int = 0,
    ):
        super().__init__(daemon=True, name=f"AnalyzerWorker-{worker_id}")
        self._queue = file_queue
        self._yara = yara_engine
        self._dashboard = dashboard
        self._quarantine_dir = quarantine_dir
        self._stop_event = threading.Event()

        # Metrics exposed to the dashboard
        self.files_scanned: int = 0
        self.threats_found: int = 0
        self._current_file: str = ""

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def current_file(self) -> str:
        return self._current_file

    @property
    def is_idle(self) -> bool:
        return self._current_file == ""

    # ------------------------------------------------------------------
    # Thread main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        logger.info("%s started.", self.name)

        while not self._stop_event.is_set():
            try:
                filepath = self._queue.get(timeout=IDLE_SLEEP)
            except queue.Empty:
                continue

            self._current_file = filepath
            try:
                self._process(filepath)
            except Exception as exc:
                logger.exception("Unhandled error processing %s: %s",
                                 filepath, exc)
            finally:
                self._queue.task_done()
                self._current_file = ""

        logger.info("%s stopped.", self.name)

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def _process(self, filepath: str) -> None:
        """Run the full three-engine pipeline on *filepath*."""

        # Guard: file may have been deleted between detection and processing
        if not os.path.isfile(filepath):
            logger.warning("File gone before scan: %s", filepath)
            return

        logger.info("[%s] Scanning: %s", self.name, filepath)

        if self._dashboard:
            self._dashboard.log_event(
                f"[yellow]Scanning:[/] {os.path.basename(filepath)}"
            )
            self._dashboard.set_engine_status("Running")

        # ---- Engine 1: ClamAV ----------------------------------------
        clamav_result = run_clamav(filepath)

        # ---- Engine 2: YARA ------------------------------------------
        yara_result = self._yara.scan(filepath)

        # ---- Engine 3: Heuristics ------------------------------------
        heuristics_result = run_heuristics(filepath)

        # ---- Aggregate -----------------------------------------------
        analysis = {
            "filepath": filepath,
            "clamav": clamav_result,
            "yara": yara_result,
            "heuristics": heuristics_result,
        }

        self.files_scanned += 1

        # ---- Scoring & Remediation -----------------------------------
        action_taken = score_and_quarantine(
            analysis,
            quarantine_dir=self._quarantine_dir,
            dashboard=self._dashboard,
        )

        if action_taken:
            self.threats_found += 1

        if self._dashboard:
            self._dashboard.set_engine_status("Idle")

        logger.info("[%s] Finished: %s | quarantined=%s",
                    self.name, filepath, action_taken)
