"""
remediation/quarantine.py
--------------------------
Risk scoring engine and quarantine executor.

Scoring table
─────────────
  ClamAV signature match   → 100 pts
  YARA rule match          →  70 pts  (per file, not per rule)
  Extension spoofing       →  50 pts
  High Shannon entropy     →  30 pts

Score threshold for automatic quarantine: ≥ 70 pts.

Quarantine procedure
────────────────────
  1. Move the file to <quarantine_dir>/<original_basename>.<timestamp>
  2. Strip all permissions with os.chmod(path, 0o000)
  3. Log the event and notify the dashboard
"""

import os
import shutil
import logging
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------
SCORE_CLAMAV         = 100
SCORE_YARA           = 70
SCORE_SPOOF          = 50
SCORE_HIGH_ENTROPY   = 30

QUARANTINE_THRESHOLD = 70   # minimum score that triggers quarantine


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def calculate_risk_score(analysis: dict) -> tuple[int, list[str]]:
    """
    Compute a total risk score and a list of human-readable trigger reasons
    from the *analysis* dict produced by AnalyzerWorker.

    Parameters
    ----------
    analysis : dict
        {
            "filepath": str,
            "clamav":   { "malicious": bool, "threat_name": str|None, ... },
            "yara":     { "malicious": bool, "matches": list[str], ... },
            "heuristics": {
                "high_entropy": bool, "entropy": float,
                "spoofed": bool, "real_mime": str, "claimed_ext": str,
            },
        }

    Returns
    -------
    (score: int, reasons: list[str])
    """
    score   = 0
    reasons = []

    clamav = analysis.get("clamav", {})
    yara   = analysis.get("yara", {})
    heur   = analysis.get("heuristics", {})

    # ---- ClamAV ----------------------------------------------------------
    if clamav.get("malicious"):
        score += SCORE_CLAMAV
        threat = clamav.get("threat_name") or "Unknown signature"
        reasons.append(f"ClamAV: {threat} (+{SCORE_CLAMAV})")

    # ---- YARA ------------------------------------------------------------
    if yara.get("malicious"):
        score += SCORE_YARA
        matched = ", ".join(yara.get("matches", [])) or "unnamed rule"
        reasons.append(f"YARA: {matched} (+{SCORE_YARA})")

    # ---- Extension spoofing ----------------------------------------------
    if heur.get("spoofed"):
        score += SCORE_SPOOF
        real  = heur.get("real_mime", "?")
        claim = heur.get("claimed_ext", "?") or "(none)"
        reasons.append(
            f"Extension spoof: claims '{claim}' but is '{real}' (+{SCORE_SPOOF})"
        )

    # ---- High entropy ----------------------------------------------------
    if heur.get("high_entropy"):
        score += SCORE_HIGH_ENTROPY
        entropy_val = heur.get("entropy", 0.0)
        reasons.append(f"High entropy: {entropy_val:.4f} (+{SCORE_HIGH_ENTROPY})")

    return score, reasons


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def quarantine_file(filepath: str, quarantine_dir: str) -> str:
    """
    Move *filepath* into *quarantine_dir* and strip all permissions.

    The destination filename includes a timestamp to avoid collisions.

    Returns the path of the quarantined file, or raises on failure.
    """
    Path(quarantine_dir).mkdir(parents=True, exist_ok=True)

    basename = os.path.basename(filepath)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    dest_name = f"{basename}.{timestamp}.quarantined"
    dest_path = os.path.join(quarantine_dir, dest_name)

    try:
        shutil.move(filepath, dest_path)
        logger.info("Quarantined '%s' → '%s'", filepath, dest_path)
    except (OSError, PermissionError) as exc:
        logger.error("Failed to move '%s' to quarantine: %s", filepath, exc)
        raise

    # Strip all read/write/execute bits so the file is inert
    try:
        os.chmod(dest_path, 0o000)
        logger.info("Permissions stripped on: %s", dest_path)
    except (OSError, PermissionError) as exc:
        # Non-fatal – file is already moved; log and continue
        logger.warning("chmod(0o000) failed on '%s': %s", dest_path, exc)

    return dest_path


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def score_and_quarantine(
    analysis: dict,
    quarantine_dir: str = "./quarantine_zone",
    dashboard=None,
) -> bool:
    """
    Score the analysis result and quarantine the file if the risk
    score meets or exceeds QUARANTINE_THRESHOLD.

    Parameters
    ----------
    analysis      : dict returned by AnalyzerWorker._process
    quarantine_dir: destination directory for quarantined files
    dashboard     : optional Dashboard instance for live UI updates

    Returns True if the file was quarantined, False otherwise.
    """
    filepath = analysis.get("filepath", "")
    score, reasons = calculate_risk_score(analysis)
    reason_str = " | ".join(reasons) if reasons else "Clean"

    logger.info(
        "Risk score for '%s': %d/250  reasons=[%s]",
        os.path.basename(filepath), score, reason_str
    )

    # ---- Notify dashboard of scan result (all files) --------------------
    if dashboard:
        dashboard.log_event(
            f"[white]Score:[/] [bold]{score}[/bold]/250 "
            f"— {os.path.basename(filepath)}"
        )

    # ---- Below threshold: safe ------------------------------------------
    if score < QUARANTINE_THRESHOLD:
        if dashboard:
            dashboard.log_event(
                f"[green]Clean:[/] {os.path.basename(filepath)} "
                f"(score={score})"
            )
        return False

    # ---- At or above threshold: quarantine ------------------------------
    logger.warning(
        "THREAT DETECTED – score %d ≥ %d, quarantining: %s",
        score, QUARANTINE_THRESHOLD, filepath,
    )

    quarantined_path = None
    try:
        quarantined_path = quarantine_file(filepath, quarantine_dir)
    except Exception as exc:
        logger.error("Quarantine failed for '%s': %s", filepath, exc)
        if dashboard:
            dashboard.add_threat_alert(
                filepath=filepath,
                score=score,
                reasons=reasons,
                quarantined=False,
            )
        return False

    # Notify dashboard about the confirmed threat
    if dashboard:
        dashboard.add_threat_alert(
            filepath=filepath,
            score=score,
            reasons=reasons,
            quarantined=True,
            quarantined_path=quarantined_path,
        )

    return True
