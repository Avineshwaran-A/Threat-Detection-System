"""
engines/heuristics.py
---------------------
Heuristics analysis engine.

Provides two independent checks:
  1. Shannon Entropy  – high entropy (>7.0) suggests encryption /
                        packing, a common obfuscation technique.
  2. Extension Spoofing – compares the real MIME type (from libmagic)
                          against the extension the file *claims* to have.
"""

import os
import math
import logging
from pathlib import Path

import magic  # python-magic

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MIME → expected extensions mapping (subset; extend as needed)
# ---------------------------------------------------------------------------
# Maps a MIME type prefix/exact string to a set of legitimate extensions.
MIME_TO_EXTENSIONS: dict[str, set[str]] = {
    # Executables / code
    "application/x-executable":       {".elf", ".bin", ".out"},
    "application/x-sharedlib":        {".so"},
    "application/x-msdos-program":    {".exe", ".com", ".bat"},
    "application/x-dosexec":          {".exe", ".com", ".dll", ".sys"},
    "application/x-msdownload":       {".exe", ".dll"},
    "application/x-pe-app-32bit-i386":{".exe", ".dll", ".sys"},
    # Archives / compressed
    "application/zip":                {".zip", ".jar", ".apk", ".docx",
                                       ".xlsx", ".pptx", ".odt"},
    "application/x-rar-compressed":   {".rar"},
    "application/gzip":               {".gz", ".tgz", ".tar.gz"},
    "application/x-bzip2":            {".bz2", ".tbz2"},
    "application/x-7z-compressed":    {".7z"},
    "application/x-tar":              {".tar"},
    # Documents
    "application/pdf":                {".pdf"},
    "application/msword":             {".doc"},
    "application/vnd.ms-excel":       {".xls"},
    "application/vnd.ms-powerpoint":  {".ppt"},
    # Scripts
    "text/x-python":                  {".py"},
    "text/x-shellscript":             {".sh", ".bash"},
    "text/x-perl":                    {".pl"},
    # Images
    "image/jpeg":                     {".jpg", ".jpeg"},
    "image/png":                      {".png"},
    "image/gif":                      {".gif"},
    "image/bmp":                      {".bmp"},
    "image/webp":                     {".webp"},
    # Audio / Video
    "audio/mpeg":                     {".mp3"},
    "video/mp4":                      {".mp4"},
    "video/x-msvideo":                {".avi"},
    # Office XML
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
                                      {".docx"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
                                      {".xlsx"},
}

# MIME types that indicate executable / dangerous content when the
# extension suggests something benign (e.g., a ".pdf" that is actually ELF)
DANGEROUS_MIMES: frozenset[str] = frozenset({
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-msdos-program",
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-pe-app-32bit-i386",
    "application/x-shellscript",
})

# Entropy threshold above which a file is considered "high-entropy"
HIGH_ENTROPY_THRESHOLD = 7.0

# Maximum bytes to read for entropy calculation (avoids stalling on
# multi-GB files while still sampling meaningfully)
ENTROPY_SAMPLE_BYTES = 1_048_576  # 1 MiB


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_entropy(filepath: str) -> float:
    """
    Calculate the Shannon entropy of the file's byte distribution.

    Returns a float in [0.0, 8.0].
    A value > HIGH_ENTROPY_THRESHOLD (7.0) suggests the file may be
    encrypted, compressed without a known header, or obfuscated.

    Returns -1.0 on IO errors so callers can distinguish "not measured"
    from "genuinely low entropy".
    """
    try:
        with open(filepath, "rb") as fh:
            data = fh.read(ENTROPY_SAMPLE_BYTES)

        if not data:
            return 0.0

        # Frequency table across 256 possible byte values
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        total = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    except (OSError, PermissionError) as exc:
        logger.warning("Entropy calculation failed for %s: %s", filepath, exc)
        return -1.0


def detect_extension_spoofing(filepath: str) -> dict:
    """
    Compare the file's actual MIME type (via libmagic) against the
    extension it claims to have.

    Returns a dict:
        {
            "spoofed":        bool,
            "real_mime":      str,
            "claimed_ext":    str,
            "dangerous_mime": bool,
        }
    """
    result = {
        "spoofed": False,
        "real_mime": "unknown",
        "claimed_ext": "",
        "dangerous_mime": False,
    }

    try:
        mime_detector = magic.Magic(mime=True)
        real_mime: str = mime_detector.from_file(filepath)
        result["real_mime"] = real_mime

        claimed_ext = Path(filepath).suffix.lower()
        result["claimed_ext"] = claimed_ext

        # Is this MIME type inherently dangerous?
        result["dangerous_mime"] = real_mime in DANGEROUS_MIMES

        # Check whether the extension is acceptable for this MIME type
        expected_exts = MIME_TO_EXTENSIONS.get(real_mime)
        if expected_exts is not None and claimed_ext not in expected_exts:
            result["spoofed"] = True
            logger.warning(
                "Extension spoofing detected: %s claims '%s' but is '%s'",
                os.path.basename(filepath),
                claimed_ext,
                real_mime,
            )

        # Also flag: executable MIME type + non-executable extension
        if result["dangerous_mime"] and claimed_ext not in {
            ".exe", ".dll", ".elf", ".bin", ".sh", ".com", ".so", ".sys", ".bat"
        }:
            result["spoofed"] = True

    except (OSError, PermissionError, Exception) as exc:
        logger.warning("MIME detection failed for %s: %s", filepath, exc)

    return result


def run_heuristics(filepath: str) -> dict:
    """
    Run all heuristic checks against *filepath* and return a unified
    result dict consumed by the risk scorer.

    Returns:
        {
            "entropy":          float,   # Shannon entropy value
            "high_entropy":     bool,    # True if entropy > threshold
            "spoofed":          bool,    # True if extension mismatch
            "real_mime":        str,
            "claimed_ext":      str,
            "dangerous_mime":   bool,
        }
    """
    logger.debug("Running heuristics on: %s", filepath)

    entropy = calculate_entropy(filepath)
    spoof_result = detect_extension_spoofing(filepath)

    return {
        "entropy": entropy,
        "high_entropy": (entropy >= HIGH_ENTROPY_THRESHOLD) if entropy >= 0 else False,
        "spoofed": spoof_result["spoofed"],
        "real_mime": spoof_result["real_mime"],
        "claimed_ext": spoof_result["claimed_ext"],
        "dangerous_mime": spoof_result["dangerous_mime"],
    }
