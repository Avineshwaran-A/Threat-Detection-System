#!/usr/bin/env bash
# setup.sh
# --------
# One-shot environment bootstrap for HybridShield.
# Run once before the first launch:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

VENV_DIR=".venv"
PYTHON=${PYTHON:-python3}

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   HybridShield — Environment Setup               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── 1. System-level libraries ──────────────────────────────────────────────
echo "[1/5] Checking system dependencies …"

if command -v apt-get &>/dev/null; then
    echo "      Detected: apt (Debian/Ubuntu)"
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        libmagic1 \
        libmagic-dev \
        clamav \
        clamav-daemon \
        yara \
        libyara-dev \
        build-essential \
        python3-dev \
        python3-venv
elif command -v dnf &>/dev/null; then
    echo "      Detected: dnf (Fedora/RHEL)"
    sudo dnf install -y \
        file-libs \
        file-devel \
        clamav \
        clamd \
        yara \
        yara-devel \
        gcc \
        python3-devel
elif command -v pacman &>/dev/null; then
    echo "      Detected: pacman (Arch)"
    sudo pacman -Sy --noconfirm \
        file \
        clamav \
        yara \
        base-devel \
        python
fi

# ── 2. Python virtual environment ──────────────────────────────────────────
echo ""
echo "[2/5] Creating Python virtual environment in ${VENV_DIR} …"
$PYTHON -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "[3/5] Upgrading pip …"
pip install --quiet --upgrade pip

# ── 3. Python packages ─────────────────────────────────────────────────────
echo "[4/5] Installing Python dependencies …"
pip install --quiet -r requirements.txt

# ── 4. ClamAV virus database ───────────────────────────────────────────────
echo ""
echo "[5/5] Updating ClamAV virus database (freshclam) …"
echo "      (This may take a few minutes on first run)"
if command -v freshclam &>/dev/null; then
    sudo freshclam || echo "      WARNING: freshclam failed – check /etc/clamav/freshclam.conf"
else
    echo "      WARNING: freshclam not found – skipping database update"
fi

# Optional: enable and start clamd service
if command -v systemctl &>/dev/null; then
    echo ""
    echo "      Enabling clamd.service (clamav-daemon) …"
    sudo systemctl enable --now clamav-daemon 2>/dev/null || \
    sudo systemctl enable --now clamd         2>/dev/null || \
    echo "      NOTE: Could not start clamd via systemctl. Start manually if needed."
fi

# ── 5. Final instructions ─────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   Setup complete!                                ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Activate env : source .venv/bin/activate        ║"
echo "║  Start system : python main.py                   ║"
echo "║  Options      : python main.py --help            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
