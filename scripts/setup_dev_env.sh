#!/usr/bin/env bash

# NetSentinel Development Environment Setup Script
# Works with python3-venv and uv.

set -euo pipefail

echo "=== NetSentinel Development Environment Setup ==="

# Check Python version
python_ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$(printf '%s\n' "3.12" "$python_ver" | sort -V | head -n1)" != "3.12" ]; then
    echo "[-] Error: Python 3.12 or higher is required. Found: $python_ver"
    exit 1
fi
echo "[+] Python version: $python_ver (OK)"

# Check virtual environment tool
if command -v uv &> /dev/null; then
    echo "[+] Found 'uv'. Using uv for fast environment setup..."
    uv venv .venv --system-site-packages
    source .venv/bin/activate
    uv pip install -e ".[dev]"
else
    echo "[*] 'uv' not found. Falling back to standard venv..."
    python3 -m venv .venv --system-site-packages
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -e ".[dev]"
fi

echo "[+] Python dependencies installed successfully."

# Check for system level dependencies
echo "=== Checking System Dependencies ==="
DEPS=("nmap" "arp-scan" "tshark" "blueprint-compiler")
for dep in "${DEPS[@]}"; do
    if command -v "$dep" &> /dev/null; then
        echo "[+] $dep: Installed ($(command -v "$dep"))"
    else
        echo "[-] WARNING: '$dep' is not installed or not in PATH."
        echo "    To install run: sudo apt install $dep (or equivalent on Ubuntu)"
    fi
done

# Compile GSettings schemas locally
if command -v glib-compile-schemas &> /dev/null; then
    echo "[+] Compiling GSettings schemas..."
    glib-compile-schemas data/
else
    echo "[-] WARNING: 'glib-compile-schemas' not found. Cannot compile settings schemas."
fi

echo "=== Setup Completed ==="
echo "Run 'source .venv/bin/activate' to enter the virtual environment."
