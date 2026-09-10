#!/usr/bin/env bash

# NetSentinel Development Environment Setup Script (Rust 2021 Workspace)

set -euo pipefail

echo "=== NetSentinel Development Environment Setup (Rust / GTK4 / eBPF) ==="

# Check for Rust toolchain
if command -v cargo &> /dev/null && command -v rustc &> /dev/null; then
    echo "[+] Found Rust toolchain:"
    rustc --version
    cargo --version
else
    echo "[-] Rust toolchain not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Check for required system development libraries & tools
echo "=== Checking Required System Libraries & Tools ==="
SYS_DEPS=("pkg-config" "clang" "nmap" "arp-scan" "tshark")
MISSING=()

for dep in "${SYS_DEPS[@]}"; do
    if command -v "$dep" &> /dev/null; then
        echo "[+] $dep: Installed ($(command -v "$dep"))"
    else
        echo "[-] WARNING: '$dep' is not installed or not in PATH."
        MISSING+=("$dep")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "[!] To install missing system packages on Ubuntu 24.04 LTS, run:"
    echo "    sudo apt update && sudo apt install -y build-essential pkg-config libgtk-4-dev libadwaita-1-dev libdbus-1-dev libssl-dev clang nmap arp-scan tshark"
fi

# Compile GSettings schemas locally if data/ exists
if [ -d "data" ] && command -v glib-compile-schemas &> /dev/null; then
    echo "[+] Compiling GSettings schemas in data/..."
    glib-compile-schemas data/
fi

echo "=== Development Environment Setup Completed ==="
echo "Run 'cargo check' or 'cargo test' to verify the build."
