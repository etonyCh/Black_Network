#!/usr/bin/env bash

# Script d'installation des politiques D-Bus et de lancement des démons en mode Développement

set -euo pipefail

echo "=== Configuration D-Bus et Démons NetSentinel (Mode Dev) ==="

if [ "$EUID" -ne 0 ]; then
    echo "[-] Ce script doit être exécuté avec les privilèges root (sudo)."
    echo "    Usage: sudo ./scripts/run_dev_daemons.sh"
    exit 1
fi

echo "[+] Copie des configurations D-Bus vers /etc/dbus-1/system.d/..."
cp -v packaging/dbus-system.d/*.conf /etc/dbus-1/system.d/

echo "[+] Rechargement du service D-Bus système..."
systemctl reload dbus

echo "[+] Compilation des binaires en mode release..."
cargo build --release --bins --exclude netsentinel-capture-ebpf

echo "[+] Démarrage du démon netsentinel-discoverd sur le bus système..."
./target/release/netsentinel-discoverd
