#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STAGING_DIR="${WORKSPACE_DIR}/target/staging"

echo "▶ Préparation de l'arborescence de staging dans ${STAGING_DIR}..."

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/usr/bin"
mkdir -p "${STAGING_DIR}/usr/libexec"
mkdir -p "${STAGING_DIR}/etc/apparmor.d"
mkdir -p "${STAGING_DIR}/etc/dbus-1/system.d"
mkdir -p "${STAGING_DIR}/etc/systemd/system"
mkdir -p "${STAGING_DIR}/usr/share/polkit-1/actions"

# Copie des binaires compiliés (release profile)
BINS=("netsentinel-discoverd" "netsentinel-scand" "netsentinel-captured" "netsentinel-interceptd")
for bin in "${BINS[@]}"; do
    if [ -f "${WORKSPACE_DIR}/target/release/${bin}" ]; then
        install -Dm755 "${WORKSPACE_DIR}/target/release/${bin}" "${STAGING_DIR}/usr/libexec/${bin}"
        echo "  [+] /usr/libexec/${bin}"
    fi
done

if [ -f "${WORKSPACE_DIR}/target/release/netsentinel" ]; then
    install -Dm755 "${WORKSPACE_DIR}/target/release/netsentinel" "${STAGING_DIR}/usr/bin/netsentinel"
    echo "  [+] /usr/bin/netsentinel"
fi

# Copie des configurations de sécurité & services
if [ -d "${WORKSPACE_DIR}/packaging/apparmor" ]; then
    cp -a "${WORKSPACE_DIR}/packaging/apparmor/"* "${STAGING_DIR}/etc/apparmor.d/" 2>/dev/null || true
fi

if [ -d "${WORKSPACE_DIR}/packaging/dbus-system.d" ]; then
    cp -a "${WORKSPACE_DIR}/packaging/dbus-system.d/"* "${STAGING_DIR}/etc/dbus-1/system.d/" 2>/dev/null || true
fi

if [ -d "${WORKSPACE_DIR}/packaging/systemd" ]; then
    cp -a "${WORKSPACE_DIR}/packaging/systemd/"* "${STAGING_DIR}/etc/systemd/system/" 2>/dev/null || true
fi

if [ -d "${WORKSPACE_DIR}/packaging/polkit" ]; then
    cp -a "${WORKSPACE_DIR}/packaging/polkit/"* "${STAGING_DIR}/usr/share/polkit-1/actions/" 2>/dev/null || true
fi

echo "✅ Arborescence de staging Debian prête avec succès dans target/staging !"
