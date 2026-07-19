# NetSentinel

NetSentinel is a native GNOME/GTK4 cyber-security application for Ubuntu 24.04 LTS "Noble Numbat", built with Python and Libadwaita. It is designed to perform network mapping, vulnerability auditing, traffic analysis, active reconnaissance, and secure AI-assisted remediation suggestions.

## Key Security Architecture

NetSentinel implements a strict separation of privileges to limit the attack surface:
- **`netsentinel-ui`**: Non-privileged frontend running inside a Flatpak sandbox (limited filesystem and network access). Communicates with the daemon via D-Bus system bus.
- **`netsentinel-helperd`**: Privileged system helper daemon running as a dedicated system user (`netsentinel-helper`) with specific Linux capabilities (e.g., `cap_net_raw` for raw socket interaction). Access is gated by Polkit policies.

For more details, see the [NetSentinel Specification](docs/cahier-des-charges/NetSentinel_Cahier_des_Charges_v2.md).

## Prerequisites

- Ubuntu 24.04 LTS "Noble Numbat"
- Python 3.12+
- `nmap` (APT version)
- `arp-scan` (APT version)
- `wireshark`/`tshark` (for packet capture parsing)

## Development Setup

To initialize the development environment:

```bash
chmod +x scripts/setup_dev_env.sh
./scripts/setup_dev_env.sh
```

To run version checks:

```bash
chmod +x scripts/check_versions.sh
./scripts/check_versions.sh
```

## Running the Tests

```bash
poetry run pytest
# or if using uv:
uv run pytest
```

## License

Restricted. Authorized testing purposes only. See Rules of Engagement.
