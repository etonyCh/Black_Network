# NetSentinel

NetSentinel is a native GNOME/GTK4 cyber-security & network audit application for Ubuntu 24.04 LTS "Noble Numbat", built in **Rust (2021 edition)** with **Libadwaita** and **GTK4**. It performs L2 network mapping, eBPF packet capture, vulnerability auditing, PQC readiness checks, MitM web interception/replay, active reconnaissance, and secure AI-assisted remediation suggestions via Google Gemini.

## Key Security Architecture

NetSentinel implements strict privilege separation across a multi-crate Rust Cargo workspace:

- **`netsentinel` (UI)**: Non-privileged GTK4/Libadwaita frontend running inside a Flatpak sandbox (`org.netsentinel.NetSentinel`). Communicates with backend system daemons over the D-Bus system bus via `zbus`.
- **System Daemons (`netsentinel-*d`)**: Dedicated micro-services running on the host with targeted Linux capabilities (e.g. `CAP_NET_RAW` for raw socket & ARP interaction, eBPF probes via `aya`). Access is gated by **Polkit** policies:
  - `netsentinel-discoverd` (`org.netsentinel.Discover1`): L2 ARP network discovery
  - `netsentinel-captured` (`org.netsentinel.Capture1`): Passive eBPF kernel packet capture
  - `netsentinel-scand` (`org.netsentinel.Scan1`): Port scan & CVE vulnerability audit
  - `netsentinel-interceptd` (`org.netsentinel.Intercept1`): MitM HTTP/HTTPS proxy & replay

For full details, see the [NetSentinel Specification](docs/cahier-des-charges/NetSentinel_Cahier_des_Charges_v2.md).

## Cargo Workspace Structure

```
.
├── Cargo.toml                 # Workspace Cargo manifest
├── crates/
│   ├── netsentinel-proto/     # D-Bus IPC traits & shared data contracts
│   ├── netsentinel-core/      # Safety engine (PDDL, AI Gateway, Audit Ledger, Vuln scan, PQC)
│   ├── netsentinel-discover/  # L2 ARP discovery daemon (netsentinel-discoverd)
│   ├── netsentinel-capture/   # eBPF packet capture daemon (netsentinel-captured)
│   ├── netsentinel-capture-ebpf/ # Kernel eBPF bytecode source
│   ├── netsentinel-capture-common/ # Shared kernel/userspace eBPF types
│   ├── netsentinel-scan/      # Vulnerability scanner daemon (netsentinel-scand)
│   ├── netsentinel-intercept/ # Web proxy interceptor daemon (netsentinel-interceptd)
│   └── netsentinel-gtk/       # GTK4 / Libadwaita user interface (netsentinel)
├── data/                      # GSettings schemas, desktop files, PQC & CVE databases
├── docs/                      # Specification & 12 STRIDE threat model documents
├── packaging/                 # Flatpak manifest & Debian helper packaging (.deb, polkit, systemd)
└── scripts/                   # Development environment setup & version check scripts
```

## Prerequisites

- Ubuntu 24.04 LTS "Noble Numbat"
- Rust 1.75+ (Cargo 2021 edition)
- System Libraries: `libgtk-4-dev`, `libadwaita-1-dev`, `libdbus-1-dev`, `clang`, `bpftool`
- System Tools: `nmap`, `arp-scan`, `tshark`

## Development Setup

To initialize the development environment and install required build tools:

```bash
chmod +x scripts/setup_dev_env.sh
./scripts/setup_dev_env.sh
```

To run version and dependency checks:

```bash
chmod +x scripts/check_versions.sh
./scripts/check_versions.sh
```

## Building & Running the Tests

To check workspace compilation:

```bash
cargo check
```

To run all unit and integration tests across all crates:

```bash
cargo test
```

To build a release binary:

```bash
cargo build --release
```

## License

Restricted. Authorized testing purposes only. See Rules of Engagement.

