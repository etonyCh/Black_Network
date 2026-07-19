import re
from typing import Any

from netsentinel.utils.subprocess_safe import SubprocessExecutionError, safe_run

# Regular expression to match clean interface names
INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9\-]+$")


def run_arpscan(interface: str) -> list[dict[str, Any]]:
    """
    Executes arp-scan on the specified interface and parses the results.
    """
    if not INTERFACE_REGEX.match(interface):
        raise ValueError(f"Invalid interface name: {interface}")

    # Build command arguments
    # Requires cap_net_raw or running as netsentinel-helper system user
    cmd = ["arp-scan", "--interface", interface, "--localnet"]

    try:
        res = safe_run(cmd, timeout=15.0)
        return parse_arpscan_output(res.stdout)
    except SubprocessExecutionError as e:
        # If execution fails because binary is missing or lacks privileges
        raise RuntimeError(f"arp-scan execution failed: {e}") from e


def parse_arpscan_output(stdout: str) -> list[dict[str, Any]]:
    """
    Parses arp-scan text output into a list of structured dictionaries.
    Example line: "192.168.1.1\t00:11:22:33:44:55\tCisco Systems, Inc."
    """
    results = []
    lines = stdout.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Format is normally: IP \t MAC \t Vendor
        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip()
            vendor = parts[2].strip() if len(parts) > 2 else "Unknown"

            # Validate IP and MAC format to make sure we don't return garbage
            # IP: 4 octets or IPv6
            # MAC: 6 hex pairs
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip) and re.match(
                r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac
            ):
                results.append({"ip": ip, "mac": mac, "vendor": vendor})
    return results
