import re
from typing import Any

from netsentinel.utils.network_validation import is_valid_cidr, is_valid_domain, is_valid_ip
from netsentinel.utils.subprocess_safe import SubprocessExecutionError, safe_run


def run_nmap_ping_scan(target: str) -> list[dict[str, Any]]:
    """
    Executes a host discovery ping scan (nmap -sn) and returns discovered hosts.
    """
    # Strict validation of target to block shell arguments or bad formatting
    if not (is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target)):
        raise ValueError(f"Target format is invalid: {target}")

    cmd = ["nmap", "-sn", target]

    try:
        res = safe_run(cmd, timeout=30.0)
        return parse_nmap_ping_output(res.stdout)
    except SubprocessExecutionError as e:
        raise RuntimeError(f"nmap execution failed: {e}") from e


def parse_nmap_ping_output(stdout: str) -> list[dict[str, Any]]:
    """
    Parses nmap -sn stdout report.
    Returns list of hosts, e.g.: [{'ip': '192.168.1.1', 'hostname': 'router.local', 'status': 'up'}]
    """
    hosts = []
    lines = stdout.splitlines()

    current_host: dict[str, Any] = {}

    # Matches "Nmap scan report for router.local (192.168.1.1)"
    report_with_dns = re.compile(r"^Nmap scan report for ([\w\.-]+) \(([\d\.]+)\)")
    # Matches "Nmap scan report for 192.168.1.1"
    report_ip_only = re.compile(r"^Nmap scan report for ([\d\.]+)")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match_dns = report_with_dns.match(line)
        if match_dns:
            if current_host:
                hosts.append(current_host)
            current_host = {
                "hostname": match_dns.group(1),
                "ip": match_dns.group(2),
                "status": "down",  # default status until confirmed
            }
            continue

        match_ip = report_ip_only.match(line)
        if match_ip:
            if current_host:
                hosts.append(current_host)
            current_host = {"hostname": "Unknown", "ip": match_ip.group(1), "status": "down"}
            continue

        if "Host is up" in line and current_host:
            current_host["status"] = "up"

    if current_host:
        hosts.append(current_host)

    # Return only hosts that are up
    return [h for h in hosts if h.get("status") == "up"]
