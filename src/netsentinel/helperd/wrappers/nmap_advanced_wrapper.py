import re
from typing import Any

from netsentinel.utils.network_validation import is_valid_cidr, is_valid_domain, is_valid_ip
from netsentinel.utils.subprocess_safe import SubprocessExecutionError, safe_run


def run_advanced_scan(target: str, mode: str = "balanced") -> dict[str, Any]:
    """
    Runs advanced scans (quick, balanced, deep/PQC) with timing limits.
    """
    if not (is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target)):
        raise ValueError(f"Target format is invalid: {target}")

    if mode not in ("quick", "balanced", "deep"):
        raise ValueError(f"Invalid scan mode: {mode}")

    # Build command based on mode
    if mode == "quick":
        # Fast port scan, rate-limited to prevent DoS
        cmd = ["nmap", "-F", "--max-rate", "300", "-T3", target]
    elif mode == "balanced":
        # Standard port scan, rate-limited
        cmd = ["nmap", "-p-", "--max-rate", "200", "-T3", target]
    else:  # deep
        # Deep cipher scans for PQC compatibility audit
        # Uses nmap built-in script scanners
        cmd = [
            "nmap",
            "-p",
            "22,443",
            "--script",
            "ssh2-enum-algos,ssl-enum-ciphers",
            "--max-rate",
            "100",
            "-T3",
            target,
        ]

    try:
        res = safe_run(cmd, timeout=60.0)
        return parse_advanced_nmap_output(res.stdout, mode)
    except SubprocessExecutionError as e:
        raise RuntimeError(f"Advanced nmap scan failed: {e}") from e


def parse_advanced_nmap_output(stdout: str, mode: str) -> dict[str, Any]:
    """
    Parses advanced scan output. Extracts ports and ciphers.
    """
    results: dict[str, Any] = {"ports": [], "ciphers": []}

    # Extract open ports, e.g. "22/tcp open  ssh"
    port_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+([\w\-]+)")

    # Extract ciphers from script outputs
    # Typically listed as: "   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    # or "       aes256-gcm@openssh.com"
    # or "|       aes256-gcm@openssh.com"
    cipher_re = re.compile(r"^[\|\s_]*([a-zA-Z0-9\-@_\.]+(?:_WITH_|-|@)[a-zA-Z0-9\-@_\.]+)")

    lines = stdout.splitlines()
    for line in lines:
        match_port = port_re.match(line.strip())
        if match_port:
            results["ports"].append(
                {
                    "port": int(match_port.group(1)),
                    "protocol": match_port.group(2),
                    "service": match_port.group(3),
                }
            )
            continue

        if mode == "deep":
            # Simple heuristic parsing to grab cipher lines in ssl/ssh scripts
            match_cipher = cipher_re.match(line)
            if match_cipher:
                cipher_name = match_cipher.group(1).strip()
                ignored_keywords = (
                    "ciphers",
                    "compressors",
                    "kex_algorithms",
                    "server_host_key_algorithms",
                    "encryption_algorithms",
                    "mac_algorithms",
                )
                if cipher_name not in ignored_keywords:
                    results["ciphers"].append(cipher_name)

    return results
