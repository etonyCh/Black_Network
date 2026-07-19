import logging
import re
import subprocess  # nosec B404

# Interface validation regex
INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9\-]+$")

# Strict BPF validation: only allows alphanumeric, spaces, and specific networking keywords.
# Rejects special characters like semicolons, backticks, quotes, braces, redirection operators, etc.
BPF_SAFE_REGEX = re.compile(r"^[a-zA-Z0-9\s\.\-\/]+$")
BPF_KEYWORDS = {
    "tcp",
    "udp",
    "port",
    "host",
    "src",
    "dst",
    "and",
    "or",
    "not",
    "ip",
    "arp",
    "icmp",
    "ether",
    "net",
    "mask",
    "portrange",
    "less",
    "greater",
    "gateway",
}


class BpfValidator:
    @staticmethod
    def validate(bpf_filter: str) -> bool:
        """
        Validates if a BPF filter string is completely safe.
        """
        if not bpf_filter:
            return True  # Empty filter is safe

        if not BPF_SAFE_REGEX.match(bpf_filter):
            return False

        # Verify all alphanumeric terms in the BPF filter are standard words or numbers
        words = re.findall(r"\b[a-zA-Z]+\b", bpf_filter.lower())
        for word in words:
            if word not in BPF_KEYWORDS:
                logging.warning("BPF keyword validation failed for word: %s", word)
                return False

        return True


def start_dumpcap_capture(interface: str, bpf_filter: str = "") -> subprocess.Popen[bytes]:
    """
    Spawns dumpcap capture process on interface with BPF filter.
    Returns the Popen process handle.
    """
    if not INTERFACE_REGEX.match(interface):
        raise ValueError(f"Invalid interface name: {interface}")

    if not BpfValidator.validate(bpf_filter):
        raise ValueError(f"Invalid or unsafe BPF filter: {bpf_filter}")

    # Build command list (dumpcap writing raw pcap bytes to stdout)
    cmd = ["dumpcap", "-i", interface, "-w", "-"]
    if bpf_filter:
        cmd.extend(["-f", bpf_filter])

    try:
        logging.info("Starting dumpcap process: %s", " ".join(cmd))
        # safe Popen execution using list layout and shell=False (default)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec B603
    except Exception as e:
        raise RuntimeError(f"Failed to start dumpcap: {e}") from e
