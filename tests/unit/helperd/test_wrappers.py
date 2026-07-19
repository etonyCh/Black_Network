from unittest.mock import patch

import pytest

from netsentinel.helperd.wrappers.arpscan_wrapper import parse_arpscan_output, run_arpscan
from netsentinel.helperd.wrappers.nmap_wrapper import parse_nmap_ping_output, run_nmap_ping_scan

# Mock Outputs
ARPSCAN_OUTPUT = """
Interface: wlan0, type: EN10MB, address: 00:11:22:33:44:55
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1\t00:11:22:33:44:55\tCisco Systems, Inc.
192.168.1.100\t00:aa:bb:cc:dd:ee\tApple, Inc.
192.168.1.254\t11:22:33:44:55:66\tUnknown

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.453 seconds.
"""

NMAP_OUTPUT = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-07-18 20:00 UTC
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0021s latency).
Nmap scan report for 192.168.1.100
Host is up (0.0015s latency).
Nmap scan report for 192.168.1.105
Host is down.
Nmap done: 256 IP addresses (2 hosts up) scanned in 2.10 seconds
"""


def test_parse_arpscan_output():
    results = parse_arpscan_output(ARPSCAN_OUTPUT)
    assert len(results) == 3
    assert results[0] == {
        "ip": "192.168.1.1",
        "mac": "00:11:22:33:44:55",
        "vendor": "Cisco Systems, Inc.",
    }
    assert results[1] == {
        "ip": "192.168.1.100",
        "mac": "00:aa:bb:cc:dd:ee",
        "vendor": "Apple, Inc.",
    }
    assert results[2] == {
        "ip": "192.168.1.254",
        "mac": "11:22:33:44:55:66",
        "vendor": "Unknown",
    }


def test_parse_nmap_ping_output():
    results = parse_nmap_ping_output(NMAP_OUTPUT)
    assert len(results) == 2
    assert results[0] == {"hostname": "router.local", "ip": "192.168.1.1", "status": "up"}
    assert results[1] == {"hostname": "Unknown", "ip": "192.168.1.100", "status": "up"}


@patch("netsentinel.helperd.wrappers.arpscan_wrapper.safe_run")
def test_run_arpscan_success(mock_safe_run):
    from subprocess import CompletedProcess

    mock_safe_run.return_value = CompletedProcess(
        args=["arp-scan"], returncode=0, stdout=ARPSCAN_OUTPUT, stderr=""
    )

    hosts = run_arpscan("wlan0")
    assert len(hosts) == 3
    mock_safe_run.assert_called_once_with(
        ["arp-scan", "--interface", "wlan0", "--localnet"], timeout=15.0
    )


def test_run_arpscan_invalid_interface():
    with pytest.raises(ValueError, match="Invalid interface name"):
        run_arpscan("wlan0; rm -rf /")


@patch("netsentinel.helperd.wrappers.nmap_wrapper.safe_run")
def test_run_nmap_success(mock_safe_run):
    from subprocess import CompletedProcess

    mock_safe_run.return_value = CompletedProcess(
        args=["nmap"], returncode=0, stdout=NMAP_OUTPUT, stderr=""
    )

    hosts = run_nmap_ping_scan("192.168.1.0/24")
    assert len(hosts) == 2
    mock_safe_run.assert_called_once_with(["nmap", "-sn", "192.168.1.0/24"], timeout=30.0)


def test_run_nmap_invalid_target():
    with pytest.raises(ValueError, match="Target format is invalid"):
        run_nmap_ping_scan("192.168.1.1; malformed")
