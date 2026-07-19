from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from netsentinel.helperd.wrappers.nmap_advanced_wrapper import (
    parse_advanced_nmap_output,
    run_advanced_scan,
)

ADVANCED_NMAP_OUTPUT_DEEP = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-07-18 20:10 UTC
Nmap scan report for 192.168.1.5
Host is up (0.0010s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (6)
|       sntrup761x25519-sha512@openssh.com
|       curve25519-sha256@libssh.org
|   encryption_algorithms: (2)
|_      aes256-gcm@openssh.com
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.3:
|     ciphers:
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|_      TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A

Nmap done: 1 IP address (1 host up) scanned in 5.30 seconds
"""


def test_parse_advanced_nmap_output_deep():
    results = parse_advanced_nmap_output(ADVANCED_NMAP_OUTPUT_DEEP, mode="deep")

    # Verify ports
    assert len(results["ports"]) == 2
    assert results["ports"][0] == {"port": 22, "protocol": "tcp", "service": "ssh"}
    assert results["ports"][1] == {"port": 443, "protocol": "tcp", "service": "https"}

    # Verify ciphers extracted
    ciphers = results["ciphers"]
    assert "sntrup761x25519-sha512@openssh.com" in ciphers
    assert "curve25519-sha256@libssh.org" in ciphers
    assert "aes256-gcm@openssh.com" in ciphers


@patch("netsentinel.helperd.wrappers.nmap_advanced_wrapper.safe_run")
def test_run_advanced_scan_quick(mock_safe_run):
    mock_safe_run.return_value = CompletedProcess(
        args=["nmap"], returncode=0, stdout="PORT STATE\n80/tcp open http", stderr=""
    )

    results = run_advanced_scan("10.0.0.1", mode="quick")
    assert results["ports"] == [{"port": 80, "protocol": "tcp", "service": "http"}]
    mock_safe_run.assert_called_once_with(
        ["nmap", "-F", "--max-rate", "300", "-T3", "10.0.0.1"], timeout=60.0
    )


@patch("netsentinel.helperd.wrappers.nmap_advanced_wrapper.safe_run")
def test_run_advanced_scan_balanced(mock_safe_run):
    mock_safe_run.return_value = CompletedProcess(args=["nmap"], returncode=0, stdout="", stderr="")

    run_advanced_scan("10.0.0.1", mode="balanced")
    mock_safe_run.assert_called_once_with(
        ["nmap", "-p-", "--max-rate", "200", "-T3", "10.0.0.1"], timeout=60.0
    )


@patch("netsentinel.helperd.wrappers.nmap_advanced_wrapper.safe_run")
def test_run_advanced_scan_deep(mock_safe_run):
    mock_safe_run.return_value = CompletedProcess(args=["nmap"], returncode=0, stdout="", stderr="")

    run_advanced_scan("10.0.0.1", mode="deep")
    mock_safe_run.assert_called_once_with(
        [
            "nmap",
            "-p",
            "22,443",
            "--script",
            "ssh2-enum-algos,ssl-enum-ciphers",
            "--max-rate",
            "100",
            "-T3",
            "10.0.0.1",
        ],
        timeout=60.0,
    )


def test_run_advanced_scan_invalid_inputs():
    # Bad target
    with pytest.raises(ValueError, match="Target format is invalid"):
        run_advanced_scan("10.0.0.1; rm -rf /")

    # Bad mode
    with pytest.raises(ValueError, match="Invalid scan mode"):
        run_advanced_scan("10.0.0.1", mode="aggressive")
