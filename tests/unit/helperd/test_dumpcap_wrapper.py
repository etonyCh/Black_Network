from unittest.mock import patch

import pytest

from netsentinel.helperd.wrappers.dumpcap_wrapper import (
    BpfValidator,
    start_dumpcap_capture,
)


def test_bpf_validator():
    # Valid filters
    assert BpfValidator.validate("") is True
    assert BpfValidator.validate("tcp port 80") is True
    assert BpfValidator.validate("udp port 53") is True
    assert BpfValidator.validate("host 10.0.0.1 and tcp") is True
    assert BpfValidator.validate("not arp and not icmp") is True

    # Invalid filters (injection checks)
    assert BpfValidator.validate("tcp port 80; rm -rf /") is False
    assert BpfValidator.validate("tcp port 80 | cat /etc/passwd") is False
    assert BpfValidator.validate("tcp port 80 & sh") is False
    assert BpfValidator.validate("port $(uname)") is False


@patch("subprocess.Popen")
def test_start_dumpcap_success(mock_popen):
    mock_popen.return_value = "mock_process"

    proc = start_dumpcap_capture("wlan0", "tcp port 443")
    assert proc == "mock_process"
    mock_popen.assert_called_once_with(
        ["dumpcap", "-i", "wlan0", "-w", "-", "-f", "tcp port 443"],
        stdout=-1,
        stderr=-1,
    )


def test_start_dumpcap_invalid_inputs():
    with pytest.raises(ValueError, match="Invalid interface name"):
        start_dumpcap_capture("wlan0; rm", "tcp")

    with pytest.raises(ValueError, match="Invalid or unsafe BPF filter"):
        start_dumpcap_capture("wlan0", "tcp; cat")
