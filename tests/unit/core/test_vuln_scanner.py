from pathlib import Path
from unittest.mock import MagicMock, patch

from netsentinel.core.audit.vuln_scanner import VulnScanner

TEST_DB_PATH = Path(__file__).parent.parent.parent.parent / "data" / "vuln_database.json"


def test_vuln_scanner_matching():
    scanner = VulnScanner(TEST_DB_PATH)
    assert len(scanner.profiles) > 0

    # 1. Test vulnerable banner matching OpenSSH regreSSHion
    banner_ssh = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    findings_ssh = scanner.audit_banner(banner_ssh)
    assert len(findings_ssh) == 1
    assert findings_ssh[0]["cve"] == "CVE-2024-6387"
    assert findings_ssh[0]["severity"] == "CRITICAL"

    # 2. Test vulnerable banner matching Apache path traversal
    banner_apache = "Apache/2.4.49 (Unix) OpenSSL/1.1.1d"
    findings_apache = scanner.audit_banner(banner_apache)
    assert len(findings_apache) == 1
    assert findings_apache[0]["cve"] == "CVE-2021-41773"

    # 3. Test non-vulnerable banner
    banner_safe = "SSH-2.0-OpenSSH_9.8p1"
    findings_safe = scanner.audit_banner(banner_safe)
    assert len(findings_safe) == 0


@patch("netsentinel.core.audit.vuln_scanner.socket.create_connection")
def test_banner_grabbing(mock_conn):
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1\n"
    mock_conn.return_value.__enter__.return_value = mock_sock

    scanner = VulnScanner(TEST_DB_PATH)
    banner = scanner.grab_banner("127.0.0.1", 22)
    assert banner == "SSH-2.0-OpenSSH_8.2p1"


@patch("netsentinel.core.audit.vuln_scanner.socket.create_connection")
def test_banner_grabbing_empty_recv(mock_conn):
    mock_sock = MagicMock()
    # First recv returns empty bytes, second recv returns banner
    mock_sock.recv.side_effect = [b"", b"HTTP/1.1 200 OK"]
    mock_conn.return_value.__enter__.return_value = mock_sock

    scanner = VulnScanner(TEST_DB_PATH)
    banner = scanner.grab_banner("127.0.0.1", 80)
    assert banner == "HTTP/1.1 200 OK"
    mock_sock.sendall.assert_called_once_with(b"HEAD / HTTP/1.0\r\n\r\n")


@patch("netsentinel.core.audit.vuln_scanner.socket.create_connection")
def test_banner_grabbing_timeout(mock_conn):
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = TimeoutError("timeout")
    mock_conn.return_value.__enter__.return_value = mock_sock

    scanner = VulnScanner(TEST_DB_PATH)
    banner = scanner.grab_banner("127.0.0.1", 22)
    assert banner == ""


@patch("netsentinel.core.audit.vuln_scanner.socket.create_connection")
def test_banner_grabbing_connection_error(mock_conn):
    mock_conn.side_effect = ConnectionRefusedError("refused")

    scanner = VulnScanner(TEST_DB_PATH)
    banner = scanner.grab_banner("127.0.0.1", 22)
    assert banner == ""
