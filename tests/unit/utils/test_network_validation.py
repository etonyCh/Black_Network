from unittest.mock import patch

from netsentinel.utils.network_validation import (
    is_in_scope,
    is_valid_cidr,
    is_valid_domain,
    is_valid_ip,
    resolve_domain,
)


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("256.256.256.256") is False
    assert is_valid_ip("abc") is False


def test_is_valid_cidr():
    assert is_valid_cidr("192.168.1.0/24") is True
    assert is_valid_cidr("2001:db8::/32") is True
    assert is_valid_cidr("192.168.1.1") is True  # single IP is parsed as /32 CIDR
    assert is_valid_cidr("192.168.1.0/33") is False
    assert is_valid_cidr("abc") is False


def test_is_valid_domain():
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.example.co.uk") is True
    assert is_valid_domain("localhost") is True
    assert is_valid_domain("my-host-123") is True
    assert is_valid_domain("invalid_domain") is False


@patch("netsentinel.utils.network_validation.socket.getaddrinfo")
def test_resolve_domain(mock_getaddrinfo):
    mock_getaddrinfo.return_value = [
        (None, None, None, None, ("192.168.1.10", 0)),
        (None, None, None, None, ("2001:db8::10", 0)),
    ]
    ips = resolve_domain("example.local")
    assert "192.168.1.10" in ips
    assert "2001:db8::10" in ips


def test_is_in_scope_ip():
    scope = ["192.168.1.0/24", "10.0.0.5"]
    assert is_in_scope("192.168.1.5", scope) is True
    assert is_in_scope("192.168.2.5", scope) is False
    assert is_in_scope("10.0.0.5", scope) is True
    assert is_in_scope("10.0.0.6", scope) is False


@patch("netsentinel.utils.network_validation.resolve_domain")
def test_is_in_scope_domain(mock_resolve):
    # If target is domain "test.example.com", mock resolution to 192.168.1.20
    mock_resolve.return_value = ["192.168.1.20"]

    # Scope by CIDR
    assert is_in_scope("test.example.com", ["192.168.1.0/24"]) is True
    assert is_in_scope("test.example.com", ["10.0.0.0/8"]) is False

    # Scope by domain name
    assert is_in_scope("test.example.com", ["example.com"]) is True
    assert is_in_scope("test.example.com", ["other.com"]) is False
