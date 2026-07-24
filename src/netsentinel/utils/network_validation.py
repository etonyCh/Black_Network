import ipaddress
import re
import socket

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,6}$"
)

HOSTNAME_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def is_valid_ip(ip_str: str) -> bool:
    """
    Validates if a string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_str: str) -> bool:
    """
    Validates if a string is a valid CIDR network (e.g. 192.168.1.0/24).
    """
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(domain_str: str) -> bool:
    """
    Validates if a string is a valid domain name or hostname.
    """
    return bool(DOMAIN_REGEX.match(domain_str) or HOSTNAME_REGEX.match(domain_str))


def resolve_domain(domain_str: str) -> list[str]:
    """
    Resolves a domain name to a list of IP addresses. Returns empty list on failure.
    """
    try:
        # Resolve to IPv4/IPv6 addresses
        addr_info = socket.getaddrinfo(domain_str, None)
        ips = {str(info[4][0]) for info in addr_info}
        return list(ips)
    except socket.gaierror:
        return []


def is_in_scope(target: str, scope_list: list[str]) -> bool:
    """
    Checks if a target (IP or Domain) is within the allowed scope list.
    Scope list elements can be IPs, CIDRs, or Domains.
    If scope_list is empty, defaults to allowing private RFC1918 network ranges.
    """
    if not scope_list:
        scope_list = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1/32"]

    # 1. Normalize target: check if it's IP or Domain
    target_is_ip = is_valid_ip(target)
    target_ips = [target] if target_is_ip else resolve_domain(target)

    for scope_item in scope_list:
        scope_item = scope_item.strip()
        if not scope_item:
            continue

        # Case A: Scope item is CIDR or IP
        if is_valid_cidr(scope_item) or is_valid_ip(scope_item):
            try:
                scope_net = ipaddress.ip_network(scope_item, strict=False)
                # If target is domain, check if any of its resolved IPs is in network
                if not target_is_ip:
                    for tip in target_ips:
                        if ipaddress.ip_address(tip) in scope_net:
                            return True
                else:
                    if ipaddress.ip_address(target) in scope_net:
                        return True
            except ValueError:
                pass

        # Case B: Scope item is domain
        else:
            # Check domain name exact match or subdomain match
            # e.g., if scope is "example.com", target "sub.example.com" or "example.com" is in scope
            if not target_is_ip:
                if target == scope_item or target.endswith("." + scope_item):
                    return True
            else:
                # Target is IP, check if any scope domain resolves to this IP
                # (less common but possible)
                resolved_scope_ips = resolve_domain(scope_item)
                if target in resolved_scope_ips:
                    return True

    return False
