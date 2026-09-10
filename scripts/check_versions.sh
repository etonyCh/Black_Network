#!/usr/bin/env python3
import sys
import re
import subprocess
import shutil

print("=== NetSentinel Version & Dependency Checker ===")

def parse_version(v_str):
    first_line = v_str.splitlines()[0] if v_str else ""
    if "Installed:" in first_line:
        first_line = first_line.split("Installed:", 1)[1]
    match = re.search(r'(\d+(?:\.\d+)+)', first_line)
    if match:
        return tuple(int(x) for x in match.group(1).split('.'))
    match_single = re.search(r'(\d+)', first_line)
    if match_single:
        return (int(match_single.group(1)),)
    return (0,)

def compare_versions(v1, v2):
    max_len = max(len(v1), len(v2))
    v1_padded = v1 + (0,) * (max_len - len(v1))
    v2_padded = v2 + (0,) * (max_len - len(v2))
    return (v1_padded >= v2_padded)

def check_cmd_version(cmd, flag, min_version, optional=False):
    if not shutil.which(cmd):
        if optional:
            print(f"[*] Optional command '{cmd}' not found in PATH")
            return True
        else:
            print(f"[-] Command '{cmd}' not found in PATH")
            return False
    try:
        out = subprocess.check_output([cmd, flag], text=True, stderr=subprocess.STDOUT)
        v_inst = parse_version(out)
        v_min = parse_version(min_version)
        if not compare_versions(v_inst, v_min):
            print(f"[-] {cmd} version {v_inst} is below required {min_version}")
            return False
        print(f"[+] {cmd} is installed and valid ({out.splitlines()[0]})")
        return True
    except Exception as e:
        print(f"[-] Error executing '{cmd} {flag}': {e}")
        return False

def check_apt(package, min_version):
    if not shutil.which("apt-cache"):
        print(f"[*] apt-cache not found. Skipping apt check for {package}")
        return True
    try:
        out = subprocess.check_output(["apt-cache", "policy", package], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Installed:" in line:
                version_str = line.split("Installed:")[1].strip()
                if not version_str or version_str == "(none)":
                    print(f"[-] APT package '{package}' is not installed")
                    return False
                v_inst = parse_version(version_str)
                v_min = parse_version(min_version)
                if not compare_versions(v_inst, v_min):
                    print(f"[-] {package} version {version_str} is below required {min_version}")
                    return False
                print(f"[+] APT package '{package}' ({version_str}) is OK")
                return True
        print(f"[-] Could not determine status for {package}")
        return False
    except Exception as e:
        print(f"[-] Error querying apt-cache policy for {package}: {e}")
        return False

failed = False

print("\n--- Checking Rust Toolchain ---")
if not check_cmd_version("rustc", "--version", "1.75.0"):
    failed = True
if not check_cmd_version("cargo", "--version", "1.75.0"):
    failed = True

print("\n--- Checking System Tools & Security Utilities ---")
tool_checks = [
    ("nmap", "--version", "7.94", False),
    ("tshark", "--version", "4.2.2", False),
    ("arp-scan", "--version", "1.10", False),
    ("clang", "--version", "14.0", True),
]

for cmd, flag, min_ver, opt in tool_checks:
    if not check_cmd_version(cmd, flag, min_ver, opt):
        failed = True

print("\n--- Checking System Libraries (APT) ---")
apt_requirements = [
    ("libgtk-4-1", "4.14"),
    ("libadwaita-1-0", "1.5"),
]

for pkg, ver in apt_requirements:
    if not check_apt(pkg, ver):
        failed = True

if failed:
    print("\n[-] Version checks FAILED. Some dependencies do not meet the minimum requirements.")
    sys.exit(1)
else:
    print("\n[+] All version & toolchain checks PASSED successfully.")
    sys.exit(0)
