#!/usr/bin/env python3
import sys
import re
import subprocess
import shutil

# Check python version
required_py = (3, 12)
if sys.version_info < required_py:
    print(f"[-] Python version {sys.version} is below required {required_py}")
    sys.exit(1)
print(f"[+] Python version {sys.version_info.major}.{sys.version_info.minor} is OK")

def parse_version(v_str):
    # Remove epoch prefix if present (e.g., '1:1.10.0' -> '1.10.0')
    if ':' in v_str:
        v_str = v_str.split(':', 1)[1]
    # Extract the leading numeric/dot portion of the version
    match = re.search(r'(\d+(?:\.\d+)+)', v_str)
    if match:
        return tuple(int(x) for x in match.group(1).split('.'))
    # Try single integer version
    match_single = re.search(r'(\d+)', v_str)
    if match_single:
        return (int(match_single.group(1)),)
    return (0,)

def compare_versions(v1, v2):
    # Pad tuples with 0 to make them equal length
    max_len = max(len(v1), len(v2))
    v1_padded = v1 + (0,) * (max_len - len(v1))
    v2_padded = v2 + (0,) * (max_len - len(v2))
    return (v1_padded >= v2_padded)

def check_apt(package, min_version):
    if not shutil.which("apt-cache"):
        print(f"[*] apt-cache not found. Skipping apt version check for {package}")
        return True
    try:
        out = subprocess.check_output(["apt-cache", "policy", package], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Installed:" in line:
                version_str = line.split("Installed:")[1].strip()
                if not version_str or version_str == "(none)":
                    print(f"[-] {package} is not installed (apt-cache policy reports none)")
                    return False
                v_inst = parse_version(version_str)
                v_min = parse_version(min_version)
                if not compare_versions(v_inst, v_min):
                    print(f"[-] {package} version {version_str} is below required {min_version}")
                    return False
                print(f"[+] {package} version {version_str} is OK (required >= {min_version})")
                return True
        print(f"[-] Could not find installed status for {package} in apt-cache policy")
        return False
    except Exception as e:
        print(f"[-] Error querying apt-cache policy for {package}: {e}")
        return False

def check_pip(package, min_version):
    # Check if installed locally first (most reliable)
    try:
        import importlib.metadata
        version_str = importlib.metadata.version(package)
        v_inst = parse_version(version_str)
        v_min = parse_version(min_version)
        if not compare_versions(v_inst, v_min):
            print(f"[-] Python package {package} version {version_str} is below required {min_version}")
            return False
        print(f"[+] Python package {package} version {version_str} is OK (required >= {min_version})")
        return True
    except importlib.metadata.PackageNotFoundError:
        # Try checking pip index versions
        if shutil.which("pip"):
            try:
                # Run pip index versions to query PyPI
                out = subprocess.check_output(["pip", "index", "versions", package], text=True, stderr=subprocess.DEVNULL)
                # Parse available versions, format is typically "LATEST: ...\nINSTALLED: ...\n" or similar
                # Let's see if we can find INSTALLED: version in pip index output
                installed_line = [line for line in out.splitlines() if "Installed:" in line]
                if installed_line:
                    version_str = installed_line[0].split("Installed:")[1].strip()
                    if version_str and version_str != "none":
                        v_inst = parse_version(version_str)
                        v_min = parse_version(min_version)
                        if not compare_versions(v_inst, v_min):
                            print(f"[-] Python package {package} version {version_str} is below required {min_version}")
                            return False
                        print(f"[+] Python package {package} version {version_str} is OK (required >= {min_version})")
                        return True
            except Exception:
                pass
        print(f"[-] Python package {package} is not installed")
        return False

# Requirements list (Package Name, Minimum Version)
apt_requirements = [
    ("libgtk-4-1", "4.14"),
    ("libadwaita-1-0", "1.5"),
    ("python3-gi", "3.48"),
    ("blueprint-compiler", "0.14"),
    ("nmap", "7.94"),
    ("tshark", "4.2.2"),
    ("arp-scan", "1.10"),
]

pip_requirements = [
    ("dbus-next", "0.2.3"),
    ("pydantic", "2.7.0"),
    ("mitmproxy", "10.0.0"),  # based on spec's mitmproxy >= 12.x or 10.x requirement
]

failed = False

print("=== Checking System Packages (APT) ===")
for pkg, ver in apt_requirements:
    if not check_apt(pkg, ver):
        failed = True

print("\n=== Checking Python Packages (PIP) ===")
for pkg, ver in pip_requirements:
    if not check_pip(pkg, ver):
        # We don't fail CI if mitmproxy or pip requirements are missing locally before env setup is run,
        # but let's record it.
        if pkg != "mitmproxy":  # mitmproxy is installed via pipx/venv, check could be warnings
            failed = True

if failed:
    print("\n[-] Version checks FAILED. Some dependencies do not meet the minimum requirements.")
    sys.exit(1)
else:
    print("\n[+] All version checks PASSED successfully.")
    sys.exit(0)
