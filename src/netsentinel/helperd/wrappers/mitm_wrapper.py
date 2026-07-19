import logging
import os
import subprocess  # nosec B404
from pathlib import Path

HANDLER_PATH = Path(__file__).parent / "mitm_handler.py"


def start_mitm_proxy(port: int, disposable_key: bytes) -> subprocess.Popen[bytes]:
    """
    Spawns mitmdump proxy on the specified port with custom handlers.
    Sets disposable Fernet key in environment variables.
    """
    if not (1024 <= port <= 65535):
        raise ValueError(f"Port must be in the ephemeral/unprivileged range: {port}")

    # Build command list
    # Runs mitmdump silently, loading the inline handler script
    cmd = ["mitmdump", "-p", str(port), "-s", str(HANDLER_PATH.resolve()), "--quiet"]

    # Setup environment with disposable Fernet key
    env = os.environ.copy()
    env["NETSENTINEL_DISPOSABLE_KEY"] = disposable_key.decode("utf-8")

    try:
        logging.info("Starting mitmdump process on port %s", port)
        # safe Popen execution using list layout and shell=False (default)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)  # nosec B603
    except Exception as e:
        raise RuntimeError(f"Failed to start mitmdump: {e}") from e


def cleanup_ca_certificates() -> None:
    """
    Removes generated mitmproxy CA certificates from standard locations
    to prevent trust stores accumulation or vulnerability leaks (RE-04).
    """
    ca_paths = [
        Path("~/.mitmproxy/mitmproxy-ca.pem").expanduser(),
        Path("~/.mitmproxy/mitmproxy-ca-cert.pem").expanduser(),
        Path("~/.mitmproxy/mitmproxy-ca-cert.p12").expanduser(),
    ]
    for path in ca_paths:
        if path.exists():
            try:
                path.unlink()
                logging.info("Cleaned up CA cert file: %s", path)
            except Exception as e:
                logging.warning("Failed to delete CA cert file %s: %s", path, e)
