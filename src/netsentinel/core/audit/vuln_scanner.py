import json
import logging
import re
import socket
from pathlib import Path
from typing import Any

DEFAULT_VULN_DB_PATH = (
    Path(__file__).parent.parent.parent.parent.parent / "data" / "vuln_database.json"
)
SYSTEM_VULN_DB_PATH = Path("/usr/share/netsentinel/data/vuln_database.json")


class VulnScanner:
    def __init__(self, db_path: Path | str | None = None):
        if db_path:
            self.db_path = Path(db_path)
        elif DEFAULT_VULN_DB_PATH.exists():
            self.db_path = DEFAULT_VULN_DB_PATH
        else:
            self.db_path = SYSTEM_VULN_DB_PATH

        self.profiles = []  # type: list[dict[str, Any]]
        self._load_database()

    def _load_database(self) -> None:
        if not self.db_path.exists():
            logging.warning("Vulnerability database not found at: %s", self.db_path)
            return

        try:
            with self.db_path.open() as f:
                data = json.load(f)
                self.profiles = data.get("profiles", [])
        except Exception as e:
            logging.error("Failed to load vulnerability database: %s", e)

    def grab_banner(self, target: str, port: int, timeout: float = 3.0) -> str:
        """
        Connects to target port and reads the service banner.
        """
        try:
            # Standard tcp socket banner grabbing
            with socket.create_connection((target, port), timeout=timeout) as sock:
                # Send a newline for protocols that wait for client prompt
                # (e.g. HTTP, SMTP) but read directly for protocols that speak first
                # (e.g. SSH, FTP)
                sock.settimeout(timeout)
                try:
                    # Peek or read first bytes
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if not banner:
                        # Try writing to force response
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    return banner
                except TimeoutError:
                    return ""
        except Exception as e:
            logging.debug("Banner grab failed on %s:%s: %s", target, port, e)
            return ""

    def audit_banner(self, banner: str) -> list[dict[str, Any]]:
        """
        Cross-checks banner string against known outdated version profiles.
        """
        findings: list[dict[str, Any]] = []
        if not banner:
            return findings

        for profile in self.profiles:
            regex_str = profile.get("regex", "")
            if not regex_str:
                continue

            try:
                # Check for substring match in banner line
                if re.search(regex_str, banner):
                    findings.append(
                        {
                            "service": profile.get("service"),
                            "cve": profile.get("cve"),
                            "summary": profile.get("summary"),
                            "severity": profile.get("severity"),
                        }
                    )
            except Exception as e:
                logging.error("Error matching regex %s: %s", regex_str, e)

        return findings
