import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from netsentinel.core.audit.ledger import AuditLedger

# Try importing Gio for GSettings consent checks
try:
    from gi.repository import Gio
except ImportError:
    Gio = None


class ReportGenerator:
    def __init__(self, db_path: Path | str | None = None):
        if db_path:
            self.ledger = AuditLedger(db_path)
        else:
            self.ledger = AuditLedger()

    def _check_consent(self, consent_key: str) -> bool:
        """
        Reads user settings from GSettings. Defaults to True if GSettings is unavailable.
        """
        if Gio is None:
            return True
        try:
            settings = Gio.Settings.new("org.netsentinel.NetSentinel")
            return bool(settings.get_boolean(consent_key))
        except Exception:
            return True

    def generate_report(
        self,
        output_path: Path | str,
        include_hosts: bool,
        include_scans: bool,
        include_alerts: bool,
    ) -> Path:
        """
        Consolidates audit log details into a styled HTML file.
        Anchors the report signature inside the ledger (RE-03).
        """
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        # Retrieve GSettings consent overrides
        consent_hosts = self._check_consent("store-hosts")
        consent_history = self._check_consent("store-history")

        # Exclude options if user did not consent
        allow_hosts = include_hosts and consent_hosts
        allow_scans = include_scans and consent_history
        allow_alerts = include_alerts and consent_history

        # Fetch ledger logs
        entries = self.ledger.export_ledger()

        hosts = []  # type: list[dict[str, Any]]
        scans = []  # type: list[dict[str, Any]]
        alerts = []  # type: list[dict[str, Any]]

        for entry in entries:
            action = entry.get("action", "")
            out_data = entry.get("output_data", "")
            in_data = entry.get("input_data", "")

            # 1. Parse Discovered Hosts
            if allow_hosts and action in ("arp_scan", "nmap_ping_scan"):
                try:
                    hosts_list = json.loads(out_data)
                    if isinstance(hosts_list, list):
                        for h in hosts_list:
                            if h not in hosts:
                                hosts.append(h)
                except Exception:  # noqa: S110 # nosec B110
                    pass

            # 2. Parse Active Vulnerability Scans
            if allow_scans and action in ("advanced_nmap_scan", "run_vuln_scan"):
                try:
                    res_obj = json.loads(out_data)
                    scans.append(
                        {
                            "timestamp": entry.get("timestamp"),
                            "action": action,
                            "input": in_data,
                            "output": res_obj,
                        }
                    )
                except Exception:  # noqa: S110 # nosec B110
                    pass

            # 3. Parse Alerts & Intercepts
            if allow_alerts and action in (
                "packet_captured",
                "request_intercepted",
                "consent_dialog",
            ):
                try:
                    alert_obj = json.loads(out_data)
                    alerts.append(
                        {"timestamp": entry.get("timestamp"), "type": action, "details": alert_obj}
                    )
                except Exception:  # noqa: S110 # nosec B110
                    pass

        # Build beautiful HTML report content
        html_content = self._build_html_template(hosts, scans, alerts)

        # Save file
        with out_file.open("w", encoding="utf-8") as f:
            f.write(html_content)

        # Compute SHA-256 signature
        report_hash = self.hash_file(out_file)

        # Log signature into cryptographic ledger chain (RE-03)
        self.ledger.append(
            action="generate_report",
            pddl_status="SUCCESS",
            input_data=f"HTML report output_path={out_file.name}",
            output_data=json.dumps({"sha256": report_hash}),
        )

        logging.info("Report compiled and anchored in ledger: %s", report_hash)
        return out_file

    def hash_file(self, filepath: Path) -> str:
        """
        Computes SHA-256 hash of a file.
        """
        hasher = hashlib.sha256()
        with filepath.open("rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _build_html_template(
        self,
        hosts: list[dict[str, Any]],
        scans: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
    ) -> str:
        """
        Renders clean modern HTML code dashboard.
        """
        hosts_rows = ""
        for h in hosts:
            ip = h.get("ip", "?")
            mac = h.get("mac", "?")
            vendor = h.get("vendor", "")
            hosts_rows += f"<tr><td>{ip}</td><td>{mac}</td><td>{vendor}</td></tr>"

        scans_rows = ""
        for s in scans:
            ts = s.get("timestamp")
            act = s.get("action")
            out_str = json.dumps(s.get("output"), indent=2)
            scans_rows += f"<tr><td>{ts}</td><td>{act}</td><td><pre>{out_str}</pre></td></tr>"

        alerts_rows = ""
        for a in alerts:
            ts = a.get("timestamp")
            atype = a.get("type")
            det_str = json.dumps(a.get("details"), indent=2)
            alerts_rows += f"<tr><td>{ts}</td><td>{atype}</td><td><pre>{det_str}</pre></td></tr>"

        # Separate css styles to keep lines short
        body_css = (
            "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; "
            "background-color: #f6f8fa; color: #24292e; margin: 0; padding: 20px;"
        )
        container_css = (
            "max-width: 1000px; margin: 0 auto; background: white; padding: 30px; "
            "border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08);"
        )
        table_css = "width: 100%; border-collapse: collapse; margin-top: 10px;"
        pre_css = (
            "background: #f6f8fa; padding: 10px; border-radius: 4px; "
            "overflow-x: auto; font-size: 13px;"
        )
        footer_css = (
            "margin-top: 50px; text-align: center; font-size: 12px; color: #586069; "
            "border-top: 1px solid #eaecef; padding-top: 20px;"
        )

        h_empty = "<tr><td colspan='3'>No host records found/permitted.</td></tr>"
        s_empty = "<tr><td colspan='3'>No scan records found/permitted.</td></tr>"
        a_empty = "<tr><td colspan='3'>No alerts logged/permitted.</td></tr>"

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>NetSentinel Audit Report</title>
    <style>
        body {{ {body_css} }}
        .container {{ {container_css} }}
        h1 {{ color: #1a73e8; border-bottom: 2px solid #eaecef; padding-bottom: 10px; }}
        h2 {{ color: #24292e; margin-top: 30px; }}
        table {{ {table_css} }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eaecef; }}
        th {{ background-color: #f1f3f4; }}
        pre {{ {pre_css} }}
        .footer {{ {footer_css} }}
    </style>
</head>
<body>
    <div class="container">
        <h1>NetSentinel Consolidated Security Audit Report</h1>
        <p>This report is cryptographically signed in the audit ledger database.</p>

        <h2>Discovered Network Devices</h2>
        <table>
            <thead>
                <tr><th>IP Address</th><th>MAC Address</th><th>Vendor / Interface</th></tr>
            </thead>
            <tbody>
                {hosts_rows if hosts_rows else h_empty}
            </tbody>
        </table>

        <h2>Active Security Vulnerability Audits</h2>
        <table>
            <thead>
                <tr><th>Timestamp</th><th>Action Type</th><th>Scan Findings</th></tr>
            </thead>
            <tbody>
                {scans_rows if scans_rows else s_empty}
            </tbody>
        </table>

        <h2>Security Alert History</h2>
        <table>
            <thead>
                <tr><th>Timestamp</th><th>Event Type</th><th>Details</th></tr>
            </thead>
            <tbody>
                {alerts_rows if alerts_rows else a_empty}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by NetSentinel. Ledger Integrity Secured via SHA-256 chaining.</p>
        </div>
    </div>
</body>
</html>
"""
