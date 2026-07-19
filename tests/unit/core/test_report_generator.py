import json
import tempfile
from pathlib import Path

from netsentinel.core.audit.ledger import AuditLedger
from netsentinel.core.audit.report_generator import ReportGenerator


def test_report_generator_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "audit_ledger.db"
        ledger = AuditLedger(db_path)

        # Append fake audit entries
        ledger.append(
            "nmap_ping_scan",
            "SUCCESS",
            output_data=json.dumps(
                [{"ip": "10.0.0.1", "mac": "00:11:22:33:44:55", "vendor": "Vendor"}]
            ),
        )
        ledger.append(
            "packet_captured",
            "SUCCESS",
            output_data=json.dumps({"protocol": "TLS", "alert": "Suspicious TLS connection"}),
        )

        generator = ReportGenerator(db_path)

        report_path = Path(tmpdir) / "report.html"
        saved = generator.generate_report(
            report_path, include_hosts=True, include_scans=True, include_alerts=True
        )

        assert saved.exists()
        content = saved.read_text(encoding="utf-8")
        assert "10.0.0.1" in content
        assert "Suspicious TLS connection" in content

        # Check ledger has signature entry
        entries = ledger.export_ledger()
        report_log = [e for e in entries if e["action"] == "generate_report"]
        assert len(report_log) == 1
        meta = json.loads(report_log[0]["output_data"])
        assert "sha256" in meta
        assert meta["sha256"] == generator.hash_file(saved)
