import sqlite3
import tempfile
from pathlib import Path

import pytest

from netsentinel.core.audit.ledger import AuditLedger


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp()
    yield path
    import os

    os.close(fd)
    p = Path(path)
    if p.exists():
        p.unlink()


def test_ledger_initialization(temp_db):
    ledger = AuditLedger(temp_db)
    assert Path(temp_db).exists()
    assert ledger.db_path == Path(temp_db)

    # Check table existence
    with sqlite3.connect(temp_db) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        )
        assert cursor.fetchone() is not None


def test_ledger_append_and_verify(temp_db):
    ledger = AuditLedger(temp_db)

    # Empty ledger should verify successfully
    is_valid, corrupt_id = ledger.verify_integrity()
    assert is_valid is True
    assert corrupt_id is None

    # Append first entry
    h1 = ledger.append(
        action="nmap -sn 192.168.1.0/24",
        pddl_status="VALIDATED",
        agent_id="L1_triage",
        model_version="gemini-1.5-pro",
        input_data="192.168.1.0/24",
        output_data="host up",
    )

    # Verify first entry
    is_valid, corrupt_id = ledger.verify_integrity()
    assert is_valid is True
    assert corrupt_id is None

    # Append second entry
    h2 = ledger.append(action="arp-scan --localnet", pddl_status="VALIDATED", agent_id="human")

    # Verify second entry
    is_valid, corrupt_id = ledger.verify_integrity()
    assert is_valid is True
    assert corrupt_id is None
    assert h1 != h2


def test_ledger_corruption_detection(temp_db):
    ledger = AuditLedger(temp_db)

    ledger.append(action="action 1", pddl_status="VALIDATED")
    ledger.append(action="action 2", pddl_status="VALIDATED")

    is_valid, corrupt_id = ledger.verify_integrity()
    assert is_valid is True

    # Manually tamper with DB
    with sqlite3.connect(temp_db) as conn:
        # Change the action of the first entry
        conn.execute("UPDATE audit_log SET action = 'tampered action' WHERE id = 1")
        conn.commit()

    # Integrity check should now fail
    is_valid, corrupt_id = ledger.verify_integrity()
    assert is_valid is False
    assert corrupt_id == 1  # First row is corrupted because its content changed
