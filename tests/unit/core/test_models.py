import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from netsentinel.core.db.models import SessionModel


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp()
    yield path
    os.close(fd)
    p = Path(path)
    if p.exists():
        p.unlink()


def test_session_initialization(temp_db):
    model = SessionModel(temp_db)
    assert Path(temp_db).exists()
    assert model.db_path == Path(temp_db)

    with sqlite3.connect(temp_db) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'"
        )
        assert cursor.fetchone() is not None


def test_create_session(temp_db):
    model = SessionModel(temp_db)

    # Empty scope should fail
    with pytest.raises(ValueError, match="Authorized scope is required"):
        model.create_session("Test", "Desc", [], "consent_hash_123")

    # Empty consent should fail
    with pytest.raises(ValueError, match="Consent hash is required"):
        model.create_session("Test", "Desc", ["10.0.0.0/24"], "")

    # Valid creation
    session_id = model.create_session(
        title="Session 1",
        description="Audit desc",
        authorized_scope=["10.0.0.0/24", "example.com"],
        consent_hash="hash_abc",
    )
    assert isinstance(session_id, str)
    assert len(session_id) > 0

    # Retrieve session
    sess = model.get_session(session_id)
    assert sess is not None
    assert sess["title"] == "Session 1"
    assert sess["description"] == "Audit desc"
    assert sess["authorized_scope"] == ["10.0.0.0/24", "example.com"]
    assert sess["consent_hash"] == "hash_abc"
    assert sess["status"] == "ACTIVE"


def test_list_and_delete_session(temp_db):
    model = SessionModel(temp_db)

    s1 = model.create_session("S1", "D1", ["192.168.1.0/24"], "hash_1")
    s2 = model.create_session("S2", "D2", ["10.0.0.1"], "hash_2")

    sessions = model.list_sessions()
    assert len(sessions) == 2
    assert sessions[0]["id"] == s2  # Ordered by created_at DESC

    # Update status
    assert model.update_status(s1, "CLOSED") is True
    assert model.get_session(s1)["status"] == "CLOSED"

    # Delete session
    assert model.delete_session(s1) is True
    assert model.get_session(s1) is None
    assert len(model.list_sessions()) == 1
