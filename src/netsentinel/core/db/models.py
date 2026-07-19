import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "netsentinel" / "netsentinel.db"


class SessionModel:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    authorized_scope TEXT NOT NULL,  -- JSON serialized list of CIDRs/Domains
                    consent_timestamp TEXT NOT NULL,
                    consent_hash TEXT NOT NULL,      -- Hash returned by audit ledger
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL             -- 'ACTIVE', 'CLOSED', etc.
                )
            """)
            conn.commit()

    def create_session(
        self, title: str, description: str | None, authorized_scope: list[str], consent_hash: str
    ) -> str:
        """
        Creates a new session. Scope and consent are strictly required (RE-01, RE-02).
        """
        if not authorized_scope:
            raise ValueError("Authorized scope is required and cannot be empty.")
        if not consent_hash:
            raise ValueError("Consent hash is required (RE-01).")

        session_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        scope_json = json.dumps(authorized_scope)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    id, title, description, authorized_scope,
                    consent_timestamp, consent_hash, created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                (session_id, title, description, scope_json, created_at, consent_hash, created_at),
            )
            conn.commit()
        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieves a single session by its ID.
        """
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                res = dict(row)
                res["authorized_scope"] = json.loads(res["authorized_scope"])
                return res
        return None

    def list_sessions(self) -> list[dict[str, Any]]:
        """
        Returns list of all sessions.
        """
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC")
            sessions = []
            for row in cursor.fetchall():
                d = dict(row)
                d["authorized_scope"] = json.loads(d["authorized_scope"])
                sessions.append(d)
            return sessions

    def delete_session(self, session_id: str) -> bool:
        """
        Deletes a session. Returns True if deleted, False if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            return cursor.rowcount > 0

    def update_status(self, session_id: str, status: str) -> bool:
        """
        Updates session status (e.g. 'CLOSED').
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE sessions SET status = ? WHERE id = ?", (status, session_id)
            )
            conn.commit()
            return cursor.rowcount > 0
