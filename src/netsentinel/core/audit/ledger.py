import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "netsentinel" / "audit_ledger.db"


class AuditLedger:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        # Returns a standard sqlite3 connection.
        # Future phases can wrap this in SQLCipher if required.
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT,
                    model_version TEXT,
                    action TEXT NOT NULL,
                    input_data TEXT,
                    output_data TEXT,
                    pddl_status TEXT NOT NULL,
                    pddl_rule_violation TEXT,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def _get_last_entry(self, conn: sqlite3.Connection) -> tuple[int, str] | None:
        cursor = conn.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            return row[0], row[1]
        return None

    def _calculate_hash(self, prev_hash: str, content: dict[str, Any]) -> str:
        # Deterministic serialization of the content dict
        serialized_content = json.dumps(content, sort_keys=True)
        hasher = hashlib.sha256()
        hasher.update(prev_hash.encode("utf-8"))
        hasher.update(serialized_content.encode("utf-8"))
        return hasher.hexdigest()

    def append(
        self,
        action: str,
        pddl_status: str,
        agent_id: str | None = None,
        model_version: str | None = None,
        input_data: str | None = None,
        output_data: str | None = None,
        pddl_rule_violation: str | None = None,
    ) -> str:
        """
        Appends a new cryptographically chained entry to the audit log.
        Returns the computed hash of the new entry.
        """
        timestamp = datetime.now(UTC).isoformat()

        # Build content representation for hashing
        content = {
            "timestamp": timestamp,
            "agent_id": agent_id,
            "model_version": model_version,
            "action": action,
            "input_data": input_data,
            "output_data": output_data,
            "pddl_status": pddl_status,
            "pddl_rule_violation": pddl_rule_violation,
        }

        with self._get_connection() as conn:
            last_entry = self._get_last_entry(conn)
            prev_hash = "0" * 64 if last_entry is None else last_entry[1]

            new_hash = self._calculate_hash(prev_hash, content)

            conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, agent_id, model_version, action,
                    input_data, output_data, pddl_status, pddl_rule_violation,
                    prev_hash, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    agent_id,
                    model_version,
                    action,
                    input_data,
                    output_data,
                    pddl_status,
                    pddl_rule_violation,
                    prev_hash,
                    new_hash,
                ),
            )
            conn.commit()
            return new_hash

    def verify_integrity(self) -> tuple[bool, int | None]:
        """
        Verifies the cryptographic chain integrity.
        Returns (True, None) if valid, or (False, corrupt_row_id) if corrupted.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, timestamp, agent_id, model_version, action,
                       input_data, output_data, pddl_status, pddl_rule_violation,
                       prev_hash, hash
                FROM audit_log ORDER BY id ASC
                """
            )
            rows = cursor.fetchall()

            expected_prev_hash = "0" * 64
            for row in rows:
                row_id = row[0]
                timestamp = row[1]
                agent_id = row[2]
                model_version = row[3]
                action = row[4]
                input_data = row[5]
                output_data = row[6]
                pddl_status = row[7]
                pddl_rule_violation = row[8]
                prev_hash = row[9]
                stored_hash = row[10]

                # Check chain link
                if prev_hash != expected_prev_hash:
                    return False, row_id

                # Recompute hash
                content = {
                    "timestamp": timestamp,
                    "agent_id": agent_id,
                    "model_version": model_version,
                    "action": action,
                    "input_data": input_data,
                    "output_data": output_data,
                    "pddl_status": pddl_status,
                    "pddl_rule_violation": pddl_rule_violation,
                }
                computed_hash = self._calculate_hash(prev_hash, content)

                if computed_hash != stored_hash:
                    return False, row_id

                expected_prev_hash = stored_hash

            return True, None

    def export_ledger(self) -> list[dict[str, Any]]:
        """
        Exports all ledger entries as a list of dictionaries.
        """
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM audit_log ORDER BY id ASC")
            return [dict(row) for row in cursor.fetchall()]
