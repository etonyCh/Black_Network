# STRIDE Threat Model - Module F: History

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Forging Session IDs or timestamps in UI. | Viewing or modifying unrelated test sessions. | Use UUIDv4 or autoincrement IDs strictly validated within the database context. |
| **Tampering** | Editing session's "Authorized Scope" (RE-02) after creation to run out-of-scope scans. | Bypassing scope guardchecks. | Scope definition is immutable after session initialization. Any change requires creating a new session. |
| **Repudiation** | User deleting session logs to erase evidence of illegal scans. | Missing audit trail. | Session deletion does not purge the cryptographically chained audit log ledger, which is append-only. |
| **Information Disclosure** | Unauthorized local user reading historical session data. | Leaking targets, vulnerabilities, and captured credentials. | Use SQLCipher database encryption with credentials derived from GNOME Keyring. |
| **Denial of Service** | Flooding session database with entries. | DB size exhaustion leading to app lockups. | Enforce database cleaning and session limits (e.g. systemd timer for 30-day auto-purge §9.4). |
| **Elevation of Privilege** | SQL injection via "session title" or "description" query search. | Bypassing DB access controls or executing code. | Use SQLite parameterized queries exclusively. Never interpolate strings or use f-strings in queries. |
