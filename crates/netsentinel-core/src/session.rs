use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

// ============================================================================
// Modèle de données
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionScope {
    pub targets: Vec<String>,
}

impl SessionScope {
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn contains(&self, target: &str) -> bool {
        use ipnet::IpNet;
        use std::net::IpAddr;
        use std::str::FromStr;

        let t = target.trim().to_lowercase();
        for scope in &self.targets {
            let s = scope.trim().to_lowercase();
            if t == s {
                return true;
            }
            if let (Ok(t_ip), Ok(s_net)) = (IpAddr::from_str(&t), IpNet::from_str(&s)) {
                if s_net.contains(&t_ip) {
                    return true;
                }
            }
            if t.ends_with(&format!(".{}", s)) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: i64,
    pub title: String,
    pub scope_json: String,
    pub consent_hash: String,
    pub consent_timestamp: f64,
    pub created_at: String,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Completed,
    Archived,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Archived => "archived",
        }
    }

    pub fn from_label(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "completed" => Self::Completed,
            "archived" => Self::Archived,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFinding {
    pub id: i64,
    pub session_id: i64,
    pub target: String,
    pub port: u16,
    pub service: String,
    pub cve: String,
    pub severity: String,
    pub description: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHost {
    pub id: i64,
    pub session_id: i64,
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    pub discovered_at: String,
}

// ============================================================================
// Settings
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub network_interface: String,
    pub gemini_api_key_ref: String,
    pub retention_period_days: u32,
    pub store_hosts: bool,
    pub store_history: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            network_interface: "eth0".to_string(),
            gemini_api_key_ref: "keyring:netsentinel/gemini_api_key".to_string(),
            retention_period_days: 30,
            store_hosts: true,
            store_history: true,
        }
    }
}

// ============================================================================
// SessionManager — SQLite centralisé
// ============================================================================

pub struct SessionManager {
    conn: Mutex<Connection>,
}

impl SessionManager {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!(" création dossier session DB : {:?}", parent))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("ouverture SQLite sessions : {:?}", path))?;
        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_db()?;
        Ok(mgr)
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("SQLite sessions in-memory")?;
        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_db()?;
        Ok(mgr)
    }

    fn init_db(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS sessions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT NOT NULL,
                 scope_json TEXT NOT NULL,
                 consent_hash TEXT NOT NULL,
                 consent_timestamp REAL NOT NULL,
                 created_at TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'active'
             );

             CREATE TABLE IF NOT EXISTS session_findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id INTEGER NOT NULL,
                 target TEXT NOT NULL,
                 port INTEGER NOT NULL DEFAULT 0,
                 service TEXT NOT NULL DEFAULT '',
                 cve TEXT NOT NULL DEFAULT '',
                 severity TEXT NOT NULL DEFAULT 'Info',
                 description TEXT NOT NULL DEFAULT '',
                 discovered_at TEXT NOT NULL,
                 FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
             );

             CREATE TABLE IF NOT EXISTS session_hosts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id INTEGER NOT NULL,
                 ip TEXT NOT NULL,
                 mac TEXT NOT NULL,
                 vendor TEXT NOT NULL DEFAULT '',
                 hostname TEXT NOT NULL DEFAULT '',
                 discovered_at TEXT NOT NULL,
                 FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
             );

             CREATE TABLE IF NOT EXISTS app_settings (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_findings_session ON session_findings(session_id);
             CREATE INDEX IF NOT EXISTS idx_hosts_session ON session_hosts(session_id);",
        )?;
        Ok(())
    }

    // ---- Sessions ----

    pub fn create_session(&self, title: &str, scope: &SessionScope) -> Result<Session> {
        let now = Utc::now().to_rfc3339();
        let consent_payload = format!("{}:{}", title, now);
        let consent_hash = format!("sha256:{:x}", Sha256::digest(consent_payload.as_bytes()));
        let consent_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let scope_json = serde_json::to_string(scope)?;

        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        conn.execute(
            "INSERT INTO sessions (title, scope_json, consent_hash, consent_timestamp, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![title, scope_json, consent_hash, consent_timestamp, now, "active"],
        )?;
        let id = conn.last_insert_rowid();

        Ok(Session {
            id,
            title: title.to_string(),
            scope_json,
            consent_hash,
            consent_timestamp,
            created_at: now,
            status: SessionStatus::Active,
        })
    }

    pub fn get_session(&self, id: i64) -> Result<Option<Session>> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, title, scope_json, consent_hash, consent_timestamp, created_at, status
             FROM sessions WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Session {
                id: row.get(0)?,
                title: row.get(1)?,
                scope_json: row.get(2)?,
                consent_hash: row.get(3)?,
                consent_timestamp: row.get(4)?,
                created_at: row.get(5)?,
                status: SessionStatus::from_label(&row.get::<_, String>(6)?),
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn get_active_session(&self) -> Result<Option<Session>> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, title, scope_json, consent_hash, consent_timestamp, created_at, status
             FROM sessions WHERE status = 'active' ORDER BY id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map([], |row| {
            Ok(Session {
                id: row.get(0)?,
                title: row.get(1)?,
                scope_json: row.get(2)?,
                consent_hash: row.get(3)?,
                consent_timestamp: row.get(4)?,
                created_at: row.get(5)?,
                status: SessionStatus::from_label(&row.get::<_, String>(6)?),
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn complete_session(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        conn.execute(
            "UPDATE sessions SET status = 'completed' WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn list_sessions(&self, limit: u32) -> Result<Vec<Session>> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, title, scope_json, consent_hash, consent_timestamp, created_at, status
             FROM sessions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(Session {
                id: row.get(0)?,
                title: row.get(1)?,
                scope_json: row.get(2)?,
                consent_hash: row.get(3)?,
                consent_timestamp: row.get(4)?,
                created_at: row.get(5)?,
                status: SessionStatus::from_label(&row.get::<_, String>(6)?),
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ---- Findings ----

    #[allow(clippy::too_many_arguments)]
    pub fn add_finding(
        &self,
        session_id: i64,
        target: &str,
        port: u16,
        service: &str,
        cve: &str,
        severity: &str,
        description: &str,
    ) -> Result<SessionFinding> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        conn.execute(
            "INSERT INTO session_findings (session_id, target, port, service, cve, severity, description, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![session_id, target, port, service, cve, severity, description, now],
        )?;
        let id = conn.last_insert_rowid();
        Ok(SessionFinding {
            id,
            session_id,
            target: target.to_string(),
            port,
            service: service.to_string(),
            cve: cve.to_string(),
            severity: severity.to_string(),
            description: description.to_string(),
            discovered_at: now,
        })
    }

    pub fn get_findings(&self, session_id: i64) -> Result<Vec<SessionFinding>> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, session_id, target, port, service, cve, severity, description, discovered_at
             FROM session_findings WHERE session_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(SessionFinding {
                id: row.get(0)?,
                session_id: row.get(1)?,
                target: row.get(2)?,
                port: row.get(3)?,
                service: row.get(4)?,
                cve: row.get(5)?,
                severity: row.get(6)?,
                description: row.get(7)?,
                discovered_at: row.get(8)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ---- Hosts ----

    pub fn add_host(
        &self,
        session_id: i64,
        ip: &str,
        mac: &str,
        vendor: &str,
        hostname: &str,
    ) -> Result<SessionHost> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        conn.execute(
            "INSERT INTO session_hosts (session_id, ip, mac, vendor, hostname, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![session_id, ip, mac, vendor, hostname, now],
        )?;
        let id = conn.last_insert_rowid();
        Ok(SessionHost {
            id,
            session_id,
            ip: ip.to_string(),
            mac: mac.to_string(),
            vendor: vendor.to_string(),
            hostname: hostname.to_string(),
            discovered_at: now,
        })
    }

    pub fn get_hosts(&self, session_id: i64) -> Result<Vec<SessionHost>> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, session_id, ip, mac, vendor, hostname, discovered_at
             FROM session_hosts WHERE session_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(SessionHost {
                id: row.get(0)?,
                session_id: row.get(1)?,
                ip: row.get(2)?,
                mac: row.get(3)?,
                vendor: row.get(4)?,
                hostname: row.get(5)?,
                discovered_at: row.get(6)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ---- Settings ----

    pub fn get_settings(&self) -> Result<AppSettings> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let mut settings = AppSettings::default();
        let mut stmt = conn.prepare("SELECT key, value FROM app_settings")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows.flatten() {
            match row.0.as_str() {
                "network_interface" => settings.network_interface = row.1,
                "gemini_api_key_ref" => settings.gemini_api_key_ref = row.1,
                "retention_period_days" => {
                    settings.retention_period_days = row.1.parse().unwrap_or(30)
                }
                "store_hosts" => settings.store_hosts = row.1 == "true",
                "store_history" => settings.store_history = row.1 == "true",
                _ => {}
            }
        }
        Ok(settings)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        conn.execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<()> {
        self.set_setting("network_interface", &settings.network_interface)?;
        self.set_setting("gemini_api_key_ref", &settings.gemini_api_key_ref)?;
        self.set_setting(
            "retention_period_days",
            &settings.retention_period_days.to_string(),
        )?;
        self.set_setting("store_hosts", &settings.store_hosts.to_string())?;
        self.set_setting("store_history", &settings.store_history.to_string())?;
        Ok(())
    }

    // ---- Purge (rétention) ----

    pub fn purge_expired(&self, retention_days: u32) -> Result<u32> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let cutoff = Utc::now()
            .checked_sub_signed(chrono::Duration::days(retention_days as i64))
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        let deleted = conn.execute(
            "DELETE FROM sessions WHERE created_at < ?1 AND status != 'active'",
            params![cutoff],
        )?;
        Ok(deleted as u32)
    }

    // ---- Consent hash RE-01 ----

    pub fn generate_consent_hash(&self, operator: &str, target: &str) -> String {
        use sha2::{Digest, Sha256};
        let payload = format!(
            "{}:{}:{}",
            operator,
            target,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        format!("sha256:{:x}", Sha256::digest(payload.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mgr = SessionManager::in_memory().unwrap();
        let scope = SessionScope {
            targets: vec!["192.168.1.0/24".to_string()],
        };
        let session = mgr.create_session("Test Audit", &scope).unwrap();
        assert_eq!(session.status, SessionStatus::Active);
        assert!(!session.consent_hash.is_empty());

        let fetched = mgr.get_session(session.id).unwrap().unwrap();
        assert_eq!(fetched.title, "Test Audit");

        let active = mgr.get_active_session().unwrap();
        assert!(active.is_some());

        mgr.complete_session(session.id).unwrap();
        let completed = mgr.get_session(session.id).unwrap().unwrap();
        assert_eq!(completed.status, SessionStatus::Completed);
    }

    #[test]
    fn test_scope_contains() {
        let scope = SessionScope {
            targets: vec![
                "192.168.1.0/24".to_string(),
                "10.0.0.5".to_string(),
                "corp.local".to_string(),
            ],
        };
        assert!(scope.contains("192.168.1.42"));
        assert!(scope.contains("10.0.0.5"));
        assert!(scope.contains("pc1.corp.local"));
        assert!(!scope.contains("10.0.0.1"));
        assert!(!scope.contains("192.168.2.1"));
    }

    #[test]
    fn test_findings_and_hosts() {
        let mgr = SessionManager::in_memory().unwrap();
        let scope = SessionScope {
            targets: vec!["10.0.0.0/24".to_string()],
        };
        let session = mgr.create_session("Test", &scope).unwrap();

        let finding = mgr
            .add_finding(
                session.id,
                "10.0.0.1",
                22,
                "OpenSSH",
                "CVE-2024-6387",
                "Critical",
                "regreSSHion",
            )
            .unwrap();
        assert_eq!(finding.session_id, session.id);

        let findings = mgr.get_findings(session.id).unwrap();
        assert_eq!(findings.len(), 1);

        mgr.add_host(
            session.id,
            "10.0.0.1",
            "AA:BB:CC:DD:EE:FF",
            "TestVendor",
            "",
        )
        .unwrap();
        let hosts = mgr.get_hosts(session.id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].mac, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_settings_roundtrip() {
        let mgr = SessionManager::in_memory().unwrap();
        let default_settings = mgr.get_settings().unwrap();
        assert_eq!(default_settings.network_interface, "eth0");

        let mut settings = default_settings;
        settings.network_interface = "wlan0".to_string();
        settings.retention_period_days = 7;
        mgr.save_settings(&settings).unwrap();

        let loaded = mgr.get_settings().unwrap();
        assert_eq!(loaded.network_interface, "wlan0");
        assert_eq!(loaded.retention_period_days, 7);
    }
}
