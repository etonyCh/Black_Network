use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::pddl::{PDDLAction, PDDLContext, PDDLEngine, PDDLResult, PDDLStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub model_version: Option<String>,
    pub action: String,
    pub input_data: Option<String>,
    pub output_data: Option<String>,
    pub pddl_status: String,
    pub pddl_rule_violation: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

use std::sync::Mutex;

pub struct AuditLedger {
    conn: Mutex<Connection>,
    pddl_engine: PDDLEngine,
}

impl AuditLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Échec création dossier parent ledger : {:?}", parent))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Échec ouverture SQLite ledger : {:?}", path))?;
        let ledger = Self {
            conn: Mutex::new(conn),
            pddl_engine: PDDLEngine::default_rules(),
        };
        ledger.init_db()?;
        Ok(ledger)
    }

    pub fn in_memory() -> Result<Self> {
        let conn =
            Connection::open_in_memory().context("Échec ouverture SQLite ledger in-memory")?;
        let ledger = Self {
            conn: Mutex::new(conn),
            pddl_engine: PDDLEngine::default_rules(),
        };
        ledger.init_db()?;
        Ok(ledger)
    }

    pub fn with_engine(mut self, engine: PDDLEngine) -> Self {
        self.pddl_engine = engine;
        self
    }

    fn init_db(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poison error: {}", e))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
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
            );",
        )?;
        Ok(())
    }

    pub fn calculate_hash(prev_hash: &str, content: &serde_json::Value) -> String {
        let serialized = serde_json::to_string(content).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(serialized.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn get_last_entry(&self, conn: &Connection) -> Result<Option<(i64, String)>> {
        let mut stmt = conn.prepare("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let hash: String = row.get(1)?;
            Ok(Some((id, hash)))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        action: &str,
        pddl_status: &str,
        agent_id: Option<&str>,
        model_version: Option<&str>,
        input_data: Option<&str>,
        output_data: Option<&str>,
        pddl_rule_violation: Option<&str>,
    ) -> Result<String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poison error: {}", e))?;
        let timestamp = Utc::now().to_rfc3339();

        let content = serde_json::json!({
            "action": action,
            "agent_id": agent_id,
            "input_data": input_data,
            "model_version": model_version,
            "output_data": output_data,
            "pddl_rule_violation": pddl_rule_violation,
            "pddl_status": pddl_status,
            "timestamp": timestamp,
        });

        let last_entry = self.get_last_entry(&conn)?;
        let prev_hash = last_entry.map(|(_, h)| h).unwrap_or_else(|| "0".repeat(64));
        let new_hash = Self::calculate_hash(&prev_hash, &content);

        conn.execute(
            "INSERT INTO audit_log (
                timestamp, agent_id, model_version, action,
                input_data, output_data, pddl_status, pddl_rule_violation,
                prev_hash, hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
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
            ],
        )?;

        Ok(new_hash)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_and_append(
        &self,
        action: &PDDLAction,
        ctx: &PDDLContext,
        agent_id: Option<&str>,
        model_version: Option<&str>,
        input_data: Option<&str>,
        output_data: Option<&str>,
        deny_non_compliant: bool,
    ) -> Result<(PDDLResult, Option<String>)> {
        let result = self.pddl_engine.validate(action, ctx);
        let (status_str, violation) = result.to_ledger_columns();
        let action_name = result
            .rule_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", action.action_type));

        if deny_non_compliant
            && matches!(result.status, PDDLStatus::NonCompliant | PDDLStatus::Error)
        {
            return Err(anyhow!(
                "[PDDL {}] {}: {} — détails: {}",
                status_str,
                action_name,
                violation.as_deref().unwrap_or("interdit par règle"),
                result.details
            ));
        }

        let new_hash = self.append(
            &action_name,
            status_str,
            agent_id,
            model_version,
            input_data,
            output_data,
            violation.as_deref(),
        )?;

        Ok((result, Some(new_hash)))
    }

    pub fn verify_integrity(&self) -> Result<(bool, Option<i64>)> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poison error: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, agent_id, model_version, action,
                    input_data, output_data, pddl_status, pddl_rule_violation,
                    prev_hash, hash
             FROM audit_log ORDER BY id ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })?;

        let mut expected_prev_hash = "0".repeat(64);

        for row_res in rows {
            let (
                id,
                timestamp,
                agent_id,
                model_version,
                action,
                input_data,
                output_data,
                pddl_status,
                pddl_rule_violation,
                prev_hash,
                stored_hash,
            ) = row_res?;

            if prev_hash != expected_prev_hash {
                return Ok((false, Some(id)));
            }

            let content = serde_json::json!({
                "action": action,
                "agent_id": agent_id,
                "input_data": input_data,
                "model_version": model_version,
                "output_data": output_data,
                "pddl_rule_violation": pddl_rule_violation,
                "pddl_status": pddl_status,
                "timestamp": timestamp,
            });

            let computed_hash = Self::calculate_hash(&prev_hash, &content);
            if computed_hash != stored_hash {
                return Ok((false, Some(id)));
            }

            expected_prev_hash = stored_hash;
        }

        Ok((true, None))
    }

    pub fn export_ledger(&self) -> Result<Vec<AuditEntry>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poison error: {}", e))?;
        let mut stmt = conn.prepare("SELECT * FROM audit_log ORDER BY id ASC")?;
        let entries = stmt
            .query_map([], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    agent_id: row.get(2)?,
                    model_version: row.get(3)?,
                    action: row.get(4)?,
                    input_data: row.get(5)?,
                    output_data: row.get(6)?,
                    pddl_status: row.get(7)?,
                    pddl_rule_violation: row.get(8)?,
                    prev_hash: row.get(9)?,
                    hash: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_append_and_chaining() -> Result<()> {
        let ledger = AuditLedger::in_memory()?;
        let h1 = ledger.append("SCAN", "COMPLIANT", Some("agent-1"), None, None, None, None)?;
        assert_eq!(h1.len(), 64);

        let h2 = ledger.append(
            "CAPTURE",
            "COMPLIANT",
            Some("agent-1"),
            None,
            None,
            None,
            None,
        )?;
        assert_eq!(h2.len(), 64);
        assert_ne!(h1, h2);

        let (valid, corrupt_id) = ledger.verify_integrity()?;
        assert!(valid);
        assert_eq!(corrupt_id, None);

        let entries = ledger.export_ledger()?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "SCAN");
        assert_eq!(entries[1].action, "CAPTURE");
        assert_eq!(entries[1].prev_hash, h1);

        Ok(())
    }

    #[test]
    fn test_ledger_validate_and_append() -> Result<()> {
        let ledger = AuditLedger::in_memory()?;
        let action = PDDLAction {
            action_type: crate::pddl::ActionType::Scan,
            requires_consent: true,
            requires_scope: true,
            ..Default::default()
        };

        let ctx = PDDLContext {
            consent_hash: Some("sha256:1234".to_string()),
            authorized_scope: vec!["192.168.1.0/24".to_string()],
            target: Some("192.168.1.5".to_string()),
            ..Default::default()
        };

        let (res, hash) = ledger.validate_and_append(
            &action,
            &ctx,
            Some("scan-agent"),
            None,
            None,
            None,
            true,
        )?;

        assert_eq!(res.status, PDDLStatus::Compliant);
        assert!(hash.is_some());

        let (valid, _) = ledger.verify_integrity()?;
        assert!(valid);

        Ok(())
    }
}
