use chrono::{DateTime, Utc};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub target: String,
    pub operator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

pub struct AuditLogger {
    key: hmac::Key,
    log_path: String,
}

impl AuditLogger {
    pub fn new(secret: &str, log_path: &str) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        Self {
            key,
            log_path: log_path.to_string(),
        }
    }

    pub fn log_action(&self, action: &str, target: &str, operator: &str) -> anyhow::Result<()> {
        let mut entry = AuditEntry {
            timestamp: Utc::now(),
            action: action.to_string(),
            target: target.to_string(),
            operator: operator.to_string(),
            signature: None,
        };

        // Serialize without signature for signing
        let data_to_sign = serde_json::to_string(&entry)?;
        
        let signature = hmac::sign(&self.key, data_to_sign.as_bytes());
        entry.signature = Some(hex::encode(signature.as_ref()));

        // Serialize final JSON with signature
        let final_json = serde_json::to_string(&entry)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(&self.log_path))?;

        writeln!(file, "{}", final_json)?;
        
        Ok(())
    }

    #[allow(dead_code)]
    pub fn verify_entry(secret: &str, json_line: &str) -> bool {
        let Ok(mut entry) = serde_json::from_str::<AuditEntry>(json_line) else {
            return false;
        };

        let Some(recorded_sig) = entry.signature.take() else {
            return false;
        };

        let Ok(data_to_verify) = serde_json::to_string(&entry) else {
            return false;
        };

        let Ok(decoded_sig) = hex::decode(&recorded_sig) else {
            return false;
        };

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        hmac::verify(&key, data_to_verify.as_bytes(), &decoded_sig).is_ok()
    }
}
