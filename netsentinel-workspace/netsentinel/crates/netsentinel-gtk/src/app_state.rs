use netsentinel_core::ledger::AuditLedger;
use netsentinel_core::session::SessionManager;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub session_manager: SessionManager,
    pub ledger: AuditLedger,
}

impl AppState {
    pub fn new() -> Self {
        let data_dir = dirs().unwrap_or_else(|| PathBuf::from("/tmp/netsentinel"));
        let db_path = data_dir.join("sessions.db");
        let session_manager = SessionManager::open(db_path).unwrap_or_else(|e| {
            tracing::warn!(" fallback in-memory session DB: {e}");
            SessionManager::in_memory().expect("in-memory session DB failed")
        });
        let ledger_path = data_dir.join("audit_ledger.db");
        let ledger = AuditLedger::open(&ledger_path).unwrap_or_else(|e| {
            tracing::warn!(" fallback in-memory ledger: {e}");
            AuditLedger::in_memory().expect("in-memory ledger failed")
        });
        Self {
            session_manager,
            ledger,
        }
    }
}

fn dirs() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Some(PathBuf::from(xdg).join("netsentinel"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".local/share/netsentinel"));
    }
    None
}

pub type SharedState = Arc<AppState>;
