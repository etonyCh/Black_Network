use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PDDLStatus {
    Compliant,
    NonCompliant,
    Partial,
    Error,
}

impl PDDLStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::NonCompliant => "NON_COMPLIANT",
            Self::Partial => "PARTIAL",
            Self::Error => "ERROR",
        }
    }

    pub fn is_worse_than(&self, other: PDDLStatus) -> bool {
        let order = |s| match s {
            Self::Compliant => 0,
            Self::Partial => 1,
            Self::NonCompliant => 2,
            Self::Error => 3,
        };
        order(*self) > order(other)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    Discover,
    Scan,
    Capture,
    InterceptStart,
    InterceptEnd,
    SessionCreate,
    ReportGenerate,
    Export,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDDLContext {
    pub session_id: Option<i64>,
    pub authorized_scope: Vec<String>,
    pub consent_hash: Option<String>,
    pub consent_timestamp: Option<f64>,
    pub target: Option<String>,
    pub session_started_at: Option<f64>,
    pub max_session_duration_seconds: u32,
    pub session_already_active: bool,
    pub operator: Option<String>,
    pub planned_seconds: Option<u32>,
}

impl Default for PDDLContext {
    fn default() -> Self {
        Self {
            session_id: None,
            authorized_scope: Vec::new(),
            consent_hash: None,
            consent_timestamp: None,
            target: None,
            session_started_at: None,
            max_session_duration_seconds: 1800,
            session_already_active: false,
            operator: None,
            planned_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDDLAction {
    pub action_type: ActionType,
    pub description: String,
    pub requires_consent: bool,
    pub requires_scope: bool,
    pub requires_unicity: bool,
}

impl Default for PDDLAction {
    fn default() -> Self {
        Self {
            action_type: ActionType::Unknown,
            description: String::new(),
            requires_consent: true,
            requires_scope: true,
            requires_unicity: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDDLResult {
    pub status: PDDLStatus,
    pub rule_violation: Option<String>,
    pub rule_name: Option<String>,
    pub details: serde_json::Value,
    pub messages: Vec<String>,
}

impl PDDLResult {
    pub fn compliant(rule_name: &'static str) -> Self {
        Self {
            status: PDDLStatus::Compliant,
            rule_violation: None,
            rule_name: Some(rule_name.to_string()),
            details: serde_json::json!({}),
            messages: Vec::new(),
        }
    }

    pub fn non_compliant(rule_name: &'static str, violation: impl Into<String>) -> Self {
        Self {
            status: PDDLStatus::NonCompliant,
            rule_violation: Some(violation.into()),
            rule_name: Some(rule_name.to_string()),
            details: serde_json::json!({}),
            messages: Vec::new(),
        }
    }

    pub fn partial(rule_name: &'static str, violation: impl Into<String>) -> Self {
        Self {
            status: PDDLStatus::Partial,
            rule_violation: Some(violation.into()),
            rule_name: Some(rule_name.to_string()),
            details: serde_json::json!({}),
            messages: Vec::new(),
        }
    }

    pub fn to_ledger_columns(&self) -> (&'static str, Option<String>) {
        let status_str = self.status.as_str();
        let violation = self.rule_violation.as_ref().map(|v| {
            format!("{}: {}", self.rule_name.as_deref().unwrap_or("?"), v)
        });
        (status_str, violation)
    }
}

pub trait PDDLRule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, action: &PDDLAction, ctx: &PDDLContext) -> PDDLResult;
}

// ----------------------------------------------------------------------------
// RE-01 : Consentement explicite
// ----------------------------------------------------------------------------
pub struct RE01ConsentRule;

impl PDDLRule for RE01ConsentRule {
    fn id(&self) -> &'static str {
        "RE-01"
    }

    fn evaluate(&self, action: &PDDLAction, ctx: &PDDLContext) -> PDDLResult {
        if !action.requires_consent {
            let mut res = PDDLResult::compliant(self.id());
            res.messages.push("Aucun consentement requis pour cette action.".to_string());
            return res;
        }

        let Some(hash) = &ctx.consent_hash else {
            return PDDLResult::non_compliant(
                self.id(),
                "consent_hash absent ou vide — consentement RE-01 non obtenu",
            );
        };

        if hash.trim().is_empty() {
            return PDDLResult::non_compliant(
                self.id(),
                "consent_hash absent ou vide — consentement RE-01 non obtenu",
            );
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        if let Some(ts) = ctx.consent_timestamp {
            if ts > now {
                return PDDLResult::non_compliant(
                    self.id(),
                    "consent_timestamp dans le futur — invalide",
                );
            }
        }

        let mut res = PDDLResult::compliant(self.id());
        res.details = serde_json::json!({
            "consent_hash_len": hash.len(),
            "consent_age_seconds": ctx.consent_timestamp.map(|ts| now - ts).unwrap_or(0.0),
        });
        res
    }
}

// ----------------------------------------------------------------------------
// RE-02a : Scope matching
// ----------------------------------------------------------------------------
pub struct RE02ScopeRule;

impl RE02ScopeRule {
    fn match_target(target: &str, scope: &str) -> bool {
        let t = target.trim();
        let s = scope.trim();

        if t.eq_ignore_ascii_case(s) {
            return true;
        }

        // Check target IP in CIDR scope
        if let (Ok(t_ip), Ok(s_net)) = (IpAddr::from_str(t), IpNet::from_str(s)) {
            return s_net.contains(&t_ip);
        }

        // Check target subnet in scope subnet
        if let (Ok(t_net), Ok(s_net)) = (IpNet::from_str(t), IpNet::from_str(s)) {
            return s_net.contains(&t_net);
        }

        // Domain suffix check
        let t_clean = t.to_lowercase();
        let s_clean = s.to_lowercase();
        if t_clean.ends_with(&format!(".{}", s_clean)) {
            return true;
        }

        false
    }
}

impl PDDLRule for RE02ScopeRule {
    fn id(&self) -> &'static str {
        "RE-02a"
    }

    fn evaluate(&self, action: &PDDLAction, ctx: &PDDLContext) -> PDDLResult {
        if !action.requires_scope {
            let mut res = PDDLResult::compliant(self.id());
            res.messages.push("Action sans cible réseau : périmètre non applicable.".to_string());
            return res;
        }

        let Some(target) = &ctx.target else {
            return PDDLResult::partial(self.id(), "cible absente du contexte");
        };

        if target.trim().is_empty() {
            return PDDLResult::partial(self.id(), "cible absente du contexte");
        }

        if ctx.authorized_scope.is_empty() {
            return PDDLResult::non_compliant(
                self.id(),
                "aucun authorized_scope défini dans SessionModel — RE-02a exige un périmètre explicite",
            );
        }

        for scope in &ctx.authorized_scope {
            if Self::match_target(target, scope) {
                let mut res = PDDLResult::compliant(self.id());
                res.details = serde_json::json!({
                    "matched_scope": scope,
                    "target": target,
                });
                return res;
            }
        }

        PDDLResult::non_compliant(
            self.id(),
            format!(
                "cible `{}` hors du périmètre autorisé [{}]",
                target,
                ctx.authorized_scope.join(", ")
            ),
        )
    }
}

// ----------------------------------------------------------------------------
// RE-02b : Timeout & Unicity
// ----------------------------------------------------------------------------
pub struct RE02TimeoutRule;

impl PDDLRule for RE02TimeoutRule {
    fn id(&self) -> &'static str {
        "RE-02b"
    }

    fn evaluate(&self, action: &PDDLAction, ctx: &PDDLContext) -> PDDLResult {
        if action.requires_unicity || action.action_type == ActionType::InterceptStart {
            if ctx.session_already_active {
                return PDDLResult::non_compliant(
                    self.id(),
                    "session intercept déjà active (RE-02b : unicité)",
                );
            }

            if let Some(planned) = ctx.planned_seconds {
                if planned > ctx.max_session_duration_seconds {
                    return PDDLResult::non_compliant(
                        self.id(),
                        format!(
                            "durée demandée {}s > max autorisé {}s",
                            planned, ctx.max_session_duration_seconds
                        ),
                    );
                }
            }
        }

        if matches!(
            action.action_type,
            ActionType::Capture | ActionType::Scan | ActionType::InterceptStart
        ) {
            if let Some(started_at) = ctx.session_started_at {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
                let elapsed = (now - started_at).max(0.0);
                if elapsed > ctx.max_session_duration_seconds as f64 {
                    return PDDLResult::non_compliant(
                        self.id(),
                        format!(
                            "durée écoulée {:.0}s > {}s (RE-02b)",
                            elapsed, ctx.max_session_duration_seconds
                        ),
                    );
                }
            }
        }

        PDDLResult::compliant(self.id())
    }
}

// ----------------------------------------------------------------------------
// Engine Pipeline
// ----------------------------------------------------------------------------
pub struct PDDLEngine {
    rules: Vec<Box<dyn PDDLRule>>,
}

impl Default for PDDLEngine {
    fn default() -> Self {
        Self::default_rules()
    }
}

impl PDDLEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn default_rules() -> Self {
        let mut engine = Self::new();
        engine.register(RE01ConsentRule);
        engine.register(RE02ScopeRule);
        engine.register(RE02TimeoutRule);
        engine
    }

    pub fn register(&mut self, rule: impl PDDLRule + 'static) {
        self.rules.push(Box::new(rule));
    }

    pub fn validate(&self, action: &PDDLAction, ctx: &PDDLContext) -> PDDLResult {
        let mut aggregate = PDDLResult::compliant("aggregate");
        let mut worst_status = PDDLStatus::Compliant;
        let mut per_rule_status = serde_json::Map::new();

        for rule in &self.rules {
            let res = rule.evaluate(action, ctx);
            per_rule_status.insert(rule.id().to_string(), serde_json::json!(res.status.as_str()));

            if res.status.is_worse_than(worst_status) {
                worst_status = res.status;
            }

            if res.status == PDDLStatus::NonCompliant && aggregate.rule_violation.is_none() {
                aggregate.rule_violation = res.rule_violation;
                aggregate.rule_name = res.rule_name;
            }

            aggregate.messages.extend(res.messages);
        }

        aggregate.status = worst_status;
        aggregate.details = serde_json::json!({
            "per_rule_status": per_rule_status
        });
        aggregate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_re01_consent_rule() {
        let engine = PDDLEngine::default_rules();
        let action = PDDLAction {
            action_type: ActionType::InterceptStart,
            requires_consent: true,
            ..Default::default()
        };

        // Missing consent
        let ctx = PDDLContext::default();
        let res = engine.validate(&action, &ctx);
        assert_eq!(res.status, PDDLStatus::NonCompliant);
        assert_eq!(res.rule_name.as_deref(), Some("RE-01"));

        // Valid consent
        let ctx = PDDLContext {
            consent_hash: Some("sha256:abcd".to_string()),
            authorized_scope: vec!["192.168.1.0/24".to_string()],
            target: Some("192.168.1.10".to_string()),
            ..Default::default()
        };
        let res = engine.validate(&action, &ctx);
        assert_eq!(res.status, PDDLStatus::Compliant);
    }

    #[test]
    fn test_re02a_scope_rule() {
        let rule = RE02ScopeRule;
        assert!(RE02ScopeRule::match_target("192.168.1.5", "192.168.1.0/24"));
        assert!(!RE02ScopeRule::match_target("10.0.0.1", "192.168.1.0/24"));
        assert!(RE02ScopeRule::match_target("pc1.corp.local", "corp.local"));
        assert!(!RE02ScopeRule::match_target("pc1.other.com", "corp.local"));

        let action = PDDLAction {
            action_type: ActionType::Scan,
            requires_scope: true,
            ..Default::default()
        };

        let ctx = PDDLContext {
            authorized_scope: vec!["192.168.1.0/24".to_string()],
            target: Some("10.0.0.5".to_string()),
            consent_hash: Some("hash".to_string()),
            ..Default::default()
        };
        let res = rule.evaluate(&action, &ctx);
        assert_eq!(res.status, PDDLStatus::NonCompliant);
    }

    #[test]
    fn test_re02b_timeout_rule() {
        let rule = RE02TimeoutRule;
        let action = PDDLAction {
            action_type: ActionType::InterceptStart,
            requires_unicity: true,
            ..Default::default()
        };

        let ctx = PDDLContext {
            session_already_active: true,
            ..Default::default()
        };
        let res = rule.evaluate(&action, &ctx);
        assert_eq!(res.status, PDDLStatus::NonCompliant);
        assert!(res.rule_violation.unwrap().contains("unicité"));
    }
}
