use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcReferenceEntry {
    pub algorithm: String,
    pub nist_level: u8,
    pub status: String,
    pub key_exchange: Option<Vec<String>>,
    pub signature: Option<Vec<String>>,
    pub classical_security_bits: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcAuditResult {
    pub algorithm: String,
    pub status: String,
    pub nist_level: u8,
    pub is_quantum_safe: bool,
    pub risk_level: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcAuditReport {
    pub service: String,
    pub version: String,
    pub algorithm_detected: String,
    pub audit_result: PqcAuditResult,
    pub timestamp: f64,
}

pub struct PqcAuditor {
    entries: Vec<PqcReferenceEntry>,
}

impl PqcAuditor {
    pub fn load_reference(json_path: &str) -> anyhow::Result<Self> {
        let data = fs::read_to_string(json_path)
            .map_err(|e| anyhow::anyhow!("Impossible de lire pqc_nist_reference.json: {e}"))?;
        let entries: Vec<PqcReferenceEntry> = serde_json::from_str(&data)?;
        Ok(Self { entries })
    }

    pub fn in_memory() -> Self {
        Self {
            entries: vec![
                PqcReferenceEntry {
                    algorithm: "kyber".into(),
                    nist_level: 3,
                    status: "standardized".into(),
                    key_exchange: Some(vec!["TLS 1.3".into()]),
                    signature: None,
                    classical_security_bits: Some(192),
                },
                PqcReferenceEntry {
                    algorithm: "dilithium".into(),
                    nist_level: 2,
                    status: "standardized".into(),
                    key_exchange: None,
                    signature: Some(vec!["X.509".into(), "SSH".into()]),
                    classical_security_bits: Some(128),
                },
            ],
        }
    }

    pub fn evaluate(
        &self,
        _service: &str,
        algorithm: &str,
        _version: &str,
    ) -> PqcAuditResult {
        let algo_lower = algorithm.to_lowercase();

        let matched = self.entries.iter().find(|e| {
            e.algorithm.to_lowercase() == algo_lower
                || algo_lower.contains(&e.algorithm.to_lowercase())
                || e.algorithm.to_lowercase().contains(&algo_lower)
        });

        match matched {
            Some(entry) => {
                let is_quantum_safe = matches!(
                    entry.status.as_str(),
                    "standardized" | "recommended"
                );
                let risk_level = if is_quantum_safe {
                    "LOW"
                } else {
                    "MEDIUM"
                };
                let recommendation = if is_quantum_safe {
                    format!(
                        "Algorithme PQC {} (niveau NIST {}) standardisé — sicher pour usage actuel",
                        entry.algorithm, entry.nist_level
                    )
                } else {
                    format!(
                        "Algorithme {} non standardisé — envisager migration vers Kyber/Dilithium",
                        entry.algorithm
                    )
                };
                PqcAuditResult {
                    algorithm: entry.algorithm.clone(),
                    status: entry.status.clone(),
                    nist_level: entry.nist_level,
                    is_quantum_safe,
                    risk_level: risk_level.into(),
                    recommendation,
                }
            }
            None => {
                let is_classical = algo_lower.starts_with("rsa")
                    || algo_lower.starts_with("ecdsa")
                    || algo_lower.starts_with("ecdh")
                    || algo_lower.contains("aes")
                    || algo_lower.contains("chacha")
                    || algo_lower.contains("poly1305")
                    || algo_lower.contains("sha");
                let risk_level = if is_classical {
                    "HIGH"
                } else {
                    "MEDIUM"
                };
                let recommendation = if is_classical {
                    format!(
                        "Algorithme classique {algorithm} — vulnérable aux attaques quantiques, migrer vers PQC NIST"
                    )
                } else {
                    format!(
                        "Algorithme {algorithm} non reconnu dans la référence NIST PQC — vérifier manuellement"
                    )
                };
                PqcAuditResult {
                    algorithm: algorithm.into(),
                    status: if is_classical {
                        "classical-vulnerable"
                    } else {
                        "unknown"
                    }
                    .into(),
                    nist_level: 0,
                    is_quantum_safe: false,
                    risk_level: risk_level.into(),
                    recommendation,
                }
            }
        }
    }

    pub fn parse_crypto_from_banner<'a>(
        &self,
        banner: &'a str,
    ) -> Vec<(&'a str, &'a str)> {
        let mut detected = Vec::new();
        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("aes-128-gcm")
            || banner_lower.contains("aes-256-gcm")
            || banner_lower.contains("aes128-gcm")
            || banner_lower.contains("aes256-gcm")
        {
            detected.push(("AES-GCM", banner));
        }
        if banner_lower.contains("chacha20") {
            detected.push(("ChaCha20", banner));
        }
        if banner_lower.contains("ecdsa") || banner_lower.contains("ecdh") {
            detected.push(("ECDH/ECDSA", banner));
        }
        if banner_lower.contains("rsa") {
            detected.push(("RSA", banner));
        }
        if banner_lower.contains("kyber") || banner_lower.contains("x25519kyber") {
            detected.push(("Kyber", banner));
        }
        if banner_lower.contains("dilithium") {
            detected.push(("Dilithium", banner));
        }
        if banner_lower.contains("ml-kem") || banner_lower.contains("ml-kem-768") {
            detected.push(("ML-KEM", banner));
        }
        if banner_lower.contains("ml-dsa") {
            detected.push(("ML-DSA", banner));
        }
        if banner_lower.contains("ssh") && banner_lower.contains("aes") {
            detected.push(("SSH-AES", banner));
        }
        detected
    }

    pub fn audit_service_banner(
        &self,
        service: &str,
        version: &str,
        banner: &str,
    ) -> Vec<PqcAuditReport> {
        let detected = self.parse_crypto_from_banner(banner);
        let mut reports = Vec::new();

        for (algo, _) in detected {
            let audit_result = self.evaluate(service, algo, version);
            let report = PqcAuditReport {
                service: service.into(),
                version: version.into(),
                algorithm_detected: algo.into(),
                audit_result,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            };
            reports.push(report);
        }

        reports
    }

    pub fn get_summary_stats(
        &self,
        reports: &[PqcAuditReport],
    ) -> HashMap<String, u32> {
        let mut stats = HashMap::new();
        for r in reports {
            *stats
                .entry(r.audit_result.status.clone())
                .or_insert(0) += 1;
            *stats
                .entry(r.audit_result.risk_level.clone())
                .or_insert(0) += 1;
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_known_classical() {
        let auditor = PqcAuditor::in_memory();
        let result = auditor.evaluate("ssh", "AES-256-GCM", "8.9");
        assert_eq!(result.status, "classical-vulnerable");
        assert!(!result.is_quantum_safe);
        assert_eq!(result.risk_level, "HIGH");
    }

    #[test]
    fn test_evaluate_kyber() {
        let auditor = PqcAuditor::in_memory();
        let result = auditor.evaluate("tls", "Kyber", "1.3");
        assert_eq!(result.status, "standardized");
        assert!(result.is_quantum_safe);
        assert_eq!(result.risk_level, "LOW");
    }

    #[test]
    fn test_evaluate_unknown() {
        let auditor = PqcAuditor::in_memory();
        let result = auditor.evaluate("ssh", "Blowfish", "2.0");
        assert!(!result.is_quantum_safe);
        assert_eq!(result.risk_level, "MEDIUM");
    }

    #[test]
    fn test_parse_crypto_from_banner() {
        let auditor = PqcAuditor::in_memory();
        let detected = auditor.parse_crypto_from_banner(
            "SSH-2.0-OpenSSH_9.3 aes256-gcm,chacha20-poly1305 ecdsa-sha2-nistp256"
        );
        assert!(!detected.is_empty());
        let algo_names: Vec<&str> = detected.iter().map(|(a, _)| *a).collect();
        assert!(algo_names.contains(&"AES-GCM"));
        assert!(algo_names.contains(&"ECDH/ECDSA"));
    }

    #[test]
    fn test_audit_service_banner_generates_reports() {
        let auditor = PqcAuditor::in_memory();
        let reports = auditor.audit_service_banner(
            "ssh",
            "9.3",
            "SSH-2.0-OpenSSH_9.3 aes256-gcm ecdsa-sha2-nistp256"
        );
        assert!(!reports.is_empty());
        for r in &reports {
            assert!(!r.audit_result.recommendation.is_empty());
        }
    }
}
