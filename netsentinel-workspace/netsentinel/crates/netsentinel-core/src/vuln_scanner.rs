use anyhow::{anyhow, Context, Result};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const EXPECTED_SHA256: &str =
    "a25df4f6a3e73d8a4105f6401cacdffdc7f1b473f96e1621a4be71d6348fa71e";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnProfile {
    pub service: String,
    pub regex: String,
    pub cve: String,
    pub summary: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub service: String,
    pub cve: String,
    pub summary: String,
    pub severity: Severity,
    pub matched_banner: String,
}

#[derive(Debug)]
pub struct VulnScanner {
    profiles: Vec<(VulnProfile, Regex)>,
    regex_set: Option<RegexSet>,
    pub actual_sha256: Option<String>,
}

impl VulnScanner {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
            regex_set: None,
            actual_sha256: None,
        }
    }

    pub fn load_from_json_string(
        content: &str,
        strict: bool,
        expected_sha256: &str,
    ) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let actual_sha256 = format!("{:x}", hasher.finalize());

        if strict && actual_sha256 != expected_sha256 {
            return Err(anyhow!(
                "Refus chargement vuln_database — intégrité SHA256 violée. Expected={} Got={}",
                expected_sha256,
                actual_sha256
            ));
        }

        let parsed: serde_json::Value =
            serde_json::from_str(content).context("Parsing JSON vuln_database a échoué")?;

        let profiles_json = parsed
            .get("profiles")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("profiles array manquant / mauvais type"))?;

        let mut scanner = Self::new();
        scanner.actual_sha256 = Some(actual_sha256);

        for p in profiles_json {
            let service = p.get("service").and_then(|v| v.as_str()).unwrap_or("");
            let regex_str = p.get("regex").and_then(|v| v.as_str()).unwrap_or("");
            let cve = p.get("cve").and_then(|v| v.as_str()).unwrap_or("");
            let summary = p.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let severity_str = p.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");

            if regex_str.is_empty() {
                continue;
            }

            let severity = match severity_str.to_uppercase().as_str() {
                "LOW" => Severity::Low,
                "MEDIUM" => Severity::Medium,
                "HIGH" => Severity::High,
                "CRITICAL" => Severity::Critical,
                _ => Severity::Info,
            };

            if let Ok(re) = Regex::new(regex_str) {
                let profile = VulnProfile {
                    service: service.to_string(),
                    regex: regex_str.to_string(),
                    cve: cve.to_string(),
                    summary: summary.to_string(),
                    severity,
                };
                scanner.profiles.push((profile, re));
            }
        }

        let regex_patterns: Vec<&str> = scanner
            .profiles
            .iter()
            .map(|(p, _)| p.regex.as_str())
            .collect();
        if let Ok(set) = RegexSet::new(&regex_patterns) {
            scanner.regex_set = Some(set);
        }

        Ok(scanner)
    }

    pub fn load_from_file(
        path: impl AsRef<Path>,
        strict: bool,
        expected_sha256: &str,
    ) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "Impossible de lire le fichier vuln_database : {:?}",
                path.as_ref()
            )
        })?;
        Self::load_from_json_string(&content, strict, expected_sha256)
    }

    pub fn audit_banner(&self, banner: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        if banner.trim().is_empty() {
            return findings;
        }

        if let Some(set) = &self.regex_set {
            let matches = set.matches(banner);
            for index in matches {
                let (profile, _) = &self.profiles[index];
                findings.push(VulnFinding {
                    service: profile.service.clone(),
                    cve: profile.cve.clone(),
                    summary: profile.summary.clone(),
                    severity: profile.severity,
                    matched_banner: banner.trim().to_string(),
                });
            }
        } else {
            for (profile, re) in &self.profiles {
                if re.is_match(banner) {
                    findings.push(VulnFinding {
                        service: profile.service.clone(),
                        cve: profile.cve.clone(),
                        summary: profile.summary.clone(),
                        severity: profile.severity,
                        matched_banner: banner.trim().to_string(),
                    });
                }
            }
        }

        findings
    }

    pub async fn grab_banner(target: &str, port: u16, timeout: Duration) -> Result<String> {
        let addr = format!("{}:{}", target, port);
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow!("Timeout connection à {}", addr))??;

        let mut buf = [0u8; 1024];
        let read_res = tokio::time::timeout(timeout, stream.read(&mut buf)).await;

        match read_res {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                if !banner.is_empty() {
                    return Ok(banner);
                }
            }
            _ => {}
        }

        // Try sending HTTP probe to trigger a server response banner
        let probe = b"HEAD / HTTP/1.0\r\n\r\n";
        let _ = stream.write_all(probe).await;

        let mut buf = [0u8; 1024];
        if let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            if n > 0 {
                return Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string());
            }
        }

        Ok(String::new())
    }
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DB_JSON: &str = r#"{
        "title": "NetSentinel Vulnerability DB",
        "version": "1.0",
        "profiles": [
            {
                "service": "OpenSSH",
                "regex": "OpenSSH_([0-8]\\.|9\\.[0-7])",
                "cve": "CVE-2024-6387",
                "summary": "RCE via regreSSHion in OpenSSH",
                "severity": "CRITICAL"
            },
            {
                "service": "nginx",
                "regex": "nginx/1\\.(1[0-8]|20)",
                "cve": "CVE-2021-23017",
                "summary": "1-byte memory overwrite in resolver",
                "severity": "HIGH"
            }
        ]
    }"#;

    #[test]
    fn test_vuln_scanner_regex_matching() -> Result<()> {
        let scanner = VulnScanner::load_from_json_string(SAMPLE_DB_JSON, false, "")?;

        // Test OpenSSH regreSSHion match
        let findings = scanner.audit_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cve, "CVE-2024-6387");
        assert_eq!(findings[0].severity, Severity::Critical);

        // Test safe OpenSSH (no match)
        let safe_findings = scanner.audit_banner("SSH-2.0-OpenSSH_9.8p1");
        assert_eq!(safe_findings.len(), 0);

        Ok(())
    }

    #[test]
    fn test_sha256_strict_integrity_rejection() {
        let err = VulnScanner::load_from_json_string(
            SAMPLE_DB_JSON,
            true,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("intégrité SHA256 violée"));
    }
}
