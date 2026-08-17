use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::ledger::AuditEntry;
use crate::vuln_scanner::VulnFinding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Markdown,
    Json,
    Html,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_markdown(
        title: &str,
        findings: &[VulnFinding],
        ledger_entries: &[AuditEntry],
    ) -> String {
        let mut md = String::new();
        let now = Utc::now().to_rfc3339();

        md.push_str(&format!("# Rapport de Sécurité NetSentinel — {}\n\n", title));
        md.push_str(&format!("**Généré le :** {}\n", now));
        md.push_str(&format!("**Total des vulnérabilités identifiées :** {}\n", findings.len()));
        md.push_str(&format!("**Total des événements d'audit :** {}\n\n", ledger_entries.len()));

        md.push_str("---\n\n");
        md.push_str("## 1. Vulnérabilités Identifiées\n\n");

        if findings.is_empty() {
            md.push_str("*Aucune vulnérabilité n'a été détectée dans le périmètre visualisé.*\n\n");
        } else {
            md.push_str("| Service | CVE | Sévérité | Résumé | Bannière |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
            for f in findings {
                md.push_str(&format!(
                    "| {} | `{}` | **{}** | {} | `{}` |\n",
                    f.service,
                    if f.cve.is_empty() { "N/A" } else { &f.cve },
                    f.severity.as_str(),
                    f.summary,
                    f.matched_banner.replace('|', "\\|")
                ));
            }
            md.push('\n');
        }

        md.push_str("## 2. Journal Cryptographique d'Audit (Ledger)\n\n");

        if ledger_entries.is_empty() {
            md.push_str("*Aucun enregistrement d'audit disponible dans le registre.*\n\n");
        } else {
            md.push_str("| ID | Horodatage | Action | Statut PDDL | Hash SHA-256 (Empreinte) |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
            for e in ledger_entries {
                let short_hash = if e.hash.len() > 16 {
                    format!("{}...", &e.hash[..16])
                } else {
                    e.hash.clone()
                };
                md.push_str(&format!(
                    "| {} | {} | {} | `{}` | `{}` |\n",
                    e.id, e.timestamp, e.action, e.pddl_status, short_hash
                ));
            }
            md.push('\n');
        }

        md.push_str("---\n*NetSentinel Cybersecurity Platform — Conforme PDDL & Cryptographie Post-Quantique*\n");
        md
    }

    pub fn generate_json(
        title: &str,
        findings: &[VulnFinding],
        ledger_entries: &[AuditEntry],
    ) -> String {
        let report_obj = serde_json::json!({
            "title": title,
            "generated_at": Utc::now().to_rfc3339(),
            "findings_count": findings.len(),
            "findings": findings,
            "audit_ledger_count": ledger_entries.len(),
            "audit_ledger": ledger_entries,
        });

        serde_json::to_string_pretty(&report_obj).unwrap_or_default()
    }

    pub fn generate_html(
        title: &str,
        findings: &[VulnFinding],
        ledger_entries: &[AuditEntry],
    ) -> String {
        let mut html = String::new();
        let now = Utc::now().to_rfc3339();

        html.push_str("<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<title>NetSentinel Security Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 2rem; }\n");
        html.push_str("h1, h2 { color: #38bdf8; }\n");
        html.push_str("table { width: 100%; border-collapse: collapse; margin-top: 1rem; margin-bottom: 2rem; }\n");
        html.push_str("th, td { border: 1px solid #334155; padding: 12px; text-align: left; }\n");
        html.push_str("th { background: #1e293b; color: #f1f5f9; }\n");
        html.push_str("tr:nth-child(even) { background: #1e293b; }\n");
        html.push_str("code { background: #0284c7; padding: 2px 6px; border-radius: 4px; color: #fff; }\n");
        html.push_str(".badge-critical { background: #ef4444; padding: 4px 8px; border-radius: 4px; font-weight: bold; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str(&format!("<h1>Rapport de Sécurité NetSentinel — {}</h1>\n", title));
        html.push_str(&format!("<p><strong>Généré le :</strong> {}</p>\n", now));

        html.push_str("<h2>1. Vulnérabilités Identifiées</h2>\n");
        html.push_str("<table><thead><tr><th>Service</th><th>CVE</th><th>Sévérité</th><th>Résumé</th></tr></thead><tbody>\n");
        for f in findings {
            html.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td><span class=\"badge-critical\">{}</span></td><td>{}</td></tr>\n",
                f.service,
                if f.cve.is_empty() { "N/A" } else { &f.cve },
                f.severity.as_str(),
                f.summary
            ));
        }
        html.push_str("</tbody></table>\n");

        html.push_str("<h2>2. Journal Cryptographique d'Audit</h2>\n");
        html.push_str("<table><thead><tr><th>ID</th><th>Horodatage</th><th>Action</th><th>Statut PDDL</th><th>Hash SHA-256</th></tr></thead><tbody>\n");
        for e in ledger_entries {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>\n",
                e.id, e.timestamp, e.action, e.pddl_status, e.hash
            ));
        }
        html.push_str("</tbody></table>\n</body>\n</html>\n");

        html
    }

    pub fn export_report(
        path: impl AsRef<Path>,
        format: ExportFormat,
        title: &str,
        findings: &[VulnFinding],
        ledger_entries: &[AuditEntry],
    ) -> Result<()> {
        let content = match format {
            ExportFormat::Markdown => Self::generate_markdown(title, findings, ledger_entries),
            ExportFormat::Json => Self::generate_json(title, findings, ledger_entries),
            ExportFormat::Html => Self::generate_html(title, findings, ledger_entries),
        };

        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Échec création dossier parent rapport : {:?}", parent))?;
        }

        std::fs::write(path.as_ref(), content)
            .with_context(|| format!("Échec écriture du rapport : {:?}", path.as_ref()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln_scanner::Severity;

    #[test]
    fn test_report_generation_formats() -> Result<()> {
        let findings = vec![VulnFinding {
            service: "OpenSSH".to_string(),
            cve: "CVE-2024-6387".to_string(),
            summary: "RCE regreSSHion".to_string(),
            severity: Severity::Critical,
            matched_banner: "SSH-2.0-OpenSSH_8.9p1".to_string(),
        }];

        let entries = vec![AuditEntry {
            id: 1,
            timestamp: "2026-08-17T14:00:00Z".to_string(),
            agent_id: Some("agent-1".to_string()),
            model_version: None,
            action: "SCAN".to_string(),
            input_data: None,
            output_data: None,
            pddl_status: "COMPLIANT".to_string(),
            pddl_rule_violation: None,
            prev_hash: "0".repeat(64),
            hash: "a".repeat(64),
        }];

        let md = ReportGenerator::generate_markdown("Test Audit", &findings, &entries);
        assert!(md.contains("# Rapport de Sécurité NetSentinel — Test Audit"));
        assert!(md.contains("CVE-2024-6387"));

        let json = ReportGenerator::generate_json("Test Audit", &findings, &entries);
        assert!(json.contains("CVE-2024-6387"));

        let html = ReportGenerator::generate_html("Test Audit", &findings, &entries);
        assert!(html.contains("<title>NetSentinel Security Report</title>"));

        Ok(())
    }
}
