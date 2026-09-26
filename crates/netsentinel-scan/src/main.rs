//! netsentinel-scand
//!
//! Service D-Bus `org.netsentinel.Scan1`. Pilote nmap (découverte de
//! ports/services — inchangé, rien à réimplémenter) puis Nuclei (détection
//! de CVE par templates YAML, plus à jour que les scripts NSE `--script
//! vuln`) et consolide les deux en une liste de `ScanFinding` structurée.
//!
//! Important : ce service ne tourne PAS en root. Il a uniquement besoin de
//! sockets réseau normales — `nmap -sV` (sans `-sS`/scan SYN qui exige
//! CAP_NET_RAW) et `nuclei` fonctionnent tous deux en scan TCP connect
//! classique. Voir packaging/apparmor/usr.libexec.netsentinel-scand.

use anyhow::{Context, Result};
use netsentinel_proto::{ScanFinding, Severity, SCAN_BUS_NAME, SCAN_OBJECT_PATH};
use serde::Deserialize;
use tokio::process::Command;
use tracing::warn;
use zbus::{connection, interface};

struct ScanService;

#[interface(name = "org.netsentinel.Scan1")]
impl ScanService {
    async fn deep_scan(&self, target: &str) -> zbus::fdo::Result<Vec<ScanFinding>> {
        tracing::info!(%target, "démarrage du scan approfondi");

        let mut findings =
            tokio::time::timeout(std::time::Duration::from_secs(100), run_nmap(target))
                .await
                .map_err(|_| zbus::fdo::Error::Failed("timeout nmap (>100s)".into()))?
                .map_err(|e| zbus::fdo::Error::Failed(format!("échec nmap: {e}")))?;

        if std::env::var_os("NETSENTINEL_SKIP_NUCLEI").is_some() {
            return Ok(findings);
        }
        match tokio::time::timeout(std::time::Duration::from_secs(100), run_nuclei(target)).await {
            Ok(Ok(nf)) => findings.extend(nf),
            Ok(Err(e)) => {
                warn!(%target, "Nuclei indisponible (optionnel) — poursuite avec nmap seul: {e}");
            }
            Err(_) => {
                warn!(%target, "Nuclei timeout (>100s) — poursuite avec nmap seul");
            }
        }

        tracing::info!(count = findings.len(), "scan terminé");
        Ok(findings)
    }
}

/// Découverte de ports/services via nmap, sortie "greppable" (`-oG -`) qui
/// évite une dépendance de parsing XML pour ce scaffold.
async fn run_nmap(target: &str) -> Result<Vec<ScanFinding>> {
    let bin = if std::path::Path::new("/usr/bin/nmap").exists() {
        "/usr/bin/nmap"
    } else {
        "nmap"
    };
    let output = Command::new(bin)
        .args([
            "-sV",
            "-T4",
            "-F",
            "--host-timeout",
            "60s",
            "-oG",
            "-",
            target,
        ])
        .output()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "lancement de nmap ({bin}: {e}; vérifier installation + profil AppArmor ix)"
            )
        })?;

    if !output.status.success() {
        anyhow::bail!("nmap a retourné un code d'erreur: {}", output.status);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    for line in stdout.lines().filter(|l| l.starts_with("Host:")) {
        // Format greppable : "Host: 192.168.1.1 ()  Ports: 80/open/tcp//http///, 443/open/tcp//https///"
        let Some(ports_section) = line.split("Ports: ").nth(1) else {
            continue;
        };
        for port_entry in ports_section.split(", ") {
            let fields: Vec<&str> = port_entry.split('/').collect();
            if fields.len() < 5 || fields[1] != "open" {
                continue;
            }
            findings.push(ScanFinding {
                target: target.to_string(),
                port: fields[0].parse().unwrap_or(0),
                service: fields[4].to_string(),
                cve: String::new(),
                severity: Severity::Info,
                description: format!("Port ouvert détecté par nmap ({}/{})", fields[0], fields[2]),
            });
        }
    }

    Ok(findings)
}

#[derive(Debug, Deserialize)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    template_id: String,
    info: NucleiInfo,
    #[serde(default)]
    host: String,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: String,
    severity: String,
    #[serde(default)]
    classification: Option<NucleiClassification>,
}

#[derive(Debug, Deserialize)]
struct NucleiClassification {
    #[serde(rename = "cve-id", default)]
    cve_id: Vec<String>,
}

/// Détection de CVE/misconfigurations via Nuclei (sortie JSON Lines, une
/// ligne par finding — beaucoup plus simple à consommer que le XML nmap).
///
/// IMPORTANT : ce code tourne en tant qu'utilisateur système `netsentinel-scan`
/// (sans $HOME writable ni accès réseau non explicit pour download de
/// templates). On force donc -no-update + -ut pour éviter toute tentative de
/// mise à jour des YAML (templating offline uniquement via ceux installés
/// système dans /usr/share/nuclei-templates/ ou le PPA ProjectDiscovery).
async fn run_nuclei(target: &str) -> Result<Vec<ScanFinding>> {
    let bin = ["/usr/bin/nuclei", "/usr/local/bin/nuclei", "nuclei"]
        .into_iter()
        .find(|p| {
            if p.contains('/') {
                std::path::Path::new(p).exists()
            } else {
                true
            }
        })
        .unwrap_or("nuclei");
    if bin.contains('/') && !std::path::Path::new(bin).exists() {
        tracing::info!("nuclei absent, audit dégradé nmap seul");
        return Ok(Vec::new());
    }
    let output = Command::new(bin)
        .args([
            "-target",
            target,
            "-jsonl",
            "-silent",
            "-no-update",
            "-ut",
            "-update-templates-url",
            "file:///usr/share/nuclei-templates",
            "-timeout",
            "5",
            "-rl",
            "150",
            "-c",
            "25",
            "-retries",
            "0",
            "-severity",
            "critical,high,medium",
            "-etags",
            "intrusive,fuzz",
        ])
        .output()
        .await
        .context("lancement de nuclei (vérifier qu'il est installé et dans le PATH)")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(result) = serde_json::from_str::<NucleiResult>(line) else {
            tracing::warn!(%line, "ligne nuclei non parsable, ignorée");
            continue;
        };

        let cve = result
            .info
            .classification
            .and_then(|c| c.cve_id.first().cloned());

        findings.push(ScanFinding {
            target: result.host,
            port: 0,
            service: String::new(),
            cve: cve.unwrap_or_default(),
            severity: map_severity(&result.info.severity),
            description: format!("{} ({})", result.info.name, result.template_id),
        });
    }

    Ok(findings)
}

fn map_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let _conn = connection::Builder::system()?
        .name(SCAN_BUS_NAME)?
        .serve_at(SCAN_OBJECT_PATH, ScanService)?
        .build()
        .await
        .context("impossible de démarrer le service D-Bus Scan1")?;

    tracing::info!(bus = SCAN_BUS_NAME, "netsentinel-scand prêt");
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests;
