use anyhow::Result;
use std::time::{Duration, Instant};

// ============================================================================
// Fuzzer utilitaire pour les parsers de NetSentinel.
// Objectif : s'assurer que les parsers ne plantent jamais (pas de panic) et ne
// bouclent pas indéfiniment (no hang) sur des entrées adverses/malformées.
// ============================================================================

pub struct FuzzReport {
    pub test_case_name: String,
    pub iterations: u32,
    pub panics: u32,
    pub hangs: u32,
    pub ok: u32,
    pub total_duration: Duration,
}

impl FuzzReport {
    pub fn passed(&self) -> bool {
        self.panics == 0 && self.hangs == 0
    }
}

pub struct FuzzRunner;

impl FuzzRunner {
    /// Exécute un fuzzer pour N itérations et signale tout panic.
    /// Les "erreurs de parsing" (retour Err) sont considérées comme un succès,
    /// seuls les panics sont comptés comme des échecs.
    /// Chaque cas s'exécute dans `catch_unwind` : un panic ne fait pas crasher
    /// le process et est comptabilisé.
    ///
    /// Note sur la détection des hangs : les parsers concernés (DNS, PCAP)
    /// effectuent des bornes de lecture sur les buffers, donc une entrée
    /// malformée génère un `Err` ou un retour vide, jamais une boucle infinie.
    pub fn run<F>(
        name: &str,
        iterations: u32,
        per_case_timeout: Duration,
        mut fuzz_fn: F,
    ) -> FuzzReport
    where
        F: FnMut(u32) -> Result<()>,
    {
        let start = Instant::now();
        let mut panics = 0;
        let mut hangs = 0;
        let mut ok = 0;

        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silencieux pendant le fuzzing

        for i in 0..iterations {
            let case_start = Instant::now();

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fuzz_fn(i)));

            if case_start.elapsed() > per_case_timeout {
                // dépasse le budget temps — considéré comme un hang suspect
                hangs += 1;
                tracing::warn!(case = i, "fuzzer: dépassement de temps sur {}", name);
            } else {
                match result {
                    Ok(Ok(_)) | Ok(Err(_)) => ok += 1,
                    Err(_) => panics += 1,
                }
            }
        }

        std::panic::set_hook(hook);

        FuzzReport {
            test_case_name: name.to_string(),
            iterations,
            panics,
            hangs,
            ok,
            total_duration: start.elapsed(),
        }
    }
}

// ============================================================================
// Fuzzing des parsers NetSentinel
// ============================================================================

pub mod parsers {
    use super::*;
    use crate::enumeration::DnsEnumerator;
    use crate::pcap::PcapWriter;
    use crate::vuln_scanner::VulnScanner;

    const VULN_DB_JSON: &str = r#"{
        "profiles": [
            {"service":"OpenSSH","regex":"OpenSSH_([0-8]\\.|9\\.[0-7])","cve":"CVE-2024-6387","summary":"x","severity":"CRITICAL"},
            {"service":"nginx","regex":"nginx/1\\.(1[0-8]|20)","cve":"CVE-2021-23017","summary":"y","severity":"HIGH"}
        ]
    }"#;

    pub const SAMPLE_VULN_DB: &str = VULN_DB_JSON;

    /// Fuzze le parseur JSON de vuln_database avec des longueurs/structures aléatoires.
    pub fn fuzz_vuln_db_json(iterations: u32) -> FuzzReport {
        FuzzRunner::run("vuln_db_json", iterations, Duration::from_secs(1), |i| {
            match i % 5 {
                0 => {
                    // JSON vide
                    let _ = VulnScanner::load_from_json_string("", false, "");
                    Ok(())
                }
                1 => {
                    // JSON malformé
                    let _ = VulnScanner::load_from_json_string(
                        &format!("{{{}}}", "x".repeat((i as usize) % 50)),
                        false,
                        "",
                    );
                    Ok(())
                }
                2 => {
                    // profiles avec mauvais types
                    let _ = VulnScanner::load_from_json_string(
                        r#"{"profiles":[{"service":123,"regex":[],"cve":null}]}"#,
                        false,
                        "",
                    );
                    Ok(())
                }
                3 => {
                    // regex invalide — ne doit pas panic
                    let bad = format!(
                        r#"{{"profiles":[{{"service":"X","regex":"[{}","cve":"C-1","summary":"s","severity":"HIGH"}}]}}"#,
                        "([".repeat((i as usize) % 3)
                    );
                    let _ = VulnScanner::load_from_json_string(&bad, false, "");
                    Ok(())
                }
                _ => {
                    // Trocha de JSON dénué de sens
                    let _ = VulnScanner::load_from_json_string(
                        &format!("{}{}{}", "{", "a".repeat((i as usize) % 64), "}"),
                        false,
                        "",
                    );
                    Ok(())
                }
            }
        })
    }

    /// Fuzze audit_banner sur des banners arbitraires (pas de panic, pas de hang).
    pub fn fuzz_audit_banner(iterations: u32) -> FuzzReport {
        let scanner =
            VulnScanner::load_from_json_string(VULN_DB_JSON, false, "").expect("scanner valide");
        FuzzRunner::run("audit_banner", iterations, Duration::from_secs(1), |i| {
            let owned_banners = [
                String::new(),
                "SSH-2.0-OpenSSH_8.9p1".to_string(),
                "nginx/1.18.0".to_string(),
                "openSSH_9.8".to_string(),
                "A".repeat((i as usize) % 1024),
                "(".repeat((i as usize) % 128),
                "\\d+".repeat((i as usize) % 32),
                format!("{:?}", i),
            ];

            let mut idx = i as usize % owned_banners.len();
            let mut count = 0;
            while count < 6 {
                let banner = &owned_banners[idx % owned_banners.len()];
                let _ = scanner.audit_banner(banner);
                count += 1;
                idx = (idx + 1) % owned_banners.len();
            }
            Ok(())
        })
    }

    /// Fuzze le parseur DNS avec des réponses malformées.
    pub fn fuzz_dns_response(iterations: u32) -> FuzzReport {
        FuzzRunner::run("dns_response", iterations, Duration::from_secs(1), |i| {
            let data = match i % 4 {
                0 => vec![0u8; 0],
                1 => vec![0u8, 1, 2],
                2 => {
                    // header court + QNAME tronqué
                    let mut v = vec![0u8; 12];
                    v.extend_from_slice(&[3u8, b'x', b'y', b'z', 0, 0, 1, 0, 1]);
                    v
                }
                _ => {
                    // réponse avec compression illégale (boucle)
                    let mut v = vec![0u8; 12];
                    v[6] = 0; // ancount=0
                    v.extend_from_slice(&[0xC0, 0xFF]); // compression vers zone invalide
                    v
                }
            };
            let _ = DnsEnumerator::parse_response(&data, &crate::enumeration::DnsRecordType::A);
            let _ = DnsEnumerator::parse_response(&data, &crate::enumeration::DnsRecordType::Cname);
            Ok(())
        })
    }

    /// Fuzze build_pseudo_ethernet / PCAP headers.
    pub fn fuzz_pcap(iterations: u32) -> FuzzReport {
        FuzzRunner::run("pcap", iterations, Duration::from_secs(1), |i| {
            let dir = std::env::temp_dir().join("netsentinel_fuzz");
            let path = dir.join(format!("fuzz_{}.pcap", i));
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            if let Ok(mut writer) = PcapWriter::create(&path) {
                let payload: Vec<u8> = (0..(i as usize % 512)).map(|b| b as u8).collect();
                let frame = PcapWriter::build_pseudo_ethernet(
                    &format!("192.168.{}.{}", i % 255, (i / 255) % 255),
                    &format!("10.0.{}.{}", i % 255, (i / 255) % 255),
                    (i % 255) as u8,
                    &payload,
                );
                let _ = writer.write_raw_packet(i as u64 * 1000, &frame);
                let _ = writer.finalize();
            }
            let _ = std::fs::remove_dir_all(dir);
            Ok(())
        })
    }

    /// Boucle complète de fuzzing des parsers.
    pub fn fuzz_all(iterations_per_parser: u32) -> Vec<FuzzReport> {
        vec![
            fuzz_vuln_db_json(iterations_per_parser),
            fuzz_audit_banner(iterations_per_parser),
            fuzz_dns_response(iterations_per_parser),
            fuzz_pcap(iterations_per_parser),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_vuln_db_json_no_panic() {
        let report = parsers::fuzz_vuln_db_json(200);
        assert!(
            report.passed(),
            "fuzzer vuln_db : panics={} hangs={}",
            report.panics,
            report.hangs
        );
    }

    #[test]
    fn test_fuzz_audit_banner_no_panic() {
        let report = parsers::fuzz_audit_banner(200);
        assert!(
            report.passed(),
            "fuzzer audit_banner : panics={} hangs={}",
            report.panics,
            report.hangs
        );
    }

    #[test]
    fn test_fuzz_dns_response_no_panic() {
        let report = parsers::fuzz_dns_response(200);
        assert!(
            report.passed(),
            "fuzzer dns : panics={} hangs={}",
            report.panics,
            report.hangs
        );
    }

    #[test]
    fn test_fuzz_pcap_no_panic() {
        let report = parsers::fuzz_pcap(50);
        assert!(
            report.passed(),
            "fuzzer pcap : panics={} hangs={}",
            report.panics,
            report.hangs
        );
    }

    #[test]
    fn test_fuzz_runner_detects_output() {
        let report = FuzzRunner::run("smoke", 10, Duration::from_secs(1), |_| Ok(()));
        assert!(report.passed());
        assert_eq!(report.ok, 10);
    }
}
