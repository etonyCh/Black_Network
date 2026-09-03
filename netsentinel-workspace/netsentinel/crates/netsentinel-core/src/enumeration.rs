use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Mx,
    Ns,
    Txt,
    Cname,
    Soa,
}

impl DnsRecordType {
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Mx => 15,
            Self::Ns => 2,
            Self::Txt => 16,
            Self::Cname => 5,
            Self::Soa => 6,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub ip_addresses: Vec<String>,
    pub found: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryResult {
    pub path: String,
    pub status_code: u16,
    pub content_length: u64,
    pub redirect: Option<String>,
    pub interesting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerationReport {
    pub domain: String,
    pub dns_records: Vec<DnsResult>,
    pub subdomains: Vec<SubdomainResult>,
    pub directories: Vec<DirectoryResult>,
    pub timestamp: f64,
    pub duration_secs: f64,
}

// ============================================================================
// DNS Enumerator
// ============================================================================

pub struct DnsEnumerator {
    resolver: String,
    timeout_ms: u32,
}

impl Clone for DnsEnumerator {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            timeout_ms: self.timeout_ms,
        }
    }
}

impl DnsEnumerator {
    pub fn new(resolver: &str, timeout_ms: u32) -> Self {
        Self {
            resolver: resolver.to_string(),
            timeout_ms,
        }
    }

    pub fn default_resolver() -> Self {
        Self::new("8.8.8.8", 3000)
    }

    fn build_query(domain: &str, record_type: &DnsRecordType) -> Vec<u8> {        let mut query = Vec::with_capacity(512);

        // Transaction ID
        let tx_id: u16 = 0x1234;
        query.extend_from_slice(&tx_id.to_be_bytes());
        // Flags: standard query, recursion desired
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        // Questions: 1, Answer/Auth/Additional: 0
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());

        // QNAME
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // root label

        // QTYPE + QCLASS
        query.extend_from_slice(&record_type.as_u16().to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes()); // IN class

        query
    }

    pub fn parse_response(data: &[u8], record_type: &DnsRecordType) -> Vec<(String, u32, String)> {
        let mut results = Vec::new();
        if data.len() < 12 {
            return results;
        }

        let answer_count = u16::from_be_bytes([data[6], data[7]]) as usize;

        // Sauter le header (12) + parser QNAME pour trouver la fin des questions
        let mut offset = 12;
        while offset < data.len() && data[offset] != 0 {
            let label_len = data[offset] as usize;
            if label_len & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + label_len;
        }
        offset += 5; // null + QTYPE(2) + QCLASS(2)

        for _ in 0..answer_count {
            if offset + 12 > data.len() {
                break;
            }

            // Name (potentiellement compressé)
            if data[offset] & 0xC0 == 0xC0 {
                offset += 2;
            } else {
                while offset < data.len() && data[offset] != 0 {
                    offset += 1 + data[offset] as usize;
                }
                offset += 1;
            }

            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let _class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let rdata = &data[offset..offset + rdlength];

            match rtype {
                1 if rdlength == 4 => {
                    // A record
                    let ip = format!(
                        "{}.{}.{}.{}",
                        rdata[0], rdata[1], rdata[2], rdata[3]
                    );
                    results.push((record_type.as_str().to_string(), ttl, ip));
                }
                28 if rdlength == 16 => {
                    // AAAA record
                    let ip = std::net::Ipv6Addr::from([
                        rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5], rdata[6],
                        rdata[7], rdata[8], rdata[9], rdata[10], rdata[11], rdata[12], rdata[13],
                        rdata[14], rdata[15],
                    ]);
                    results.push((record_type.as_str().to_string(), ttl, ip.to_string()));
                }
                15 if rdlength >= 3 => {
                    // MX record
                    let preference =
                        u16::from_be_bytes([rdata[0], rdata[1]]);
                    let exchange = Self::parse_name(data, offset);
                    results.push((
                        "MX".to_string(),
                        ttl,
                        format!("{preference} {exchange}"),
                    ));
                }
                2 => {
                    // NS record
                    let ns = Self::parse_name(data, offset);
                    results.push(("NS".to_string(), ttl, ns));
                }
                5 => {
                    // CNAME
                    let cname = Self::parse_name(data, offset);
                    results.push(("CNAME".to_string(), ttl, cname));
                }
                16 => {
                    // TXT
                    let mut txt = String::new();
                    let mut i = 0;
                    while i < rdata.len() {
                        let len = rdata[i] as usize;
                        i += 1;
                        if i + len <= rdata.len() {
                            if !txt.is_empty() {
                                txt.push(' ');
                            }
                            txt.push_str(
                                &String::from_utf8_lossy(&rdata[i..i + len]),
                            );
                        }
                        i += len;
                    }
                    results.push(("TXT".to_string(), ttl, txt));
                }
                _ => {}
            }

            offset += rdlength;
        }

        results
    }

    /// Décode un nom DNS (éventuellement avec compression) depuis `data` à
    /// partir de `offset`. Protège contre les boucles de pointeurs malveillants
    /// (max 16 sauts) et les lectures hors bornes : retourne "" en cas de risque.
    fn parse_name(data: &[u8], offset: usize) -> String {
        let mut name = String::new();
        let mut pos = offset;
        let mut jumps = 0;
        let mut last_jump_pos = None;

        loop {
            if pos + 1 > data.len() {
                break;
            }
            let len = data[pos] as usize;

            if len == 0 {
                break;
            }
            if len & 0xC0 == 0xC0 {
                // Pointeur de compression (2 octets : 0b11 + offset 14 bits)
                if pos + 2 > data.len() {
                    break;
                }
                let target = u16::from_be_bytes([data[pos] & 0x3F, data[pos + 1]]) as usize;
                if target >= pos {
                    // pointeur vers l'avant = potentielle boucle → abandon
                    break;
                }
                jumps += 1;
                if jumps > 16 {
                    break; // trop de sauts → boucle de compression
                }
                if last_jump_pos == Some(pos) {
                    break;
                }
                last_jump_pos = Some(pos);
                pos = target;
                continue;
            }
            if len & 0xC0 != 0 {
                break; // label étendu non supporté
            }
            pos += 1;
            if pos + len > data.len() {
                break;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
            pos += len;
        }

        name
    }

    pub async fn query(
        &self,
        domain: &str,
        record_type: &DnsRecordType,
    ) -> Result<Vec<DnsResult>> {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind UDP pour DNS")?;
        sock.connect(&self.resolver).await?;

        let query = Self::build_query(domain, record_type);
        sock.send(&query).await?;

        let mut buf = vec![0u8; 4096];
        let n = timeout(
            Duration::from_millis(self.timeout_ms as u64),
            sock.recv(&mut buf),
        )
        .await
        .context("timeout DNS")?
        .context("recv DNS")?;
        buf.truncate(n);

        let parsed = Self::parse_response(&buf, record_type);
        Ok(parsed
            .into_iter()
            .map(|(rtype, ttl, value)| DnsResult {
                name: domain.to_string(),
                record_type: rtype,
                value,
                ttl,
            })
            .collect())
    }

    pub async fn enumerate_all(
        &self,
        domain: &str,
        record_types: &[DnsRecordType],
    ) -> Vec<DnsResult> {
        let mut all = Vec::new();
        for rt in record_types {
            if let Ok(results) = self.query(domain, rt).await {
                all.extend(results);
            }
        }
        all
    }
}

// ============================================================================
// Subdomain Brute-Force
// ============================================================================

pub struct SubdomainBruter {
    dns: DnsEnumerator,
    concurrency: usize,
}

impl SubdomainBruter {
    pub fn new(dns: DnsEnumerator, concurrency: usize) -> Self {
        Self { dns, concurrency }
    }

    pub fn default_bruter(domain: &str) -> Self {
        let _ = domain;
        Self::new(DnsEnumerator::default_resolver(), 20)
    }

    pub async fn brute(
        &self,
        domain: &str,
        wordlist: &[String],
    ) -> Vec<SubdomainResult> {
        use futures::stream::{self, StreamExt};

        let domain = domain.to_string();
        let dns = DnsEnumerator::new(&self.dns.resolver, self.dns.timeout_ms);
        let concurrency = self.concurrency;

        let results: Vec<SubdomainResult> = stream::iter(wordlist.iter())
            .map(|sub| {
                let domain = domain.clone();
                let dns = DnsEnumerator::new(&dns.resolver, dns.timeout_ms);
                async move {
                    let fqdn = format!("{sub}.{domain}");
                    match dns.query(&fqdn, &DnsRecordType::A).await {
                        Ok(records) if !records.is_empty() => {
                            let ips: Vec<String> =
                                records.into_iter().map(|r| r.value).collect();
                            SubdomainResult {
                                subdomain: fqdn,
                                ip_addresses: ips,
                                found: true,
                            }
                        }
                        _ => SubdomainResult {
                            subdomain: fqdn,
                            ip_addresses: Vec::new(),
                            found: false,
                        },
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        results
    }

    pub async fn brute_top(
        &self,
        domain: &str,
    ) -> Vec<SubdomainResult> {
        let wordlist = Self::default_wordlist();
        self.brute(domain, &wordlist).await
    }

    fn default_wordlist() -> Vec<String> {
        vec![
            "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
            "dns", "mx", "mx1", "mx2", "webmail", "email", "vpn", "proxy",
            "api", "dev", "staging", "test", "beta", "alpha", "admin",
            "portal", "login", "app", "cdn", "static", "media", "images",
            "blog", "news", "forum", "wiki", "docs", "support", "help",
            "shop", "store", "pay", "billing", "status", "monitor",
            "grafana", "prometheus", "jenkins", "ci", "cd", "git", "gitlab",
            "github", "bitbucket", "jira", "confluence", "sonarqube",
            "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
            "kibana", "logstash", "kafka", "rabbitmq", "nats",
            "k8s", "kubernetes", "docker", "registry", "harbor",
            "minio", "s3", "aws", "gcp", "azure", "cloud",
            "auth", "sso", "oauth", "ldap", "radius", "cert", "ca",
            "owa", "exchange", "sharepoint", "teams", "slack", "discord",
            "ipa", "freeipa", "zyxel", "unifi", "mikrotik", "pfsense",
            "router", "switch", "ap", "wifi", "iot", "cam", "camera",
            "nas", "backup", "archive", "log", "logs", "syslog", "ntp",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
}

// ============================================================================
// Directory Brute-Force (HTTP)
// ============================================================================

pub struct DirectoryBruter {
    base_url: String,
    concurrency: usize,
    timeout_ms: u32,
    interesting_status: Vec<u16>,
    wordlist: Vec<String>,
}

impl DirectoryBruter {
    pub fn new(base_url: &str, concurrency: usize, timeout_ms: u32) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            concurrency,
            timeout_ms,
            interesting_status: vec![200, 301, 302, 403, 500],
            wordlist: Vec::new(),
        }
    }

    pub fn with_wordlist(mut self, wordlist: Vec<String>) -> Self {
        self.wordlist = wordlist;
        self
    }

    pub async fn scan(&self, paths: &[String]) -> Vec<DirectoryResult> {
        use futures::stream::{self, StreamExt};

        let base = self.base_url.clone();
        let timeout_ms = self.timeout_ms;
        let interesting = self.interesting_status.clone();
        let concurrency = self.concurrency;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms as u64))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        let results: Vec<DirectoryResult> = stream::iter(paths.iter())
            .map(|path| {
                let url = format!("{}/{}", base, path.trim_start_matches('/'));
                let client = client.clone();
                let interesting = interesting.clone();
                async move {
                    match client.get(&url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let content_length = resp.content_length().unwrap_or(0);
                            let redirect = resp
                                .headers()
                                .get("location")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            let is_interesting = interesting.contains(&status);
                            DirectoryResult {
                                path: path.clone(),
                                status_code: status,
                                content_length,
                                redirect,
                                interesting: is_interesting,
                            }
                        }
                        Err(_) => DirectoryResult {
                            path: path.clone(),
                            status_code: 0,
                            content_length: 0,
                            redirect: None,
                            interesting: false,
                        },
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        results
    }

    pub fn default_wordlist() -> Vec<String> {
        vec![
            "admin", "administrator", "login", "wp-admin", "wp-login.php",
            "phpmyadmin", "phpMyAdmin", "pma", "server-status", "server-info",
            "robots.txt", "sitemap.xml", ".env", ".git", ".git/config",
            ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd", ".DS_Store",
            "backup", "backups", "db", "database", "dump", "export", "import",
            "config", "configuration", "settings", "setup", "install",
            "api", "api/v1", "api/v2", "graphql", "swagger", "docs",
            "static", "assets", "css", "js", "images", "img", "media",
            "uploads", "upload", "files", "download", "downloads",
            "test", "tests", "testing", "staging", "dev", "development",
            "debug", "trace", "status", "health", "healthz", "ready", "readyz",
            "info", "version", "metrics", "prometheus",
            "cgi-bin", "bin", "sh", "bash", "exec", "cmd", "shell",
            "console", "dashboard", "panel", "manager",
            "robots.txt", ".well-known/security.txt", "favicon.ico",
            "crossdomain.xml", "clientaccesspolicy.xml",
            "elmah.axd", "trace.axd", "web.config", "config.xml",
            "wp-content", "wp-includes", "xmlrpc.php",
            "Jenkins", "jenkins", "sonar", "sonarqube",
            ".env.production", ".env.development", ".env.local",
            "Makefile", "Dockerfile", "docker-compose.yml",
            "package.json", "composer.json", "Gemfile",
            "README.md", "CHANGELOG.md", "LICENSE",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
}

// ============================================================================
// Full Enumeration Pipeline
// ============================================================================

pub struct Enumerator {
    dns: DnsEnumerator,
    concurrency: usize,
}

impl Enumerator {
    pub fn new(resolver: &str, timeout_ms: u32, concurrency: usize) -> Self {
        Self {
            dns: DnsEnumerator::new(resolver, timeout_ms),
            concurrency,
        }
    }

    pub fn default_enumerator() -> Self {
        Self::new("8.8.8.8", 3000, 20)
    }

    pub async fn full_enumeration(&self, domain: &str) -> EnumerationReport {
        let start = std::time::Instant::now();

        // DNS
        let record_types = vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Mx,
            DnsRecordType::Ns,
            DnsRecordType::Txt,
            DnsRecordType::Cname,
        ];
        let dns_records = self.dns.enumerate_all(domain, &record_types).await;

        // Subdomain brute-force
        let bruter = SubdomainBruter::new(self.dns.clone(), self.concurrency);
        let subdomains = bruter.brute_top(domain).await;
        let found_subs: Vec<String> = subdomains
            .iter()
            .filter(|s| s.found)
            .map(|s| s.subdomain.clone())
            .collect();

        // Directory brute-force sur chaque sous-domaine trouvé
        let mut all_dirs = Vec::new();
        let dir_wordlist = DirectoryBruter::default_wordlist();
        for sub in &found_subs {
            let url = format!("http://{sub}");
            let dir_bruter =
                DirectoryBruter::new(&url, self.concurrency, self.dns.timeout_ms)
                    .with_wordlist(dir_wordlist.clone());
            let dirs = dir_bruter.scan(&dir_wordlist).await;
            all_dirs.extend(dirs);
        }

        let duration = start.elapsed().as_secs_f64();

        EnumerationReport {
            domain: domain.to_string(),
            dns_records,
            subdomains,
            directories: all_dirs,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            duration_secs: duration,
        }
    }

    pub fn load_wordlist_from_file(
        path: impl AsRef<Path>,
    ) -> Result<Vec<String>> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("lecture wordlist: {:?}", path.as_ref()))?;
        Ok(content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_build() {
        let query = DnsEnumerator::build_query("example.com", &DnsRecordType::A);
        assert!(query.len() > 20);
        // Vérifie le QNAME encodé
        assert_eq!(query[12], 7); // "example" = 7 lettres
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3); // "com" = 3 lettres
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0); // root label
    }

    #[test]
    fn test_dns_record_types() {
        assert_eq!(DnsRecordType::A.as_u16(), 1);
        assert_eq!(DnsRecordType::Aaaa.as_u16(), 28);
        assert_eq!(DnsRecordType::Mx.as_u16(), 15);
        assert_eq!(DnsRecordType::Ns.as_u16(), 2);
        assert_eq!(DnsRecordType::Txt.as_u16(), 16);
    }

    #[test]
    fn test_subdomain_default_wordlist_not_empty() {
        let wl = SubdomainBruter::default_wordlist();
        assert!(wl.len() > 50);
        assert!(wl.contains(&"www".to_string()));
        assert!(wl.contains(&"mail".to_string()));
        assert!(wl.contains(&"api".to_string()));
    }

    #[test]
    fn test_directory_default_wordlist_not_empty() {
        let wl = DirectoryBruter::default_wordlist();
        assert!(wl.len() > 50);
        assert!(wl.contains(&"admin".to_string()));
        assert!(wl.contains(&".env".to_string()));
        assert!(wl.contains(&"robots.txt".to_string()));
    }

    #[test]
    fn test_directory_result_interesting() {
        let r = DirectoryResult {
            path: "admin".to_string(),
            status_code: 200,
            content_length: 1234,
            redirect: None,
            interesting: true,
        };
        assert!(r.interesting);
    }
}
