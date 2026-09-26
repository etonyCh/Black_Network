//! netsentinel-proto
//!
//! Types et définitions D-Bus partagés entre les 3 démons NetSentinel et le
//! client GTK. Ce crate est la SEULE source de vérité pour les noms de bus,
//! les chemins d'objets et les signatures de méthodes : toute modification
//! d'une interface se fait ici, jamais en dupliquant les signatures côté
//! client et côté serveur.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// Noms de bus / chemins d'objets — un service D-Bus par niveau de privilège
// ---------------------------------------------------------------------

pub const DISCOVER_BUS_NAME: &str = "org.netsentinel.Discover1";
pub const DISCOVER_OBJECT_PATH: &str = "/org/netsentinel/Discover1";

pub const CAPTURE_BUS_NAME: &str = "org.netsentinel.Capture1";
pub const CAPTURE_OBJECT_PATH: &str = "/org/netsentinel/Capture1";

pub const SCAN_BUS_NAME: &str = "org.netsentinel.Scan1";
pub const SCAN_OBJECT_PATH: &str = "/org/netsentinel/Scan1";

// ---------------------------------------------------------------------
// Types de données partagés
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, zbus::zvariant::Type)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    #[serde(default)]
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, zbus::zvariant::Type)]
pub struct CapturedPacket {
    pub timestamp_ms: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub length: u32,
    pub unencrypted: bool,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, zbus::zvariant::Type)]
pub struct ScanFinding {
    pub target: String,
    pub port: u16,
    pub service: String,
    pub cve: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, zbus::zvariant::Type)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("D-Bus error: {0}")]
    Zbus(#[from] zbus::Error),
    #[error("interface non implémentée : {0}")]
    NotImplemented(String),
}

// ---------------------------------------------------------------------
// Proxies D-Bus consommés par le client GTK (générés via zbus::proxy)
// ---------------------------------------------------------------------

#[zbus::proxy(
    interface = "org.netsentinel.Discover1",
    default_service = "org.netsentinel.Discover1",
    default_path = "/org/netsentinel/Discover1"
)]
pub trait Discover1 {
    /// Lance un balayage ARP actif sur l'interface donnée (ex: "wlan0").
    /// Retourne la liste des hôtes une fois le scan terminé.
    async fn scan(&self, interface: &str, timeout_ms: u32) -> zbus::Result<Vec<DiscoveredHost>>;

    /// Signal émis pour chaque hôte découvert pendant le scan (mise à jour live UI).
    #[zbus(signal)]
    fn host_discovered(&self, host: DiscoveredHost) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.netsentinel.Capture1",
    default_service = "org.netsentinel.Capture1",
    default_path = "/org/netsentinel/Capture1"
)]
pub trait Capture1 {
    async fn start_capture(&self, interface: &str) -> zbus::Result<()>;
    async fn stop_capture(&self) -> zbus::Result<String>; // renvoie le chemin du .pcap

    #[zbus(signal)]
    fn packet_captured(&self, packet: CapturedPacket) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.netsentinel.Scan1",
    default_service = "org.netsentinel.Scan1",
    default_path = "/org/netsentinel/Scan1"
)]
pub trait Scan1 {
    /// Lance nmap (découverte de ports/services) puis Nuclei (détection CVE)
    /// contre la cible et retourne les findings consolidés.
    async fn deep_scan(&self, target: &str) -> zbus::Result<Vec<ScanFinding>>;

    #[zbus(signal)]
    fn scan_progress(&self, percent: u8, status: String) -> zbus::Result<()>;
}
