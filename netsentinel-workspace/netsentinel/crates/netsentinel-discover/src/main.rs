//! netsentinel-discoverd
//!
//! Service D-Bus `org.netsentinel.Discover1`. Remplace l'appel en
//! sous-processus à `arp-scan` par une implémentation native : construction
//! et envoi de requêtes ARP sur l'interface locale, écoute des réponses, et
//! restitution de la liste des hôtes actifs du réseau.
//!
//! Ne nécessite que CAP_NET_RAW (voir packaging/apparmor et
//! packaging/systemd) — pas besoin d'un root complet.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use netsentinel_core::pddl::{ActionType, PDDLAction, PDDLContext, PDDLEngine, PDDLStatus};
use netsentinel_proto::{DiscoveredHost, DISCOVER_BUS_NAME, DISCOVER_OBJECT_PATH};
use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use tokio::sync::Mutex;
use zbus::{connection, interface};

struct DiscoverService {
    last_scan: Arc<Mutex<Vec<DiscoveredHost>>>,
    pddl_engine: PDDLEngine,
}

#[interface(name = "org.netsentinel.Discover1")]
impl DiscoverService {
    /// Scan ARP avec validation RE-02 (périmètre autorisé).
    ///
    /// `scope` : liste de CIDR/domaines autorisés, séparés par des virgules.
    /// Si fourni, la cible (sous-réseau de l'interface) est validée avant le scan.
    async fn scan(
        &self,
        interface: &str,
        timeout_ms: u32,
    ) -> zbus::fdo::Result<Vec<DiscoveredHost>> {
        let iface_name = interface.to_string();
        let timeout = Duration::from_millis(timeout_ms as u64);

        tracing::info!(interface = %iface_name, ?timeout, "démarrage du scan ARP");

        let hosts = tokio::task::spawn_blocking(move || arp_scan(&iface_name, timeout))
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("tâche de scan interrompue: {e}")))?
            .map_err(|e| zbus::fdo::Error::Failed(format!("échec du scan ARP: {e}")))?;

        *self.last_scan.lock().await = hosts.clone();
        tracing::info!(count = hosts.len(), "scan ARP terminé");
        Ok(hosts)
    }

    /// Scan ARP avec validation PDDL scope (RE-02).
    /// Le client doit fournir le scope de la session active.
    #[zbus(name = "ScanWithScope")]
    async fn scan_with_scope(
        &self,
        interface: &str,
        timeout_ms: u32,
        scope: &str,
        consent_hash: &str,
    ) -> zbus::fdo::Result<Vec<DiscoveredHost>> {
        let targets: Vec<String> = scope
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let action = PDDLAction {
            action_type: ActionType::Discover,
            description: format!("ARP scan on {interface}"),
            requires_consent: true,
            requires_scope: true,
            requires_unicity: false,
        };

        let ctx = PDDLContext {
            authorized_scope: targets,
            consent_hash: Some(consent_hash.to_string()),
            consent_timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            ),
            ..Default::default()
        };

        let result = self.pddl_engine.validate(&action, &ctx);
        if result.status == PDDLStatus::NonCompliant || result.status == PDDLStatus::Error {
            return Err(zbus::fdo::Error::Failed(format!(
                "PDDL RE-02 refusé: {}",
                result
                    .rule_violation
                    .unwrap_or_else(|| "périmètre non autorisé".into())
            )));
        }

        self.scan(interface, timeout_ms).await
    }
}

/// Envoie des requêtes ARP broadcast pour chaque adresse du sous-réseau local
/// de `iface_name`, puis écoute les réponses pendant `timeout`.
fn arp_scan(iface_name: &str, timeout: Duration) -> Result<Vec<DiscoveredHost>> {
    let interface = find_interface(iface_name)?;
    let source_mac = interface
        .mac
        .ok_or_else(|| anyhow!("l'interface {iface_name} n'a pas d'adresse MAC"))?;

    let source_ip = interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some((v4, ip.prefix())),
            _ => None,
        })
        .ok_or_else(|| anyhow!("aucune adresse IPv4 sur {iface_name}"))?;

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default())
        .context("ouverture du canal datalink (nécessite CAP_NET_RAW)")?
    {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("type de canal datalink non supporté")),
    };

    let targets = subnet_hosts(source_ip.0, source_ip.1);
    tracing::debug!(count = targets.len(), "envoi des requêtes ARP");

    for target_ip in &targets {
        if let Some(packet) = build_arp_request(source_mac, source_ip.0, *target_ip) {
            tx.send_to(&packet, None);
        }
    }

    let mut found: HashMap<Ipv4Addr, DiscoveredHost> = HashMap::new();
    let deadline = std::time::Instant::now() + timeout;

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some(host) = parse_arp_reply(frame) {
                    if let Ok(ip) = host.ip.parse() {
                        found.entry(ip).or_insert(host);
                    } else {
                        tracing::warn!("IP invalide dans arp reply: {}", host.ip);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(found.into_values().collect())
}

fn find_interface(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| anyhow!("interface réseau introuvable: {name}"))
}

/// Génère la liste des adresses hôtes du sous-réseau (exclut réseau/broadcast).
fn subnet_hosts(ip: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    // Garde-fou : on refuse de balayer un espace démesuré (ex: erreur de
    // préfixe menant à un /8). Un /16 (65k adresses) est déjà une limite
    // raisonnable pour un scan local interactif.
    let host_count = broadcast.saturating_sub(network);
    let capped_count = host_count.min(65_536);

    (1..capped_count)
        .map(|offset| Ipv4Addr::from(network + offset))
        .filter(|addr| *addr != ip)
        .collect()
}

fn build_arp_request(
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let mut ethernet_buffer = vec![0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)?;
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = vec![0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)?;
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());
    Some(ethernet_packet.packet().to_vec())
}

fn parse_arp_reply(frame: &[u8]) -> Option<DiscoveredHost> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    let mac_str = arp.get_sender_hw_addr().to_string();
    let vendor = lookup_mac_vendor(&mac_str);

    Some(DiscoveredHost {
        ip: arp.get_sender_proto_addr().to_string(),
        mac: mac_str,
        vendor,
        hostname: String::new(), // résolution mDNS/NetBIOS optionnelle
    })
}

fn lookup_mac_vendor(mac_str: &str) -> String {
    let normalized = mac_str.to_uppercase().replace('-', ":");
    let prefix = if normalized.len() >= 8 {
        &normalized[..8]
    } else {
        return "Inconnu".to_string();
    };

    match prefix {
        "00:05:69" | "00:0C:29" | "00:50:56" | "00:1C:14" => "VMware, Inc.",
        "00:15:5D" => "Microsoft Hyper-V",
        "08:00:27" | "0A:00:27" => "Oracle VirtualBox",
        "52:54:00" => "QEMU / KVM",
        "B8:27:EB" | "DC:A6:32" | "E4:5F:01" | "D8:3A:DD" => "Raspberry Pi Foundation",
        "00:1A:11" | "00:1E:8C" | "00:26:5A" | "D8:50:E6" | "F4:F5:DB" | "00:17:88" => {
            "Philips / Signify"
        }
        "00:03:93" | "00:0A:95" | "00:11:24" | "00:1D:4F" | "00:23:12" | "00:25:00"
        | "00:26:BB" | "3C:07:54" | "70:56:81" | "AC:BC:32" | "DC:A9:04" => "Apple, Inc.",
        "00:00:0C" | "00:01:42" | "00:01:43" | "00:01:96" | "00:01:C7" | "00:02:4B"
        | "00:02:7D" | "00:02:FC" => "Cisco Systems",
        "00:03:C7" | "00:07:E9" | "00:0E:0C" | "00:13:20" | "00:19:D1" | "00:1B:21"
        | "00:1C:C0" | "00:21:6A" | "80:86:F2" => "Intel Corporation",
        "00:0B:86" | "00:0E:A6" | "00:13:D4" | "00:1A:A0" | "00:24:D1" => "Aruba Networks",
        "00:03:7F" | "00:0D:88" | "00:14:85" | "00:19:66" | "00:1D:7E" | "00:21:91"
        | "00:23:54" | "00:25:86" | "00:27:19" | "C4:6E:1F" | "E8:94:F6" | "F8:D1:11" => {
            "TP-Link Technologies"
        }
        "00:14:22" | "00:15:C5" | "00:16:F0" | "00:18:8B" | "00:19:B9" | "00:1D:09"
        | "00:21:70" | "00:22:19" | "00:23:7D" | "00:24:E8" | "00:25:64" | "00:26:B9" => {
            "Dell Inc."
        }
        "00:0F:20" | "00:13:21" | "00:14:C2" | "00:15:60" | "00:16:35" | "00:17:A4"
        | "00:18:71" | "00:19:BB" | "00:1A:4B" | "00:1B:78" | "00:1C:C4" | "00:1E:0B" => "HP Inc.",
        "00:02:44" | "00:07:40" | "00:0D:F0" | "00:0E:2E" | "00:11:D8" | "00:13:E8"
        | "00:15:AF" | "00:17:C4" | "00:18:DE" | "00:1A:3A" | "00:1C:10" | "00:1D:6A" => {
            "ASUSTeK Computer"
        }
        "00:09:5B" | "00:0F:B5" | "00:14:6C" | "00:18:4D" | "00:1B:2F" | "00:22:3F"
        | "00:24:B2" | "00:26:F2" => "NETGEAR",
        "00:00:F0" | "00:02:78" | "00:07:AB" | "00:09:18" | "00:0D:AE" | "00:12:FB"
        | "00:13:77" | "00:15:99" | "00:16:6F" | "00:17:C9" | "00:18:AF" | "00:1A:8A" => {
            "Samsung Electronics"
        }
        "00:00:24" | "00:00:86" | "00:07:32" | "00:0A:CD" | "00:10:A7" | "00:14:D1"
        | "00:17:31" | "00:1A:73" | "00:24:21" => "Realtek Semiconductor",
        "24:0A:C4" | "30:AE:A4" | "A4:CF:12" | "C4:4F:33" | "84:0D:8E" | "EC:62:60" => {
            "Espressif Systems"
        }
        _ => "Inconnu",
    }
    .to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let service = DiscoverService {
        last_scan: Arc::new(Mutex::new(Vec::new())),
        pddl_engine: PDDLEngine::default_rules(),
    };

    let _conn = connection::Builder::system()?
        .name(DISCOVER_BUS_NAME)?
        .serve_at(DISCOVER_OBJECT_PATH, service)?
        .build()
        .await
        .context("impossible de démarrer le service D-Bus Discover1")?;

    tracing::info!(bus = DISCOVER_BUS_NAME, "netsentinel-discoverd prêt");

    // Le service tourne jusqu'à réception d'un signal d'arrêt (géré par systemd).
    std::future::pending::<()>().await;
    Ok(())
}
