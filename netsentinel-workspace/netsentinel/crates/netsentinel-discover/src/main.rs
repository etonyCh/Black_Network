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
use netsentinel_proto::{DiscoveredHost, DISCOVER_BUS_NAME, DISCOVER_OBJECT_PATH};
use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use tokio::sync::Mutex;
use zbus::{connection, interface};

struct DiscoverService {
    // état minimal ; un vrai déploiement garderait ici la dernière liste de
    // résultats, un cache de vendors OUI, etc.
    last_scan: Arc<Mutex<Vec<DiscoveredHost>>>,
}

#[interface(name = "org.netsentinel.Discover1")]
impl DiscoverService {
    async fn scan(&self, interface: &str, timeout_ms: u32) -> zbus::fdo::Result<Vec<DiscoveredHost>> {
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
        let packet = build_arp_request(source_mac, source_ip.0, *target_ip);
        tx.send_to(&packet, None);
    }

    let mut found: HashMap<Ipv4Addr, DiscoveredHost> = HashMap::new();
    let deadline = std::time::Instant::now() + timeout;

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some(host) = parse_arp_reply(frame) {
                    found.entry(host.ip.parse().unwrap()).or_insert(host);
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

fn build_arp_request(source_mac: MacAddr, source_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
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
    ethernet_packet.packet().to_vec()
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

    Some(DiscoveredHost {
        ip: arp.get_sender_proto_addr().to_string(),
        mac: arp.get_sender_hw_addr().to_string(),
        vendor: String::new(),     // TODO: lookup OUI local (base IEEE embarquée)
        hostname: String::new(),   // TODO: résolution mDNS/NetBIOS optionnelle
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let service = DiscoverService {
        last_scan: Arc::new(Mutex::new(Vec::new())),
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
