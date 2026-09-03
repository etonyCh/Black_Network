//! netsentinel-captured
//!
//! Service D-Bus `org.netsentinel.Capture1`. Capture eBPF via Aya (XDP)
//! avec écriture PCAP réelle sur disque.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::perf::{PerfEvent, PerfEventArray},
    programs::Xdp,
    util::online_cpus,
    Ebpf,
};
use netsentinel_capture_common::PacketLog;
use netsentinel_core::pcap::PcapWriter;
use netsentinel_proto::{CapturedPacket, CAPTURE_BUS_NAME, CAPTURE_OBJECT_PATH};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use zbus::{interface, object_server::SignalContext};

struct CaptureState {
    _ebpf: Ebpf,
    pcap_writer: Arc<Mutex<PcapWriter>>,
    pcap_path: PathBuf,
}

struct CaptureService {
    state: Arc<Mutex<Option<CaptureState>>>,
    connection: zbus::Connection,
}

fn default_pcap_path() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".local/share"))
                .unwrap_or_else(|_| PathBuf::from("/tmp"))
        })
        .join("netsentinel/captures");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    base.join(format!("capture_{}.pcap", ts))
}

#[interface(name = "org.netsentinel.Capture1")]
impl CaptureService {
    async fn start_capture(&self, interface: &str) -> zbus::fdo::Result<()> {
        let mut state = self.state.lock().await;
        if state.is_some() {
            return Err(zbus::fdo::Error::Failed(
                "une capture est déjà en cours".into(),
            ));
        }

        let pcap_path = default_pcap_path();
        tracing::info!(interface, path = %pcap_path.display(), "démarrage capture eBPF + PCAP");

        let pcap_writer = PcapWriter::create(&pcap_path)
            .map_err(|e| zbus::fdo::Error::Failed(format!("erreur création PCAP: {e}")))?;
        let pcap_writer = Arc::new(Mutex::new(pcap_writer));

        // 1. Charger le programme eBPF
        let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/netsentinel-capture-ebpf"
        )))
        .map_err(|e| zbus::fdo::Error::Failed(format!("erreur chargement ebpf: {e}")))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            tracing::warn!("impossible d'initialiser aya-log: {e}");
        }

        // 2. Attacher XDP
        let program: &mut Xdp = ebpf
            .program_mut("netsentinel_capture_ebpf")
            .ok_or_else(|| zbus::fdo::Error::Failed("programme eBPF introuvable".into()))?
            .try_into()
            .map_err(|e| zbus::fdo::Error::Failed(format!("erreur try_into Xdp: {e}")))?;

        program
            .load()
            .map_err(|e| zbus::fdo::Error::Failed(format!("erreur load XDP: {e}")))?;
        program
            .attach(interface, aya::programs::xdp::XdpMode::default())
            .map_err(|e| {
                zbus::fdo::Error::Failed(format!("erreur attach XDP sur {interface}: {e}"))
            })?;

        // 3. PerfEventArray → signaux D-Bus + écriture PCAP
        let events_map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| zbus::fdo::Error::Failed("map EVENTS introuvable".into()))?;
        let mut perf_array = PerfEventArray::try_from(events_map)
            .map_err(|e| zbus::fdo::Error::Failed(format!("erreur map EVENTS: {e}")))?;

        let connection = self.connection.clone();
        let pcap_writer_shared = pcap_writer.clone();

        for cpu_id in online_cpus()
            .map_err(|e| zbus::fdo::Error::Failed(format!("erreur online cpus: {:?}", e)))?
        {
            let buf = perf_array
                .open(cpu_id, None)
                .map_err(|e| zbus::fdo::Error::Failed(format!("erreur open perf array: {e}")))?;

            let conn_clone = connection.clone();
            let pcap_writer_clone = pcap_writer_shared.clone();

            tokio::spawn(async move {
                let mut async_fd = match tokio::io::unix::AsyncFd::new(buf) {
                    Ok(fd) => fd,
                    Err(e) => {
                        tracing::error!("erreur création AsyncFd: {e}");
                        return;
                    }
                };

                let signal_ctxt = match SignalContext::new(&conn_clone, CAPTURE_OBJECT_PATH) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::error!("erreur création SignalContext: {e}");
                        return;
                    }
                };

                loop {
                    let mut guard = match async_fd.readable_mut().await {
                        Ok(g) => g,
                        Err(e) => {
                            tracing::error!("erreur AsyncFd readable_mut: {e}");
                            break;
                        }
                    };
                    guard.get_inner_mut().for_each(|event| {
                        if let PerfEvent::Sample { head, tail } = event {
                            let mut data = [0u8; std::mem::size_of::<PacketLog>()];
                            let head_len = head.len().min(data.len());
                            data[..head_len].copy_from_slice(&head[..head_len]);
                            if head_len < data.len() {
                                let tail_len = (data.len() - head_len).min(tail.len());
                                data[head_len..head_len + tail_len]
                                    .copy_from_slice(&tail[..tail_len]);
                            }

                            let ptr = data.as_ptr() as *const PacketLog;
                            let log = unsafe { ptr.read_unaligned() };

                            let src = std::net::Ipv4Addr::from(log.src_addr).to_string();
                            let dst = std::net::Ipv4Addr::from(log.dst_addr).to_string();

                            let ts_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;

                            let captured_packet = CapturedPacket {
                                timestamp_ms: ts_ms,
                                src_ip: src.clone(),
                                dst_ip: dst.clone(),
                                protocol: match log.protocol {
                                    6 => "TCP".to_string(),
                                    17 => "UDP".to_string(),
                                    1 => "ICMP".to_string(),
                                    p => format!("Proto {}", p),
                                },
                                length: log.length,
                                unencrypted: log.unencrypted == 1,
                            };

                            // Écriture PCAP
                            {
                                let frame = PcapWriter::build_pseudo_ethernet(
                                    &src,
                                    &dst,
                                    log.protocol,
                                    &data[std::mem::size_of::<PacketLog>()..]
                                        .get(..log.length as usize)
                                        .unwrap_or_default(),
                                );
                                let writer_clone = pcap_writer_clone.clone();
                                tokio::spawn(async move {
                                    let mut w = writer_clone.lock().await;
                                    let _ = w.write_raw_packet(ts_ms, &frame);
                                });
                            }

                            // Signal D-Bus
                            let signal_ctxt = signal_ctxt.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    CaptureService::packet_captured(&signal_ctxt, captured_packet)
                                        .await
                                {
                                    tracing::error!("Erreur émission signal D-Bus: {e}");
                                }
                            });
                        }
                    });
                    guard.clear_ready();
                }
            });
        }

        *state = Some(CaptureState {
            _ebpf: ebpf,
            pcap_writer,
            pcap_path,
        });
        Ok(())
    }

    async fn stop_capture(&self) -> zbus::fdo::Result<String> {
        let mut state = self.state.lock().await;
        match state.take() {
            Some(capture_state) => {
                let path = capture_state.pcap_path.to_string_lossy().to_string();
                let count = capture_state
                    .pcap_writer
                    .lock()
                    .await
                    .finalize()
                    .map_err(|e| zbus::fdo::Error::Failed(format!("erreur finalize PCAP: {e}")))?;
                tracing::info!(path = %path, packets = count, "capture arrêtée, PCAP finalisé");
                Ok(path)
            }
            None => Err(zbus::fdo::Error::Failed("aucune capture en cours".into())),
        }
    }

    #[zbus(signal)]
    async fn packet_captured(
        signal_ctxt: &zbus::object_server::SignalContext<'_>,
        packet: CapturedPacket,
    ) -> zbus::Result<()>;
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let connection = zbus::Connection::system()
        .await
        .context("impossible de créer la connexion D-Bus système")?;

    let service = CaptureService {
        state: Arc::new(Mutex::new(None)),
        connection: connection.clone(),
    };

    connection
        .object_server()
        .at(CAPTURE_OBJECT_PATH, service)
        .await?;
    connection.request_name(CAPTURE_BUS_NAME).await?;

    tracing::info!(
        bus = CAPTURE_BUS_NAME,
        "netsentinel-captured prêt (eBPF + PCAP writing)"
    );
    std::future::pending::<()>().await;
    Ok(())
}
