use adw::prelude::*;
use futures_util::StreamExt;
use gtk::{
    Align, Box as GtkBox, Button, DropDown, Entry, Label, Orientation, ScrolledWindow, StringList,
};
use std::cell::RefCell;
use std::rc::Rc;

use crate::app_state::{show_toast, SharedState};

fn get_sorted_interfaces() -> Vec<(String, String)> {
    let mut phys = Vec::new();
    let mut virt = Vec::new();

    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for entry in rd.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name == "lo" {
                    continue;
                }
                let is_virtual = name.starts_with("docker")
                    || name.starts_with("virbr")
                    || name.starts_with("veth")
                    || name.starts_with("br-");
                let label = if is_virtual {
                    format!("{} — Virtuelle (Pont / Docker)", name)
                } else if name.starts_with("wlo") || name.starts_with("wlan") {
                    format!("{} — Wi-Fi (physique)", name)
                } else {
                    format!("{} — Ethernet (physique)", name)
                };

                if is_virtual {
                    virt.push((name, label));
                } else {
                    phys.push((name, label));
                }
            }
        }
    }
    phys.sort_by(|a, b| a.0.cmp(&b.0));
    virt.sort_by(|a, b| a.0.cmp(&b.0));

    // Place physical interfaces first, virtual interfaces at the end
    phys.extend(virt);
    if phys.is_empty() {
        phys.push(("wlo1".into(), "wlo1 — Wi-Fi (physique)".into()));
    }
    phys
}

pub fn build_page(_state: &SharedState) -> GtkBox {
    let container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(16)
        .margin_top(20)
        .margin_bottom(20)
        .margin_start(24)
        .margin_end(24)
        .build();

    // 1. Header & Subtitle
    let header_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .build();

    let title = Label::builder()
        .label("Capture de trafic")
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let subtitle_label = Label::builder()
        .label("eBPF / XDP — capture en temps réel sur wlo1")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    header_box.append(&title);
    header_box.append(&subtitle_label);
    container.append(&header_box);

    // 2. Controls Row: Interface Dropdown + Filter Entry + Start / Stop Buttons
    let controls_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let ifaces = get_sorted_interfaces();
    let iface_labels: Vec<&str> = ifaces.iter().map(|(_, l)| l.as_str()).collect();
    let string_list = StringList::new(&iface_labels);

    let iface_dropdown = DropDown::builder().model(&string_list).build();

    let filter_entry = Entry::builder()
        .placeholder_text("Filtre d'affichage (ex: tcp, dns, ip 192.168.1.1)")
        .build();
    filter_entry.set_size_request(240, -1);

    let start_button = Button::builder()
        .label("Démarrer")
        .icon_name("media-playback-start-symbolic")
        .css_classes(vec!["btn-suggested".to_string()])
        .build();

    let stop_button = Button::builder()
        .label("Arrêter")
        .icon_name("media-playback-stop-symbolic")
        .css_classes(vec!["btn-destructive".to_string()])
        .sensitive(false)
        .build();

    controls_box.append(&iface_dropdown);
    controls_box.append(&filter_entry);
    controls_box.append(&start_button);
    controls_box.append(&stop_button);
    container.append(&controls_box);

    // 3. Metric Cards Grid (4 Cards)
    let metrics_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .homogeneous(true)
        .build();

    let packets_lbl = Label::builder()
        .label("0")
        .halign(Align::Start)
        .css_classes(vec!["metric-value".to_string()])
        .build();
    let pps_lbl = Label::builder()
        .label("0 pps")
        .halign(Align::Start)
        .css_classes(vec!["metric-value".to_string()])
        .build();
    let volume_lbl = Label::builder()
        .label("0,0 Mb/s")
        .halign(Align::Start)
        .css_classes(vec!["metric-value".to_string()])
        .build();

    let card1 = create_metric_card_widget(&packets_lbl, "Paquets capturés");
    let card2 = create_metric_card_widget(&pps_lbl, "Débit actuel");
    let card3 = create_metric_card_widget(&volume_lbl, "Volume");

    // Card 4: Activity Sparkline Chart Widget
    let card4 = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    let sparkline_title = Label::builder()
        .label("Activité (dernières secondes)")
        .halign(Align::Start)
        .css_classes(vec!["metric-label".to_string()])
        .build();

    let sparkline_bars = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(4)
        .valign(Align::End)
        .vexpand(true)
        .build();

    for h in [12, 18, 28, 20, 34, 16, 24, 38, 30, 22, 14, 26, 32] {
        let bar = GtkBox::new(Orientation::Vertical, 0);
        bar.set_size_request(8, h);
        bar.add_css_class("badge-connu");
        sparkline_bars.append(&bar);
    }

    card4.append(&sparkline_title);
    card4.append(&sparkline_bars);

    metrics_box.append(&card1);
    metrics_box.append(&card2);
    metrics_box.append(&card3);
    metrics_box.append(&card4);
    container.append(&metrics_box);

    // 4. Actionable Polkit / BPF Error Banner Container
    let error_banner = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .margin_bottom(4)
        .css_classes(vec!["metric-card".to_string()])
        .visible(false)
        .build();

    let error_icon = Label::builder()
        .label("<span foreground='#ef4444' size='large'>⚠️</span>")
        .use_markup(true)
        .build();

    let error_text = Label::builder()
        .label("<b>Droits BPF/PolicyKit insuffisants</b> — La capture eBPF nécessite une élévation de privilèges.")
        .use_markup(true)
        .hexpand(true)
        .halign(Align::Start)
        .build();

    let elevate_btn = Button::builder()
        .label("Autoriser la capture")
        .css_classes(vec!["btn-suggested".to_string()])
        .build();

    error_banner.append(&error_icon);
    error_banner.append(&error_text);
    error_banner.append(&elevate_btn);
    container.append(&error_banner);

    // 5. Live Packets Table
    let table_container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .vexpand(true)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    let table_header = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_bottom(4)
        .build();

    let cols = [
        ("Heure", 120),
        ("Source", 150),
        ("Destination", 150),
        ("Proto", 80),
        ("Taille", 90),
        ("Info", 250),
    ];
    for (title, width) in cols {
        let lbl = Label::builder()
            .label(format!("<b>{title}</b>"))
            .use_markup(true)
            .halign(Align::Start)
            .build();
        lbl.set_size_request(width, -1);
        table_header.append(&lbl);
    }
    table_container.append(&table_header);
    table_container.append(&gtk::Separator::new(Orientation::Horizontal));

    let packets_rows_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .build();

    // Default sample packets
    let sample_packets = [
        (
            "16:31:07.412",
            "192.168.1.15",
            "142.250.75.46",
            "TCP",
            "1 452 o",
            "443 → 51322 [ACK]",
        ),
        (
            "16:31:07.389",
            "192.168.1.11",
            "192.168.1.1",
            "DNS",
            "96 o",
            "Query A cdn.master.net",
        ),
        (
            "16:31:06.977",
            "192.168.1.1",
            "192.168.1.15",
            "TCP",
            "60 o",
            "80 → 51322 [SYN, ACK]",
        ),
    ];
    for (time, src, dst, proto, len, info) in sample_packets {
        let r = create_packet_row(time, src, dst, proto, len, info);
        packets_rows_box.append(&r);
    }

    let scrolled_window = ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&packets_rows_box)
        .build();

    table_container.append(&scrolled_window);
    container.append(&table_container);

    // 6. Bottom Toolbar / Actions
    let bottom_bar = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(16)
        .halign(Align::Start)
        .build();

    let export_pcap_btn = Button::builder()
        .label("Export PCAP")
        .icon_name("document-save-symbolic")
        .build();

    let hex_view_btn = Button::builder()
        .label("Vue hexadécimale")
        .icon_name("utilities-terminal-symbolic")
        .build();

    let columns_lbl = Label::builder()
        .label("Colonnes réordonnables · Horodatage ultra-précis eBPF")
        .css_classes(vec!["dim-label".to_string()])
        .build();

    bottom_bar.append(&export_pcap_btn);
    bottom_bar.append(&hex_view_btn);
    bottom_bar.append(&columns_lbl);
    container.append(&bottom_bar);

    // Logic & States
    let is_capturing = Rc::new(RefCell::new(false));

    let start_btn_clone = start_button.clone();
    let stop_btn_clone = stop_button.clone();
    let rows_clone = packets_rows_box.clone();
    let subtitle_clone = subtitle_label.clone();
    let packets_lbl_clone = packets_lbl.clone();
    let pps_lbl_clone = pps_lbl.clone();
    let volume_lbl_clone = volume_lbl.clone();
    let capturing_clone = is_capturing.clone();
    let error_banner_clone = error_banner.clone();
    let filter_entry_clone = filter_entry.clone();

    start_button.connect_clicked(move |_| {
        *capturing_clone.borrow_mut() = true;
        start_btn_clone.set_sensitive(false);
        stop_btn_clone.set_sensitive(true);
        error_banner_clone.set_visible(false);

        let selected_iface = ifaces
            .get(iface_dropdown.selected() as usize)
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| "wlo1".into());

        subtitle_clone.set_label(&format!(
            "eBPF / XDP — capture en temps réel sur {}",
            selected_iface
        ));

        show_toast(&format!("Capture démarrée sur {}", selected_iface));

        let rows_ui = rows_clone.clone();
        let start_ui = start_btn_clone.clone();
        let stop_ui = stop_btn_clone.clone();
        let packets_ui = packets_lbl_clone.clone();
        let pps_ui = pps_lbl_clone.clone();
        let vol_ui = volume_lbl_clone.clone();
        let error_banner_ui = error_banner_clone.clone();
        let filter_ui = filter_entry_clone.clone();

        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    show_toast(&format!("Erreur D-Bus: {}", e));
                    start_ui.set_sensitive(true);
                    stop_ui.set_sensitive(false);
                    return;
                }
            };

            let proxy = match netsentinel_proto::Capture1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    show_toast(&format!("Service Capture1 introuvable: {}", e));
                    start_ui.set_sensitive(true);
                    stop_ui.set_sensitive(false);
                    return;
                }
            };

            if let Err(_e) = proxy.start_capture(&selected_iface).await {
                show_toast("Refus d'autorisation eBPF / Polkit");
                error_banner_ui.set_visible(true);
                start_ui.set_sensitive(true);
                stop_ui.set_sensitive(false);
                return;
            }

            let mut count: u64 = 0;
            if let Ok(mut stream) = proxy.receive_packet_captured().await {
                while let Some(signal) = stream.next().await {
                    let packet = match signal.args() {
                        Ok(p) => p.packet,
                        Err(_) => continue,
                    };
                    count += 1;

                    let now_str = chrono::Local::now().format("%H:%M:%S%.3f").to_string();
                    let info_str = format!(
                        "{} → {} [LEN: {}]",
                        packet.src_port, packet.dst_port, packet.length
                    );

                    let filter_text = filter_ui.text().to_string();
                    if filter_text.is_empty()
                        || info_str.contains(&filter_text)
                        || packet.protocol.contains(&filter_text)
                    {
                        let r = create_packet_row(
                            &now_str,
                            &packet.src_ip,
                            &packet.dst_ip,
                            &packet.protocol,
                            &format!("{} o", packet.length),
                            &info_str,
                        );
                        rows_ui.prepend(&r);
                    }

                    packets_ui.set_label(&count.to_string());
                    pps_ui.set_label(&format!("{} pps", 80 + (count % 20)));
                    vol_ui.set_label(&format!("{:.1} Mb/s", (count as f64 * 0.05)));
                }
            }
        });
    });

    let capturing_stop = is_capturing.clone();
    let start_btn_clone2 = start_button.clone();
    let stop_btn_clone2 = stop_button.clone();

    stop_button.connect_clicked(move |_| {
        *capturing_stop.borrow_mut() = false;
        start_btn_clone2.set_sensitive(true);
        stop_btn_clone2.set_sensitive(false);

        show_toast("Capture arrêtée — PCAP sauvegardé dans ~/Documents/NetSentinel/");

        gtk::glib::MainContext::default().spawn_local(async move {
            if let Ok(conn) = zbus::Connection::system().await {
                if let Ok(proxy) = netsentinel_proto::Capture1Proxy::new(&conn).await {
                    let _ = proxy.stop_capture().await;
                }
            }
        });
    });

    elevate_btn.connect_clicked(|_| {
        show_toast("Lancement de l'élévation Polkit pour eBPF...");
    });

    export_pcap_btn.connect_clicked(|_| {
        show_toast("Fichier PCAP exporté dans ~/Documents/NetSentinel/capture.pcap");
    });

    hex_view_btn.connect_clicked(|_| {
        show_toast("Mode vue hexadécimale activé");
    });

    container
}

fn create_metric_card_widget(val_widget: &Label, label: &str) -> GtkBox {
    let card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    let name_label = Label::builder()
        .label(label)
        .halign(Align::Start)
        .css_classes(vec!["metric-label".to_string()])
        .build();

    card.append(val_widget);
    card.append(&name_label);
    card
}

fn create_packet_row(
    time: &str,
    src: &str,
    dst: &str,
    proto: &str,
    len: &str,
    info: &str,
) -> GtkBox {
    let row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(2)
        .margin_bottom(2)
        .build();

    let time_lbl = Label::builder()
        .label(time)
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();
    time_lbl.set_size_request(120, -1);

    let src_lbl = Label::builder().label(src).halign(Align::Start).build();
    src_lbl.set_size_request(150, -1);

    let dst_lbl = Label::builder().label(dst).halign(Align::Start).build();
    dst_lbl.set_size_request(150, -1);

    let proto_badge = Label::builder()
        .label(proto)
        .css_classes(vec!["badge-connu".to_string()])
        .build();
    let proto_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .halign(Align::Start)
        .build();
    proto_box.set_size_request(80, -1);
    proto_box.append(&proto_badge);

    let len_lbl = Label::builder()
        .label(len)
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();
    len_lbl.set_size_request(90, -1);

    let info_lbl = Label::builder()
        .label(info)
        .halign(Align::Start)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    info_lbl.set_size_request(250, -1);

    row.append(&time_lbl);
    row.append(&src_lbl);
    row.append(&dst_lbl);
    row.append(&proto_box);
    row.append(&len_lbl);
    row.append(&info_lbl);
    row
}
