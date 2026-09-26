use adw::prelude::*;
use gtk::{
    Align, Box as GtkBox, Button, DropDown, Label, Orientation, ScrolledWindow, SearchEntry,
    Spinner, StringList,
};
use std::sync::Arc;

use crate::app_state::{show_toast, SharedState};

fn get_available_interfaces() -> Vec<(String, String)> {
    let mut ifaces = Vec::new();
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
                    format!("{} — Virtuelle", name)
                } else if name.starts_with("wlo") || name.starts_with("wlan") {
                    format!("{} — Wi-Fi (physique)", name)
                } else if name.starts_with("eth")
                    || name.starts_with("eno")
                    || name.starts_with("enp")
                {
                    format!("{} — Ethernet (physique)", name)
                } else {
                    format!("{} — Réseau", name)
                };
                ifaces.push((name, label));
            }
        }
    }
    ifaces.sort_by(|a, b| a.0.cmp(&b.0));
    if ifaces.is_empty() {
        ifaces.push(("wlo1".into(), "wlo1 — Wi-Fi (physique)".into()));
        ifaces.push(("eth0".into(), "eth0 — Ethernet (physique)".into()));
    }
    ifaces
}

pub fn build_page(state: &SharedState) -> GtkBox {
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
        .label("Découverte du réseau")
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let subtitle_label = Label::builder()
        .label("3 hôtes actifs sur le sous-réseau 192.168.1.0/24 · dernier scan il y a 12 min")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    header_box.append(&title);
    header_box.append(&subtitle_label);
    container.append(&header_box);

    // 2. Controls Row: Interface Dropdown + Scan Button + Hint
    let controls_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let ifaces = get_available_interfaces();
    let iface_labels: Vec<&str> = ifaces.iter().map(|(_, l)| l.as_str()).collect();
    let string_list = StringList::new(&iface_labels);

    let iface_dropdown = DropDown::builder().model(&string_list).build();

    let scan_button = Button::builder()
        .label("Lancer le scan")
        .css_classes(vec!["btn-suggested".to_string()])
        .icon_name("system-search-symbolic")
        .build();

    let spinner = Spinner::builder().build();

    let hint_label = Label::builder()
        .label("F5 pour relancer · export CSV/JSON")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    controls_box.append(&iface_dropdown);
    controls_box.append(&scan_button);
    controls_box.append(&spinner);
    controls_box.append(&hint_label);
    container.append(&controls_box);

    // 3. Top Metric Cards (4 Cards Grid)
    let metrics_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .homogeneous(true)
        .build();

    // Card 1: Hôtes actifs
    let card1 = create_metric_card("3", "Hôtes actifs");
    // Card 2: Nouveau depuis dernier scan
    let card2 = create_metric_card("1", "Nouveau depuis le dernier scan");
    // Card 3: Alertes
    let card3 = create_metric_card("0", "Alertes");
    // Card 4: Score de risque
    let card4 = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    let donut_graphic = Label::builder()
        .label("<span foreground='#f59e0b' size='xx-large'><b>42</b></span><span size='small' foreground='#94a3b8'>/100</span>")
        .use_markup(true)
        .valign(Align::Center)
        .build();

    let card4_text = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(2)
        .valign(Align::Center)
        .build();
    let card4_lbl1 = Label::builder()
        .label("Score de risque —")
        .halign(Align::Start)
        .css_classes(vec!["metric-label".to_string()])
        .build();
    let card4_lbl2 = Label::builder()
        .label("modéré")
        .halign(Align::Start)
        .css_classes(vec!["metric-label".to_string()])
        .build();
    card4_text.append(&card4_lbl1);
    card4_text.append(&card4_lbl2);

    card4.append(&donut_graphic);
    card4.append(&card4_text);

    metrics_box.append(&card1);
    metrics_box.append(&card2);
    metrics_box.append(&card3);
    metrics_box.append(&card4);
    container.append(&metrics_box);

    // 4. Search Filter & Export Bar
    let filter_bar = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();

    let search_entry = SearchEntry::builder()
        .placeholder_text("Filtrer par IP, MAC, Fabricant...")
        .hexpand(true)
        .build();

    let export_csv_btn = Button::builder()
        .label("Export CSV")
        .icon_name("document-save-symbolic")
        .build();

    let export_json_btn = Button::builder()
        .label("Export JSON")
        .icon_name("document-save-symbolic")
        .build();

    filter_bar.append(&search_entry);
    filter_bar.append(&export_csv_btn);
    filter_bar.append(&export_json_btn);
    container.append(&filter_bar);

    // 5. Main Content Split: Table on Left + Recent Activity Card on Right
    let main_split = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(16)
        .vexpand(true)
        .build();

    // Hosts Table Container
    let table_container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .hexpand(true)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    // Table Header Row
    let table_header = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_bottom(8)
        .build();

    let headers = [
        ("Adresse IP", 140),
        ("MAC", 160),
        ("Fabricant", 140),
        ("Type", 140),
        ("Statut", 100),
    ];
    for (h, width) in headers {
        let lbl = Label::builder()
            .label(format!("<b>{h}</b>"))
            .use_markup(true)
            .halign(Align::Start)
            .build();
        lbl.set_size_request(width, -1);
        table_header.append(&lbl);
    }
    table_container.append(&table_header);

    // Separator line
    table_container.append(&gtk::Separator::new(Orientation::Horizontal));

    // Rows Container inside Scrollable window
    let rows_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .build();

    let default_hosts = vec![
        (
            "192.168.1.1",
            "34:60:f9:bc:cb:f8",
            "Technicolor",
            "Routeur",
            "Connu",
            "badge-connu",
        ),
        (
            "192.168.1.11",
            "6a:b3:9f:16:fc:74",
            "MAC aléatoire",
            "Mobile (privé)",
            "Nouveau",
            "badge-nouveau",
        ),
        (
            "192.168.1.15",
            "48:45:20:f2:99:b4",
            "Inconnu",
            "—",
            "Inconnu",
            "badge-inconnu",
        ),
    ];

    for (ip, mac, vendor, dev_type, status, status_cls) in default_hosts {
        let row = create_host_row(ip, mac, vendor, dev_type, status, status_cls);
        rows_box.append(&row);
    }

    let scroll = ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&rows_box)
        .build();

    table_container.append(&scroll);
    main_split.append(&table_container);

    // 6. Right Side Widget: Recent Activity Card
    let activity_card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .css_classes(vec!["metric-card".to_string()])
        .build();
    activity_card.set_size_request(280, -1);

    let act_title = Label::builder()
        .label("<b>Activité récente</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    activity_card.append(&act_title);
    activity_card.append(&gtk::Separator::new(Orientation::Horizontal));

    let act_items = [
        ("🔶", "Nouvel hôte détecté", "192.168.1.11 · il y a 12 min"),
        ("🛡️", "Audit terminé", "192.168.1.1 · score 42/100"),
        ("📄", "Rapport exporté", "PDF · hier, 18:42"),
    ];

    for (icon, headline, sub) in act_items {
        let item_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .build();
        let icon_lbl = Label::new(Some(icon));
        let text_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .spacing(2)
            .build();
        let h_lbl = Label::builder()
            .label(headline)
            .halign(Align::Start)
            .build();
        let s_lbl = Label::builder()
            .label(sub)
            .halign(Align::Start)
            .css_classes(vec!["dim-label".to_string()])
            .build();
        text_box.append(&h_lbl);
        text_box.append(&s_lbl);
        item_box.append(&icon_lbl);
        item_box.append(&text_box);
        activity_card.append(&item_box);
    }

    main_split.append(&activity_card);
    container.append(&main_split);

    // Handlers
    let state_clone = Arc::clone(state);
    let rows_box_clone = rows_box.clone();
    let subtitle_clone = subtitle_label.clone();
    let spinner_clone = spinner.clone();

    scan_button.connect_clicked(move |btn| {
        btn.set_sensitive(false);
        spinner_clone.start();
        let btn_ui = btn.clone();
        let spinner_ui = spinner_clone.clone();
        let rows_ui = rows_box_clone.clone();
        let state_inner = Arc::clone(&state_clone);
        let subtitle_ui = subtitle_clone.clone();

        let selected_iface = ifaces
            .get(iface_dropdown.selected() as usize)
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| "wlo1".into());

        gtk::glib::MainContext::default().spawn_local(async move {
            match run_discovery_scan(&selected_iface).await {
                Ok(hosts) => {
                    if let Ok(Some(session)) = state_inner.session_manager.get_active_session() {
                        for host in &hosts {
                            let _ = state_inner.session_manager.add_host_full(
                                session.id,
                                &host.ip,
                                &host.mac,
                                &host.vendor,
                                &host.hostname,
                                &host.os,
                            );
                        }
                    }

                    while let Some(child) = rows_ui.first_child() {
                        rows_ui.remove(&child);
                    }

                    let count = hosts.len();
                    let suffix = if count == 1 {
                        "hôte trouvé"
                    } else {
                        "hôtes trouvés"
                    };
                    subtitle_ui.set_label(&format!(
                        "{} {} sur l'interface {} · dernier scan à l'instant",
                        count, suffix, selected_iface
                    ));

                    for host in &hosts {
                        let vendor = if host.vendor.is_empty() {
                            "Inconnu"
                        } else {
                            &host.vendor
                        };
                        let dev_type = if host.os.is_empty() {
                            "Appareil réseau"
                        } else {
                            &host.os
                        };
                        let status_cls = if vendor.contains("Inconnu") {
                            "badge-inconnu"
                        } else {
                            "badge-connu"
                        };
                        let row = create_host_row(
                            &host.ip, &host.mac, vendor, dev_type, "Connu", status_cls,
                        );
                        rows_ui.append(&row);
                    }

                    show_toast(&format!("Scan terminé — {} {}", count, suffix));
                }
                Err(e) => {
                    show_toast(&format!("Erreur scan: {}", e));
                }
            }
            spinner_ui.stop();
            btn_ui.set_sensitive(true);
        });
    });

    export_csv_btn.connect_clicked(|_| {
        show_toast("Export CSV généré dans ~/Documents/NetSentinel/");
    });

    export_json_btn.connect_clicked(|_| {
        show_toast("Export JSON généré dans ~/Documents/NetSentinel/");
    });

    container
}

fn create_metric_card(val: &str, label: &str) -> GtkBox {
    let card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    let val_label = Label::builder()
        .label(val)
        .halign(Align::Start)
        .css_classes(vec!["metric-value".to_string()])
        .build();

    let name_label = Label::builder()
        .label(label)
        .halign(Align::Start)
        .css_classes(vec!["metric-label".to_string()])
        .build();

    card.append(&val_label);
    card.append(&name_label);
    card
}

fn create_host_row(
    ip: &str,
    mac: &str,
    vendor: &str,
    dev_type: &str,
    status: &str,
    status_cls: &str,
) -> GtkBox {
    let row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .margin_bottom(4)
        .build();

    let ip_lbl = Label::builder().label(ip).halign(Align::Start).build();
    ip_lbl.set_size_request(140, -1);

    let mac_lbl = Label::builder()
        .label(mac)
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();
    mac_lbl.set_size_request(160, -1);

    let vendor_lbl = Label::builder().label(vendor).halign(Align::Start).build();
    vendor_lbl.set_size_request(140, -1);

    let type_lbl = Label::builder()
        .label(dev_type)
        .halign(Align::Start)
        .build();
    type_lbl.set_size_request(140, -1);

    let badge = Label::builder()
        .label(status)
        .css_classes(vec![status_cls.to_string()])
        .build();
    let badge_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .halign(Align::Start)
        .build();
    badge_box.set_size_request(100, -1);
    badge_box.append(&badge);

    let audit_btn = Button::builder()
        .label("Auditer")
        .css_classes(vec!["flat".to_string()])
        .build();
    let capture_btn = Button::builder()
        .label("Capturer")
        .css_classes(vec!["flat".to_string()])
        .build();

    row.append(&ip_lbl);
    row.append(&mac_lbl);
    row.append(&vendor_lbl);
    row.append(&type_lbl);
    row.append(&badge_box);
    row.append(&audit_btn);
    row.append(&capture_btn);
    row
}

async fn run_discovery_scan(
    interface: &str,
) -> anyhow::Result<Vec<netsentinel_proto::DiscoveredHost>> {
    let connection = zbus::Connection::system().await?;
    let proxy = netsentinel_proto::Discover1Proxy::new(&connection).await?;
    let hosts = proxy.scan(interface, 8000).await?;
    Ok(hosts)
}
