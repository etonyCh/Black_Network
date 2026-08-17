use adw::prelude::*;
use adw::{ActionRow, PreferencesGroup};
use gtk::{
    Align, Box as GtkBox, Button, DropDown, Label, ListBox, Orientation, ScrolledWindow,
    SelectionMode, StringList,
};
use std::path::Path;
use futures_util::StreamExt;

fn list_network_interfaces() -> Vec<String> {
    let mut ifaces: Vec<String> = Vec::new();
    if let Ok(readdir) = std::fs::read_dir(Path::new("/sys/class/net")) {
        for entry in readdir.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                let name = name.to_string();
                if name != "lo" {
                    ifaces.push(name);
                }
            }
        }
    }
    ifaces.sort();
    if ifaces.is_empty() {
        ifaces.push("eth0".into());
        ifaces.push("wlan0".into());
    }
    ifaces
}

pub fn build_page() -> GtkBox {
    let container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();

    let title = Label::builder()
        .label("<b>Capture de trafic (eBPF/XDP)</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let description = Label::builder()
        .label("Capture ultra-rapide des paquets directement dans le noyau Linux (Aya eBPF, zero-copy XDP).")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    // Configuration : DropDown interfaces plutôt que EntryRow textuel
    let iface_names = list_network_interfaces();
    let iface_list_model = StringList::new(
        &iface_names
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>(),
    );
    let iface_dropdown = DropDown::builder()
        .model(&iface_list_model)
        .enable_search(true)
        .build();

    let config_group = PreferencesGroup::new();
    config_group.set_title("Configuration");
    config_group.set_description(Some(
        "Sélectionnez une interface physique (nécessite le droit Polkit org.netsentinel.capture.run).",
    ));
    let iface_row = ActionRow::builder()
        .title("Interface réseau")
        .subtitle("Carte Ethernet ou Wi-Fi à monitorer")
        .activatable_widget(&iface_dropdown)
        .build();
    iface_row.add_suffix(&iface_dropdown);
    config_group.add(&iface_row);
    container.append(&config_group);

    // Boutons Démarrer / Arrêter
    let action_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let start_button = Button::builder()
        .label("Démarrer la capture")
        .css_classes(vec!["suggested-action".to_string()])
        .build();

    let stop_button = Button::builder()
        .label("Arrêter")
        .css_classes(vec!["destructive-action".to_string()])
        .sensitive(false)
        .build();

    let status_label = Label::builder()
        .label("<i>Prêt — aucune capture en cours</i>")
        .use_markup(true)
        .halign(Align::Start)
        .build();

    action_box.append(&start_button);
    action_box.append(&stop_button);
    container.append(&action_box);
    container.append(&status_label);

    // Liste paquets en temps réel
    let results_header = Label::builder()
        .label("<b>Paquets capturés</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    container.append(&results_header);

    let list_box = ListBox::builder()
        .selection_mode(SelectionMode::None)
        .css_classes(vec!["boxed-list".to_string()])
        .build();

    let scrolled_window = ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(400)
        .vexpand(true)
        .child(&list_box)
        .build();

    container.append(&scrolled_window);

    // ========== HANDLER : START ==========
    let start_btn_clone = start_button.clone();
    let stop_btn_clone = stop_button.clone();
    let list_box_clone = list_box.clone();
    let status_clone = status_label.clone();
    let iface_dropdown_clone = iface_dropdown.clone();

    start_button.connect_clicked(move |_| {
        let iface = iface_dropdown_clone
            .selected_item()
            .and_then(|o| o.downcast_ref::<gtk::StringObject>().map(|s| s.string().to_string()))
            .unwrap_or_else(|| "eth0".into());

        start_btn_clone.set_sensitive(false);
        stop_btn_clone.set_sensitive(true);
        status_clone.set_markup(&format!(
            "<span foreground='#3584e4'>⏺ Capture en cours sur <b>{}</b>...</span>",
            iface
        ));

        while let Some(child) = list_box_clone.first_child() {
            list_box_clone.remove(&child);
        }

        let list_box_ui = list_box_clone.clone();
        let start_btn_ui = start_btn_clone.clone();
        let stop_btn_ui = stop_btn_clone.clone();
        let status_ui = status_clone.clone();

        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    status_ui.set_markup(&format!(
                        "<span foreground='red'>❌ Échec connexion D-Bus système : {}</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    stop_btn_ui.set_sensitive(false);
                    return;
                }
            };

            let proxy = match netsentinel_proto::Capture1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    status_ui.set_markup(&format!(
                        "<span foreground='red'>❌ Service Capture1 introuvable : {}</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    stop_btn_ui.set_sensitive(false);
                    return;
                }
            };

            if let Err(e) = proxy.start_capture(&iface).await {
                status_ui.set_markup(&format!(
                    "<span foreground='red'>❌ start_capture() refusé : {}\n→ Vérifier Polkit / capacité eBPF du noyau.</span>",
                    e
                ));
                start_btn_ui.set_sensitive(true);
                stop_btn_ui.set_sensitive(false);
                return;
            }

            let mut packet_count: u64 = 0;
            if let Ok(mut stream) = proxy.receive_packet_captured().await {
                while let Some(signal) = stream.next().await {
                    let packet = match signal.args() {
                        Ok(p) => p.packet,
                        Err(_) => continue,
                    };

                    let mut title = format!(
                        "{} → {} ({})",
                        packet.src_ip, packet.dst_ip, packet.protocol
                    );
                    let row = ActionRow::builder()
                        .subtitle(format!(
                            "Taille: {} o · horodatage {:.2}s",
                            packet.length, (packet.timestamp_ms as f64 / 1000.0)
                        ))
                        .build();

                    if packet.unencrypted {
                        title.push_str("  ⚠️ NON CHIFFRÉ");
                        row.add_css_class("error");
                    }
                    row.set_title(&title);

                    list_box_ui.prepend(&row);
                    packet_count += 1;

                    if packet_count.is_multiple_of(100) {
                        status_ui.set_markup(&format!(
                            "<span foreground='#3584e4'>⏺ {} paquets capturés sur {}...</span>",
                            packet_count, iface
                        ));
                    }

                    if packet_count > 1000 {
                        if let Some(last) = list_box_ui.last_child() {
                            list_box_ui.remove(&last);
                            packet_count -= 1;
                        }
                    }
                }
            }
        });
    });

    // ========== HANDLER : STOP ==========
    let stop_btn_clone = stop_button.clone();
    let start_btn_clone2 = start_button.clone();
    let status_clone2 = status_label.clone();

    stop_button.connect_clicked(move |_| {
        stop_btn_clone.set_sensitive(false);
        start_btn_clone2.set_sensitive(true);
        status_clone2.set_markup("<i>Arrêt en cours...</i>");

        let status_ui = status_clone2.clone();
        gtk::glib::MainContext::default().spawn_local(async move {
            if let Ok(connection) = zbus::Connection::system().await {
                if let Ok(proxy) = netsentinel_proto::Capture1Proxy::new(&connection).await {
                    match proxy.stop_capture().await {
                        Ok(path) => {
                            status_ui.set_markup(&format!(
                                "<span foreground='#26a269'>✅ Capture arrêtée. PCAP sauvegardé : <tt>{}</tt></span>",
                                path
                            ));
                        }
                        Err(e) => {
                            status_ui.set_markup(&format!(
                                "<span foreground='orange'>⚠️ stop_capture : {}</span>",
                                e
                            ));
                        }
                    }
                }
            }
        });
    });

    container
}
