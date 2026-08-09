use adw::prelude::*;
use adw::{ActionRow, EntryRow, PreferencesGroup};
use gtk::{Align, Box as GtkBox, Button, Label, ListBox, Orientation, ScrolledWindow, SelectionMode};
use futures_util::StreamExt;

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
        .label("<b>Capture de trafic (eBPF)</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();
    
    let description = Label::builder()
        .label("Capture ultra-rapide des paquets réseau par le noyau Linux.")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    let config_group = PreferencesGroup::new();
    let interface_entry = EntryRow::builder()
        .title("Interface réseau (ex: eth0, wlan0)")
        .text("eth0")
        .build();
    config_group.add(&interface_entry);
    
    container.append(&config_group);

    let action_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let start_button = Button::builder()
        .label("Démarrer")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    
    let stop_button = Button::builder()
        .label("Arrêter")
        .css_classes(vec!["destructive-action".to_string()])
        .sensitive(false)
        .build();

    action_box.append(&start_button);
    action_box.append(&stop_button);
    container.append(&action_box);

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

    let start_btn_clone = start_button.clone();
    let stop_btn_clone = stop_button.clone();
    let list_box_clone = list_box.clone();
    
    start_button.connect_clicked(move |_| {
        let iface = interface_entry.text().to_string();
        start_btn_clone.set_sensitive(false);
        stop_btn_clone.set_sensitive(true);

        // Clear list
        while let Some(child) = list_box_clone.first_child() {
            list_box_clone.remove(&child);
        }

        let list_box_ui = list_box_clone.clone();
        
        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Erreur D-Bus: {}", e);
                    return;
                }
            };
            
            let proxy = match netsentinel_proto::Capture1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("Erreur proxy: {}", e);
                    return;
                }
            };

            if let Err(e) = proxy.start_capture(&iface).await {
                tracing::error!("Erreur start_capture: {}", e);
                return;
            }

            let mut packet_count = 0;
            if let Ok(mut stream) = proxy.receive_packet_captured().await {
                while let Some(signal) = stream.next().await {
                    let packet = match signal.args() {
                        Ok(p) => p.packet,
                        Err(_) => continue,
                    };
                    
                    let mut title = format!("{} -> {} ({})", packet.src_ip, packet.dst_ip, packet.protocol);
                    let row = ActionRow::builder()
                        .subtitle(format!("Taille: {} octets", packet.length))
                        .build();
                    
                    if packet.unencrypted {
                        title.push_str(" [NON CHIFFRÉ !]");
                        row.add_css_class("error"); // highlights the row in red if GTK theme supports it
                    }
                    row.set_title(&title);

                    list_box_ui.prepend(&row);
                    packet_count += 1;

                    // Limit to 1000 items
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

    let stop_btn_clone = stop_button.clone();
    let start_btn_clone2 = start_button.clone();
    
    stop_button.connect_clicked(move |_| {
        stop_btn_clone.set_sensitive(false);
        start_btn_clone2.set_sensitive(true);

        gtk::glib::MainContext::default().spawn_local(async move {
            if let Ok(connection) = zbus::Connection::system().await {
                if let Ok(proxy) = netsentinel_proto::Capture1Proxy::new(&connection).await {
                    let _ = proxy.stop_capture().await;
                }
            }
        });
    });

    container
}
