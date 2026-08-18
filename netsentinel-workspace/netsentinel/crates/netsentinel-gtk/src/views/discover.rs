use adw::prelude::*;
use adw::{ActionRow, EntryRow, PreferencesGroup};
use gtk::{Align, Box as GtkBox, Button, Label, Orientation, Spinner};

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
        .label("<b>Découverte du réseau</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let description = Label::builder()
        .label("Analysez votre réseau local pour découvrir les appareils connectés.")
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

    let scan_button = Button::builder()
        .label("Lancer le scan")
        .css_classes(vec!["suggested-action".to_string()])
        .build();

    let spinner = Spinner::builder().build();

    action_box.append(&scan_button);
    action_box.append(&spinner);
    container.append(&action_box);

    let results_group = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(vec!["boxed-list".to_string()])
        .build();

    let results_container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .build();
    results_container.append(
        &Label::builder()
            .label("<b>Résultats</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build(),
    );
    results_container.append(&results_group);

    container.append(&results_container);

    let results_group_clone = results_group.clone();

    scan_button.connect_clicked(move |btn| {
        let iface = interface_entry.text().to_string();
        let spinner_clone = spinner.clone();
        let results = results_group_clone.clone();
        let btn_clone = btn.clone();

        btn_clone.set_sensitive(false);
        spinner_clone.start();

        // Clear previous results
        while let Some(child) = results.first_child() {
            results.remove(&child);
        }

        gtk::glib::MainContext::default().spawn_local(async move {
            match run_discovery_scan(&iface).await {
                Ok(hosts) => {
                    let is_empty = hosts.is_empty();
                    for host in hosts {
                        let row = ActionRow::builder()
                            .title(host.ip.clone())
                            .subtitle(format!(
                                "MAC: {} | Vendor: {} | Hostname: {}",
                                host.mac,
                                if host.vendor.is_empty() {
                                    "Inconnu"
                                } else {
                                    &host.vendor
                                },
                                if host.hostname.is_empty() {
                                    "Inconnu"
                                } else {
                                    &host.hostname
                                }
                            ))
                            .build();
                        results.append(&row);
                    }
                    if is_empty {
                        let row = ActionRow::builder().title("Aucun appareil trouvé").build();
                        results.append(&row);
                    }
                }
                Err(e) => {
                    let row = ActionRow::builder()
                        .title("Erreur lors du scan")
                        .subtitle(e.to_string())
                        .build();
                    results.append(&row);
                }
            }
            spinner_clone.stop();
            btn_clone.set_sensitive(true);
        });
    });

    container
}

async fn run_discovery_scan(
    interface: &str,
) -> anyhow::Result<Vec<netsentinel_proto::DiscoveredHost>> {
    let connection = zbus::Connection::system().await?;
    let proxy = netsentinel_proto::Discover1Proxy::new(&connection).await?;
    let hosts = proxy.scan(interface, 5000).await?;
    Ok(hosts)
}
