use adw::prelude::*;
use adw::{ActionRow, EntryRow, PreferencesGroup};
use gtk::{Align, Box as GtkBox, Button, Label, ListBox, Orientation, ScrolledWindow, SelectionMode, Spinner};
use netsentinel_proto::Severity;

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
        .label("<b>Audit de Vulnérabilités</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();
    
    let description = Label::builder()
        .label("Découverte de services (nmap) et détection de failles (nuclei).")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    let config_group = PreferencesGroup::new();
    let target_entry = EntryRow::builder()
        .title("Cible (IP ou Hostname)")
        .text("127.0.0.1")
        .build();
    config_group.add(&target_entry);
    
    container.append(&config_group);

    let action_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let start_button = Button::builder()
        .label("Lancer l'audit")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    
    let spinner = Spinner::builder()
        .halign(Align::Center)
        .valign(Align::Center)
        .build();

    action_box.append(&start_button);
    action_box.append(&spinner);
    container.append(&action_box);

    let results_group = ListBox::builder()
        .selection_mode(SelectionMode::None)
        .css_classes(vec!["boxed-list".to_string()])
        .build();
    
    let results_container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .vexpand(true)
        .build();
    
    let scrolled_window = ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(400)
        .vexpand(true)
        .child(&results_group)
        .build();

    results_container.append(&Label::builder().label("<b>Résultats</b>").use_markup(true).halign(Align::Start).build());
    results_container.append(&scrolled_window);
    container.append(&results_container);

    let start_btn_clone = start_button.clone();
    let spinner_clone = spinner.clone();
    let results_clone = results_group.clone();
    
    start_button.connect_clicked(move |_| {
        let target = target_entry.text().to_string();
        start_btn_clone.set_sensitive(false);
        spinner_clone.start();

        while let Some(child) = results_clone.first_child() {
            results_clone.remove(&child);
        }

        let start_btn_ui = start_btn_clone.clone();
        let spinner_ui = spinner_clone.clone();
        let results_ui = results_clone.clone();
        
        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Erreur D-Bus: {}", e);
                    start_btn_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };
            
            let proxy = match netsentinel_proto::Scan1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("Erreur proxy: {}", e);
                    start_btn_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };

            match proxy.deep_scan(&target).await {
                Ok(findings) => {
                    let is_empty = findings.is_empty();
                    for finding in findings {
                        let severity_text = format!("{:?}", finding.severity);
                        let title = format!("{} (Port {}) - [{}]", finding.service, finding.port, severity_text);
                        let row = ActionRow::builder()
                            .title(title)
                            .subtitle(format!("{} | CVE: {}", finding.description, finding.cve))
                            .build();
                        
                        match finding.severity {
                            Severity::Critical | Severity::High => {
                                row.add_css_class("error"); // Rouge
                            },
                            Severity::Medium => {
                                row.add_css_class("warning"); // Orange/Jaune si géré
                            },
                            _ => {}
                        }
                        results_ui.append(&row);
                    }
                    if is_empty {
                        let row = ActionRow::builder()
                            .title("Aucune vulnérabilité trouvée")
                            .build();
                        results_ui.append(&row);
                    }
                }
                Err(e) => {
                    let row = ActionRow::builder()
                        .title("Erreur lors de l'audit")
                        .subtitle(e.to_string())
                        .build();
                    row.add_css_class("error");
                    results_ui.append(&row);
                }
            }
            
            start_btn_ui.set_sensitive(true);
            spinner_ui.stop();
        });
    });

    container
}
