use adw::prelude::*;
use adw::{ActionRow, EntryRow, PreferencesGroup};
use gtk::{
    Align, Box as GtkBox, Button, Label, LevelBar, ListBox, Orientation, ScrolledWindow,
    SelectionMode, Spinner,
};
use netsentinel_proto::Severity;
use std::path::Path;

fn nuclei_is_installed() -> bool {
    Path::new("/usr/bin/nuclei").exists() || Path::new("/usr/local/bin/nuclei").exists()
}

fn severity_level(sev: Severity) -> f64 {
    match sev {
        Severity::Critical => 1.0,
        Severity::High => 0.8,
        Severity::Medium => 0.55,
        Severity::Low => 0.3,
        _ => 0.05,
    }
}

fn severity_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "success",
    }
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
        .label("<b>Audit de vulnérabilités</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let description = Label::builder()
        .label("Cartographie des services ouverts (nmap -sV) puis détection de CVE/misconfig (Nuclei YAML).")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    // Bannière d'état Nuclei (optionnel recommandé)
    let nuclei_banner = if nuclei_is_installed() {
        Label::builder()
            .label("<span foreground='#26a269'>✅ Nuclei détecté — audit complet (nmap + CVE/YAML)</span>")
            .use_markup(true)
            .halign(Align::Start)
            .build()
    } else {
        Label::builder()
            .label("<span foreground='#e5a50a'>⚠️ Nuclei non installé — audit en mode dégradé (nmap seul, sans CVE).\nInstaller depuis ProjectDiscovery/releases puis déposer les templates YAML dans <tt>/usr/share/nuclei-templates/</tt>.</span>")
            .use_markup(true)
            .wrap(true)
            .halign(Align::Start)
            .build()
    };
    container.append(&nuclei_banner);

    // Configuration de la cible
    let config_group = PreferencesGroup::new();
    config_group.set_title("Cible");
    config_group.set_description(Some(
        "Adresse IP ou hostname LAN appartenant au périmètre autorisé (RE-02).",
    ));
    let target_entry = EntryRow::builder()
        .title("Cible")
        .text("192.168.1.1")
        .build();
    config_group.add(&target_entry);
    container.append(&config_group);

    // Boutons
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

    // Barre de niveau global de risque
    let risk_label = Label::builder()
        .label("Score de risque global")
        .halign(Align::Start)
        .build();
    let risk_bar = LevelBar::builder()
        .min_value(0.0)
        .max_value(1.0)
        .value(0.0)
        .build();
    risk_bar.add_offset_value(gtk::LEVEL_BAR_OFFSET_LOW, 0.3);
    risk_bar.add_offset_value(gtk::LEVEL_BAR_OFFSET_HIGH, 0.7);
    let risk_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .build();
    risk_box.append(&risk_label);
    risk_box.append(&risk_bar);
    container.append(&risk_box);

    // Résultats
    let summary_label = Label::builder()
        .label("<i>Aucun audit réalisé pour l'instant.</i>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    container.append(&summary_label);

    let results_group = ListBox::builder()
        .selection_mode(SelectionMode::None)
        .css_classes(vec!["boxed-list".to_string()])
        .build();

    let results_container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .vexpand(true)
        .build();

    let scrolled_window = ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(400)
        .vexpand(true)
        .child(&results_group)
        .build();

    results_container.append(&scrolled_window);
    container.append(&results_container);

    // ========== HANDLER ==========
    let start_btn_clone = start_button.clone();
    let spinner_clone = spinner.clone();
    let results_clone = results_group.clone();
    let summary_clone = summary_label.clone();
    let risk_bar_clone = risk_bar.clone();

    start_button.connect_clicked(move |_| {
        let target = target_entry.text().to_string();
        if target.trim().is_empty() {
            return;
        }
        start_btn_clone.set_sensitive(false);
        spinner_clone.start();
        summary_clone.set_markup("<i>Audit en cours... patience, nmap peut prendre 1 à 3 minutes.</i>");

        while let Some(child) = results_clone.first_child() {
            results_clone.remove(&child);
        }

        let start_btn_ui = start_btn_clone.clone();
        let spinner_ui = spinner_clone.clone();
        let results_ui = results_clone.clone();
        let summary_ui = summary_clone.clone();
        let risk_ui = risk_bar_clone.clone();

        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    summary_ui.set_markup(&format!(
                        "<span foreground='red'>❌ Connexion D-Bus : {}</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };

            let proxy = match netsentinel_proto::Scan1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    summary_ui.set_markup(&format!(
                        "<span foreground='red'>❌ Service Scan1 : {}</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };

            match proxy.deep_scan(&target).await {
                Ok(findings) => {
                    let total = findings.len();
                    let mut crit = 0u32;
                    let mut high = 0u32;
                    let mut med = 0u32;
                    let mut low = 0u32;
                    let mut max_risk = 0.0_f64;

                    for finding in findings {
                        let risk = severity_level(finding.severity);
                        if risk > max_risk {
                            max_risk = risk;
                        }
                        let counter_row = match finding.severity {
                            Severity::Critical => {
                                crit += 1;
                                Some("crit")
                            }
                            Severity::High => {
                                high += 1;
                                Some("high")
                            }
                            Severity::Medium => {
                                med += 1;
                                Some("med")
                            }
                            Severity::Low => {
                                low += 1;
                                Some("low")
                            }
                            _ => None,
                        };

                        let sev_label = format!("{:?}", finding.severity);
                        let port_txt = if finding.port > 0 {
                            format!("TCP/{}", finding.port)
                        } else {
                            "(sans port — Nuclei template)".into()
                        };
                        let service_txt = if finding.service.is_empty() {
                            finding.cve.clone()
                        } else {
                            finding.service.clone()
                        };

                        let title = format!("{} · {} · [{}]", port_txt, service_txt, sev_label);

                        let subtitle = if finding.cve.is_empty() {
                            finding.description.clone()
                        } else {
                            format!("{} · CVE: {}", finding.description, finding.cve)
                        };

                        let row = ActionRow::builder()
                            .title(&title)
                            .subtitle(&subtitle)
                            .build();
                        let _ = counter_row;
                        row.add_css_class(severity_class(finding.severity));
                        results_ui.append(&row);
                    }

                    risk_ui.set_value(max_risk);

                    if total == 0 {
                        summary_ui.set_markup(
                            "<span foreground='#26a269'>✅ 0 finding — surface auditee saine.</span>",
                        );
                        let row = ActionRow::builder()
                            .title("Aucune vulnérabilité ouverte détectée")
                            .subtitle(
                                "Les ports filtrés (non répondants) ne sont pas affichés — ré-exécutez avec -sS depuis root si besoin.",
                            )
                            .build();
                        results_ui.append(&row);
                    } else {
                        summary_ui.set_markup(&format!(
                            "<b>{}</b> findings — <span foreground='red'>C:{} H:{}</span> · <span foreground='orange'>M:{}</span> · <span foreground='dim-label'>L:{}</span>",
                            total, crit, high, med, low
                        ));
                    }
                }
                Err(e) => {
                    let row = ActionRow::builder()
                        .title("Échec de l'audit")
                        .subtitle(e.to_string())
                        .build();
                    row.add_css_class("error");
                    results_ui.append(&row);
                    summary_ui.set_markup(&format!(
                        "<span foreground='red'>❌ deep_scan : {}</span>",
                        e
                    ));
                }
            }

            start_btn_ui.set_sensitive(true);
            spinner_ui.stop();
        });
    });

    container
}
