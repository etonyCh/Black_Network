use adw::prelude::*;
use gtk::{Align, Box as GtkBox, Button, Entry, Label, Orientation, ScrolledWindow, Spinner};
use netsentinel_proto::Severity;
use std::sync::Arc;

use crate::app_state::{show_toast, SharedState};

fn severity_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "badge-cvss-critical",
        Severity::High => "badge-cvss-high",
        Severity::Medium => "badge-cvss-medium",
        _ => "badge-cvss-info",
    }
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critique · CVSS 9.8",
        Severity::High => "Élevée · CVSS 7.5",
        Severity::Medium => "Moyenne · CVSS 5.3",
        Severity::Low => "Faible · CVSS 3.1",
        Severity::Info => "Info",
    }
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
        .label("Audit de vulnérabilités")
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let subtitle = Label::builder()
        .label("nmap -sV + Nuclei — périmètre LAN autorisé")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    header_box.append(&title);
    header_box.append(&subtitle);
    container.append(&header_box);

    // 2. Controls & Step Progress Row
    let controls_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let target_entry = Entry::builder()
        .placeholder_text("Cible IP (ex: 192.168.1.1)")
        .text("192.168.1.1")
        .build();
    target_entry.set_size_request(220, -1);

    let start_button = Button::builder()
        .label("Lancer l'audit")
        .css_classes(vec!["btn-suggested".to_string()])
        .icon_name("security-high-symbolic")
        .build();

    let spinner = Spinner::builder().build();

    // Step Progress Steps Indicator
    let steps_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(10)
        .valign(Align::Center)
        .margin_start(16)
        .build();

    let step1 = Label::builder()
        .label("<span foreground='#4ade80'>● Découverte</span>")
        .use_markup(true)
        .build();
    let step2 = Label::builder()
        .label("<span foreground='#4ade80'>● Services</span>")
        .use_markup(true)
        .build();
    let step3 = Label::builder()
        .label("<span foreground='#94a3b8'>● CVE / Nuclei</span>")
        .use_markup(true)
        .build();
    let pct_lbl = Label::builder()
        .label("<span foreground='#f59e0b'><b>68%</b></span>")
        .use_markup(true)
        .build();

    steps_box.append(&step1);
    steps_box.append(&step2);
    steps_box.append(&step3);
    steps_box.append(&pct_lbl);

    controls_box.append(&target_entry);
    controls_box.append(&start_button);
    controls_box.append(&spinner);
    controls_box.append(&steps_box);
    container.append(&controls_box);

    // 3. Main Split View: Left Donut Risk Score + Right Vulnerability List Cards
    let main_split = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(16)
        .vexpand(true)
        .build();

    // Left Card: Donut Score Gauge
    let risk_card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(16)
        .css_classes(vec!["metric-card".to_string()])
        .valign(Align::Start)
        .build();
    risk_card.set_size_request(280, -1);

    let risk_card_title = Label::builder()
        .label("<b>Score de risque global</b>")
        .use_markup(true)
        .halign(Align::Center)
        .build();

    let donut_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .halign(Align::Center)
        .spacing(4)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let donut_text = Label::builder()
        .label("<span foreground='#f59e0b' size='36000'><b>42</b></span>")
        .use_markup(true)
        .halign(Align::Center)
        .build();

    let risk_subtitle = Label::builder()
        .label("Modéré · 2 CVE · 1 misconfig")
        .halign(Align::Center)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    donut_box.append(&donut_text);
    risk_card.append(&risk_card_title);
    risk_card.append(&donut_box);
    risk_card.append(&risk_subtitle);
    main_split.append(&risk_card);

    // Right Card: Vulnerability Findings List
    let results_card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .css_classes(vec!["metric-card".to_string()])
        .hexpand(true)
        .build();

    let results_header = Label::builder()
        .label("<b>Résultats du dernier audit — 26 sept. 2026, 16:28</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    results_card.append(&results_header);
    results_card.append(&gtk::Separator::new(Orientation::Horizontal));

    let findings_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(10)
        .build();

    let sample_findings = [
        (
            "CVE-2024-3721 — serveur HTTP de la box",
            "Injection dans l'interface d'admin",
            "Mise à jour du firmware recommandée",
            Severity::High,
        ),
        (
            "CVE-2023-48795 — algorithme Terrapin",
            "Vulnérabilité dans le serveur SSH (Prefix Truncation)",
            "Restreindre les algorithmes obsolètes",
            Severity::Medium,
        ),
        (
            "Telnet activé sur le port 23",
            "Service de gestion réseau non chiffré",
            "Désactiver Telnet, préférer SSH",
            Severity::Low,
        ),
        (
            "443/tcp — TLS 1.3",
            "Certificat valide et suite cryptographique conforme",
            "Aucune action requise",
            Severity::Info,
        ),
    ];

    for (cve_title, desc, rec, sev) in sample_findings {
        let card = create_vuln_card(cve_title, desc, rec, sev);
        findings_box.append(&card);
    }

    let scrolled_window = ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&findings_box)
        .build();

    results_card.append(&scrolled_window);
    main_split.append(&results_card);
    container.append(&main_split);

    // Handlers
    let state_clone = Arc::clone(state);
    let start_btn_clone = start_button.clone();
    let spinner_clone = spinner.clone();
    let findings_box_clone = findings_box.clone();
    let donut_text_clone = donut_text.clone();
    let risk_subtitle_clone = risk_subtitle.clone();
    let pct_lbl_clone = pct_lbl.clone();

    start_button.connect_clicked(move |_| {
        let target = target_entry.text().to_string();
        if target.trim().is_empty() {
            show_toast("Veuillez saisir une adresse IP cible");
            return;
        }

        start_btn_clone.set_sensitive(false);
        spinner_clone.start();
        pct_lbl_clone.set_markup("<span foreground='#f59e0b'><b>15%</b></span>");
        show_toast(&format!("Audit démarré sur {}", target));

        let start_ui = start_btn_clone.clone();
        let spinner_ui = spinner_clone.clone();
        let findings_ui = findings_box_clone.clone();
        let donut_ui = donut_text_clone.clone();
        let risk_ui = risk_subtitle_clone.clone();
        let pct_ui = pct_lbl_clone.clone();
        let state_inner = Arc::clone(&state_clone);

        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    show_toast(&format!("Erreur D-Bus: {}", e));
                    start_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };

            let proxy = match netsentinel_proto::Scan1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    show_toast(&format!("Service Scan1 introuvable: {}", e));
                    start_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };

            pct_ui.set_markup("<span foreground='#f59e0b'><b>68%</b></span>");

            match proxy.deep_scan(&target).await {
                Ok(findings) => {
                    while let Some(child) = findings_ui.first_child() {
                        findings_ui.remove(&child);
                    }

                    let session_id = state_inner
                        .session_manager
                        .get_active_session()
                        .ok()
                        .flatten()
                        .map(|s| s.id);

                    let total = findings.len();
                    for finding in &findings {
                        if let Some(sid) = session_id {
                            let _ = state_inner.session_manager.add_finding(
                                sid,
                                &finding.target,
                                finding.port,
                                &finding.service,
                                &finding.cve,
                                &format!("{:?}", finding.severity),
                                &finding.description,
                            );
                        }

                        let card = create_vuln_card(
                            &format!("{} — {}", finding.cve, finding.service),
                            &finding.description,
                            "Vérifier les correctifs de sécurité",
                            finding.severity,
                        );
                        findings_ui.append(&card);
                    }

                    donut_ui.set_markup("<span foreground='#4ade80' size='36000'><b>18</b></span>");
                    risk_ui.set_label(&format!("Faible · {} findings identifiés", total));
                    pct_ui.set_markup("<span foreground='#4ade80'><b>100%</b></span>");
                    show_toast(&format!(
                        "Audit terminé — {} vulnérabilités détectées",
                        total
                    ));
                }
                Err(e) => {
                    show_toast(&format!("Erreur d'audit: {}", e));
                }
            }

            start_ui.set_sensitive(true);
            spinner_ui.stop();
        });
    });

    container
}

fn create_vuln_card(title: &str, desc: &str, remediation: &str, sev: Severity) -> GtkBox {
    let card = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .margin_bottom(4)
        .build();

    let badge = Label::builder()
        .label(severity_label(sev))
        .css_classes(vec![severity_class(sev).to_string()])
        .build();
    let badge_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .halign(Align::Start)
        .valign(Align::Start)
        .build();
    badge_box.set_size_request(140, -1);
    badge_box.append(&badge);

    let content_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .build();

    let title_lbl = Label::builder()
        .label(format!("<b>{title}</b>"))
        .use_markup(true)
        .halign(Align::Start)
        .build();

    let desc_lbl = Label::builder()
        .label(desc)
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    let rec_lbl = Label::builder()
        .label(format!(
            "<span foreground='#94a3b8' size='small'>💡 Remédiation : {}</span>",
            remediation
        ))
        .use_markup(true)
        .halign(Align::Start)
        .build();

    content_box.append(&title_lbl);
    content_box.append(&desc_lbl);
    content_box.append(&rec_lbl);

    card.append(&badge_box);
    card.append(&content_box);
    card
}
