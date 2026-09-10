use adw::prelude::*;
use adw::{ComboRow, EntryRow, PreferencesGroup};
use gtk::glib;
use gtk::{Align, Box as GtkBox, Button, Label, Orientation, ScrolledWindow, StringList, TextView};
use netsentinel_core::ledger::AuditEntry;
use netsentinel_core::report::{ExportFormat, ReportGenerator};
use netsentinel_core::vuln_scanner::VulnFinding;

use crate::app_state::SharedState;

pub fn build_page(state: &SharedState) -> GtkBox {
    let container = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();

    let title = Label::builder()
        .label("<b>Rapports de Sécurité</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let description = Label::builder()
        .label("Générez et exportez des rapports d'audit consolidés conformes aux normes PDDL et d'audit cryptographique.")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    // Indicateur de données disponibles
    let data_status = Label::builder()
        .label("")
        .use_markup(true)
        .halign(Align::Start)
        .wrap(true)
        .build();
    container.append(&data_status);

    // Configuration
    let config_group = PreferencesGroup::new();
    config_group.set_title("Configuration du rapport");

    let report_title_entry = EntryRow::builder()
        .title("Titre de la session / audit")
        .text("Audit Réseau Local NetSentinel")
        .build();

    let export_path_entry = EntryRow::builder()
        .title("Chemin d'export du fichier")
        .text("/tmp/netsentinel_rapport.html")
        .build();

    let format_model = StringList::new(&["HTML (.html)", "Markdown (.md)", "JSON (.json)"]);
    let format_combo = ComboRow::builder()
        .title("Format de sortie")
        .model(&format_model)
        .selected(0)
        .build();

    config_group.add(&report_title_entry);
    config_group.add(&export_path_entry);
    config_group.add(&format_combo);
    container.append(&config_group);

    // Boutons
    let action_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let generate_button = Button::builder()
        .label("📄 Générer & Exporter le Rapport")
        .css_classes(vec!["suggested-action".to_string()])
        .build();

    action_box.append(&generate_button);
    container.append(&action_box);

    // Prévisualisation
    let preview_label = Label::builder()
        .label("<b>Aperçu du contenu</b>")
        .use_markup(true)
        .halign(Align::Start)
        .margin_top(12)
        .build();
    container.append(&preview_label);

    let text_view = TextView::builder()
        .editable(false)
        .monospace(true)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(6)
        .margin_end(6)
        .build();

    let scrolled_window = ScrolledWindow::builder()
        .child(&text_view)
        .min_content_height(250)
        .hexpand(true)
        .vexpand(true)
        .css_classes(vec!["card".to_string()])
        .build();

    container.append(&scrolled_window);

    let status_label = Label::builder()
        .label("<i>Prêt à générer.</i>")
        .use_markup(true)
        .halign(Align::Start)
        .wrap(true)
        .build();
    container.append(&status_label);

    // Mettre à jour le statut des données
    let state_for_status = Arc::clone(state);
    let data_status_clone = data_status.clone();
    glib::idle_add_local_once(move || {
        let mut parts = Vec::new();

        if let Ok(Some(session)) = state_for_status.session_manager.get_active_session() {
            if let Ok(findings) = state_for_status.session_manager.get_findings(session.id) {
                parts.push(format!(
                    "{} findings en session #{}",
                    findings.len(),
                    session.id
                ));
            }
            if let Ok(hosts) = state_for_status.session_manager.get_hosts(session.id) {
                parts.push(format!("{} hôtes découverts", hosts.len()));
            }
        }

        match state_for_status.session_manager.get_settings() {
            Ok(_) => parts.push("DB session: ✅".to_string()),
            Err(_) => parts.push("DB session: ❌".to_string()),
        }

        data_status_clone.set_markup(&format!(
            "<b>Données disponibles:</b> {}",
            if parts.is_empty() {
                "aucune session active — le rapport utilisera des données de démonstration."
                    .to_string()
            } else {
                parts.join(" · ")
            }
        ));
    });

    // HANDLER : Générer
    let title_entry_clone = report_title_entry.clone();
    let path_entry_clone = export_path_entry.clone();
    let combo_clone = format_combo.clone();
    let status_clone = status_label.clone();
    let tv_clone = text_view.clone();
    let state_clone = Arc::clone(state);

    generate_button.connect_clicked(move |_| {
        let title_text = title_entry_clone.text().to_string();
        let export_path = path_entry_clone.text().to_string();
        let selected_idx = combo_clone.selected();

        let (format, default_ext) = match selected_idx {
            1 => (ExportFormat::Markdown, ".md"),
            2 => (ExportFormat::Json, ".json"),
            _ => (ExportFormat::Html, ".html"),
        };

        // Collecter les données RÉELLES depuis la session active + ledger
        let (findings, ledger_entries) = collect_report_data(&state_clone);

        let content = match format {
            ExportFormat::Markdown => {
                ReportGenerator::generate_markdown(&title_text, &findings, &ledger_entries)
            }
            ExportFormat::Json => {
                ReportGenerator::generate_json(&title_text, &findings, &ledger_entries)
            }
            ExportFormat::Html => {
                ReportGenerator::generate_html(&title_text, &findings, &ledger_entries)
            }
        };

        let buffer = tv_clone.buffer();
        buffer.set_text(&content);

        let mut final_path = export_path.clone();
        if !final_path.ends_with(default_ext) {
            final_path.push_str(default_ext);
        }

        match ReportGenerator::export_report(
            &final_path,
            format,
            &title_text,
            &findings,
            &ledger_entries,
        ) {
            Ok(_) => {
                status_clone.set_markup(&format!(
                    "<span foreground='#26a269'>✅ Rapport généré et exporté avec succès vers <b>{}</b></span>",
                    glib::markup_escape_text(&final_path)
                ));
            }
            Err(e) => {
                status_clone.set_markup(&format!(
                    "<span foreground='red'>❌ Échec de l'exportation : {}</span>",
                    glib::markup_escape_text(&e.to_string())
                ));
            }
        }
    });

    container
}

use std::sync::Arc;

fn collect_report_data(state: &SharedState) -> (Vec<VulnFinding>, Vec<AuditEntry>) {
    let findings = if let Ok(Some(session)) = state.session_manager.get_active_session() {
        state
            .session_manager
            .get_findings(session.id)
            .unwrap_or_default()
            .into_iter()
            .map(|f| {
                let severity = match f.severity.to_lowercase().as_str() {
                    "critical" => netsentinel_core::Severity::Critical,
                    "high" => netsentinel_core::Severity::High,
                    "medium" => netsentinel_core::Severity::Medium,
                    "low" => netsentinel_core::Severity::Low,
                    _ => netsentinel_core::Severity::Info,
                };
                VulnFinding {
                    service: f.service,
                    cve: f.cve,
                    summary: f.description,
                    severity,
                    matched_banner: f.target,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let ledger = state.ledger.export_ledger().unwrap_or_default();

    (findings, ledger)
}
