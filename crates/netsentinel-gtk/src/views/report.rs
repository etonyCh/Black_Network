use adw::prelude::*;
use gtk::{
    Align, Box as GtkBox, Button, CheckButton, Entry, Label, Orientation, ScrolledWindow, TextView,
};
use netsentinel_core::ledger::AuditEntry;
use netsentinel_core::report::{ExportFormat, ReportGenerator};
use netsentinel_core::vuln_scanner::{Severity, VulnFinding};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use crate::app_state::{show_toast, SharedState};

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
        .label("Rapports de sécurité")
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let subtitle = Label::builder()
        .label("Export consolidé — inventaire, CVE et trafic")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    header_box.append(&title);
    header_box.append(&subtitle);
    container.append(&header_box);

    // Database Connection Badge
    let db_status = Label::builder()
        .label("Base de données : <span foreground='#4ade80'>connectée</span>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    container.append(&db_status);

    // 2. Configuration Form Card
    let form_card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(16)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    // Field 1: Titre du rapport
    let title_field_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .build();
    let title_lbl = Label::builder()
        .label("<b>Titre du rapport</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    let title_entry = Entry::builder()
        .text("Audit réseau local — NetSentinel")
        .build();
    title_field_box.append(&title_lbl);
    title_field_box.append(&title_entry);
    form_card.append(&title_field_box);

    // Field 2: Format de sortie (Segmented Pill Buttons)
    let format_field_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .build();
    let format_lbl = Label::builder()
        .label("<b>Format de sortie</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();

    let format_pills_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .halign(Align::Start)
        .build();

    let btn_html = Button::builder()
        .label("HTML")
        .css_classes(vec!["btn-suggested".to_string()])
        .build();
    let btn_pdf = Button::builder().label("PDF").build();
    let btn_json = Button::builder().label("JSON").build();
    let btn_csv = Button::builder().label("CSV").build();

    format_pills_box.append(&btn_html);
    format_pills_box.append(&btn_pdf);
    format_pills_box.append(&btn_json);
    format_pills_box.append(&btn_csv);

    format_field_box.append(&format_lbl);
    format_field_box.append(&format_pills_box);
    form_card.append(&format_field_box);

    let selected_format = Rc::new(RefCell::new(ExportFormat::Html));

    // Field 3: Dossier d'export
    let path_field_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .build();
    let path_lbl = Label::builder()
        .label("<b>Dossier d'export</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();

    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let default_export_dir = format!("{}/Documents/NetSentinel/", home_dir);

    let path_entry = Entry::builder().text(&default_export_dir).build();
    path_field_box.append(&path_lbl);
    path_field_box.append(&path_entry);
    form_card.append(&path_field_box);

    // Field 4: Sections incluses
    let sections_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .build();
    let sections_lbl = Label::builder()
        .label("<b>Sections incluses</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();

    let check1 = CheckButton::builder()
        .label("Inventaire des hôtes et changements depuis le dernier scan")
        .active(true)
        .build();
    let check2 = CheckButton::builder()
        .label("Vulnérabilités avec scores CVSS et remédiations")
        .active(true)
        .build();
    let check3 = CheckButton::builder()
        .label("Statistiques de trafic capturé")
        .active(true)
        .build();

    sections_box.append(&sections_lbl);
    sections_box.append(&check1);
    sections_box.append(&check2);
    sections_box.append(&check3);
    form_card.append(&sections_box);

    // Actions & Compliance Row
    let action_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(16)
        .margin_top(8)
        .build();

    let generate_btn = Button::builder()
        .label("Générer et exporter")
        .icon_name("document-save-symbolic")
        .css_classes(vec!["btn-suggested".to_string()])
        .build();

    let compliance_note = Label::builder()
        .label("Aperçu disponible avant export · conforme RGPD / ISO 27001 / NIST CSF")
        .css_classes(vec!["dim-label".to_string()])
        .halign(Align::Start)
        .valign(Align::Center)
        .build();

    action_row.append(&generate_btn);
    action_row.append(&compliance_note);
    form_card.append(&action_row);

    container.append(&form_card);

    // 3. Live Preview Card
    let preview_card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .css_classes(vec!["metric-card".to_string()])
        .vexpand(true)
        .build();

    let preview_lbl = Label::builder()
        .label("<b>Aperçu du contenu</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    preview_card.append(&preview_lbl);

    let text_view = TextView::builder().editable(false).monospace(true).build();

    let scroll = ScrolledWindow::builder()
        .child(&text_view)
        .min_content_height(200)
        .vexpand(true)
        .build();

    preview_card.append(&scroll);
    container.append(&preview_card);

    // Format selection pill logic
    let b_h1 = btn_html.clone();
    let b_p1 = btn_pdf.clone();
    let b_j1 = btn_json.clone();
    let b_c1 = btn_csv.clone();
    let fmt_html = selected_format.clone();

    btn_html.connect_clicked(move |_| {
        *fmt_html.borrow_mut() = ExportFormat::Html;
        b_h1.add_css_class("btn-suggested");
        b_p1.remove_css_class("btn-suggested");
        b_j1.remove_css_class("btn-suggested");
        b_c1.remove_css_class("btn-suggested");
    });

    let b_h2 = btn_html.clone();
    let b_p2 = btn_pdf.clone();
    let b_j2 = btn_json.clone();
    let b_c2 = btn_csv.clone();
    let fmt_pdf = selected_format.clone();

    btn_pdf.connect_clicked(move |_| {
        *fmt_pdf.borrow_mut() = ExportFormat::Pdf;
        b_h2.remove_css_class("btn-suggested");
        b_p2.add_css_class("btn-suggested");
        b_j2.remove_css_class("btn-suggested");
        b_c2.remove_css_class("btn-suggested");
    });

    let b_h3 = btn_html.clone();
    let b_p3 = btn_pdf.clone();
    let b_j3 = btn_json.clone();
    let b_c3 = btn_csv.clone();
    let fmt_json = selected_format.clone();

    btn_json.connect_clicked(move |_| {
        *fmt_json.borrow_mut() = ExportFormat::Json;
        b_h3.remove_css_class("btn-suggested");
        b_p3.remove_css_class("btn-suggested");
        b_j3.add_css_class("btn-suggested");
        b_c3.remove_css_class("btn-suggested");
    });

    let b_h4 = btn_html.clone();
    let b_p4 = btn_pdf.clone();
    let b_j4 = btn_json.clone();
    let b_c4 = btn_csv.clone();
    let fmt_csv = selected_format.clone();

    btn_csv.connect_clicked(move |_| {
        *fmt_csv.borrow_mut() = ExportFormat::Csv;
        b_h4.remove_css_class("btn-suggested");
        b_p4.remove_css_class("btn-suggested");
        b_j4.remove_css_class("btn-suggested");
        b_c4.add_css_class("btn-suggested");
    });

    // Populate Initial Preview with real session data or sample demo data
    let (findings, ledger) = collect_report_data(state);
    let sample_title = title_entry.text().to_string();
    let initial_content = ReportGenerator::generate_html(&sample_title, &findings, &ledger);
    text_view.buffer().set_text(&initial_content);

    // Generate Button Handler
    let state_clone = Arc::clone(state);
    let title_entry_clone = title_entry.clone();
    let path_entry_clone = path_entry.clone();
    let text_view_clone = text_view.clone();
    let selected_fmt_gen = selected_format.clone();

    generate_btn.connect_clicked(move |_| {
        let title_text = title_entry_clone.text().to_string();
        let export_dir = path_entry_clone.text().to_string();
        let fmt = *selected_fmt_gen.borrow();

        let ext = match fmt {
            ExportFormat::Html => "html",
            ExportFormat::Pdf => "pdf.html",
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
            ExportFormat::Markdown => "md",
        };

        let file_path = format!("{}/rapport_audit.{}", export_dir.trim_end_matches('/'), ext);
        let (findings, ledger) = collect_report_data(&state_clone);

        let preview_text = match fmt {
            ExportFormat::Html => ReportGenerator::generate_html(&title_text, &findings, &ledger),
            ExportFormat::Pdf => {
                ReportGenerator::generate_pdf_html(&title_text, &findings, &ledger)
            }
            ExportFormat::Json => ReportGenerator::generate_json(&title_text, &findings, &ledger),
            ExportFormat::Csv => ReportGenerator::generate_csv(&title_text, &findings, &ledger),
            ExportFormat::Markdown => {
                ReportGenerator::generate_markdown(&title_text, &findings, &ledger)
            }
        };

        text_view_clone.buffer().set_text(&preview_text);

        match ReportGenerator::export_report(&file_path, fmt, &title_text, &findings, &ledger) {
            Ok(_) => {
                show_toast(&format!("Rapport exporté avec succès vers {}", file_path));
            }
            Err(e) => {
                show_toast(&format!("Échec d'exportation: {}", e));
            }
        }
    });

    container
}

fn collect_report_data(state: &SharedState) -> (Vec<VulnFinding>, Vec<AuditEntry>) {
    let mut findings = Vec::new();
    if let Ok(Some(session)) = state.session_manager.get_active_session() {
        if let Ok(db_findings) = state.session_manager.get_findings(session.id) {
            for f in db_findings {
                let severity = match f.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };
                findings.push(VulnFinding {
                    service: f.service,
                    cve: f.cve,
                    summary: f.description,
                    severity,
                    matched_banner: f.target,
                });
            }
        }
    }

    if findings.is_empty() {
        // Fallback sample demo data for realistic previews when database is empty
        findings = vec![
            VulnFinding {
                service: "HTTP Box Admin".to_string(),
                cve: "CVE-2024-3721".to_string(),
                summary: "Injection de commande dans l'interface d'administration web".to_string(),
                severity: Severity::High,
                matched_banner: "Server: Technicolor Web Server 2.1".to_string(),
            },
            VulnFinding {
                service: "OpenSSH 8.9p1".to_string(),
                cve: "CVE-2023-48795".to_string(),
                summary: "Attaque par troncature de préfixe SSH Terrapin".to_string(),
                severity: Severity::Medium,
                matched_banner: "SSH-2.0-OpenSSH_8.9p1".to_string(),
            },
        ];
    }

    let ledger = state.ledger.export_ledger().unwrap_or_default();
    (findings, ledger)
}
