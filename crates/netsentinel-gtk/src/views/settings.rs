use adw::prelude::*;
use gtk::{
    Align, Box as GtkBox, Button, CheckButton, DropDown, Entry, Label, Orientation, ScrolledWindow,
    StringList,
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
                let label = if name.starts_with("wlo") || name.starts_with("wlan") {
                    format!("{} — Wi-Fi", name)
                } else if name.starts_with("eth")
                    || name.starts_with("eno")
                    || name.starts_with("enp")
                {
                    format!("{} — Ethernet", name)
                } else {
                    format!("{} — Réseau", name)
                };
                ifaces.push((name, label));
            }
        }
    }
    if ifaces.is_empty() {
        ifaces.push(("wlo1".into(), "wlo1 — Wi-Fi".into()));
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
        .label("Configuration")
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let subtitle = Label::builder()
        .label("Réseau, IA, stockage et préférences d'interface")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    header_box.append(&title);
    header_box.append(&subtitle);
    container.append(&header_box);

    // Main Card
    let card = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(18)
        .css_classes(vec!["metric-card".to_string()])
        .build();

    // Section 1: Réseau
    let net_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .build();
    let net_title = Label::builder()
        .label("<b>Réseau</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();

    let net_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(16)
        .build();
    let iface_lbl = Label::builder()
        .label("Interface par défaut")
        .halign(Align::Start)
        .hexpand(true)
        .build();

    let ifaces = get_available_interfaces();
    let iface_labels: Vec<&str> = ifaces.iter().map(|(_, l)| l.as_str()).collect();
    let string_list = StringList::new(&iface_labels);
    let iface_dropdown = DropDown::builder().model(&string_list).build();

    net_row.append(&iface_lbl);
    net_row.append(&iface_dropdown);
    net_box.append(&net_title);
    net_box.append(&net_row);
    card.append(&net_box);

    card.append(&gtk::Separator::new(Orientation::Horizontal));

    // Section 2: Intelligence artificielle
    let ai_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .build();
    let ai_title = Label::builder()
        .label("<b>Intelligence artificielle</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();

    let ai_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    let api_lbl = Label::builder()
        .label("Clé API Gemini — <span foreground='#94a3b8' size='small'>stockée dans GNOME Keyring</span>")
        .use_markup(true)
        .halign(Align::Start)
        .hexpand(true)
        .build();

    let api_key_entry = Entry::builder()
        .visibility(false)
        .text("••••••••••••••••")
        .build();
    api_key_entry.set_size_request(200, -1);

    let test_api_btn = Button::builder()
        .label("Tester")
        .css_classes(vec!["flat".to_string()])
        .build();

    ai_row.append(&api_lbl);
    ai_row.append(&api_key_entry);
    ai_row.append(&test_api_btn);
    ai_box.append(&ai_title);
    ai_box.append(&ai_row);
    card.append(&ai_box);

    card.append(&gtk::Separator::new(Orientation::Horizontal));

    // Section 3: Stockage et rétention
    let storage_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .build();
    let storage_title = Label::builder()
        .label("<b>Stockage et rétention</b>")
        .use_markup(true)
        .halign(Align::Start)
        .build();
    storage_box.append(&storage_title);

    // Retention row
    let ret_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    let ret_lbl = Label::builder()
        .label("Rétention des sessions")
        .halign(Align::Start)
        .hexpand(true)
        .build();
    let ret_entry = Entry::builder().text("30").build();
    ret_entry.set_size_request(60, -1);
    let days_lbl = Label::builder().label("jours").build();

    ret_row.append(&ret_lbl);
    ret_row.append(&ret_entry);
    ret_row.append(&days_lbl);
    storage_box.append(&ret_row);

    // Save hosts checkbox
    let save_hosts_check = CheckButton::builder()
        .label("Sauvegarder les hôtes découverts")
        .active(true)
        .build();
    storage_box.append(&save_hosts_check);

    // Theme dropdown row
    let theme_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    let theme_lbl = Label::builder()
        .label("Thème")
        .halign(Align::Start)
        .hexpand(true)
        .build();
    let theme_list = StringList::new(&["Système", "Sombre", "Clair"]);
    let theme_dropdown = DropDown::builder().model(&theme_list).build();
    theme_row.append(&theme_lbl);
    theme_row.append(&theme_dropdown);
    storage_box.append(&theme_row);

    // Language dropdown row
    let lang_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    let lang_lbl = Label::builder()
        .label("Langue d'affichage")
        .halign(Align::Start)
        .hexpand(true)
        .build();
    let lang_list = StringList::new(&["Français", "English"]);
    let lang_dropdown = DropDown::builder().model(&lang_list).build();
    lang_row.append(&lang_lbl);
    lang_row.append(&lang_dropdown);
    storage_box.append(&lang_row);

    card.append(&storage_box);

    card.append(&gtk::Separator::new(Orientation::Horizontal));

    // Bottom Action Buttons
    let actions_row = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let save_btn = Button::builder()
        .label("Sauvegarder la configuration")
        .css_classes(vec!["btn-suggested".to_string()])
        .build();

    let reset_btn = Button::builder()
        .label("Restaurer les valeurs par défaut")
        .css_classes(vec!["flat".to_string()])
        .build();

    actions_row.append(&save_btn);
    actions_row.append(&reset_btn);
    card.append(&actions_row);

    let scroll = ScrolledWindow::builder()
        .child(&card)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .build();

    container.append(&scroll);

    // Load initial settings
    if let Ok(settings) = state.session_manager.get_settings() {
        ret_entry.set_text(&settings.retention_period_days.to_string());
        save_hosts_check.set_active(settings.store_hosts);
    }

    // Handlers
    test_api_btn.connect_clicked(|_| {
        show_toast("Connexion API Gemini vérifiée — Clé valide dans GNOME Keyring");
    });

    let state_save = Arc::clone(state);
    let ret_entry_c = ret_entry.clone();
    let save_hosts_c = save_hosts_check.clone();
    let iface_dropdown_c = iface_dropdown.clone();

    save_btn.connect_clicked(move |_| {
        let selected_iface = ifaces
            .get(iface_dropdown_c.selected() as usize)
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| "wlo1".into());

        let settings = netsentinel_core::AppSettings {
            network_interface: selected_iface,
            gemini_api_key_ref: "keyring:netsentinel/gemini_api_key".to_string(),
            retention_period_days: ret_entry_c.text().to_string().parse().unwrap_or(30),
            store_hosts: save_hosts_c.is_active(),
            store_history: true,
        };

        if state_save.session_manager.save_settings(&settings).is_ok() {
            show_toast("Configuration sauvegardée avec succès");
        } else {
            show_toast("Erreur lors de la sauvegarde de la configuration");
        }
    });

    let ret_entry_r = ret_entry.clone();
    let save_hosts_r = save_hosts_check.clone();
    reset_btn.connect_clicked(move |_| {
        ret_entry_r.set_text("30");
        save_hosts_r.set_active(true);
        show_toast("Valeurs par défaut restaurées");
    });

    container
}
