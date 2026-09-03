use adw::prelude::*;
use adw::{ActionRow, PreferencesGroup, SwitchRow};
use gtk::{glib, Align, Box as GtkBox, Button, Entry, Label, Orientation};
use std::sync::Arc;

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
        .label("<b>Configuration</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let description = Label::builder()
        .label("Paramètres réseau, stockage et session.")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    // ---- Section Réseau ----
    let net_group = PreferencesGroup::new();
    net_group.set_title("Réseau");

    let iface_entry = Entry::builder()
        .halign(Align::Fill)
        .hexpand(true)
        .placeholder_text("eth0, wlan0...")
        .build();
    let iface_row = ActionRow::builder()
        .title("Interface réseau par défaut")
        .subtitle("Utilisée pour la découverte et la capture")
        .activatable_widget(&iface_entry)
        .build();
    iface_row.add_suffix(&iface_entry);
    net_group.add(&iface_row);
    container.append(&net_group);

    // ---- Section IA ----
    let ai_group = PreferencesGroup::new();
    ai_group.set_title("Intelligence Artificielle (Gemini)");

    let api_key_entry = Entry::builder()
        .halign(Align::Fill)
        .hexpand(true)
        .visibility(false)
        .placeholder_text("keyring:netsentinel/gemini_api_key")
        .build();
    let api_key_row = ActionRow::builder()
        .title("Référence clé API Gemini")
        .subtitle("Stockée dans GNOME Keyring, jamais en clair sur disque")
        .activatable_widget(&api_key_entry)
        .build();
    api_key_row.add_suffix(&api_key_entry);
    ai_group.add(&api_key_row);
    container.append(&ai_group);

    // ---- Section Données ----
    let data_group = PreferencesGroup::new();
    data_group.set_title("Stockage & Rétention");

    let retention_entry = Entry::builder()
        .halign(Align::Fill)
        .hexpand(true)
        .text("30")
        .input_purpose(gtk::InputPurpose::Digits)
        .build();
    let retention_row = ActionRow::builder()
        .title("Rétention des sessions (jours)")
        .subtitle("Purge automatique après cette durée")
        .activatable_widget(&retention_entry)
        .build();
    retention_row.add_suffix(&retention_entry);
    data_group.add(&retention_row);

    let store_hosts_row = SwitchRow::builder()
        .title("Sauvegarder les hôtes découverts")
        .active(true)
        .build();
    data_group.add(&store_hosts_row);

    let store_history_row = SwitchRow::builder()
        .title("Sauvegarder l'historique des sessions")
        .active(true)
        .build();
    data_group.add(&store_history_row);
    container.append(&data_group);

    // ---- Section Session active ----
    let session_group = PreferencesGroup::new();
    session_group.set_title("Session active");

    let session_status_label = Label::builder()
        .label("<i>Chargement...</i>")
        .use_markup(true)
        .halign(Align::Start)
        .wrap(true)
        .build();
    session_group.add(&session_status_label);

    let scope_display = Label::builder()
        .label("")
        .use_markup(true)
        .halign(Align::Start)
        .wrap(true)
        .build();
    session_group.add(&scope_display);
    container.append(&session_group);

    // Charger l'état actuel
    if let Ok(settings) = state.session_manager.get_settings() {
        iface_entry.set_text(&settings.network_interface);
        api_key_entry.set_text(&settings.gemini_api_key_ref);
        retention_entry.set_text(&settings.retention_period_days.to_string());
        store_hosts_row.set_active(settings.store_hosts);
        store_history_row.set_active(settings.store_history);
    }

    if let Ok(Some(session)) = state.session_manager.get_active_session() {
        session_status_label.set_markup(&format!(
            "<b>Session #{}:</b> {} — <span foreground='#26a269'>active</span>",
            session.id,
            glib::markup_escape_text(&session.title)
        ));
        if let Ok(scope) =
            serde_json::from_str::<netsentinel_core::SessionScope>(&session.scope_json)
        {
            scope_display.set_markup(&format!(
                "<b>Périmètre RE-02:</b> {}",
                glib::markup_escape_text(&scope.targets.join(", "))
            ));
        }
    } else {
        session_status_label.set_markup(
            "<span foreground='#e5a50a'>Aucune session active — créez une session dans l'onglet Découverte ou Intercepteur.</span>",
        );
    }

    // ---- Bouton sauvegarder ----
    let save_button = Button::builder()
        .label("Sauvegarder la configuration")
        .css_classes(vec!["suggested-action".to_string()])
        .halign(Align::Start)
        .margin_top(12)
        .build();
    container.append(&save_button);

    let status_label = Label::builder().label("").halign(Align::Start).build();
    container.append(&status_label);

    let state_clone = Arc::clone(state);
    let iface_clone = iface_entry.clone();
    let api_clone = api_key_entry.clone();
    let ret_clone = retention_entry.clone();
    let hosts_clone = store_hosts_row.clone();
    let history_clone = store_history_row.clone();
    let status_clone = status_label.clone();

    save_button.connect_clicked(move |_| {
        let settings = netsentinel_core::AppSettings {
            network_interface: iface_clone.text().to_string(),
            gemini_api_key_ref: api_clone.text().to_string(),
            retention_period_days: ret_clone.text().to_string().parse().unwrap_or(30),
            store_hosts: hosts_clone.is_active(),
            store_history: history_clone.is_active(),
        };
        match state_clone.session_manager.save_settings(&settings) {
            Ok(()) => {
                status_clone
                    .set_markup("<span foreground='#26a269'>✅ Configuration sauvegardée.</span>");
            }
            Err(e) => {
                status_clone
                    .set_markup(&format!("<span foreground='red'>❌ Erreur : {}</span>", e));
            }
        }
    });

    container
}
