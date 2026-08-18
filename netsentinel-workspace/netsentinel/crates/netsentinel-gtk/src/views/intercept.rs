use adw::prelude::*;
use adw::{ActionRow, EntryRow, PreferencesGroup};
use gtk::{
    glib, Align, Box as GtkBox, Button, CheckButton, Entry, Label, LevelBar, Orientation, Spinner,
};
use std::time::Instant;

const MAX_SECONDS: u32 = 30 * 60; // RE-02: 30 min

fn format_hms(total_secs: u32) -> String {
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
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
        .label("<b>Intercepteur (MitM ARP Spoof)</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();

    let description = Label::builder()
        .label("Usurpation bidirectionnelle de tables ARP pour observation de trafic. Durée bornée à 30 min, restauration automatique (reARP × 3).")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    // Avertissement légal + consentement (RE-01 RE-02)
    let consent_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .margin_top(6)
        .margin_bottom(6)
        .build();

    let warning_label = Label::builder()
        .label("<span foreground='crimson'><b>⚠️ ACTION DÉSTRUCTRICE — CONSENTEMENT EXPLICITE OBLIGATOIRE (RE-01)</b></span>\n\
                L'ARP Spoofing casse le routage direct de la cible. <u>TOUTE action est journalisée</u> dans /var/log/netsentinel_audit.jsonl avec signature HMAC-SHA256, horodatage UTC et opérateur.")
        .use_markup(true)
        .wrap(true)
        .halign(Align::Start)
        .build();

    let consent_check = CheckButton::builder()
        .label("Je dispose d'une autorisation écrite pour auditer cette cible et j'accepte la journalisation immuable.")
        .margin_top(6)
        .build();

    consent_box.append(&warning_label);
    consent_box.append(&consent_check);
    container.append(&consent_box);

    // Paramètres
    let config_group = PreferencesGroup::new();
    config_group.set_title("Paramètres de session");

    let target_entry = EntryRow::builder()
        .title("Cible (IP v4 du poste victime)")
        .text("192.168.1.10")
        .build();

    // Jeton d'autorisation — Saisie manuelle car /etc/netsentinel.env est root:root 0600
    // (on ne lit PAS de secrets système depuis une UI non privilégiée).
    let token_entry_inner = Entry::builder()
        .placeholder_text("NETSENTINEL_AUTH_TOKEN (identique au démon)")
        .visibility(false)
        .input_purpose(gtk::InputPurpose::Password)
        .invisible_char('\u{2022}' as u32)
        .build();
    let token_entry = ActionRow::builder()
        .title("Jeton d'autorisation (RE-01)")
        .subtitle("Doit correspondre à `NETSENTINEL_AUTH_TOKEN` de netsentinel-interceptd.service")
        .activatable_widget(&token_entry_inner)
        .build();
    token_entry.add_suffix(&token_entry_inner);

    let operator_entry = EntryRow::builder()
        .title("Identifiant opérateur (audit)")
        .text("gtk-operator")
        .build();

    config_group.add(&target_entry);
    config_group.add(&token_entry);
    config_group.add(&operator_entry);
    container.append(&config_group);

    // Boutons
    let action_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let start_button = Button::builder()
        .label("🔥 Démarrer la session MitM")
        .css_classes(vec!["destructive-action".to_string()])
        .sensitive(false)
        .build();

    let stop_button = Button::builder()
        .label("🛑 Arrêter + reARP")
        .sensitive(false)
        .build();

    let spinner = Spinner::builder()
        .halign(Align::Center)
        .valign(Align::Center)
        .build();

    action_box.append(&start_button);
    action_box.append(&stop_button);
    action_box.append(&spinner);
    container.append(&action_box);

    // Progression temporelle (RE-02 : durée max 30 min)
    let timer_label = Label::builder()
        .label(format!(
            "⏱ Temps restant autorisé : <b>{}</b>  (30:00 max)",
            format_hms(MAX_SECONDS)
        ))
        .use_markup(true)
        .halign(Align::Start)
        .build();
    let timer_bar = LevelBar::builder()
        .min_value(0.0)
        .max_value(1.0)
        .value(0.0)
        .build();
    timer_bar.add_offset_value(gtk::LEVEL_BAR_OFFSET_HIGH, 0.8);
    timer_bar.add_offset_value(gtk::LEVEL_BAR_OFFSET_LOW, 0.3);
    container.append(&timer_label);
    container.append(&timer_bar);

    // Log label
    let log_label = Label::builder()
        .label("<i>Prêt — le consentement ET le jeton sont requis.</i>")
        .use_markup(true)
        .wrap(true)
        .halign(Align::Start)
        .build();
    container.append(&log_label);

    // ========== Logique d'activation : consent ET jeton non vide ==========
    let consent_for_gate = consent_check.clone();
    let token_for_gate = token_entry_inner.clone();
    let start_for_gate = start_button.clone();

    fn refresh_start_gate(consent: &CheckButton, token: &Entry, btn: &Button) {
        let ok = consent.is_active() && !token.text().trim().is_empty();
        btn.set_sensitive(ok);
    }

    consent_for_gate.connect_toggled(glib::clone!(
        #[strong]
        token_for_gate,
        #[strong]
        start_for_gate,
        move |c| {
            refresh_start_gate(c, &token_for_gate, &start_for_gate);
        }
    ));
    token_for_gate.connect_changed(glib::clone!(
        #[strong]
        consent_for_gate,
        #[strong]
        start_for_gate,
        move |t| {
            refresh_start_gate(&consent_for_gate, t, &start_for_gate);
        }
    ));

    // ========== HANDLER : START ==========
    let start_btn_clone = start_button.clone();
    let stop_btn_clone = stop_button.clone();
    let spinner_clone = spinner.clone();
    let log_label_clone = log_label.clone();
    let timer_label_clone = timer_label.clone();
    let timer_bar_clone = timer_bar.clone();
    let token_text_entry = token_entry_inner.clone();
    let operator_text_clone = operator_entry.clone();
    let consent_clone = consent_check.clone();

    // Minuteur local UI (rafraîchi toutes les secondes via timeout glib)
    let session_started_cell: std::rc::Rc<std::cell::RefCell<Option<Instant>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let session_started_cell_start = session_started_cell.clone();

    start_button.connect_clicked(move |_| {
        let target = target_entry.text().to_string();
        let auth_token = token_text_entry.text().to_string();
        let operator = operator_text_clone.text().to_string();

        if target.trim().is_empty() || auth_token.trim().is_empty() {
            log_label_clone.set_markup(
                "<span foreground='red'>Cible ET jeton obligatoires.</span>",
            );
            return;
        }

        start_btn_clone.set_sensitive(false);
        stop_btn_clone.set_sensitive(true);
        spinner_clone.start();
        log_label_clone.set_markup("<i>Demande de session D-Bus + Polkit org.netsentinel.intercept.run (auth_admin SANS cache)...</i>");

        let start_btn_ui = start_btn_clone.clone();
        let stop_btn_ui = stop_btn_clone.clone();
        let spinner_ui = spinner_clone.clone();
        let log_ui = log_label_clone.clone();
        let timer_lbl_ui = timer_label_clone.clone();
        let timer_bar_ui = timer_bar_clone.clone();
        let consent_ui = consent_clone.clone();
        let started_cell = session_started_cell_start.clone();

        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    log_ui.set_markup(&format!(
                        "<span foreground='red'>❌ D-Bus système : {}</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    stop_btn_ui.set_sensitive(false);
                    spinner_ui.stop();
                    return;
                }
            };

            let proxy = match netsentinel_proto::Intercept1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    log_ui.set_markup(&format!(
                        "<span foreground='red'>❌ Service Intercept1 introuvable : {}\n→ vérifiez `systemctl status netsentinel-interceptd` (désactivé par défaut postinst).</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    stop_btn_ui.set_sensitive(false);
                    spinner_ui.stop();
                    return;
                }
            };

            match proxy
                .request_session(&target, auth_token.trim(), &operator)
                .await
            {
                Ok(true) => {
                    log_ui.set_markup(&format!(
                        "<span foreground='#26a269'>✅ Session MitM <b>{}</b> démarrée. Opérateur: <b>{}</b>.\n\
                        Timeout serveur 30 min actif + UI minuteur. Un journal HMAC-SHA256 est écrit.</span>",
                        target, operator
                    ));
                    *started_cell.borrow_mut() = Some(Instant::now());

                    // Démarre le minuteur UI local (tick 1s)
                    glib::timeout_add_seconds_local(1, glib::clone!(#[strong] timer_lbl_ui, #[strong] timer_bar_ui, #[strong] started_cell, move || {
                        let Some(started) = *started_cell.borrow() else {
                            return glib::ControlFlow::Break;
                        };
                        let elapsed = started.elapsed().as_secs() as u32;
                        if elapsed >= MAX_SECONDS {
                            timer_lbl_ui.set_markup("⏱ Temps écoulé — la session doit être/est automatiquement terminée par le démon.");
                            timer_bar_ui.set_value(1.0);
                            return glib::ControlFlow::Break;
                        }
                        let remaining = MAX_SECONDS - elapsed;
                        timer_lbl_ui.set_markup(&format!(
                            "⏱ Temps restant : <b>{}</b> · écoulé {}/1800s",
                            format_hms(remaining), elapsed
                        ));
                        let pct = elapsed as f64 / MAX_SECONDS as f64;
                        timer_bar_ui.set_value(pct);
                        glib::ControlFlow::Continue
                    }));
                }
                Ok(false) => {
                    log_ui.set_markup(
                        "<span foreground='red'>❌ Session refusée côté démon : jeton invalide OU session déjà active (unicité RE-02).</span>",
                    );
                    start_btn_ui.set_sensitive(true);
                    stop_btn_ui.set_sensitive(false);
                }
                Err(e) => {
                    log_ui.set_markup(&format!(
                        "<span foreground='red'>❌ Échec request_session : {}\n→ Le plus souvent : authentification Polkit annulée ou CAP_NET_ADMIN absent.</span>",
                        e
                    ));
                    start_btn_ui.set_sensitive(true);
                    stop_btn_ui.set_sensitive(false);
                }
            }
            spinner_ui.stop();
            let _ = consent_ui;
        });
    });

    // ========== HANDLER : STOP ==========
    let stop_btn_clone2 = stop_button.clone();
    let start_btn_clone2 = start_button.clone();
    let log_label_clone2 = log_label.clone();
    let consent_check_clone = consent_check.clone();
    let token_for_stop = token_entry_inner.clone();
    let stop_start_for_gate = start_for_gate;
    let session_stopped_cell = session_started_cell.clone();
    let timer_label_final = timer_label.clone();
    let timer_bar_final = timer_bar.clone();

    stop_button.connect_clicked(move |_| {
        stop_btn_clone2.set_sensitive(false);
        log_label_clone2.set_markup("<i>Envoi EndSession (reARP × 3 + restauration IP forward)...</i>");

        let log_ui = log_label_clone2.clone();
        let start_btn_ui = start_btn_clone2.clone();
        let gate_consent = consent_check_clone.clone();
        let gate_token = token_for_stop.clone();
        let gate_btn = stop_start_for_gate.clone();
        let stop_cell = session_stopped_cell.clone();
        let tl = timer_label_final.clone();
        let tb = timer_bar_final.clone();

        gtk::glib::MainContext::default().spawn_local(async move {
            if let Ok(connection) = zbus::Connection::system().await {
                if let Ok(proxy) = netsentinel_proto::Intercept1Proxy::new(&connection).await {
                    match proxy.end_session().await {
                        Ok(()) => {
                            log_ui.set_markup(
                                "<span foreground='#26a269'>✅ Session arrêtée — reARP OK, IP forward restauré. Consultez /var/log/netsentinel_audit.jsonl.</span>",
                            );
                        }
                        Err(e) => {
                            log_ui.set_markup(&format!(
                                "<span foreground='orange'>⚠️ end_session : {}</span>",
                                e
                            ));
                        }
                    }
                }
            }
            // Reset UI gate
            refresh_start_gate(&gate_consent, &gate_token, &gate_btn);
            start_btn_ui.set_sensitive(gate_consent.is_active() && !gate_token.text().trim().is_empty());
            *stop_cell.borrow_mut() = None;
            tl.set_markup(&format!(
                "⏱ Temps restant autorisé : <b>{}</b>  (30:00 max)",
                format_hms(MAX_SECONDS)
            ));
            tb.set_value(0.0);
        });
    });

    container
}
