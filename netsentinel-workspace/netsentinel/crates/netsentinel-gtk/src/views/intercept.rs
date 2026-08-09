use adw::prelude::*;
use adw::{EntryRow, PreferencesGroup};
use gtk::{Align, Box as GtkBox, Button, CheckButton, Label, Orientation, Spinner};

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
        .label("<b>Intercepteur (MitM)</b>")
        .use_markup(true)
        .halign(Align::Start)
        .css_classes(vec!["title-1".to_string()])
        .build();
    
    let description = Label::builder()
        .label("Lancement d'attaques Man-in-the-Middle (ARP/DNS Spoofing).")
        .halign(Align::Start)
        .css_classes(vec!["dim-label".to_string()])
        .build();

    container.append(&title);
    container.append(&description);

    // Consent box
    let consent_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .build();
    
    let warning_label = Label::builder()
        .label("<b>⚠️ AVERTISSEMENT LÉGAL ET TECHNIQUE</b>\nL'interception de trafic réseau est une action destructrice. Assurez-vous d'avoir l'autorisation explicite d'auditer cette cible. Toute action sera journalisée et signée de manière cryptographique.")
        .use_markup(true)
        .wrap(true)
        .halign(Align::Start)
        .css_classes(vec!["error".to_string()])
        .build();
    
    let consent_check = CheckButton::builder()
        .label("Je comprends les risques et j'autorise l'interception")
        .build();

    consent_box.append(&warning_label);
    consent_box.append(&consent_check);
    container.append(&consent_box);

    let config_group = PreferencesGroup::new();
    let target_entry = EntryRow::builder()
        .title("Cible (IP)")
        .text("192.168.1.10")
        .build();
    config_group.add(&target_entry);
    
    container.append(&config_group);

    let action_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::Start)
        .build();

    let start_button = Button::builder()
        .label("Démarrer la Session")
        .css_classes(vec!["destructive-action".to_string()])
        .sensitive(false) // Disabled by default
        .build();
    
    let stop_button = Button::builder()
        .label("Arrêter")
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

    // Enable start button only if consent is checked
    let start_btn_clone_for_check = start_button.clone();
    consent_check.connect_toggled(move |btn| {
        start_btn_clone_for_check.set_sensitive(btn.is_active());
    });

    // UI logger for feedback
    let log_label = Label::builder()
        .label("<i>En attente d'initialisation...</i>")
        .use_markup(true)
        .wrap(true)
        .halign(Align::Start)
        .build();
    container.append(&log_label);

    let start_btn_clone = start_button.clone();
    let stop_btn_clone = stop_button.clone();
    let spinner_clone = spinner.clone();
    let log_label_clone = log_label.clone();
    
    start_button.connect_clicked(move |_| {
        let target = target_entry.text().to_string();
        start_btn_clone.set_sensitive(false);
        stop_btn_clone.set_sensitive(true);
        spinner_clone.start();
        log_label_clone.set_markup("<i>Demande de session en cours...</i>");

        let start_btn_ui = start_btn_clone.clone();
        let spinner_ui = spinner_clone.clone();
        let log_ui = log_label_clone.clone();
        
        gtk::glib::MainContext::default().spawn_local(async move {
            let connection = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    log_ui.set_markup(&format!("<span foreground='red'>Erreur D-Bus: {}</span>", e));
                    start_btn_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };
            
            let proxy = match netsentinel_proto::Intercept1Proxy::new(&connection).await {
                Ok(p) => p,
                Err(e) => {
                    log_ui.set_markup(&format!("<span foreground='red'>Erreur proxy: {}</span>", e));
                    start_btn_ui.set_sensitive(true);
                    spinner_ui.stop();
                    return;
                }
            };

            // TODO: Generate a real auth token in Phase 3
            match proxy.request_session(&target, "dummy_token", "gtk-operator").await {
                Ok(true) => {
                    log_ui.set_markup("<span foreground='green'>Session d'interception autorisée et démarrée.</span>");
                }
                Ok(false) => {
                    log_ui.set_markup("<span foreground='red'>Session refusée par le démon (Consentement invalide).</span>");
                    start_btn_ui.set_sensitive(true);
                }
                Err(e) => {
                    log_ui.set_markup(&format!("<span foreground='red'>Erreur lors du démarrage: {}</span>", e));
                    start_btn_ui.set_sensitive(true);
                }
            }
            
            spinner_ui.stop();
        });
    });

    let stop_btn_clone2 = stop_button.clone();
    let start_btn_clone2 = start_button.clone();
    let log_label_clone2 = log_label.clone();
    let consent_check_clone = consent_check.clone();

    stop_button.connect_clicked(move |_| {
        stop_btn_clone2.set_sensitive(false);
        start_btn_clone2.set_sensitive(consent_check_clone.is_active());
        log_label_clone2.set_markup("<i>Arrêt de la session en cours...</i>");

        let log_ui = log_label_clone2.clone();

        gtk::glib::MainContext::default().spawn_local(async move {
            if let Ok(connection) = zbus::Connection::system().await {
                if let Ok(proxy) = netsentinel_proto::Intercept1Proxy::new(&connection).await {
                    let _ = proxy.end_session().await;
                    log_ui.set_markup("<i>Session terminée.</i>");
                }
            }
        });
    });

    container
}
