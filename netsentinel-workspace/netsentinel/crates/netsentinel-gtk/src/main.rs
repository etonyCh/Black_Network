//! netsentinel (client GTK4 / Libadwaita)
//!
//! Fenêtre principale avec navigation latérale + flux guidé en étapes
//! (Découverte → Capture → Audit → Intercepteur → Rapport → Configuration),
//! conforme au HIG GNOME.
//!
//! Pont async : les appels D-Bus vers les démons sont faits via
//! `glib::MainContext::spawn_local` (exécuteur du thread UI). C'est le motif
//! recommandé pour gtk4-rs — pas de thread séparé nécessaire pour de simples
//! appels D-Bus request/response. Pour les signaux (mises à jour live), on
//! utilise un flux zbus consommé dans la même tâche locale.

use adw::prelude::*;
use adw::{
    Application, ApplicationWindow, HeaderBar, NavigationPage, NavigationSplitView, ToolbarView,
};
use gtk::{Label, ListBox, ListBoxRow, SelectionMode, Stack};
use std::sync::Arc;

mod app_state;
mod views;

use app_state::AppState;

const APP_ID: &str = "org.netsentinel.App";

fn main() -> gtk::glib::ExitCode {
    tracing_subscriber::fmt().init();

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let _guard = rt.enter();

    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &Application) {
    let state = Arc::new(AppState::new());

    let content_stack = Stack::builder().build();
    content_stack.add_titled(
        &views::discover::build_page(&state),
        Some("discover"),
        "Découverte",
    );
    content_stack.add_titled(
        &views::capture::build_page(&state),
        Some("capture"),
        "Capture",
    );
    content_stack.add_titled(
        &views::scan::build_page(&state),
        Some("scan"),
        "Audit",
    );
    content_stack.add_titled(
        &views::intercept::build_page(&state),
        Some("intercept"),
        "Intercepteur",
    );
    content_stack.add_titled(
        &views::report::build_page(&state),
        Some("report"),
        "Rapport",
    );
    content_stack.add_titled(
        &views::settings::build_page(&state),
        Some("settings"),
        "Configuration",
    );

    let sidebar_list = ListBox::builder()
        .selection_mode(SelectionMode::Single)
        .css_classes(vec!["navigation-sidebar".to_string()])
        .build();

    for (label, stack_id) in [
        ("🔍  Découverte", "discover"),
        ("📡  Capture", "capture"),
        ("🛡️  Audit", "scan"),
        ("⚠️  Intercepteur", "intercept"),
        ("📄  Rapport", "report"),
        ("⚙️  Configuration", "settings"),
    ] {
        let row = ListBoxRow::new();
        row.set_child(Some(&Label::new(Some(label))));
        row.set_widget_name(stack_id);
        sidebar_list.append(&row);
    }

    {
        let content_stack = content_stack.clone();
        sidebar_list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                content_stack.set_visible_child_name(&row.widget_name());
            }
        });
    }

    let sidebar_page = NavigationPage::builder()
        .title("NetSentinel")
        .child(&{
            let tv = ToolbarView::new();
            tv.add_top_bar(&HeaderBar::new());
            tv.set_content(Some(&sidebar_list));
            tv
        })
        .build();

    let content_page = NavigationPage::builder()
        .title("Détails")
        .child(&{
            let tv = ToolbarView::new();
            tv.add_top_bar(&HeaderBar::new());
            tv.set_content(Some(&content_stack));
            tv
        })
        .build();

    let split_view = NavigationSplitView::builder()
        .sidebar(&sidebar_page)
        .content(&content_page)
        .build();

    let window = ApplicationWindow::builder()
        .application(app)
        .title("NetSentinel")
        .default_width(1100)
        .default_height(720)
        .content(&split_view)
        .build();

    window.present();
}
