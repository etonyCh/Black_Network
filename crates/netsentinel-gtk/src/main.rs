//! netsentinel (client GTK4 / Libadwaita)
//!
//! Fenêtre principale avec navigation latérale et interface redessinée conforme aux maquettes
//! (Découverte → Capture → Audit → Rapport → Configuration).

use adw::prelude::*;
use adw::{
    Application, ApplicationWindow, HeaderBar, NavigationPage, NavigationSplitView, ToastOverlay,
    ToolbarView,
};
use gtk::gdk::Display;
use gtk::{
    Align, Box as GtkBox, CssProvider, Image, Label, ListBox, ListBoxRow, Orientation,
    SelectionMode, Stack,
};
use std::sync::Arc;

mod app_state;
mod views;

use app_state::{set_toast_overlay, AppState};

const APP_ID: &str = "org.netsentinel.App";

fn main() -> gtk::glib::ExitCode {
    tracing_subscriber::fmt().init();

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let _guard = rt.enter();

    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

fn load_css() {
    let provider = CssProvider::new();
    let css = r#"
        window {
            background-color: #0f1015;
            color: #e2e8f0;
        }

        .sidebar-header-box {
            padding: 16px 12px 12px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.07);
        }

        .sidebar-title {
            font-size: 1.15rem;
            font-weight: 700;
            color: #ffffff;
        }

        .sidebar-version {
            font-size: 0.78rem;
            color: #94a3b8;
            font-weight: 500;
        }

        .navigation-sidebar {
            background-color: #13141a;
            padding: 8px;
        }

        .navigation-sidebar row {
            border-radius: 8px;
            padding: 10px 14px;
            margin-bottom: 4px;
            font-weight: 500;
            color: #94a3b8;
            transition: all 0.15s ease-in-out;
        }

        .navigation-sidebar row:hover {
            background-color: rgba(255, 255, 255, 0.05);
            color: #f1f5f9;
        }

        .navigation-sidebar row:selected {
            background-color: #f8fafc;
            color: #0f172a;
            font-weight: 600;
        }

        .navigation-sidebar row:selected image {
            color: #0f172a;
        }

        .sidebar-footer {
            padding: 12px 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.07);
            font-size: 0.82rem;
            color: #94a3b8;
        }

        .badge-tool-detected {
            background-color: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 6px;
            padding: 4px 10px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .metric-card {
            background-color: #171821;
            border: 1px solid #262836;
            border-radius: 12px;
            padding: 16px;
        }

        .metric-value {
            font-size: 1.85rem;
            font-weight: 700;
            color: #ffffff;
        }

        .metric-label {
            font-size: 0.82rem;
            color: #94a3b8;
        }

        .badge-connu {
            background-color: #14532d;
            color: #4ade80;
            border-radius: 12px;
            padding: 2px 10px;
            font-size: 0.78rem;
            font-weight: 600;
        }

        .badge-nouveau {
            background-color: #713f12;
            color: #fde047;
            border-radius: 12px;
            padding: 2px 10px;
            font-size: 0.78rem;
            font-weight: 600;
        }

        .badge-inconnu {
            background-color: #334155;
            color: #cbd5e1;
            border-radius: 12px;
            padding: 2px 10px;
            font-size: 0.78rem;
            font-weight: 600;
        }

        .badge-cvss-critical {
            background-color: #7f1d1d;
            color: #fca5a5;
            border-radius: 6px;
            padding: 4px 8px;
            font-weight: 700;
            font-size: 0.78rem;
        }

        .badge-cvss-high {
            background-color: #7c2d12;
            color: #ffedd5;
            border-radius: 6px;
            padding: 4px 8px;
            font-weight: 700;
            font-size: 0.78rem;
        }

        .badge-cvss-medium {
            background-color: #713f12;
            color: #fef08a;
            border-radius: 6px;
            padding: 4px 8px;
            font-weight: 700;
            font-size: 0.78rem;
        }

        .badge-cvss-info {
            background-color: #064e3b;
            color: #a7f3d0;
            border-radius: 6px;
            padding: 4px 8px;
            font-weight: 600;
            font-size: 0.78rem;
        }

        .btn-suggested {
            background-color: #f8fafc;
            color: #0f172a;
            font-weight: 600;
            border-radius: 8px;
            padding: 8px 16px;
            border: none;
        }

        .btn-suggested:hover {
            background-color: #e2e8f0;
        }

        .btn-destructive {
            background-color: rgba(239, 68, 68, 0.1);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
            border-radius: 8px;
            padding: 8px 16px;
        }

        .btn-destructive:hover {
            background-color: rgba(239, 68, 68, 0.2);
        }
    "#;
    provider.load_from_data(css);
    if let Some(display) = Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

fn build_ui(app: &Application) {
    load_css();
    let state = Arc::new(AppState::new());

    let toast_overlay = ToastOverlay::new();
    set_toast_overlay(toast_overlay.clone());

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
    content_stack.add_titled(&views::scan::build_page(&state), Some("scan"), "Audit");
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

    // Sidebar Items using symbolic icons
    let sidebar_list = ListBox::builder()
        .selection_mode(SelectionMode::Single)
        .css_classes(vec!["navigation-sidebar".to_string()])
        .build();

    let items = [
        (
            "system-search-symbolic",
            "Découverte",
            "discover",
            "NetSentinel — Découverte",
        ),
        (
            "network-transmit-receive-symbolic",
            "Capture",
            "capture",
            "NetSentinel — Capture",
        ),
        (
            "security-high-symbolic",
            "Audit",
            "scan",
            "NetSentinel — Audit",
        ),
        (
            "document-properties-symbolic",
            "Rapport",
            "report",
            "NetSentinel — Rapport",
        ),
        (
            "emblem-system-symbolic",
            "Configuration",
            "settings",
            "NetSentinel — Configuration",
        ),
    ];

    for (icon_name, label_text, stack_id, _) in items {
        let row = ListBoxRow::new();
        let box_row = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .margin_top(4)
            .margin_bottom(4)
            .margin_start(4)
            .margin_end(4)
            .build();

        let img = Image::from_icon_name(icon_name);
        let lbl = Label::new(Some(label_text));
        box_row.append(&img);
        box_row.append(&lbl);
        row.set_child(Some(&box_row));
        row.set_widget_name(stack_id);
        sidebar_list.append(&row);
    }

    // Select first row by default
    if let Some(first_row) = sidebar_list.row_at_index(0) {
        sidebar_list.select_row(Some(&first_row));
    }

    // Header bar for Content area with dynamic title & tool badges
    let content_header_bar = HeaderBar::new();
    let content_page_title = Label::builder()
        .label("NetSentinel — Découverte")
        .css_classes(vec!["title-2".to_string()])
        .build();
    content_header_bar.set_title_widget(Some(&content_page_title));

    // Right-side tool badges (nmap & Nuclei detected)
    let badges_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_end(8)
        .build();

    let nmap_badge = Label::builder()
        .label("nmap détecté")
        .css_classes(vec!["badge-tool-detected".to_string()])
        .build();
    let nuclei_badge = Label::builder()
        .label("Nuclei détecté")
        .css_classes(vec!["badge-tool-detected".to_string()])
        .build();

    badges_box.append(&nmap_badge);
    badges_box.append(&nuclei_badge);
    content_header_bar.pack_end(&badges_box);

    // Sidebar Header (Logo + Title + Version)
    let sidebar_header_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(2)
        .css_classes(vec!["sidebar-header-box".to_string()])
        .build();
    let title_lbl = Label::builder()
        .label("NetSentinel")
        .halign(Align::Start)
        .css_classes(vec!["sidebar-title".to_string()])
        .build();
    let ver_lbl = Label::builder()
        .label("v0.9.2")
        .halign(Align::Start)
        .css_classes(vec!["sidebar-version".to_string()])
        .build();
    sidebar_header_box.append(&title_lbl);
    sidebar_header_box.append(&ver_lbl);

    // Sidebar Footer (Session active badge)
    let sidebar_footer = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .css_classes(vec!["sidebar-footer".to_string()])
        .build();
    let status_dot = Label::builder()
        .label("<span foreground='#4ade80'>●</span>")
        .use_markup(true)
        .build();
    let session_info = Label::builder()
        .label("Session active · il y a 2 min")
        .build();
    sidebar_footer.append(&status_dot);
    sidebar_footer.append(&session_info);

    let sidebar_container = GtkBox::builder().orientation(Orientation::Vertical).build();
    sidebar_container.append(&sidebar_header_box);
    sidebar_container.append(&sidebar_list);

    let expander = GtkBox::new(Orientation::Vertical, 0);
    expander.set_vexpand(true);
    sidebar_container.append(&expander);
    sidebar_container.append(&sidebar_footer);

    let sidebar_header_bar = HeaderBar::new();

    {
        let content_stack = content_stack.clone();
        let content_page_title = content_page_title.clone();
        sidebar_list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                let name = row.widget_name();
                content_stack.set_visible_child_name(&name);
                let title = match name.as_str() {
                    "discover" => "NetSentinel — Découverte",
                    "capture" => "NetSentinel — Capture",
                    "scan" => "NetSentinel — Audit",
                    "report" => "NetSentinel — Rapport",
                    "settings" => "NetSentinel — Configuration",
                    _ => "NetSentinel",
                };
                content_page_title.set_label(title);
            }
        });
    }

    let sidebar_page = NavigationPage::builder()
        .title("NetSentinel")
        .child(&{
            let tv = ToolbarView::new();
            tv.add_top_bar(&sidebar_header_bar);
            tv.set_content(Some(&sidebar_container));
            tv
        })
        .build();

    let content_page = NavigationPage::builder()
        .title("NetSentinel — Découverte")
        .child(&{
            let tv = ToolbarView::new();
            tv.add_top_bar(&content_header_bar);
            tv.set_content(Some(&content_stack));
            tv
        })
        .build();

    let split_view = NavigationSplitView::builder()
        .sidebar(&sidebar_page)
        .content(&content_page)
        .build();

    toast_overlay.set_child(Some(&split_view));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("NetSentinel — Découverte")
        .default_width(1180)
        .default_height(760)
        .content(&toast_overlay)
        .build();

    window.present();
}
