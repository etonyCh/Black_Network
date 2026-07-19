import json
import logging

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from typing import Any  # noqa: E402

from gi.repository import Adw, GObject, Gtk  # noqa: E402


class InterceptorView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelInterceptorView"

    def __init__(self, **kwargs: object):
        super().__init__(title="MitM Web Decryptor", **kwargs)
        self.is_intercepting = False
        self.intercepted_flows: dict[str, dict[str, Any]] = {}

        # Main horizontal split
        split_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        split_box.set_margin_top(12)
        split_box.set_margin_bottom(12)
        split_box.set_margin_start(12)
        split_box.set_margin_end(12)
        self.set_child(split_box)

        # Left Column (Controls & Lists)
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        left_box.set_hexpand(True)
        split_box.append(left_box)

        # 1. Config group
        group_config = Adw.PreferencesGroup(title="Proxy Config")
        left_box.append(group_config)

        self.port_row = Adw.SpinRow(
            title="Proxy Port",
            subtitle="Local port to listen on (e.g. 8080)",
            adjustment=Gtk.Adjustment.new(8080, 1024, 65535, 1, 10, 0),
        )
        group_config.add(self.port_row)

        # Button toggle
        self.btn_toggle = Gtk.Button(label="Start Interceptor")
        self.btn_toggle.add_css_class("suggested-action")
        self.btn_toggle.connect("clicked", self._on_toggle_clicked)
        left_box.append(self.btn_toggle)

        # 2. Flows List
        group_flows = Adw.PreferencesGroup(title="Intercepted HTTP/HTTPS Requests")
        left_box.append(group_flows)

        self.list_box = Gtk.ListBox()
        self.list_box.connect("row-selected", self._on_flow_selected)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(300)
        scroll.set_vexpand(True)
        scroll.set_child(self.list_box)
        group_flows.add(scroll)

        # Right Column (Flow Payload Details)
        right_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        right_box.set_hexpand(True)
        split_box.append(right_box)

        group_details = Adw.PreferencesGroup(title="Request/Response Decrypted Details")
        right_box.append(group_details)

        # Text view for details
        self.txt_details = Gtk.TextView()
        self.txt_details.set_editable(False)
        self.txt_details.set_cursor_visible(False)

        scroll_details = Gtk.ScrolledWindow()
        scroll_details.set_min_content_height(400)
        scroll_details.set_vexpand(True)
        scroll_details.set_child(self.txt_details)
        group_details.add(scroll_details)

    def _on_toggle_clicked(self, _button: Gtk.Button) -> None:
        if not self.is_intercepting:
            port = int(self.port_row.get_value())
            self.is_intercepting = True
            self.btn_toggle.set_label("Stop Interceptor")
            self.btn_toggle.add_css_class("destructive-action")
            self.btn_toggle.remove_css_class("suggested-action")

            self._add_flow_row("system_info", f"Started proxy on port {port}...", "INFO", 0)
            self.emit("proxy-start-requested", port)
        else:
            self.is_intercepting = False
            self.btn_toggle.set_label("Start Interceptor")
            self.btn_toggle.add_css_class("suggested-action")
            self.btn_toggle.remove_css_class("destructive-action")

            self._add_flow_row("system_info", "Stopping proxy...", "INFO", 0)
            self.emit("proxy-stop-requested")

    def handle_request_intercepted(self, metadata_json: str) -> None:
        """
        Receives intercepted metadata from D-Bus and populates the table.
        """
        try:
            metadata = json.loads(metadata_json)
            pid = metadata.get("payload_id", "")
            url = metadata.get("url", "")
            method = metadata.get("method", "")
            status = metadata.get("status", 0)

            # Store metadata
            self.intercepted_flows[pid] = metadata

            alerts = metadata.get("alerts", [])
            alert_prefix = "ALERT: " if alerts else ""
            self._add_flow_row(
                pid,
                f"{alert_prefix}{method} {url}",
                f"HTTP {status}",
                status,
                bool(alerts),
            )

        except Exception as e:
            logging.error("Failed to parse intercepted metadata: %s", e)

    def _on_flow_selected(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        if not row:
            return

        # ActionRow sets the payload id as name or attribute
        payload_id = row.get_name()
        if payload_id == "system_info":
            self.txt_details.get_buffer().set_text(
                "System information log. No decryption payload available."
            )
            return

        # Emit signal to request decrypted details from the D-Bus helper
        self.emit("payload-decryption-requested", payload_id)

    def display_decrypted_payload(self, _payload_id: str, decrypted_json: str) -> None:
        """
        Processes and displays decrypted header and body payloads in the viewer panel.
        """
        try:
            data = json.loads(decrypted_json)
            req_headers = data.get("request_headers", {})
            req_body = data.get("request_body", "")
            resp_headers = data.get("response_headers", {})
            resp_body = data.get("response_body", "")

            # Formats details text
            req_headers_str = "\n".join([f"{k}: {v}" for k, v in req_headers.items()])
            resp_headers_str = "\n".join([f"{k}: {v}" for k, v in resp_headers.items()])

            details_text = (
                f"=== HTTP REQUEST HEADERS ===\n{req_headers_str}\n\n"
                f"=== HTTP REQUEST BODY ===\n{req_body if req_body else '[Empty Body]'}\n\n"
                f"==================================================\n\n"
                f"=== HTTP RESPONSE HEADERS ===\n{resp_headers_str}\n\n"
                f"=== HTTP RESPONSE BODY ===\n{resp_body if resp_body else '[Empty Body]'}\n"
            )

            self.txt_details.get_buffer().set_text(details_text)

        except Exception as e:
            self.txt_details.get_buffer().set_text(f"Error parsing decrypted payload: {e}")

    def _add_flow_row(
        self,
        payload_id: str,
        title: str,
        subtitle: str,
        status: int,
        is_alert: bool = False,
    ) -> None:
        row = Adw.ActionRow()
        row.set_name(payload_id)
        row.set_title(title)
        row.set_subtitle(subtitle)

        if is_alert:
            row.add_css_class("warning")
        elif status == 200:
            row.add_css_class("success")

        self.list_box.prepend(row)


# Register signals
GObject.signal_new(
    "proxy-start-requested",
    InterceptorView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_INT,),
)

GObject.signal_new(
    "proxy-stop-requested", InterceptorView, GObject.SignalFlags.RUN_LAST, GObject.TYPE_NONE, ()
)

GObject.signal_new(
    "payload-decryption-requested",
    InterceptorView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_STRING,),
)
