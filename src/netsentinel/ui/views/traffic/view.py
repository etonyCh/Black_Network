import json
import logging

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GObject, Gtk  # noqa: E402


class TrafficView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelTrafficView"

    def __init__(self, **kwargs: object):
        super().__init__(title="Passive Traffic Sniffer", **kwargs)
        self.is_capturing = False
        self.packets_count = 0
        self.proto_stats = {"DNS": 0, "HTTP": 0, "TLS": 0, "SSH": 0, "Other": 0}

        # Root layout
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        self.set_child(box)

        # 1. Capture Settings Panel
        group_settings = Adw.PreferencesGroup(title="Sniffer Settings")
        box.append(group_settings)

        self.interface_entry = Adw.EntryRow(title="Network Interface", text="wlan0")
        group_settings.add(self.interface_entry)

        self.filter_entry = Adw.EntryRow(title="BPF Capture Filter")
        group_settings.add(self.filter_entry)

        # Control buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.append(btn_box)

        self.btn_toggle = Gtk.Button(label="Start Capture")
        self.btn_toggle.add_css_class("suggested-action")
        self.btn_toggle.connect("clicked", self._on_toggle_capture_clicked)
        btn_box.append(self.btn_toggle)

        # 2. Real-time stats display
        group_stats = Adw.PreferencesGroup(title="Live Traffic Statistics")
        box.append(group_stats)

        self.lbl_stats = Gtk.Label(label="Total packets: 0 | DNS: 0 | HTTP: 0 | TLS: 0 | SSH: 0")
        self.lbl_stats.set_halign(Gtk.Align.START)
        group_stats.add(self.lbl_stats)

        # 3. Live packets and alerts section
        group_logs = Adw.PreferencesGroup(title="Recent Packets &amp; Security Alerts")
        box.append(group_logs)

        # ListBox to hold live logs
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        # ScrolledWindow to make it scrollable
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(200)
        scroll.set_vexpand(True)
        scroll.set_child(self.list_box)
        group_logs.add(scroll)

    def _on_toggle_capture_clicked(self, _button: Gtk.Button) -> None:
        if not self.is_capturing:
            interface = self.interface_entry.get_text().strip()
            bpf_filter = self.filter_entry.get_text().strip()

            if not interface:
                self._add_log_row("Error: Network interface is required.", is_error=True)
                return

            self.is_capturing = True
            self.btn_toggle.set_label("Stop Capture")
            self.btn_toggle.add_css_class("destructive-action")
            self.btn_toggle.remove_css_class("suggested-action")

            self._add_log_row(f"Starting capture on {interface} with BPF '{bpf_filter}'...")
            self.emit("capture-start-requested", interface, bpf_filter)
        else:
            self.is_capturing = False
            self.btn_toggle.set_label("Start Capture")
            self.btn_toggle.add_css_class("suggested-action")
            self.btn_toggle.remove_css_class("destructive-action")

            self._add_log_row("Stopping capture...")
            self.emit("capture-stop-requested")

    def handle_packet_metadata(self, metadata_json: str) -> None:
        """
        Receives packet metadata from D-Bus and updates sniffer counters and logs.
        """
        try:
            packet = json.loads(metadata_json)
            self.packets_count += 1

            proto = packet.get("protocol", "Other")
            if proto in self.proto_stats:
                self.proto_stats[proto] += 1
            else:
                self.proto_stats["Other"] += 1

            self._update_stats_label()

            # Format packet log line
            src = packet.get("src_ip", "?")
            dst = packet.get("dst_ip", "?")
            size = packet.get("size", 0)
            log_line = f"[{proto}] {src} -> {dst} ({size} bytes)"

            # Check for vulnerability alerts
            alert = packet.get("alert")
            if alert:
                self._add_log_row(f"ALERT: {alert} (Packet: {log_line})", is_alert=True)
            else:
                self._add_log_row(log_line)

        except Exception as e:
            logging.error("Failed to parse packet metadata: %s", e)

    def _update_stats_label(self) -> None:
        stats_str = (
            f"Total packets: {self.packets_count} | "
            f"DNS: {self.proto_stats['DNS']} | "
            f"HTTP: {self.proto_stats['HTTP']} | "
            f"TLS: {self.proto_stats['TLS']} | "
            f"SSH: {self.proto_stats['SSH']}"
        )
        self.lbl_stats.set_text(stats_str)

    def _add_log_row(self, text: str, is_alert: bool = False, is_error: bool = False) -> None:
        row = Adw.ActionRow()
        row.set_title(text)

        if is_alert:
            row.add_css_class("warning")
            # Prefixes visual markers if desired, or we rely on the styling
        elif is_error:
            row.add_css_class("error")

        # Keep list reasonably short (last 50 packets)
        # To avoid performance degradation on giant logs
        self.list_box.prepend(row)

        # Check if list exceeds 50
        children = []
        child = self.list_box.get_first_child()
        while child:
            children.append(child)
            child = child.get_next_sibling()

        if len(children) > 50:
            self.list_box.remove(children[-1])


# Register signals
GObject.signal_new(
    "capture-start-requested",
    TrafficView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_STRING, GObject.TYPE_STRING),
)

GObject.signal_new(
    "capture-stop-requested", TrafficView, GObject.SignalFlags.RUN_LAST, GObject.TYPE_NONE, ()
)
