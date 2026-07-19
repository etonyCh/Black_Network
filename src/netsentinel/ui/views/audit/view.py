import json
import logging

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GObject, Gtk  # noqa: E402

from netsentinel.utils.network_validation import is_in_scope  # noqa: E402


class AuditView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelAuditView"

    def __init__(self, **kwargs: object):
        super().__init__(title="Active Security Audit", **kwargs)
        self.active_scope = []  # type: list[str]
        self.is_spoofing = False

        # Root box layout
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        self.set_child(box)

        # 1. ARP Spoof Simulation Group
        group_spoof = Adw.PreferencesGroup(
            title="ARP Poisoning Simulation (BAS)",
            description="Simulate L2 Man-in-the-Middle state inside authorized network boundary",
        )
        box.append(group_spoof)

        self.interface_row = Adw.EntryRow(
            title="Interface", text="wlan0", placeholder_text="e.g. wlan0"
        )
        group_spoof.add(self.interface_row)

        self.target_row = Adw.EntryRow(
            title="Target Host IP", placeholder_text="e.g. 192.168.1.100"
        )
        group_spoof.add(self.target_row)

        self.gateway_row = Adw.EntryRow(
            title="Gateway Router IP", placeholder_text="e.g. 192.168.1.1"
        )
        group_spoof.add(self.gateway_row)

        self.btn_spoof = Gtk.Button(label="Start ARP Spoof")
        self.btn_spoof.add_css_class("suggested-action")
        self.btn_spoof.connect("clicked", self._on_spoof_clicked)
        group_spoof.add(self.btn_spoof)

        # 2. Vulnerability Scanning Group
        group_scan = Adw.PreferencesGroup(title="Active Service Vulnerability Scan")
        box.append(group_scan)

        self.scan_target_row = Adw.EntryRow(
            title="Scan Target Host", placeholder_text="e.g. 192.168.1.100"
        )
        group_scan.add(self.scan_target_row)

        self.scan_port_row = Adw.SpinRow(
            title="Target Port",
            subtitle="Port to grab banner from (e.g. 22, 80)",
            adjustment=Gtk.Adjustment.new(22, 1, 65535, 1, 10, 0),
        )
        group_scan.add(self.scan_port_row)

        self.btn_scan = Gtk.Button(label="Run Banner Vulnerability Scan")
        self.btn_scan.add_css_class("suggested-action")
        self.btn_scan.connect("clicked", self._on_scan_clicked)
        group_scan.add(self.btn_scan)

        # 3. Findings Log Section
        group_findings = Adw.PreferencesGroup(title="Audit Findings Logs")
        box.append(group_findings)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(180)
        scroll.set_vexpand(True)
        scroll.set_child(self.list_box)
        group_findings.add(scroll)

    def set_active_scope(self, scope: list[str]) -> None:
        """
        Sets authorized boundary.
        """
        self.active_scope = scope

    def _on_spoof_clicked(self, _button: Gtk.Button) -> None:
        if not self.is_spoofing:
            interface = self.interface_row.get_text().strip()
            target = self.target_row.get_text().strip()
            gateway = self.gateway_row.get_text().strip()

            if not (interface and target and gateway):
                self._add_log_row(
                    "Error: interface, target IP and gateway IP are required.",
                    is_error=True,
                )
                return

            # Check boundary permissions (RE-02)
            if not is_in_scope(target, self.active_scope):
                self._add_log_row(
                    f"Blocked: target {target} outside authorized scope.",
                    is_error=True,
                )
                return
            if not is_in_scope(gateway, self.active_scope):
                self._add_log_row(
                    f"Blocked: gateway {gateway} outside authorized scope.",
                    is_error=True,
                )
                return

            self.is_spoofing = True
            self.btn_spoof.set_label("Stop ARP Spoof")
            self.btn_spoof.add_css_class("destructive-action")
            self.btn_spoof.remove_css_class("suggested-action")

            self._add_log_row(f"ARP Poison loop started on {interface}: {target} <-> {gateway}")
            self.emit("arp-spoof-start-requested", interface, target, gateway)
        else:
            self.is_spoofing = False
            self.btn_spoof.set_label("Start ARP Spoof")
            self.btn_spoof.add_css_class("suggested-action")
            self.btn_spoof.remove_css_class("destructive-action")

            self._add_log_row("Stopping ARP Poison loop and restoring caches (RE-05)...")
            self.emit("arp-spoof-stop-requested")

    def _on_scan_clicked(self, _button: Gtk.Button) -> None:
        target = self.scan_target_row.get_text().strip()
        port = int(self.scan_port_row.get_value())

        if not target:
            self._add_log_row("Error: scan target host is required.", is_error=True)
            return

        if not is_in_scope(target, self.active_scope):
            self._add_log_row(
                f"Blocked: scan target {target} outside authorized scope.",
                is_error=True,
            )
            return

        self._add_log_row(f"Grabbing banner on {target}:{port}...")
        self.emit("vuln-scan-requested", target, port)

    def display_scan_results(self, banner: str, findings_json: str) -> None:
        """
        Callback updating UI logs with CVE matches.
        """
        self._add_log_row(f"Service Banner grabbed: {banner if banner else '[Empty Banner]'}")
        try:
            findings = json.loads(findings_json)
            if not findings:
                self._add_log_row("No known vulnerabilities matched in database.")
                return

            for f in findings:
                service = f.get("service", "?")
                cve = f.get("cve", "?")
                summary = f.get("summary", "")
                sev = f.get("severity", "MEDIUM")
                self._add_log_row(
                    f"VULNERABILITY FOUND [{sev}]: {service} ({cve}) - {summary}",
                    is_alert=True,
                )
        except Exception as e:
            logging.error("Failed to parse vulnerability findings: %s", e)

    def _add_log_row(self, text: str, is_alert: bool = False, is_error: bool = False) -> None:
        row = Adw.ActionRow()
        row.set_title(text)
        if is_alert:
            row.add_css_class("warning")
        elif is_error:
            row.add_css_class("error")

        self.list_box.prepend(row)


# Register custom signals
GObject.signal_new(
    "arp-spoof-start-requested",
    AuditView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING),
)

GObject.signal_new(
    "arp-spoof-stop-requested", AuditView, GObject.SignalFlags.RUN_LAST, GObject.TYPE_NONE, ()
)

GObject.signal_new(
    "vuln-scan-requested",
    AuditView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_STRING, GObject.TYPE_INT),
)
