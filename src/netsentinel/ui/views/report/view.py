from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GObject, Gtk  # noqa: E402


class ReportView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelReportView"

    def __init__(self, **kwargs: object):
        super().__init__(title="Audit Reports", **kwargs)
        self.report_history = []  # type: list[dict[str, str]]

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        self.set_child(box)

        # 1. Report contents selections preferences group
        group_content = Adw.PreferencesGroup(
            title="Configure Report Content",
            description="Select which components of the session audit log to consolidate",
        )
        box.append(group_content)

        self.sw_hosts = Adw.SwitchRow(
            title="Include Discovered Network Devices",
            subtitle="Lists IPs, MACs and hardware vendors detected on network map",
        )
        self.sw_hosts.set_active(True)
        group_content.add(self.sw_hosts)

        self.sw_scans = Adw.SwitchRow(
            title="Include Active Vulnerability Scans",
            subtitle="Details host port sweeps and matching CVE vulnerability findings",
        )
        self.sw_scans.set_active(True)
        group_content.add(self.sw_scans)

        self.sw_alerts = Adw.SwitchRow(
            title="Include Security Alert History",
            subtitle="Logs traffic sniffing cleartext credentials warnings and intercept histories",
        )
        self.sw_alerts.set_active(True)
        group_content.add(self.sw_alerts)

        # 2. Export controls group
        group_export = Adw.PreferencesGroup(
            title="Encryption and Export Settings",
            description="Protect consolidated reports inside password-locked archives",
        )
        box.append(group_export)

        self.entry_password = Adw.EntryRow(title="Archive Password")
        group_export.add(self.entry_password)

        self.btn_compile = Gtk.Button(label="Compile and Anchor Report (RE-03)")
        self.btn_compile.add_css_class("suggested-action")
        self.btn_compile.connect("clicked", self._on_compile_clicked)
        group_export.add(self.btn_compile)

        # 3. Report generation history
        group_history = Adw.PreferencesGroup(
            title="Report Signatures Registry",
            description="Lists generated reports and matching SHA-256 hashes registered in ledger",
        )
        box.append(group_history)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(180)
        scroll.set_vexpand(True)
        scroll.set_child(self.list_box)
        group_history.add(scroll)

    def _on_compile_clicked(self, _button: Gtk.Button) -> None:
        inc_hosts = self.sw_hosts.get_active()
        inc_scans = self.sw_scans.get_active()
        inc_alerts = self.sw_alerts.get_active()
        password = self.entry_password.get_text().strip()

        # Emit compilation event
        self.emit("report-generation-requested", inc_hosts, inc_scans, inc_alerts, password)

    def add_report_record(self, filepath: str, sha256_hash: str) -> None:
        """
        Updates the UI list of report signatures after D-Bus callback triggers.
        """
        row = Adw.ActionRow()
        row.set_title(f"Report: {Path(filepath).name}")
        row.set_subtitle(f"SHA-256 Hash: {sha256_hash}")
        row.add_css_class("success")

        # Save to local state
        self.report_history.append({"path": filepath, "hash": sha256_hash})
        self.list_box.prepend(row)


# Register custom signals
GObject.signal_new(
    "report-generation-requested",
    ReportView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_BOOLEAN, GObject.TYPE_BOOLEAN, GObject.TYPE_BOOLEAN, GObject.TYPE_STRING),
)
