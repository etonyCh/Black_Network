import logging

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from typing import Any  # noqa: E402

from gi.repository import Adw, GObject, Gtk  # noqa: E402

from netsentinel.core.audit.pqc_validator import PQCValidator  # noqa: E402
from netsentinel.utils.network_validation import is_in_scope  # noqa: E402


class FingerprintView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelFingerprintView"

    def __init__(self, pqc_validator: PQCValidator, **kwargs: object):
        super().__init__(title="Fingerprint & PQC Audit", **kwargs)
        self.pqc_validator = pqc_validator
        self.active_scope = []  # type: list[str]

        # Root layout
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        self.set_child(box)

        # 1. Target settings group
        group_target = Adw.PreferencesGroup(title="Scan Scope Settings")
        box.append(group_target)

        self.target_entry = Adw.EntryRow(title="Scan Target Host")
        group_target.add(self.target_entry)

        # Combo selector for scan mode
        self.mode_row = Adw.ComboRow(
            title="Scan Type",
            subtitle="Choose quick discovery, standard balanced, or deep PQC audits",
        )
        group_target.add(self.mode_row)

        self.scan_modes = ["quick", "balanced", "deep"]
        list_store = Gtk.StringList.new(self.scan_modes)
        self.mode_row.set_model(list_store)
        self.mode_row.set_selected(1)  # Default: balanced

        # Scan triggers
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.append(btn_box)

        self.btn_start = Gtk.Button(label="Run Audit Scan")
        self.btn_start.add_css_class("suggested-action")
        self.btn_start.connect("clicked", self._on_start_scan_clicked)
        btn_box.append(self.btn_start)

        # 2. Results display section
        group_results = Adw.PreferencesGroup(title="Scan Results")
        box.append(group_results)

        self.lbl_status = Gtk.Label(label="Ready to scan")
        group_results.add(self.lbl_status)

        self.lbl_pqc_status = Gtk.Label(label="PQC Scoring: Not scanned yet")
        group_results.add(self.lbl_pqc_status)

    def set_active_scope(self, scope: list[str]) -> None:
        """
        Set authorized target list (RE-02 compliance).
        """
        self.active_scope = scope

    def _on_start_scan_clicked(self, _button: Gtk.Button) -> None:
        target = self.target_entry.get_text().strip()
        if not target:
            self.lbl_status.set_text("Error: Please enter a target.")
            return

        # 1. Scope Guard Check (RE-02)
        if not is_in_scope(target, self.active_scope):
            self.lbl_status.set_text(f"Blocked: target {target} falls outside session scope.")
            logging.warning("Scan blocked: target %s outside scope %s", target, self.active_scope)
            return

        idx = self.mode_row.get_selected()
        selected_mode = self.scan_modes[idx]

        # 2. Avertissement Scan Agressif (Deep scan warning modal)
        if selected_mode == "deep":
            self._show_deep_scan_warning_dialog(target)
        else:
            self._execute_scan(target, selected_mode)

    def _show_deep_scan_warning_dialog(self, target: str) -> None:
        root = self.get_root()
        if root and isinstance(root, Gtk.Window):
            dialog = Adw.AlertDialog(
                title="Deep Scan Warning",
                body=(
                    f"Warning: Deep scans run intensive port and cryptographic script sweeps "
                    f"against '{target}'. This may impact fragile target network services.\n\n"
                    "Do you wish to proceed?"
                ),
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("proceed", "Proceed")
            dialog.set_response_appearance("proceed", Adw.ResponseAppearance.DESTRUCTIVE)

            dialog.connect(
                "response",
                lambda _d, res: self._execute_scan(target, "deep") if res == "proceed" else None,
            )
            dialog.present(root)
        else:
            # Fallback for headless tests: proceed directly
            self._execute_scan(target, "deep")

    def _execute_scan(self, target: str, mode: str) -> None:
        self.lbl_status.set_text(f"Scanning {target} ({mode})...")
        # In headful UI, this sends D-Bus call. For this view skeleton, we simulate or emit signal.
        # Let's emit a signal notifying caller that a scan is requested.
        self.emit("scan-requested", target, mode)

    def display_results(self, ports: list[dict[str, Any]], ciphers: list[str]) -> None:
        """
        Called when scan results return. Updates UI and runs PQC scoring.
        """
        ports_str = ", ".join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in ports])
        self.lbl_status.set_text(f"Ports Discovered: {ports_str if ports_str else 'None'}")

        if ciphers:
            pqc_score = self.pqc_validator.evaluate_ciphers(ciphers)
            self.lbl_pqc_status.set_text(f"PQC Readiness Scoring: {pqc_score}")
        else:
            self.lbl_pqc_status.set_text(
                "PQC Readiness Scoring: CLASSICAL_STRONG (No clear ciphers detected)"
            )


# Register custom signals
GObject.signal_new(
    "scan-requested",
    FingerprintView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_STRING, GObject.TYPE_STRING),
)
