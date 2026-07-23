import socket
from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk  # noqa: E402

from netsentinel.core.secrets.keyring_store import KeyringStore  # noqa: E402


class SettingsView(Adw.PreferencesPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelSettingsView"

    def __init__(self, keyring_store: KeyringStore, **kwargs: Any):
        super().__init__(title="Settings", icon_name="preferences-system-symbolic", **kwargs)
        self.keyring_store = keyring_store

        # Settings schema initialization
        # GSettings require compiling data/ org.netsentinel.NetSentinel.gschema.xml first
        self.settings = Gio.Settings.new("org.netsentinel.NetSentinel")

        # 1. Interface selection group
        group_net = Adw.PreferencesGroup(title="Network Settings")
        self.add(group_net)

        self.interface_row = Adw.ComboRow(
            title="Network Interface", subtitle="Select the active interface for scans and capture"
        )
        group_net.add(self.interface_row)

        # Populate interface combo box
        self.interfaces = self._get_interfaces()
        list_store = Gtk.StringList.new(self.interfaces)
        self.interface_row.set_model(list_store)

        # Bind selected interface to GSettings
        current_iface = self.settings.get_string("network-interface")
        if current_iface in self.interfaces:
            self.interface_row.set_selected(self.interfaces.index(current_iface))

        self.interface_row.connect("notify::selected", self._on_interface_changed)

        # 2. Keyring API credentials group
        group_api = Adw.PreferencesGroup(title="AI API Keys")
        self.add(group_api)

        # Keyring Row for Gemini API key
        self.api_entry_row = Adw.PasswordEntryRow(title="Gemini API Key")
        group_api.add(self.api_entry_row)

        # Load API key reference from Keyring if present
        saved_key = self.keyring_store.get_secret("gemini_api_key")
        if saved_key:
            self.api_entry_row.set_text(saved_key)

        self.api_entry_row.connect("apply", self._on_api_key_applied)

        # 3. Data retention group
        group_data = Adw.PreferencesGroup(title="Data Retention")
        self.add(group_data)

        self.retention_row = Adw.SpinRow.new_with_range(1, 365, 1)
        self.retention_row.set_title("Log Retention Period (Days)")
        self.retention_row.set_subtitle("Number of days to keep session history before purge")
        group_data.add(self.retention_row)

        # Bind GSettings directly to SpinRow value
        self.settings.bind(
            "retention-period-days", self.retention_row, "value", Gio.SettingsBindFlags.DEFAULT
        )

    def _get_interfaces(self) -> list[str]:
        try:
            return [iface[1] for iface in socket.if_nameindex()]
        except Exception:
            try:
                # Fallback to sys filesystem net directories
                net_path = Path("/sys/class/net")
                return [d.name for d in net_path.iterdir() if d.is_dir()]
            except Exception:
                return ["lo"]

    def _on_interface_changed(self, combo_row: Adw.ComboRow, _pspec: object) -> None:
        idx = combo_row.get_selected()
        if 0 <= idx < len(self.interfaces):
            selected_iface = self.interfaces[idx]
            self.settings.set_string("network-interface", selected_iface)

    def _on_api_key_applied(self, entry_row: Adw.EntryRow) -> None:
        key_value = entry_row.get_text().strip()
        if key_value:
            self.keyring_store.set_secret("gemini_api_key", key_value)
        else:
            self.keyring_store.delete_secret("gemini_api_key")
