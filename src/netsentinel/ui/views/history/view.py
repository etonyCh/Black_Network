import logging
from datetime import datetime

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GObject, Gtk  # noqa: E402

from netsentinel.core.audit.ledger import AuditLedger  # noqa: E402
from netsentinel.core.db.models import SessionModel  # noqa: E402
from netsentinel.ui.widgets.consent_dialog import ConsentDialog  # noqa: E402


class HistoryView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelHistoryView"

    def __init__(self, session_model: SessionModel, ledger: AuditLedger, **kwargs: object):
        super().__init__(title="Session History", **kwargs)
        self.session_model = session_model
        self.ledger = ledger
        self.active_session_id: str | None = None

        # Root box
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        self.set_child(box)

        # Title / Description Group
        group = Adw.PreferencesGroup(title="Sessions List")
        box.append(group)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        group.add(self.list_box)

        # Refresh button and New Session button
        actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.append(actions_box)

        self.btn_new = Gtk.Button(label="New Session")
        self.btn_new.add_css_class("suggested-action")
        self.btn_new.connect("clicked", self._on_new_session_clicked)
        actions_box.append(self.btn_new)

        self.btn_refresh = Gtk.Button(label="Refresh")
        self.btn_refresh.connect("clicked", lambda _b: self.refresh_list())
        actions_box.append(self.btn_refresh)

        # Populate initially
        self.refresh_list()

    def refresh_list(self) -> None:
        # Clear list box
        while True:
            child = self.list_box.get_first_child()
            if child is None:
                break
            self.list_box.remove(child)

        sessions = self.session_model.list_sessions()
        for sess in sessions:
            row = Adw.ActionRow(
                title=sess["title"],
                subtitle=(
                    f"Scope: {', '.join(sess['authorized_scope'])} | Status: {sess['status']}"
                ),
            )
            self.list_box.append(row)

    def _on_new_session_clicked(self, _button: Gtk.Button) -> None:
        # For a full UI application, this would open a dialog to input title,
        # description, and scope.
        self._show_new_session_dialog()

    def _show_new_session_dialog(self) -> None:
        # In a real UI we spawn a form. For this skeleton, we assume default
        # values or a simple dialog.
        dialog = ConsentDialog(self.ledger)
        dialog.connect("consent-resolved", self._on_consent_resolved)
        self.current_consent_dialog = dialog
        # For headful sessions, present it:
        root = self.get_root()
        if root and isinstance(root, Gtk.Window):
            dialog.present(root)

    def _on_consent_resolved(
        self, _dialog: ConsentDialog, accepted: bool, consent_hash: str
    ) -> None:
        if accepted:
            # Create a mock session
            mock_scope = ["192.168.1.0/24"]
            try:
                session_id = self.session_model.create_session(
                    title="Audit Session " + datetime.now().strftime("%Y-%m-%d %H:%M"),
                    description="Automated audit session.",
                    authorized_scope=mock_scope,
                    consent_hash=consent_hash,
                )
                self.active_session_id = session_id
                self.refresh_list()
                self.emit("session-activated", session_id)
            except Exception as e:
                logging.error("Error creating session: %s", e)


# Register custom signal
GObject.signal_new(
    "session-activated",
    HistoryView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_STRING,),
)
