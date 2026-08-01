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
        self.list_box.connect("row-selected", self._on_session_selected)
        self.list_box.connect("row-activated", self._on_session_activated)

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

        self.btn_use = Gtk.Button(label="Use Selected Session")
        self.btn_use.add_css_class("suggested-action")
        self.btn_use.set_sensitive(False)
        self.btn_use.connect("clicked", self._on_use_session_clicked)
        actions_box.append(self.btn_use)

        self.btn_delete = Gtk.Button(label="Delete Selected")
        self.btn_delete.add_css_class("destructive-action")
        self.btn_delete.set_sensitive(False)
        self.btn_delete.connect("clicked", self._on_delete_session_clicked)
        actions_box.append(self.btn_delete)

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
            row.set_name(sess["id"])
            self.list_box.append(row)
            if sess["id"] == self.active_session_id:
                self.list_box.select_row(row)

    def _on_new_session_clicked(self, _button: Gtk.Button) -> None:
        # Creating a session requires recording the operator's consent first.
        self._show_new_session_dialog()

    def _on_session_selected(self, _list_box: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        has_selection = row is not None
        self.btn_use.set_sensitive(has_selection)
        self.btn_delete.set_sensitive(has_selection)

    def _on_session_activated(self, _list_box: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        self._activate_session(row.get_name())

    def _on_use_session_clicked(self, _button: Gtk.Button) -> None:
        row = self.list_box.get_selected_row()
        if row is not None:
            self._activate_session(row.get_name())

    def _activate_session(self, session_id: str | None) -> None:
        if session_id and self.session_model.get_session(session_id) is not None:
            self.active_session_id = session_id
            self.emit("session-activated", session_id)

    def _on_delete_session_clicked(self, _button: Gtk.Button) -> None:
        row = self.list_box.get_selected_row()
        if row is None:
            return
        session_id = row.get_name()
        if session_id and self.session_model.delete_session(session_id):
            if self.active_session_id == session_id:
                self.active_session_id = None
                self.emit("session-deactivated")
            self.refresh_list()


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

GObject.signal_new(
    "session-deactivated",
    HistoryView,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (),
)
