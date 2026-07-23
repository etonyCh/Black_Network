import logging
import sys
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk  # noqa: E402

from netsentinel.core.audit.ledger import AuditLedger  # noqa: E402
from netsentinel.core.audit.pqc_validator import PQCValidator  # noqa: E402
from netsentinel.core.db.models import SessionModel  # noqa: E402
from netsentinel.core.secrets.keyring_store import KeyringStore  # noqa: E402
from netsentinel.ui.views.audit.view import AuditView  # noqa: E402
from netsentinel.ui.views.fingerprint_ctem_pqc.view import FingerprintView  # noqa: E402
from netsentinel.ui.views.history.view import HistoryView  # noqa: E402
from netsentinel.ui.views.interceptor.view import InterceptorView  # noqa: E402
from netsentinel.ui.views.network_map.view import NetworkMapView  # noqa: E402
from netsentinel.ui.views.report.view import ReportView  # noqa: E402
from netsentinel.ui.views.settings.view import SettingsView  # noqa: E402
from netsentinel.ui.views.traffic.view import TrafficView  # noqa: E402


class NetSentinelWindow(Adw.ApplicationWindow):  # type: ignore[misc]
    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.set_title("NetSentinel Security Client")
        self.set_default_size(1050, 700)

        # Core services initialization
        self.keyring_store = KeyringStore()
        self.ledger = AuditLedger()
        self.session_model = SessionModel()
        self.pqc_validator = PQCValidator()

        # Build UI layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.set_content(main_box)

        # Sidebar navigation stack
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

        sidebar = Gtk.StackSidebar()
        sidebar.set_stack(self.stack)

        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)

        main_box.append(sidebar)
        main_box.append(self.stack)

        # Instantiating navigation pages
        self.view_netmap = NetworkMapView()
        self.view_traffic = TrafficView()
        self.view_interceptor = InterceptorView()
        self.view_audit = AuditView()
        self.view_fingerprint = FingerprintView(pqc_validator=self.pqc_validator)
        self.view_report = ReportView()
        self.view_history = HistoryView(session_model=self.session_model, ledger=self.ledger)
        self.view_settings = SettingsView(keyring_store=self.keyring_store)

        # Adding pages to stack
        self.stack.add_titled(self.view_netmap, "netmap", "Network Map")
        self.stack.add_titled(self.view_traffic, "traffic", "Traffic Capture")
        self.stack.add_titled(self.view_interceptor, "interceptor", "MitM Interceptor")
        self.stack.add_titled(self.view_audit, "audit", "Active Audit & BAS")
        self.stack.add_titled(self.view_fingerprint, "fingerprint", "CTEM & PQC Audit")
        self.stack.add_titled(self.view_report, "report", "Audit Reports")
        self.stack.add_titled(self.view_history, "history", "Session History")
        self.stack.add_titled(self.view_settings, "settings", "Settings")


class NetSentinelApp(Adw.Application):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__(
            application_id="org.netsentinel.NetSentinel",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )

    def do_activate(self) -> None:
        win = self.props.active_window
        if not win:
            win = NetSentinelWindow(application=self)
        win.present()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    app = NetSentinelApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
