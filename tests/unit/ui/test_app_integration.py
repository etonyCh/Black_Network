import os
from pathlib import Path

import gi

# Set GSETTINGS_SCHEMA_DIR before importing Gio to ensure it reads our local schema.
data_dir = Path(__file__).parent.parent.parent.parent / "data"
os.environ["GSETTINGS_SCHEMA_DIR"] = str(data_dir.resolve())

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw  # noqa: E402

from netsentinel.ui.main import NetSentinelApp, NetSentinelWindow  # noqa: E402


def test_app_window_instantiation() -> None:
    """
    Integration test verifying that NetSentinelWindow initializes cleanly
    with all 8 GTK4/Adw views without widget or property errors.
    """
    app = NetSentinelApp()
    activated = False

    def on_activate(application: Adw.Application) -> None:
        nonlocal activated
        activated = True
        win = NetSentinelWindow(application=application)
        assert win is not None
        assert win.get_title() == "NetSentinel Security Client"
        assert len(win.stack.observe_children()) == 8
        application.quit()

    app.connect("activate", on_activate)
    app.run([])
    assert activated is True
