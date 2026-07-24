import os
from pathlib import Path

import pytest

# Set GSETTINGS_SCHEMA_DIR before importing Gio to ensure it reads our local schema.
# The schema must be compiled first (glib-compile-schemas data/)
data_dir = Path(__file__).parent.parent.parent.parent / "data"
os.environ["GSETTINGS_SCHEMA_DIR"] = str(data_dir.resolve())

import gi  # noqa: E402

gi.require_version("Gio", "2.0")
from gi.repository import Gio  # noqa: E402


def test_gsettings_schema_loading():
    # Verify the compiled schema can be loaded and read
    try:
        settings = Gio.Settings.new("org.netsentinel.NetSentinel")
    except Exception as e:
        pytest.fail(
            "Failed to load GSettings schema 'org.netsentinel.NetSentinel'. "
            f"Ensure it is compiled. Error: {e}"
        )

    # Reset to defaults before checking schema values
    settings.reset("network-interface")
    settings.reset("retention-period-days")

    # Check default values defined in XML schema
    assert settings.get_string("network-interface") == "wlan0"
    assert settings.get_string("gemini-api-key-ref") == "keyring:netsentinel/gemini_api_key"
    assert settings.get_int("retention-period-days") == 30

    # Set new values and verify persistence
    settings.set_string("network-interface", "eth0")
    assert settings.get_string("network-interface") == "eth0"

    settings.set_int("retention-period-days", 15)
    assert settings.get_int("retention-period-days") == 15

    # Reset back to defaults
    settings.reset("network-interface")
    settings.reset("retention-period-days")
    assert settings.get_string("network-interface") == "wlan0"
