import json
import os
from pathlib import Path
from unittest.mock import MagicMock

from cryptography.fernet import Fernet

from netsentinel.helperd.wrappers.mitm_handler import NetSentinelMitmAddon


def test_mitm_handler_addon(capsys):
    # Setup shared Fernet key in env
    key = Fernet.generate_key().decode()
    os.environ["NETSENTINEL_DISPOSABLE_KEY"] = key

    addon = NetSentinelMitmAddon()

    # Mock Flow
    flow = MagicMock()
    flow.request.pretty_url = "https://example.com/login"
    flow.request.method = "POST"
    flow.request.headers = {"Content-Type": "application/x-www-form-urlencoded"}
    flow.request.text = "user=alice&password=secretpassword123"

    flow.response.status_code = 200
    flow.response.headers = {"Server": "nginx"}
    flow.response.text = "Welcome Alice"

    # Call response handler
    addon.response(flow)

    # Capture stdout
    captured = capsys.readouterr().out
    assert "NETSENTINEL_MITM_JSON:" in captured

    # Parse logged JSON metadata
    json_part = captured.split("NETSENTINEL_MITM_JSON:", 1)[1].strip()
    metadata = json.loads(json_part)
    assert metadata["url"] == "https://example.com/login"
    assert metadata["method"] == "POST"
    assert metadata["status"] == 200
    assert metadata["size"] == len("Welcome Alice")
    assert "Cleartext password payload detected in request!" in metadata["alerts"]

    # Verify encrypted payload file is created in /dev/shm
    pid = metadata["payload_id"]
    file_path = Path(f"/dev/shm/netsentinel_decrypted_{pid}.enc")
    assert file_path.exists()

    # Clean up temp file
    if file_path.exists():
        file_path.unlink()
