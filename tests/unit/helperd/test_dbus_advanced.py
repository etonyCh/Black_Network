import json
from unittest.mock import patch

from netsentinel.helperd.dbus_service import NetSentinelHelperInterface


@patch("netsentinel.helperd.dbus_service.run_advanced_scan")
def test_dbus_advanced_scan_success(mock_run_advanced):
    mock_run_advanced.return_value = {
        "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
        "ciphers": ["mlkem768"],
    }

    interface = NetSentinelHelperInterface()
    response_json = interface.AdvancedScan.__wrapped__(interface, "192.168.1.1", "deep")

    response = json.loads(response_json)
    assert response["success"] is True
    assert len(response["scan_results"]["ports"]) == 1
    assert response["scan_results"]["ciphers"] == ["mlkem768"]
    mock_run_advanced.assert_called_once_with("192.168.1.1", "deep")


@patch("netsentinel.helperd.dbus_service.run_advanced_scan")
def test_dbus_advanced_scan_failure(mock_run_advanced):
    mock_run_advanced.side_effect = ValueError("Mocked advanced scan failure")

    interface = NetSentinelHelperInterface()
    response_json = interface.AdvancedScan.__wrapped__(interface, "192.168.1.1", "deep")

    response = json.loads(response_json)
    assert response["success"] is False
    assert "Mocked advanced scan failure" in response["error"]
