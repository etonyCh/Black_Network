import json
from unittest.mock import patch

from netsentinel.helperd.dbus_service import NetSentinelHelperInterface


@patch("netsentinel.helperd.dbus_service.run_arpscan")
def test_dbus_arpscan_success(mock_run_arpscan):
    mock_run_arpscan.return_value = [
        {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "vendor": "TestVendor"}
    ]

    interface = NetSentinelHelperInterface()
    response_json = interface.ArpScan.__wrapped__(interface, "wlan0")

    response = json.loads(response_json)
    assert response["success"] is True
    assert len(response["hosts"]) == 1
    assert response["hosts"][0]["ip"] == "192.168.1.10"
    mock_run_arpscan.assert_called_once_with("wlan0")


@patch("netsentinel.helperd.dbus_service.run_arpscan")
def test_dbus_arpscan_failure(mock_run_arpscan):
    mock_run_arpscan.side_effect = ValueError("Mocked scan failure")

    interface = NetSentinelHelperInterface()
    response_json = interface.ArpScan.__wrapped__(interface, "wlan0")

    response = json.loads(response_json)
    assert response["success"] is False
    assert "Mocked scan failure" in response["error"]


@patch("netsentinel.helperd.dbus_service.run_nmap_ping_scan")
def test_dbus_nmap_success(mock_run_nmap):
    mock_run_nmap.return_value = [{"hostname": "myhost", "ip": "10.0.0.5", "status": "up"}]

    interface = NetSentinelHelperInterface()
    response_json = interface.NmapScan.__wrapped__(interface, "10.0.0.0/24")

    response = json.loads(response_json)
    assert response["success"] is True
    assert len(response["hosts"]) == 1
    assert response["hosts"][0]["ip"] == "10.0.0.5"
    mock_run_nmap.assert_called_once_with("10.0.0.0/24")
