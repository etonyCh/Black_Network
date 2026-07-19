import json
from unittest.mock import MagicMock, patch

import pytest

from netsentinel.helperd.dbus_service import NetSentinelHelperInterface


@patch("netsentinel.helperd.dbus_service.ArpSpoofer")
@pytest.mark.anyio
async def test_dbus_arp_spoof_lifecycle(mock_spoofer_cls):
    mock_spoofer = MagicMock()
    mock_spoofer_cls.return_value = mock_spoofer

    interface = NetSentinelHelperInterface()
    assert interface.spoofer is None

    # 1. Start spoofing
    res_start = interface.StartArpSpoof.__wrapped__(interface, "eth0", "10.0.0.5", "10.0.0.1")
    response_start = json.loads(res_start)
    assert response_start["success"] is True
    assert interface.spoofer == mock_spoofer
    mock_spoofer.start.assert_called_once()

    # 2. Stop spoofing
    res_stop = interface.StopArpSpoof.__wrapped__(interface)
    response_stop = json.loads(res_stop)
    assert response_stop["success"] is True
    assert interface.spoofer is None
    mock_spoofer.stop.assert_called_once()


@patch("netsentinel.helperd.dbus_service.VulnScanner")
@pytest.mark.anyio
async def test_dbus_run_vuln_scan(mock_scanner_cls):
    mock_scanner = MagicMock()
    mock_scanner.grab_banner.return_value = "Apache/2.4.49"
    mock_scanner.audit_banner.return_value = [{"cve": "CVE-2021-41773", "severity": "HIGH"}]
    mock_scanner_cls.return_value = mock_scanner

    interface = NetSentinelHelperInterface()
    interface.vuln_scanner = mock_scanner

    res = interface.RunVulnScan.__wrapped__(interface, "10.0.0.5", 80)
    response = json.loads(res)
    assert response["success"] is True
    assert response["banner"] == "Apache/2.4.49"
    assert len(response["findings"]) == 1
    assert response["findings"][0]["cve"] == "CVE-2021-41773"
