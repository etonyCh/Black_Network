import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netsentinel.helperd.dbus_service import NetSentinelHelperInterface


@patch("netsentinel.helperd.dbus_service.ReportGenerator")
@pytest.mark.anyio
async def test_dbus_generate_report(mock_generator_cls):
    mock_gen = MagicMock()
    mock_gen.generate_report.return_value = Path("/tmp/netsentinel_report.html")
    mock_gen.hash_file.return_value = "fake_sha256_hash_value"
    mock_generator_cls.return_value = mock_gen

    interface = NetSentinelHelperInterface()
    interface.report_generator = mock_gen

    res = interface.GenerateReport.__wrapped__(interface, True, True, True)
    response = json.loads(res)

    assert response["success"] is True
    assert response["report_path"] == "/tmp/netsentinel_report.html"
    assert response["hash"] == "fake_sha256_hash_value"


@patch("netsentinel.helperd.dbus_service.export_to_zip")
@pytest.mark.anyio
async def test_dbus_export_zip(mock_export_zip):
    mock_export_zip.return_value = Path("/tmp/export.zip")

    interface = NetSentinelHelperInterface()

    res = interface.ExportZip.__wrapped__(interface, "/tmp/export.zip", "pwd", "/tmp/report.html")
    response = json.loads(res)

    assert response["success"] is True
    assert response["zip_path"] == "/tmp/export.zip"
