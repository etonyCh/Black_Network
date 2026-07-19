import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from netsentinel.helperd.dbus_service import NetSentinelHelperInterface


@patch("netsentinel.helperd.dbus_service.start_dumpcap_capture")
@pytest.mark.anyio
async def test_dbus_capture_lifecycle(mock_start_dumpcap):
    # Mock subprocess
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 0  # Make it exit immediately to finish task
    mock_start_dumpcap.return_value = mock_proc

    interface = NetSentinelHelperInterface()
    assert interface.capture_proc is None

    # 1. Start Capture
    res_start = interface.StartCapture.__wrapped__(interface, "wlan0", "tcp port 80")
    response = json.loads(res_start)
    assert response["success"] is True
    assert interface.capture_proc == mock_proc
    assert interface.capture_task is not None

    # Wait briefly for event loop tasks to run
    await asyncio.sleep(0.05)

    # 2. Stop Capture
    res_stop = interface.StopCapture.__wrapped__(interface)
    response_stop = json.loads(res_stop)
    assert response_stop["success"] is True
    assert interface.capture_proc is None
    assert interface.capture_task is None
