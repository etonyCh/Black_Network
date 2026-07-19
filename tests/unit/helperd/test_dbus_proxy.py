import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from netsentinel.helperd.dbus_service import NetSentinelHelperInterface


@patch("netsentinel.helperd.dbus_service.start_mitm_proxy")
@pytest.mark.anyio
async def test_dbus_proxy_lifecycle(mock_start_proxy):
    # Mock subprocess
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 0  # Make it exit immediately
    mock_start_proxy.return_value = mock_proc

    interface = NetSentinelHelperInterface()
    assert interface.proxy_proc is None

    # 1. Start Proxy
    res_start = interface.StartProxy.__wrapped__(interface, 8080)
    response = json.loads(res_start)
    assert response["success"] is True
    assert interface.proxy_proc == mock_proc
    assert interface.proxy_task is not None

    # Wait briefly for event loop tasks to run
    await asyncio.sleep(0.05)

    # 2. Stop Proxy
    res_stop = interface.StopProxy.__wrapped__(interface)
    response_stop = json.loads(res_stop)
    assert response_stop["success"] is True
    assert interface.proxy_proc is None
    assert interface.proxy_task is None
