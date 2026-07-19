from unittest.mock import MagicMock, patch

from netsentinel.helperd.wrappers.arp_spoofer import ArpPacketBuilder, ArpSpoofer


def test_arp_packet_builder():
    src_mac = "00:11:22:33:44:55"
    src_ip = "10.0.0.1"
    dst_mac = "66:77:88:99:aa:bb"
    dst_ip = "10.0.0.2"

    packet = ArpPacketBuilder.build_arp_reply(src_mac, src_ip, dst_mac, dst_ip)
    assert len(packet) == 42  # standard 14 (Eth) + 28 (ARP) = 42 bytes

    # Eth Header dst (6 bytes), src (6 bytes), type (2 bytes = 0x0806)
    assert packet[0:6] == b"\x66\x77\x88\x99\xaa\xbb"
    assert packet[6:12] == b"\x00\x11\x22\x33\x44\x55"
    assert packet[12:14] == b"\x08\x06"

    # Opcode is at index 20-21 (2 bytes = 0x0002 for ARP reply)
    assert packet[20:22] == b"\x00\x02"


@patch("netsentinel.helperd.wrappers.arp_spoofer.socket.socket")
@patch("netsentinel.helperd.wrappers.arp_spoofer.ArpSpoofer._resolve_mac")
def test_arp_spoofer_loop(mock_resolve, mock_socket):
    mock_resolve.side_effect = lambda ip: {
        "127.0.0.1": "00:11:22:33:44:55",
        "10.0.0.10": "66:77:88:99:aa:bb",
        "10.0.0.1": "aa:bb:cc:dd:ee:ff",
    }.get(ip, "00:00:00:00:00:00")

    mock_sock_inst = MagicMock()
    mock_socket.return_value = mock_sock_inst

    spoofer = ArpSpoofer("eth0", "10.0.0.10", "10.0.0.1")
    spoofer.start()
    assert spoofer.is_running is True

    # Stop and restore
    spoofer.stop()
    assert spoofer.is_running is False
    assert mock_sock_inst.send.call_count >= 2
