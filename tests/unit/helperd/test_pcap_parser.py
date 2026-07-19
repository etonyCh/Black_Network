import struct

from netsentinel.helperd.wrappers.pcap_parser import PcapParser


def make_mock_pcap_stream() -> bytes:
    # 1. Global Header (24 bytes)
    # Magic = 0xa1b2c3d4 (little endian on disk will be \xd4\xc3\xb2\xa1)
    # Major = 2, Minor = 4, Net = 1 (Ethernet)
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # 2. Packet 1 Header (16 bytes)
    # ts_sec = 1710000000, ts_usec = 500000, incl_len = 38, orig_len = 38
    pkt_hdr = struct.pack("<IIII", 1710000000, 500000, 38, 38)

    # 3. Packet 1 Payload (38 bytes)
    # Ethernet (14 bytes)
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x00\xaa\xbb\xcc\xdd\xee" + b"\x08\x00"
    # IPv4 (20 bytes)
    # IHL = 5 (20B), Protocol = 6 (TCP), Src = 10.0.0.5, Dst = 10.0.0.6
    ip = (
        b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00"
        + b"\x0a\x00\x00\x05"
        + b"\x0a\x00\x00\x06"
    )
    # TCP Ports (4 bytes: Src = 80, Dst = 12345)
    tcp = struct.pack(">HH", 80, 12345)

    return global_hdr + pkt_hdr + eth + ip + tcp


def test_pcap_parser_success():
    parser = PcapParser()
    stream = make_mock_pcap_stream()

    packets = list(parser.parse_stream(stream))
    assert len(packets) == 1

    pkt = packets[0]
    assert pkt["timestamp"] == 1710000000.5
    assert pkt["size"] == 38
    assert pkt["src_ip"] == "10.0.0.5"
    assert pkt["dst_ip"] == "10.0.0.6"
    assert pkt["src_port"] == 80
    assert pkt["dst_port"] == 12345
    assert pkt["protocol"] == "HTTP"
    assert "Cleartext protocol HTTP detected" in pkt["alert"]
