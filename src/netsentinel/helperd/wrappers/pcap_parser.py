import struct
from collections.abc import Iterator
from typing import Any


class PcapParser:
    def __init__(self) -> None:
        self.endian = "<"
        self.header_parsed = False

    def parse_stream(self, stream_bytes: bytes) -> Iterator[dict[str, Any]]:
        """
        Parses chunk of bytes from a PCAP stream.
        Yields parsed packet metadata dicts.
        """
        offset = 0
        total_len = len(stream_bytes)

        # 1. Parse Global Header (24 bytes)
        if not self.header_parsed:
            if total_len < 24:
                return  # Need more data
            magic = stream_bytes[offset : offset + 4]
            if magic == b"\xa1\xb2\xc3\xd4":
                self.endian = ">"
            elif magic == b"\xd4\xc3\xb2\xa1":
                self.endian = "<"
            else:
                # Fallback / ignore invalid header and try to read
                pass
            self.header_parsed = True
            offset += 24

        # 2. Parse Packets Loop
        while offset + 16 <= total_len:
            # Parse Packet Header
            # ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
            header_format = f"{self.endian}IIII"
            ts_sec, ts_usec, incl_len, _ = struct.unpack(
                header_format, stream_bytes[offset : offset + 16]
            )

            # Check if we have the full packet payload in this buffer chunk
            if offset + 16 + incl_len > total_len:
                break  # Wait for more data in next chunk

            packet_data = stream_bytes[offset + 16 : offset + 16 + incl_len]
            offset += 16 + incl_len

            parsed_packet = self._parse_packet_payload(packet_data, ts_sec, ts_usec)
            if parsed_packet:
                yield parsed_packet

    def _parse_packet_payload(
        self, data: bytes, ts_sec: int, ts_usec: int
    ) -> dict[str, Any] | None:
        if len(data) < 14:
            return None

        # EtherType at offset 12 (2B)
        eth_type = struct.unpack(">H", data[12:14])[0]
        if eth_type != 0x0800:
            # We only parse IPv4 packets in this helper for simplicity
            return None

        # IPv4 Header starts at offset 14
        if len(data) < 34:
            return None

        version_ihl = data[14]
        ihl = (version_ihl & 0x0F) * 4
        if len(data) < 14 + ihl:
            return None

        protocol = data[23]
        src_ip_bytes = data[26:30]
        dst_ip_bytes = data[30:34]
        src_ip = ".".join(map(str, src_ip_bytes))
        dst_ip = ".".join(map(str, dst_ip_bytes))

        src_port = 0
        dst_port = 0
        proto_name = "IPv4"
        alert = None

        l4_offset = 14 + ihl
        if protocol == 6:  # TCP
            if len(data) < l4_offset + 4:
                return None
            src_port, dst_port = struct.unpack(">HH", data[l4_offset : l4_offset + 4])
            proto_name = self._classify_tcp_protocol(src_port, dst_port)
            if proto_name in ("HTTP", "FTP", "Telnet"):
                alert = f"Cleartext protocol {proto_name} detected!"
        elif protocol == 17:  # UDP
            if len(data) < l4_offset + 4:
                return None
            src_port, dst_port = struct.unpack(">HH", data[l4_offset : l4_offset + 4])
            proto_name = "DNS" if src_port == 53 or dst_port == 53 else "UDP"

        return {
            "timestamp": ts_sec + ts_usec / 1000000.0,
            "size": len(data),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_name,
            "alert": alert,
        }

    def _classify_tcp_protocol(self, src: int, dst: int) -> str:
        ports = (src, dst)
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "TLS"
        if 22 in ports:
            return "SSH"
        if 21 in ports:
            return "FTP"
        if 23 in ports:
            return "Telnet"
        return "TCP"
