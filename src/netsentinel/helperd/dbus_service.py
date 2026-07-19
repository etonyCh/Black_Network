import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dbus_next import BusType  # type: ignore[attr-defined]
from dbus_next.aio import MessageBus  # type: ignore[attr-defined]
from dbus_next.service import ServiceInterface, method, signal

from netsentinel.core.audit.exporter import export_to_zip
from netsentinel.core.audit.report_generator import ReportGenerator
from netsentinel.core.audit.vuln_scanner import VulnScanner
from netsentinel.core.secrets.ram_store import RamStore
from netsentinel.helperd.wrappers.arp_spoofer import ArpSpoofer
from netsentinel.helperd.wrappers.arpscan_wrapper import run_arpscan
from netsentinel.helperd.wrappers.dumpcap_wrapper import start_dumpcap_capture
from netsentinel.helperd.wrappers.mitm_wrapper import cleanup_ca_certificates, start_mitm_proxy
from netsentinel.helperd.wrappers.nmap_advanced_wrapper import run_advanced_scan
from netsentinel.helperd.wrappers.nmap_wrapper import run_nmap_ping_scan
from netsentinel.helperd.wrappers.pcap_parser import PcapParser

if TYPE_CHECKING:
    s = str
    i = int
    b = bool

BUS_NAME = "org.netsentinel.Helper1"
OBJECT_PATH = "/org/netsentinel/Helper1"


class NetSentinelHelperInterface(ServiceInterface):
    def __init__(self) -> None:
        super().__init__(BUS_NAME)
        self.capture_proc = None  # type: Any
        self.capture_task = None  # type: Any
        self.ram_store = RamStore()
        self.proxy_proc = None  # type: Any
        self.proxy_task = None  # type: Any
        self.spoofer = None  # type: Any
        self.vuln_scanner = VulnScanner()
        self.report_generator = ReportGenerator()

    @method()  # type: ignore[untyped-decorator]
    def ArpScan(self, interface: "s") -> "s":  # noqa: N802
        """
        Runs privileged arp-scan on system interface.
        Returns a JSON string of discovered hosts.
        """
        try:
            logging.info("D-Bus request: ArpScan on %s", interface)
            results = run_arpscan(interface)
            return json.dumps({"success": True, "hosts": results})
        except Exception as e:
            logging.error("ArpScan failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def NmapScan(self, target: "s") -> "s":  # noqa: N802
        """
        Runs host discovery nmap ping scan on target.
        Returns a JSON string of discovered hosts.
        """
        try:
            logging.info("D-Bus request: NmapScan on %s", target)
            results = run_nmap_ping_scan(target)
            return json.dumps({"success": True, "hosts": results})
        except Exception as e:
            logging.error("NmapScan failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def AdvancedScan(self, target: "s", mode: "s") -> "s":  # noqa: N802
        """
        Runs advanced nmap scan on target with mode (quick, balanced, deep).
        Returns a JSON string of ports and ciphers.
        """
        try:
            logging.info("D-Bus request: AdvancedScan on %s with mode %s", target, mode)
            results = run_advanced_scan(target, mode)
            return json.dumps({"success": True, "scan_results": results})
        except Exception as e:
            logging.error("AdvancedScan failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def StartCapture(self, interface: "s", bpf_filter: "s") -> "s":  # noqa: N802
        """
        Starts packet capture on interface with BPF filter.
        """
        try:
            if self.capture_proc is not None:
                return json.dumps({"success": False, "error": "Capture already running"})

            logging.info("D-Bus request: StartCapture on %s with BPF %s", interface, bpf_filter)
            proc = start_dumpcap_capture(interface, bpf_filter)
            self.capture_proc = proc

            # Start background task to read stdout
            self.capture_task = asyncio.create_task(self._read_capture_stream(proc))
            return json.dumps({"success": True})
        except Exception as e:
            logging.error("StartCapture failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def StopCapture(self) -> "s":  # noqa: N802
        """
        Stops active packet capture.
        """
        try:
            logging.info("D-Bus request: StopCapture")
            self._stop_capture_internal()
            return json.dumps({"success": True})
        except Exception as e:
            logging.error("StopCapture failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def StartProxy(self, port: "i") -> "s":  # noqa: N802
        """
        Starts MitM decryption proxy on port.
        """
        try:
            if self.proxy_proc is not None:
                return json.dumps({"success": False, "error": "Proxy already running"})

            logging.info("D-Bus request: StartProxy on port %s", port)
            proc = start_mitm_proxy(port, self.ram_store.key)
            self.proxy_proc = proc

            # Start reading stdout from mitmdump
            self.proxy_task = asyncio.create_task(self._read_proxy_stream(proc))
            return json.dumps({"success": True})
        except Exception as e:
            logging.error("StartProxy failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def StopProxy(self) -> "s":  # noqa: N802
        """
        Stops MitM decryption proxy. Clears RAM storage.
        """
        try:
            logging.info("D-Bus request: StopProxy")
            self._stop_proxy_internal()
            return json.dumps({"success": True})
        except Exception as e:
            logging.error("StopProxy failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def GetDecryptedPayload(self, payload_id: "s") -> "s":  # noqa: N802
        """
        Returns decrypted packet metadata payload from RAM.
        """
        try:
            val = self.ram_store.retrieve(payload_id)
            if val is None:
                return json.dumps({"success": False, "error": "Payload not found or expired"})
            return json.dumps({"success": True, "payload": val})
        except Exception as e:
            logging.error("GetDecryptedPayload failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def StartArpSpoof(self, interface: "s", target: "s", gateway: "s") -> "s":  # noqa: N802
        """
        Starts raw ARP spoofing poisoning simulation loop.
        """
        try:
            if self.spoofer is not None:
                return json.dumps({"success": False, "error": "ARP spoofing already running"})

            logging.info("D-Bus request: StartArpSpoof target %s gateway %s", target, gateway)
            spoofer = ArpSpoofer(interface, target, gateway)
            spoofer.start()
            self.spoofer = spoofer
            return json.dumps({"success": True})
        except Exception as e:
            logging.error("StartArpSpoof failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def StopArpSpoof(self) -> "s":  # noqa: N802
        """
        Stops ARP spoofing loop and unpoisons caches.
        """
        try:
            if self.spoofer is not None:
                logging.info("D-Bus request: StopArpSpoof")
                self.spoofer.stop()
                self.spoofer = None
            return json.dumps({"success": True})
        except Exception as e:
            logging.error("StopArpSpoof failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def RunVulnScan(self, target: "s", port: "i") -> "s":  # noqa: N802
        """
        Performs banner-grabbing and vuln scanning audit.
        """
        try:
            logging.info("D-Bus request: RunVulnScan %s:%s", target, port)
            banner = self.vuln_scanner.grab_banner(target, port)
            findings = self.vuln_scanner.audit_banner(banner)
            return json.dumps({"success": True, "banner": banner, "findings": findings})
        except Exception as e:
            logging.error("RunVulnScan failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def GenerateReport(  # noqa: N802
        self, include_hosts: "b", include_scans: "b", include_alerts: "b"
    ) -> "s":
        """
        Generates HTML audit report and logs SHA-256 signature in ledger (RE-03).
        """
        try:
            logging.info("D-Bus request: GenerateReport")
            # Save in standard local share directory
            out_dir = Path.home() / ".local" / "share" / "netsentinel" / "reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            report_path = out_dir / "netsentinel_report.html"

            saved_path = self.report_generator.generate_report(
                report_path, include_hosts, include_scans, include_alerts
            )
            report_hash = self.report_generator.hash_file(saved_path)

            return json.dumps(
                {"success": True, "report_path": str(saved_path.resolve()), "hash": report_hash}
            )
        except Exception as e:
            logging.error("GenerateReport failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @method()  # type: ignore[untyped-decorator]
    def ExportZip(  # noqa: N802
        self, zip_path: "s", password: "s", report_path: "s"
    ) -> "s":
        """
        Exports audit report to password-protected ZIP archive.
        """
        try:
            logging.info("D-Bus request: ExportZip to %s", zip_path)
            res_path = export_to_zip(Path(zip_path), password, [Path(report_path)])
            return json.dumps({"success": True, "zip_path": str(res_path.resolve())})
        except Exception as e:
            logging.error("ExportZip failed: %s", e)
            return json.dumps({"success": False, "error": str(e)})

    @signal()  # type: ignore[untyped-decorator]
    def PacketCaptured(self, metadata: "s") -> "s":  # noqa: N802
        """
        Emitted when a network packet is parsed.
        """
        return metadata

    @signal()  # type: ignore[untyped-decorator]
    def RequestIntercepted(self, metadata: "s") -> "s":  # noqa: N802
        """
        Emitted when an HTTP/HTTPS exchange is intercepted by proxy.
        """
        return metadata

    def _stop_capture_internal(self) -> None:
        if self.capture_task is not None:
            self.capture_task.cancel()
            self.capture_task = None
        if self.capture_proc is not None:
            self.capture_proc.terminate()
            self.capture_proc.wait()
            self.capture_proc = None

    def _stop_proxy_internal(self) -> None:
        if self.proxy_task is not None:
            self.proxy_task.cancel()
            self.proxy_task = None
        if self.proxy_proc is not None:
            self.proxy_proc.terminate()
            self.proxy_proc.wait()
            self.proxy_proc = None
        # Revoke certs and clear RAM keys (RE-04)
        cleanup_ca_certificates()
        self.ram_store.clear()

    async def _read_capture_stream(self, proc: Any) -> None:
        parser = PcapParser()
        loop = asyncio.get_running_loop()

        while proc.poll() is None:
            try:
                # Read chunks in executor to keep loop non-blocking
                chunk = await loop.run_in_executor(None, proc.stdout.read, 8192)
                if not chunk:
                    await asyncio.sleep(0.1)
                    continue

                for packet in parser.parse_stream(chunk):
                    self.PacketCaptured(json.dumps(packet))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error("Error reading pcap stream: %s", e)
                break

    async def _read_proxy_stream(self, proc: Any) -> None:
        loop = asyncio.get_running_loop()

        while proc.poll() is None:
            try:
                line_bytes = await loop.run_in_executor(None, proc.stdout.readline)
                if not line_bytes:
                    await asyncio.sleep(0.1)
                    continue

                line = line_bytes.decode("utf-8").strip()
                if line.startswith("NETSENTINEL_MITM_JSON:"):
                    json_str = line.split("NETSENTINEL_MITM_JSON:", 1)[1]
                    # Direct notify client
                    self.RequestIntercepted(json_str)
                    # Register the payload id in main store index
                    try:
                        metadata = json.loads(json_str)
                        pid = metadata.get("payload_id")
                        if pid:
                            self.ram_store.active_ids.add(pid)
                    except Exception:  # nosec B110
                        pass
                elif line.startswith("NETSENTINEL_MITM_ERROR:"):
                    err = line.split("NETSENTINEL_MITM_ERROR:", 1)[1]
                    logging.error("mitmproxy error: %s", err)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error("Error reading proxy stream: %s", e)
                break


async def start_service(use_session_bus: bool) -> None:
    # Connect to the appropriate bus
    bus_type = "session" if use_session_bus else "system"
    logging.info("Connecting to D-Bus %s bus...", bus_type)

    try:
        if use_session_bus:
            bus = await MessageBus(bus_type=BusType.SESSION).connect()
        else:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    except Exception as e:
        logging.error("Failed to connect to %s bus: %s", bus_type, e)
        sys.exit(1)

    interface = NetSentinelHelperInterface()
    bus.export(OBJECT_PATH, interface)

    logging.info("Requesting name %s...", BUS_NAME)
    await bus.request_name(BUS_NAME)

    logging.info("Helper daemon is running successfully.")
    # Run forever
    await asyncio.get_running_loop().create_future()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="NetSentinel Privileged D-Bus Helper Daemon")
    parser.add_argument(
        "--session",
        action="store_true",
        help="Use user session bus instead of system bus (for local dev and testing)",
    )
    args = parser.parse_args()

    # If not running as root and --session is not passed, default to system bus
    # but print a warning that it might fail if system D-Bus rules are not installed.
    try:
        asyncio.run(start_service(args.session))
    except KeyboardInterrupt:
        logging.info("Daemon stopped by user.")
    except Exception as e:
        logging.critical("Daemon crashed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
