import json
import logging
from typing import Any

from gi.repository import Gio, GLib


class NetSentinelController:
    def __init__(self, app_window: Any) -> None:
        self.app = app_window
        self.proxy: Any = None
        self._init_dbus()

    def _init_dbus(self) -> None:
        try:
            self.proxy = Gio.DBusProxy.new_for_bus_sync(
                Gio.BusType.SYSTEM,
                Gio.DBusProxyFlags.NONE,
                None,
                "org.netsentinel.Helper1",
                "/org/netsentinel/Helper1",
                "org.netsentinel.Helper1",
                None,
            )
            # Connect to D-Bus signals emitted by Helper1
            self.proxy.connect("g-signal", self._on_dbus_signal)
            logging.info("Connected to NetSentinel DBus Helper")
        except Exception as e:
            logging.error("Failed to connect to DBus Helper: %s", e)

    def _on_dbus_signal(
        self, _proxy: Any, _sender_name: str, signal_name: str, parameters: Any
    ) -> None:
        if signal_name == "PacketCaptured":
            metadata = parameters.unpack()[0]
            GLib.idle_add(self.app.view_traffic.handle_packet_metadata, metadata)
        elif signal_name == "RequestIntercepted":
            metadata = parameters.unpack()[0]
            GLib.idle_add(self.app.view_interceptor.handle_request_intercepted, metadata)

    def start_capture(self, interface: str, bpf_filter: str) -> None:
        if not self.proxy:
            logging.error("DBus proxy not initialized")
            return

        def _call_done(obj: Any, result: Any) -> None:
            try:
                res = obj.call_finish(result)
                logging.info("StartCapture result: %s", res)
            except Exception as e:
                logging.error("StartCapture error: %s", e)

        self.proxy.call(
            "StartCapture",
            GLib.Variant("(ss)", (interface, bpf_filter)),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            _call_done,
        )

    def stop_capture(self) -> None:
        if not self.proxy:
            return

        def _call_done(obj: Any, result: Any) -> None:
            try:
                obj.call_finish(result)
            except Exception as e:
                logging.error("StopCapture error: %s", e)

        self.proxy.call(
            "StopCapture",
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            _call_done,
        )

    def start_arp_scan(self, interface: str) -> None:
        if not self.proxy:
            return

        def _call_done(obj: Any, result: Any) -> None:
            try:
                res = obj.call_finish(result)
                json_str = res.unpack()[0]
                data = json.loads(json_str)
                if data.get("success"):
                    GLib.idle_add(self.app.view_netmap.set_hosts, data.get("hosts", []))
                else:
                    logging.error("ArpScan failed: %s", data.get("error"))
            except Exception as e:
                logging.error("ArpScan error: %s", e)

        self.proxy.call(
            "ArpScan",
            GLib.Variant("(s)", (interface,)),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            _call_done,
        )

    def start_mitm(self, interface: str, target: str, gateway: str, port: int) -> None:
        if not self.proxy:
            return

        def _spoof_done(obj: Any, result: Any) -> None:
            try:
                res = obj.call_finish(result)
                logging.info("ArpSpoof started: %s", res)

                # Start proxy after spoof
                self.proxy.call(
                    "StartProxy",
                    GLib.Variant("(i)", (port,)),
                    Gio.DBusCallFlags.NONE,
                    -1,
                    None,
                    None,
                )
            except Exception as e:
                logging.error("StartArpSpoof error: %s", e)

        self.proxy.call(
            "StartArpSpoof",
            GLib.Variant("(sss)", (interface, target, gateway)),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            _spoof_done,
        )

    def stop_mitm(self) -> None:
        if not self.proxy:
            return

        self.proxy.call("StopArpSpoof", None, Gio.DBusCallFlags.NONE, -1, None, None)
        self.proxy.call("StopProxy", None, Gio.DBusCallFlags.NONE, -1, None, None)
