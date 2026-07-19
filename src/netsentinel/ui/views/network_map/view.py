import math
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402


class NetworkMapView(Adw.NavigationPage):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelNetworkMapView"

    def __init__(self, **kwargs: object):
        super().__init__(title="Network Map", **kwargs)
        self.hosts = []  # type: list[dict[str, str]]

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        self.set_child(box)

        # Drawing area for the map
        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_hexpand(True)
        self.drawing_area.set_vexpand(True)
        self.drawing_area.set_draw_func(self._draw_map)
        box.append(self.drawing_area)

    def set_hosts(self, hosts: list[dict[str, str]]) -> None:
        """
        Updates the hosts list and queues redraw.
        """
        self.hosts = hosts
        self.drawing_area.queue_draw()

    def _draw_map(
        self, _area: Gtk.DrawingArea, cr: object, width: int, height: int, _data: object
    ) -> None:
        # cr is a cairo.Context. In Python type hints, it's passed as object.
        # Since cairo is dynamically loaded, we access its draw methods directly.
        # Let's perform a simple node layout: circular distribution of hosts around a center node.

        # 1. Clear background (clean dark/light neutral)
        # Using basic type casting on cairo context methods
        ctx: Any = cr
        ctx.set_source_rgb(0.95, 0.95, 0.95)
        ctx.paint()

        if not self.hosts:
            # Draw placeholder message
            ctx.set_source_rgb(0.5, 0.5, 0.5)
            ctx.select_font_face("Sans", 0, 0)
            ctx.set_font_size(16)
            ctx.move_to(width / 2 - 100, height / 2)
            ctx.show_text("No active hosts discovered in session.")
            return

        # 2. Draw Gateway (Center)
        cx = width / 2.0
        cy = height / 2.0
        ctx.set_source_rgb(0.2, 0.4, 0.8)  # Accent color
        ctx.arc(cx, cy, 25, 0, 2 * math.pi)
        ctx.fill()

        ctx.set_source_rgb(1.0, 1.0, 1.0)
        ctx.select_font_face("Sans", 1, 0)
        ctx.set_font_size(10)
        ctx.move_to(cx - 20, cy + 4)
        ctx.show_text("Gateway")

        # 3. Draw Discovered Hosts
        num_hosts = len(self.hosts)
        radius = min(width, height) / 3.0

        for i, host in enumerate(self.hosts):
            angle = (2 * math.pi * i) / num_hosts
            hx = cx + radius * math.cos(angle)
            hy = cy + radius * math.sin(angle)

            # Draw connection line
            ctx.set_source_rgb(0.7, 0.7, 0.7)
            ctx.set_line_width(1.5)
            ctx.move_to(cx, cy)
            ctx.line_to(hx, hy)
            ctx.stroke()

            # Draw host circle
            ctx.set_source_rgb(0.1, 0.7, 0.3)  # Green for active
            ctx.arc(hx, hy, 18, 0, 2 * math.pi)
            ctx.fill()

            # Text Labels
            ctx.set_source_rgb(0.0, 0.0, 0.0)
            ctx.select_font_face("Sans", 0, 0)
            ctx.set_font_size(11)
            ctx.move_to(hx - 30, hy + 30)
            ctx.show_text(host.get("ip", "Unknown"))
