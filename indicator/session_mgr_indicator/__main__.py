"""session-mgr-indicator - an SNI tray icon for session-mgr's placement mode,
drawn in the same owned-glyph language as mux-indicator / comms-indicator (a
near-black rounded tile, frame colour = state) so the tray reads as one system.

It is a thin PRESENTER: the state machine lives in session-mgr, which publishes
{mode, seconds_left, arc} to STATUS_FILE each tick. This daemon reads that to
draw, and a left-click shells `session-mgr toggle` (steady <-> aggressive).
Nothing here duplicates the placement logic.

Three states by FRAME colour, one identity glyph (a 2x2 window grid, top-left
window focused):
  steady      green   -- windows stay where they are
  aggressive  amber   -- placing windows back; a depleting ring counts the
                         seconds until it settles (arc drains clockwise)
  down        grey    -- session-mgr not running (STATUS_FILE absent or stale)

Deps: dbus-next (pure-Python D-Bus) + Pillow. Drawn per size, ARGB32 in network
byte order per the StatusNotifierItem spec. `session-mgr-indicator render-test
DIR` dumps preview PNGs (dev aid, no D-Bus).
"""
import asyncio
import json
import math
import os
import sys
import time

from PIL import Image, ImageDraw

_BASE = (0x14, 0x15, 0x19)      # near-black screen
_TINT = 0.14                    # state hue bleed into the screen
# Border colour per state. Aggressive is a loud RED -- it wants the eye AND it
# must read distinct from the ORANGE gadgets beside it (mux, comms/dnd), so a
# clearly red (not amber/orange) hue; steady is a MUTED grey-green -- quiet, so
# the louder gadgets win the glance; down is neutral grey. _DULL is what the
# aggressive border leaves behind as it recedes: the "not working" grey.
FRAME = {
    "steady":     (0x54, 0x86, 0x50),   # muted green -- at rest, quiet
    "aggressive": (0xF2, 0x3A, 0x2C),   # red -- actively placing; stands out
    "down":       (0x84, 0x84, 0x8A),   # neutral grey -- daemon off
}
_DULL = FRAME["down"]                   # the receded (elapsed) border grey


def _lift(base, f):
    # A colour lifted toward white by fraction f (0 = base, 1 = white).
    return tuple(int(base[i] * (1 - f) + 0xFF * f) for i in range(3)) + (0xFF,)


# The window glyph is STATE-INDEPENDENT (identity mark): the frame carries the
# state, per the design. Windows are lifted off a neutral near-black, so they
# read identically on every state's (faintly tinted) screen.
_WIN = _lift(_BASE, 0.34)               # the three quiet windows
_WIN_HI = _lift(_BASE, 0.64)            # the focused (top-left) window


def _screen(state):
    col = FRAME.get(state, FRAME["down"])
    mix = tuple(int(_BASE[i] * (1 - _TINT) + col[i] * _TINT) for i in range(3))
    return mix + (0xFF,)


def _grid(d, s):
    # A 2x2 grid of window-rects; the top-left one is focused (brighter).
    g0, g1 = s * 0.28, s * 0.72         # glyph bounding box, inset from frame
    gap = s * 0.08
    cw = (g1 - g0 - gap) / 2
    rad = max(1, int(cw * 0.20))
    for cx, cy in ((0, 0), (1, 0), (0, 1), (1, 1)):
        x0 = g0 + cx * (cw + gap)
        y0 = g0 + cy * (cw + gap)
        fill = _WIN_HI if (cx, cy) == (0, 0) else _WIN
        d.rounded_rectangle([x0, y0, x0 + cw, y0 + cw], rad, fill=fill)


def _perimeter(m, side, r):
    # Points tracing the rounded-square border centreline, starting at the
    # UPPER-LEFT corner and walking COUNTER-CLOCKWISE (down the left edge
    # first), so a leading fraction can be drawn from that corner. Edges are
    # sampled too (not just endpoints) so the amber/grey boundary can land
    # mid-edge, not only at the corners.
    L, T, R, B = m, m, m + side, m + side
    pts = []

    def arc(cx, cy, a0, a1):
        n = max(2, int(abs(a1 - a0) / 12))
        for i in range(n + 1):
            a = math.radians(a0 + (a1 - a0) * i / n)
            pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))

    def edge(p0, p1):
        n = max(1, int(math.hypot(p1[0] - p0[0], p1[1] - p0[1]) / 3))
        for i in range(1, n + 1):
            pts.append((p0[0] + (p1[0] - p0[0]) * i / n,
                        p0[1] + (p1[1] - p0[1]) * i / n))

    arc(L + r, T + r, 225, 180)          # UL corner: apex -> left-edge top
    edge((L, T + r), (L, B - r))         # left edge, downward
    arc(L + r, B - r, 180, 90)           # LL corner
    edge((L + r, B), (R - r, B))         # bottom edge, rightward
    arc(R - r, B - r, 90, 0)             # LR corner
    edge((R, B - r), (R, T + r))         # right edge, upward
    arc(R - r, T + r, 360, 270)          # UR corner
    edge((R - r, T), (L + r, T))         # top edge, leftward
    arc(L + r, T + r, 270, 225)          # back to the UL apex
    return pts


def _border(img, s, arc_frac):
    # The border IS the cooldown bar: full amber at a kick, receding from the
    # upper-left corner counter-clockwise and leaving DULL grey behind. `arc` is
    # the fraction still amber; grey covers the elapsed (1-arc) from the start
    # point, amber holds the remainder up to the corner.
    fw = max(1, s // 11)
    inset = fw / 2.0
    pts = _perimeter(inset, s - 1 - fw, max(1.0, s // 7 - inset))
    cum = [0.0]
    for i in range(1, len(pts)):
        cum.append(cum[-1] + math.hypot(pts[i][0] - pts[i - 1][0],
                                        pts[i][1] - pts[i - 1][1]))
    total = cum[-1] or 1.0
    d = ImageDraw.Draw(img)
    d.line(pts, fill=_DULL + (0xFF,), width=fw, joint="curve")   # grey track
    a = max(0.0, min(1.0, arc_frac))
    if a <= 0:
        return
    thresh = (1.0 - a) * total
    amber = [p for p, c in zip(pts, cum) if c >= thresh]
    if len(amber) >= 2:
        d.line(amber, fill=FRAME["aggressive"] + (0xFF,), width=fw,
               joint="curve")


def _tile(state, arc, size):
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = max(2, s // 7)
    fw = max(1, s // 11)
    if state == "aggressive":
        d.rounded_rectangle([0, 0, s - 1, s - 1], r, fill=_screen(state))
        _border(img, s, arc)            # the border draws the cooldown itself
    else:
        frame = FRAME.get(state, FRAME["down"]) + (0xFF,)
        d.rounded_rectangle([0, 0, s - 1, s - 1], r,
                            fill=_screen(state), outline=frame, width=fw)
    _grid(d, s)                         # glyph on top
    return img


def _to_argb(img):
    rgba = img.tobytes("raw", "RGBA")
    out = bytearray(len(rgba))
    for i in range(0, len(rgba), 4):
        out[i] = rgba[i + 3]
        out[i + 1] = rgba[i]
        out[i + 2] = rgba[i + 1]
        out[i + 3] = rgba[i + 2]
    return bytes(out)


def icon_pixmap(state, arc, sizes=(22, 32, 48)):
    out = []
    for s in sizes:
        t = _tile(state, arc, s)
        # Match the sibling gadgets' bounding box so the tray places us level:
        # mux's badge reaches the top edge, so stamp one invisible (alpha=1)
        # pixel at the top-right corner (see comms-indicator for the rationale).
        t.putpixel((s - 1, 0), (0, 0, 0, 1))
        out.append([s, s, _to_argb(t)])
    return out


# --- state feed: read what session-mgr publishes; act via `session-mgr` -------
STATUS_FILE = os.path.join(
    os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "session-mgr.status")
SESSION_MGR = os.environ.get("SESSION_MGR", "session-mgr")   # resolved on PATH
_STALE = 5.0   # session-mgr writes every 1s; older than this => not running


def read_status():
    """(state, arc, seconds_left). 'down' when the file is absent or stale."""
    try:
        age = time.time() - os.stat(STATUS_FILE).st_mtime
        s = json.load(open(STATUS_FILE))
    except (OSError, ValueError):
        return ("down", 0.0, None)
    mode = s.get("mode")
    if age > _STALE or mode not in ("aggressive", "steady"):
        return ("down", 0.0, None)
    return (mode, float(s.get("arc", 0.0)), s.get("seconds_left"))


def _render_test(outdir):
    os.makedirs(outdir, exist_ok=True)
    rows = [("steady", 0.0), ("aggressive", 1.0), ("aggressive", 0.66),
            ("aggressive", 0.33), ("down", 0.0)]
    sizes = (22, 32, 48, 96)
    gap = 8
    w = sum(sizes) + gap * (len(sizes) + 1)
    h = len(rows) * (96 + gap) + gap
    sheet = Image.new("RGBA", (w, h), (30, 30, 34, 255))
    for r, (st, arc) in enumerate(rows):
        x = gap
        y = gap + r * (96 + gap)
        for z in sizes:
            off = (96 - z) // 2
            sheet.paste(_tile(st, arc, z), (x + off, y + off))
            x += z + gap
    p = os.path.join(outdir, "session-mgr-indicator.png")
    sheet.save(p)
    print(p)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "render-test":
        _render_test(sys.argv[2] if len(sys.argv) > 2 else "/tmp/smi-test")
        return
    asyncio.run(_run())


# --- SNI service (scaffolding mirrors comms-indicator) -----------------------
def _run():
    from dbus_next import BusType, PropertyAccess
    from dbus_next.aio import MessageBus
    from dbus_next.service import (ServiceInterface, dbus_property, method,
                                   signal)

    WATCHER = "org.kde.StatusNotifierWatcher"
    WATCHER_PATH = "/StatusNotifierWatcher"
    ITEM_PATH = "/StatusNotifierItem"

    def _tip(state, sec):
        if state == "aggressive":
            return (f"Window placement: AGGRESSIVE ({sec}s to steady)"
                    " -- click to settle now")
        if state == "steady":
            return "Window placement: STEADY -- click to kick aggressive"
        return "session-mgr not running"

    def _sig(state, arc):
        # Redraw signature: state + a coarse arc bucket, so the depleting ring
        # advances (~24 steps over the window) without a redraw every second.
        return (state, round(arc * 24))

    class Indicator(ServiceInterface):
        def __init__(self):
            super().__init__("org.kde.StatusNotifierItem")
            self._state, self._arc, self._sec = read_status()
            self._key = _sig(self._state, self._arc)
            self._pixmap = icon_pixmap(self._state, self._arc)

        def refresh(self):
            state, arc, sec = read_status()
            self._sec = sec
            key = _sig(state, arc)
            if key != self._key:
                self._state, self._arc, self._key = state, arc, key
                self._pixmap = icon_pixmap(state, arc)
                self.NewIcon()

        @dbus_property(access=PropertyAccess.READ)
        def Category(self) -> "s":
            return "ApplicationStatus"

        @dbus_property(access=PropertyAccess.READ)
        def Id(self) -> "s":
            return "session-mgr-indicator"

        @dbus_property(access=PropertyAccess.READ)
        def Title(self) -> "s":
            return "window placement"

        @dbus_property(access=PropertyAccess.READ)
        def Status(self) -> "s":
            return "Active"

        @dbus_property(access=PropertyAccess.READ)
        def IconName(self) -> "s":
            return ""

        @dbus_property(access=PropertyAccess.READ)
        def IconPixmap(self) -> "a(iiay)":
            return self._pixmap

        @dbus_property(access=PropertyAccess.READ)
        def OverlayIconName(self) -> "s":
            return ""

        @dbus_property(access=PropertyAccess.READ)
        def AttentionIconName(self) -> "s":
            return ""

        @dbus_property(access=PropertyAccess.READ)
        def AttentionIconPixmap(self) -> "a(iiay)":
            return self._pixmap

        @dbus_property(access=PropertyAccess.READ)
        def ToolTip(self) -> "(sa(iiay)ss)":
            return ["", [], "window placement", _tip(self._state, self._sec)]

        @dbus_property(access=PropertyAccess.READ)
        def ItemIsMenu(self) -> "b":
            return False

        @method()
        def Activate(self, x: "i", y: "i"):
            asyncio.get_event_loop().create_task(self._toggle())

        @method()
        def SecondaryActivate(self, x: "i", y: "i"):
            pass                        # middle-click reserved for future use

        @method()
        def Scroll(self, delta: "i", orientation: "s"):
            pass

        async def _toggle(self):
            try:
                p = await asyncio.create_subprocess_exec(
                    SESSION_MGR, "toggle",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL)
                await p.communicate()
            except OSError as e:
                print(f"session-mgr-indicator: toggle failed: {e}", flush=True)
            self.refresh()

        @signal()
        def NewIcon(self):
            pass

    async def watch(item):
        while True:
            item.refresh()
            await asyncio.sleep(1.0)

    async def go():
        bus = await MessageBus(bus_type=BusType.SESSION).connect()
        item = Indicator()
        bus.export(ITEM_PATH, item)
        name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        await bus.request_name(name)

        async def register():
            try:
                intro = await bus.introspect(WATCHER, WATCHER_PATH)
                obj = bus.get_proxy_object(WATCHER, WATCHER_PATH, intro)
                w = obj.get_interface(WATCHER)
                await w.call_register_status_notifier_item(name)
                print(f"session-mgr-indicator: registered {name}", flush=True)
            except Exception as e:
                msg = f"session-mgr-indicator: register failed: {e}"
                print(msg, flush=True)

        # (Re)register whenever the tray watcher (waybar) appears, so a
        # `wb restart` or a late-starting bar never leaves us invisible.
        di = await bus.introspect("org.freedesktop.DBus",
                                  "/org/freedesktop/DBus")
        dobj = bus.get_proxy_object("org.freedesktop.DBus",
                                    "/org/freedesktop/DBus", di)
        dbus = dobj.get_interface("org.freedesktop.DBus")

        def on_owner(n, old, new):
            if n == WATCHER and new:
                asyncio.get_event_loop().create_task(register())
        dbus.on_name_owner_changed(on_owner)

        try:
            owner = await dbus.call_get_name_owner(WATCHER)
        except Exception:
            owner = ""
        if owner:
            await register()
        else:
            print("session-mgr-indicator: waiting for the tray watcher",
                  flush=True)
        asyncio.create_task(watch(item))
        await asyncio.get_event_loop().create_future()

    return go()


if __name__ == "__main__":
    main()
