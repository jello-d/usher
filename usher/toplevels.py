"""The compositor's toplevel list, read over ext_foreign_toplevel_list_v1.

WHY THIS EXISTS AT ALL, when usher already has the wayfire IPC: an enclave
account cannot reach that IPC, and NOTHING on this side can learn a window's
position by any other route.

THREE SEPARATE REASONS, and only the last is anybody's policy. Recorded
because an earlier version of this comment gave a WRONG one (it said the
security-context allowlist carries no IPC names, which is true and
irrelevant: that allowlist filters wayland GLOBALS, and wayfire's IPC is a
separate unix socket it never governed):

  1. NO WAYLAND PROTOCOL EXPOSES A WINDOW'S POSITION, not even to the
     window's own client. `xdg_toplevel.configure` carries width, height and
     states, and that is the whole of it. So the apps an account launched do
     not know where they are either; this is Wayland's design and not a
     restriction placed on anybody.
  2. THE COMPOSITOR IS THE ONLY THING THAT KNOWS, and the only way in is
     the wayfire IPC socket.
  3. THAT SOCKET SITS IN THE SESSION USER'S XDG_RUNTIME_DIR, mode 0700, so
     another account cannot traverse to it. The socket's OWN mode is 0775,
     so the directory is the entire gate: it must never be bind-mounted or
     linked into a shared location, because that IPC is full compositor
     control (79 methods here, including setting any config option, binding
     a key to a shell command, and listing every window's title).

SO THIS IS A ROSTER AND NEVER A LAYOUT. This protocol carries title, app_id
and identifier and NOTHING POSITIONAL (measured against the XML: seven
events, zero positional terms). An account on this side can therefore answer
"which of my apps are open" and can never answer "where". It could not ACT on
an answer either, since placement is the same socket behind the same gate, so
the owner doing all the placing is the only split available rather than a
workaround. That asymmetry is why the enclave verbs are their own verbs
rather than `save` and `restore` wearing a different hat.

AND WHY A HAND-WRITTEN CLIENT. There are no Wayland bindings on this fleet
(measured: no pywayland, no lswt, nothing in the venv but pywayfire), and the
alternative was joining /proc back to a desktop entry, which is ambiguous for
14 of 139 exe keys here INCLUDING google-chrome's, with no launch-time marker
to fall back on (0 of 89 graphical processes carry GIO_LAUNCHED_DESKTOP_FILE).
That would be guessing the key on a path that STARTS PROGRAMS as another
account, and a guessed key is the one thing this store refuses. The compositor
is the authority, so we ask it.

EVERY OPCODE HERE CAME OUT OF THE PROTOCOL XML, not out of memory: an opcode
is declaration order, so a wrong one does not fail, it decodes a different
event's arguments and reports plausible nonsense. `test/tools.t` re-derives
them from the installed XMLs and fails if they drift.

A READ, AND NOTHING BUT. This module sends get_registry, bind and sync, and no
request that can change anything. It cannot move, resize, focus or close a
window, because the protocol has no such request to send.
"""
import os
import glob
import socket
import struct
import time

PROTOCOL = "ext_foreign_toplevel_list_v1"
PROTOCOL_VERSION = 1

# Wire constants, all from /usr/share/wayland/wayland.xml and
# ext-foreign-toplevel-list-v1.xml. Named rather than inlined so the check
# that re-derives them has something to compare against.
WL_DISPLAY = 1
RQ_SYNC, RQ_GET_REGISTRY = 0, 1
EV_ERROR, EV_DELETE_ID = 0, 1
RQ_BIND = 0
EV_GLOBAL, EV_GLOBAL_REMOVE = 0, 1
EV_CALLBACK_DONE = 0
EV_LIST_TOPLEVEL, EV_LIST_FINISHED = 0, 1
EV_H_CLOSED, EV_H_DONE = 0, 1
EV_H_TITLE, EV_H_APP_ID, EV_H_IDENTIFIER = 2, 3, 4

# BOUNDED, because this talks to something outside the process. A compositor
# that never stops talking must not be able to hold the caller or grow it.
MAX_TOPLEVELS = 512
MAX_BUFFER = 1 << 20
TIMEOUT = 2.0


class ProtocolError(Exception):
    """The conversation could not be completed. Carries the reason verbatim,
    because every caller reports it rather than branching on it."""


def standard_runtime_dir(euid=None):
    """The runtime directory the spec defines for a uid.

    PURE AND INJECTABLE, so the rule can be pinned without the answer
    depending on which box the suite runs on. A check that reads real system
    state is a check on the host, which has passed for the wrong reason three
    times in this tree already.
    """
    return f"/run/user/{os.geteuid() if euid is None else euid}"


def wayland_socket(env=None):
    """(path, why) for THIS process's own display socket.

    MIRRORS `pick_socket`'S RULES ON PURPOSE, including refusing on two
    candidates rather than picking one: a stale socket from a previous session
    would answer, with somebody else's windows, which is worse than an error.

    AN ABSOLUTE `WAYLAND_DISPLAY` IS HONOURED, which libwayland also accepts
    and which the nested rigs here rely on, because it is the one form that
    does not depend on XDG_RUNTIME_DIR agreeing.
    """
    e = os.environ if env is None else env
    name = e.get("WAYLAND_DISPLAY") or ""
    run = e.get("XDG_RUNTIME_DIR") or ""
    if name.startswith("/"):
        if os.path.exists(name):
            return name, ""
        return "", f"WAYLAND_DISPLAY names {name}, which does not exist"
    if name:
        if not run:
            return "", (f"WAYLAND_DISPLAY is {name} and XDG_RUNTIME_DIR is "
                        "unset, so the socket cannot be resolved")
        path = os.path.join(run, name)
        if os.path.exists(path):
            return path, ""
        return "", f"no wayland socket at {path}"
    if not run:
        # THE STANDARD LOCATION, because `sudo` clears XDG_RUNTIME_DIR and
        # these verbs are reached through one. This is the path the spec
        # defines and the only one that can be derived rather than told, so it
        # is a derivation and NOT a guess about any particular session's
        # layout. An account whose socket lives elsewhere gets the refusal
        # below, naming where this looked, which is the answer a reader can
        # act on.
        run = standard_runtime_dir()
        if not os.path.isdir(run):
            return "", ("neither WAYLAND_DISPLAY nor XDG_RUNTIME_DIR is set, "
                        f"and there is no {run} to look in")
    found = sorted(p for p in glob.glob(os.path.join(run, "wayland-*"))
                   if not p.endswith(".lock"))
    if len(found) == 1:
        return found[0], ""
    if not found:
        return "", (f"WAYLAND_DISPLAY is unset and no wayland socket is in "
                    f"{run}")
    return "", (f"WAYLAND_DISPLAY is unset and {len(found)} wayland sockets "
                f"are in {run}, so which session is meant is ambiguous: "
                + ", ".join(os.path.basename(p) for p in found))


def _send(sk, obj, opcode, body=b""):
    """One request. The header is the object id then size<<16 | opcode."""
    size = 8 + len(body)
    sk.sendall(struct.pack("<II", obj, (size << 16) | opcode) + body)


def _string(s):
    """A wire string: length INCLUDING the NUL, the bytes, then 4-byte pad."""
    b = s.encode("utf-8") + b"\0"
    return struct.pack("<I", len(b)) + b + b"\0" * (-len(b) % 4)


def _read_string(body, off):
    """(text, next offset). An empty string is length 0 and no bytes."""
    (n,) = struct.unpack_from("<I", body, off)
    off += 4
    if n == 0:
        return "", off
    if off + n > len(body):
        raise ProtocolError("the compositor sent a truncated string")
    return (body[off:off + n - 1].decode("utf-8", "replace"),
            off + n + (-n % 4))


class _Reader:
    """Message framing over the stream. No ancillary data is requested, which
    is safe here because none of the bound interfaces passes a file
    descriptor; an unread fd would be dropped and the byte stream stays
    intact either way."""

    def __init__(self, sk):
        self.sk = sk
        self.buf = b""

    def message(self, deadline):
        """(object, opcode, body), or raise on timeout or disconnect."""
        while True:
            if len(self.buf) >= 8:
                obj, hi = struct.unpack_from("<II", self.buf, 0)
                size, opcode = hi >> 16, hi & 0xFFFF
                if size < 8:
                    raise ProtocolError(
                        f"the compositor sent a {size}-byte message header")
                if len(self.buf) >= size:
                    body, self.buf = self.buf[8:size], self.buf[size:]
                    return obj, opcode, body
            left = deadline - time.monotonic()
            if left <= 0:
                raise ProtocolError(
                    "the compositor did not finish answering in time")
            self.sk.settimeout(left)
            try:
                chunk = self.sk.recv(65536)
            except socket.timeout:
                raise ProtocolError(
                    "the compositor did not finish answering in time") \
                    from None
            if not chunk:
                raise ProtocolError("the compositor closed the connection")
            self.buf += chunk
            if len(self.buf) > MAX_BUFFER:
                raise ProtocolError("the compositor sent more than this reads")


def _roundtrip(sk, rd, ids, deadline, on_event):
    """Issue wl_display.sync and dispatch until ITS done comes back.

    THE SYNC IS THE ONLY HONEST "THAT IS ALL". Requests are processed in
    order, so every event the preceding request generated is queued ahead of
    this callback's done; there is no initial-state marker on the list
    interface itself to wait for instead.
    """
    cb = ids[0]
    ids[0] += 1
    _send(sk, WL_DISPLAY, RQ_SYNC, struct.pack("<I", cb))
    while True:
        obj, opcode, body = rd.message(deadline)
        if obj == WL_DISPLAY and opcode == EV_ERROR:
            oid, code = struct.unpack_from("<II", body, 0)
            msg, _ = _read_string(body, 8)
            raise ProtocolError(f"the compositor refused: {msg} "
                                f"(object {oid}, code {code})")
        if obj == cb and opcode == EV_CALLBACK_DONE:
            return
        on_event(obj, opcode, body)


def _find_protocol(sk, rd, ids, deadline):
    """(registry object, {}) or (registry object, {name, version}).

    The registry comes back because the caller has to send `bind` to it. The
    dict is EMPTY when this compositor does not advertise PROTOCOL, which the
    caller reports rather than treating as zero windows.
    """
    reg = ids[0]
    ids[0] += 1
    _send(sk, WL_DISPLAY, RQ_GET_REGISTRY, struct.pack("<I", reg))
    seen = {}

    def on_event(obj, opcode, body):
        if obj != reg or opcode != EV_GLOBAL:
            return
        (name,) = struct.unpack_from("<I", body, 0)
        iface, off = _read_string(body, 4)
        (version,) = struct.unpack_from("<I", body, off)
        if iface == PROTOCOL:
            seen["name"], seen["version"] = name, version

    _roundtrip(sk, rd, ids, deadline, on_event)
    return reg, seen


def _collect(sk, rd, ids, reg, found, deadline):
    """Bind the list and read every toplevel the compositor shows us."""
    lst = ids[0]
    ids[0] += 1
    version = min(int(found["version"]), PROTOCOL_VERSION)
    _send(sk, reg, RQ_BIND,
          struct.pack("<I", found["name"]) + _string(PROTOCOL)
          + struct.pack("<II", version, lst))
    rows = {}

    def on_event(obj, opcode, body):
        if obj == lst and opcode == EV_LIST_TOPLEVEL:
            (handle,) = struct.unpack_from("<I", body, 0)
            if len(rows) < MAX_TOPLEVELS:
                rows[handle] = {"app_id": "", "title": "",
                                "identifier": "", "done": False}
            return
        row = rows.get(obj)
        if row is None:
            return
        if opcode == EV_H_TITLE:
            row["title"] = _read_string(body, 0)[0]
        elif opcode == EV_H_APP_ID:
            row["app_id"] = _read_string(body, 0)[0]
        elif opcode == EV_H_IDENTIFIER:
            row["identifier"] = _read_string(body, 0)[0]
        elif opcode == EV_H_DONE:
            row["done"] = True
        elif opcode == EV_H_CLOSED:
            rows.pop(obj, None)

    _roundtrip(sk, rd, ids, deadline, on_event)
    # ONLY A TOPLEVEL THAT SAW `done`, which is the protocol's own statement
    # that the handle's state is complete. A half-described window would be
    # an app-id of "" and that is exactly the wildcard key this store bans.
    return [{k: r[k] for k in ("app_id", "title", "identifier")}
            for r in rows.values() if r["done"]]


def list_toplevels(path=None, timeout=TIMEOUT, env=None):
    """(rows, why): every toplevel the compositor will show this client.

    A row is {app_id, title, identifier}; there is no geometry to report.

    THREE STATES AND NOT TWO, which this tree has shipped collapsed twice:
    an EMPTY list with why == "" is a real answer (a session with nothing
    open), and any failure is why != "" with rows empty. A caller must not
    read "no windows" as "could not look".
    """
    if path is None:
        path, why = wayland_socket(env)
        if why:
            return [], why
    try:
        sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as e:
        return [], f"cannot open a unix socket: {e}"
    try:
        try:
            sk.connect(path)
        except OSError as e:
            return [], f"cannot reach the wayland display at {path}: {e}"
        rd = _Reader(sk)
        ids = [2]
        deadline = time.monotonic() + timeout
        reg, found = _find_protocol(sk, rd, ids, deadline)
        if "name" not in found:
            return [], (f"the compositor does not offer {PROTOCOL}, so this "
                        "account cannot be told which windows are its own")
        return _collect(sk, rd, ids, reg, found, deadline), ""
    except ProtocolError as e:
        return [], str(e)
    except (OSError, struct.error) as e:
        return [], f"the wayland conversation failed: {e}"
    finally:
        sk.close()
