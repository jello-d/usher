"""Chrome: its session-file format, and the per-window identity read from it.

The DOMAIN KNOWLEDGE, kept apart from the engine that consumes it: how an SNSS
session file is framed, which file belongs to which profile, how a live window
title joins to a session window, and which of the fifty-odd chrome processes is
the browser. A LEAF -- it imports nothing from the rest of the package, so the
engine can import it at module level with no cycle.

The adapter that makes any of this reachable is ChromePlugin, which stays in
the engine beside the mux and kitty plugins: a plugin is the engine's view of
an app, and this module is the app.

WHY A WINDOW'S IDENTITY IS ITS SessionID. Chrome gives every browser window the
one app-id "google-chrome" and one pid (the browser process), so neither app-id
nor /proc can tell its windows apart -- the only per-window discriminator
wayfire exposes is the TITLE, the active tab's page title, which is volatile
(unread counts "Inbox (7)", tab switches, navigation). Keying on the title never
matched, so Chrome was never restored; keying on the active-tab URL matched, and
then dragged a window to another desktop whenever an old page was revisited, and
left 1053 store entries describing six windows. The durable handle is the
SessionID Chrome itself gives the window, which SURVIVES A RESTART (measured:
all six windows kept theirs through a --restore-last-session cycle). We read the
session file (read-only; no --remote-debugging-port, no new attack surface),
join a live window to its session window by the momentary page title (wayland
and SNSS reflect the same Chrome state at any instant), and key on the window
id. A window not yet in the session file falls back to its raw title, which is
the remaining path by which title-shaped spam can enter the store.
"""
import glob
import os
import shlex
import struct

CHROME_APPS = {"google-chrome", "chromium"}


def is_chrome(app):
    """Chrome/Chromium by app-id, case-INSENSITIVELY. A window that comes up
    through XWayland reports `Google-chrome` where the native Wayland one
    reports `google-chrome`, and BOTH turn up in a real store here. Matching
    only the lower-case form left the capitalised windows unclaimed by the
    plugin -- no URL identity, and invisible to the browser relaunch -- while
    is_browser() (a substring test) still treated them as browsers, so they got
    the settle delay and none of the benefit."""
    return (app or "").lower() in CHROME_APPS
# Seconds between starting one Chrome profile and the next. Long enough for the
# first invocation to become the browser process and open its singleton socket,
# which is what the second one needs to talk to.
CHROME_STAGGER = float(os.environ.get("SESSION_CHROME_STAGGER", 4))

# Flags usher adds when IT starts the browser. Starting the right profile is
# not enough on its own: Chrome only reopens the previous windows when the
# profile's "On startup" preference says to, and unset (the state of both
# profiles here) means the New Tab page. So usher got the profile right and
# Chrome opened a blank window.
#
#   --restore-last-session      reopen the last session regardless of that
#                               preference. This is the whole intent of the
#                               launch, and it applies ONLY to usher's own
#                               invocation, never to one started by hand.
#   --hide-crash-restore-bubble suppress "Chrome didn't shut down correctly.
#                               Restore?". A session that ends with the machine
#                               going down is recorded as exit_type=Crashed, so
#                               that bubble appears at every login, and having
#                               just ASKED for the restore we would be offering
#                               it a second time.
#
# Override with SESSION_CHROME_FLAGS (space separated), empty to pass none.
_CHROME_FLAGS_DEFAULT = "--restore-last-session --hide-crash-restore-bubble"
CHROME_FLAGS = shlex.split(
    os.environ.get("SESSION_CHROME_FLAGS", _CHROME_FLAGS_DEFAULT))
# Wayland titles Chrome sets are "<page title> - Google Chrome"; strip that
# browser suffix to recover the page title the session file stores.
CHROME_SUFFIXES = (" - Google Chrome", " - Chromium")

# SNSS command ids (Chromium components/sessions/core/session_service_commands
# .cc). Framing is fixed: int16 size, then a 1-byte id + payload of size-1; we
# always advance by size, so a payload we cannot decode never desyncs the
# stream. SetTabWindow/SetTabIndexInWindow/SetSelectedTabInWindow are raw int32
# structs; UpdateTabNavigation is a Pickle; SetSelectedNavigationIndex picks
# which of a tab's navigations is current; TabClosed/WindowClosed retire ids.
_SNSS_SET_TAB_WINDOW = 0
_SNSS_SET_TAB_INDEX = 2
_SNSS_UPDATE_TAB_NAV = 6
_SNSS_SET_SEL_NAV_INDEX = 7
_SNSS_SET_SEL_TAB_IN_WIN = 8
_SNSS_TAB_CLOSED = 16
_SNSS_WINDOW_CLOSED = 17


def _snss_i32(b, o):
    return struct.unpack_from("<i", b, o)[0], o + 4


def _snss_str(b, o):          # Pickle WriteString: int32 len, bytes, pad to 4
    n, o = _snss_i32(b, o)
    if n < 0 or o + n > len(b):
        raise ValueError("bad str")
    s = b[o:o + n]
    return s.decode("utf-8", "replace"), (o + n + 3) & ~3


def _snss_str16(b, o):        # WriteString16: int32 nchars, 2*nchars, pad to 4
    n, o = _snss_i32(b, o)
    if n < 0 or o + 2 * n > len(b):
        raise ValueError("bad str16")
    s = b[o:o + 2 * n]
    return s.decode("utf-16-le", "replace"), (o + 2 * n + 3) & ~3


def _snss_scan(path):
    """Walk one session file's records into raw tables, or None if it is not a
    session file. Split from parse_snss because the two halves fail differently:
    this one must survive a malformed record mid-stream, while resolving the
    tables afterwards is pure dict work that cannot."""
    d = open(path, "rb").read()
    if d[:4] != b"SNSS":
        return None
    off = 8                                     # skip magic + int32 version
    tab_win, tab_idx, win_sel, tab_nav = {}, {}, {}, {}
    nav, closed_tabs, closed_wins = {}, set(), set()
    while off + 2 <= len(d):
        (size,) = struct.unpack_from("<H", d, off)
        off += 2
        if size == 0 or off + size > len(d):
            break
        cid = d[off]
        p = d[off + 1:off + size]
        off += size
        try:
            if cid == _SNSS_SET_TAB_WINDOW:
                w, o = _snss_i32(p, 0)
                t, o = _snss_i32(p, o)
                tab_win[t] = w
            elif cid == _SNSS_SET_TAB_INDEX:
                t, o = _snss_i32(p, 0)
                i, o = _snss_i32(p, o)
                tab_idx[t] = i
            elif cid == _SNSS_SET_SEL_TAB_IN_WIN:
                w, o = _snss_i32(p, 0)
                i, o = _snss_i32(p, o)
                win_sel[w] = i
            elif cid == _SNSS_SET_SEL_NAV_INDEX:
                t, o = _snss_i32(p, 0)
                i, o = _snss_i32(p, o)
                tab_nav[t] = i
            elif cid == _SNSS_UPDATE_TAB_NAV:
                _sz, o = _snss_i32(p, 0)         # pickle payload-size header
                t, o = _snss_i32(p, o)
                idx, o = _snss_i32(p, o)
                url, o = _snss_str(p, o)
                title, o = _snss_str16(p, o)
                nav[(t, idx)] = (url, title)
            elif cid == _SNSS_TAB_CLOSED:
                t, o = _snss_i32(p, 0)
                closed_tabs.add(t)
            elif cid == _SNSS_WINDOW_CLOSED:
                w, o = _snss_i32(p, 0)
                closed_wins.add(w)
        except Exception:
            pass
    return tab_win, tab_idx, win_sel, tab_nav, nav, closed_tabs, closed_wins


def parse_snss(path):
    """Parse one SNSS session file into {active_page_title: (window_id, url)}
    for its open windows -- each window's selected tab, at that tab's current
    navigation. Never raises: a malformed record is skipped, a bad file
    yields {}.

    THE WINDOW ID IS THE POINT, and it was parsed and discarded here for a
    long time. Chrome's SessionID for a window is STABLE ACROSS A RESTART:
    measured on manifestor, all six windows kept their ids through a
    --restore-last-session cycle. So it is a durable per-window handle, which
    the active-tab URL is not: a URL changes every time you switch tab, which
    is how one browser accumulated 1053 store entries describing 73 places."""
    tabs = _snss_scan(path)
    if tabs is None:
        return {}
    tab_win, tab_idx, win_sel, tab_nav, nav, closed_tabs, closed_wins = tabs
    wins = {}
    for t, w in tab_win.items():
        if t in closed_tabs or w in closed_wins:
            continue
        wins.setdefault(w, []).append(t)
    out = {}
    for w, tabs_in_win in wins.items():
        sel = win_sel.get(w)
        active = next((t for t in tabs_in_win if tab_idx.get(t) == sel), None)
        if active is None:
            continue
        entry = nav.get((active, tab_nav.get(active)))
        if not entry:
            continue
        url, title = entry
        if title and url:
            out[title] = (w, url)
    return out


_snss_cache = {"sig": None, "map": {}}


def session_files():
    """Newest Session_* file per Chrome profile (browser windows only -- PWAs
    live in a separate Apps session and already carry stable app-ids)."""
    newest = {}
    for f in glob.glob(os.path.expanduser(
            "~/.config/google-chrome/*/Sessions/Session_*")):
        prof = os.path.dirname(os.path.dirname(f))
        try:
            mt = os.path.getmtime(f)
        except OSError:
            continue
        if prof not in newest or mt > newest[prof][1]:
            newest[prof] = (f, mt)
    return [v[0] for v in newest.values()]


def chrome_session_titles():
    """Merged {page_title: (window_id, raw_url)} across profiles' current
    sessions, cached and re-read only when a session file's mtime changes."""
    files = session_files()
    try:
        sig = tuple(sorted((f, os.path.getmtime(f)) for f in files))
    except OSError:
        sig = None
    if sig != _snss_cache["sig"]:
        merged = {}
        for f in files:
            try:
                merged.update(parse_snss(f))
            except Exception:
                pass
        _snss_cache["sig"] = sig
        _snss_cache["map"] = merged
    return _snss_cache["map"]


def _chrome_page_title(title):
    """The page title, with the browser-name suffix stripped."""
    for suf in CHROME_SUFFIXES:
        if title.endswith(suf):
            return title[:-len(suf)]
    return title


def chrome_window_for(title):
    """The SLOT of a live Chrome window titled `title`: `chrome:win:<id>`,
    joined through the session file on the ACTIVE TAB's page title.

    Keyed by the WINDOW, not by what it is displaying. Switching tab no longer
    makes a window a stranger, and revisiting a page seen weeks ago on another
    desktop no longer drags the window there, which the URL key did."""
    hit = chrome_session_titles().get(_chrome_page_title(title))
    return f"chrome:win:{hit[0]}" if hit else None


_BROWSER_EXES = {"chrome", "chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable"}


def is_browser_cmdline(raw):
    """True if this raw /proc/<pid>/cmdline is a BROWSER process: a browser
    executable with no `--type=` among its arguments. Everything else with the
    same name is a renderer, a gpu process or a zygote (55 of them against 1
    browser, measured), and signalling those achieves nothing useful.

    THERE ARE TWO FRAMINGS AND ONLY ONE IS THE DOCUMENTED ONE.
    /proc/<pid>/cmdline is meant to be NUL-SEPARATED, and for most processes it
    is. CHROME REWRITES ITS OWN ARGV AREA into a single space-joined string:
    measured 2026-09-29, 41 of 45 chrome processes on manifestor and 83 of 86
    on manifold carry ONE element, the browser among them. Splitting on NUL
    alone therefore produced a single "argv[0]" holding the entire command
    line, whose basename is never a browser name -- so this said False for
    every process on the box, browser_pids() returned [], and `wind-down`
    SIGNALLED NOTHING. That is the one thing wind-down exists to do.

    Treating NUL as whitespace reads both framings. Only two things are read
    here -- the first token, and whether any token is `--type=` -- so an
    argument that itself contains a space (`--profile-directory=Profile 2`)
    splitting into two tokens cannot affect the answer."""
    argv = raw.replace(b"\0", b" ").split()
    if not argv:
        return False
    exe = os.path.basename(argv[0].decode("utf-8", "replace"))
    return (exe in _BROWSER_EXES
            and not any(a.startswith(b"--type=") for a in argv))


def browser_pids():
    """Every live browser process, by is_browser_cmdline."""
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as f:
                raw = f.read()
        except OSError:
            continue
        if is_browser_cmdline(raw):
            out.append(int(d))
    return out


def chrome_profile_map():
    """normalized-URL -> the Chrome PROFILE DIRECTORY that has it open.

    Built from the same SNSS session files the chrome identity is read from, so
    it needs no new state: the profile is simply where each file LIVES
    (.../<Profile>/Sessions/Session_*). The files survive a restart, which is
    how Chrome restores itself, so this is answerable at login before Chrome
    has started."""
    out = {}
    for p in session_files():
        prof = os.path.basename(os.path.dirname(os.path.dirname(p)))
        try:
            found = parse_snss(p)
        except Exception:
            continue
        for win, _url in found.values():
            out.setdefault(f"chrome:win:{win}", prof)
    return out


def snss_build(window, tab, url, title, ver=3):
    """Build a minimal one-window/one-tab SNSS blob, for selftest's parser
    check -- the inverse of parse_snss (Pickle 4-byte alignment and all)."""
    def wi(x):
        return struct.pack("<i", x)

    def ws(s):
        b = s.encode("utf-8")
        return wi(len(b)) + b + b"\x00" * ((-len(b)) % 4)

    def ws16(s):
        b = s.encode("utf-16-le")
        return wi(len(s)) + b + b"\x00" * ((-len(b)) % 4)

    def cmd(cid, payload):
        body = bytes([cid]) + payload
        return struct.pack("<H", len(body)) + body

    pk = wi(tab) + wi(0) + ws(url) + ws16(title)
    return (b"SNSS" + wi(ver)
            + cmd(_SNSS_SET_TAB_WINDOW, wi(window) + wi(tab))
            + cmd(_SNSS_SET_TAB_INDEX, wi(tab) + wi(0))
            + cmd(_SNSS_SET_SEL_TAB_IN_WIN, wi(window) + wi(0))
            + cmd(_SNSS_SET_SEL_NAV_INDEX, wi(tab) + wi(0))
            + cmd(_SNSS_UPDATE_TAB_NAV, wi(len(pk)) + pk))
