"""Chrome: its session-file format, and the per-window identity read from it.

The DOMAIN KNOWLEDGE, kept apart from the engine that consumes it: how an SNSS
session file is framed, which file belongs to which profile, how a live window
title joins to a session window, and which of the fifty-odd chrome processes is
the browser. A LEAF: it imports nothing from the rest of the package, so the
engine can import it at module level with no cycle.

The adapter that makes any of this reachable is ChromePlugin, which stays in
the engine beside the mux and kitty plugins: a plugin is the engine's view of
an app, and this module is the app.

WHY A WINDOW'S IDENTITY IS ITS SessionID. Chrome gives every browser window the
one app-id "google-chrome" and one pid (the browser process), so neither app-id
nor /proc can tell its windows apart: the only per-window discriminator
wayfire exposes is the TITLE, the active tab's page title, which is volatile
(unread counts "Inbox (7)", tab switches, navigation). Keying on the title never
matched, so Chrome was never restored; keying on the active-tab URL matched, and
then dragged a window to another desktop whenever an old page was revisited, and
left 1053 store entries describing six windows. The handle that works is the
SessionID Chrome itself gives the window. We read the session file (read-only;
no --remote-debugging-port, no new attack surface), join a live window to its
session window by the momentary page title (wayland and SNSS reflect the same
Chrome state at any instant), and key on the window id.

IT DOES NOT SURVIVE A RESTART, which an earlier version of this comment claimed
on the strength of one observation. It is a monotonic per-session counter:
every restore mints a fresh block, measured twice on both the clean-exit and
the crash path. chrome_bind_windows is what carries a window across that
boundary, and the id is durable for exactly as long as the browser runs, which
is all identity needs it to be.

A window not yet in the session file has NO identity here: chrome_window_for
returns None and usher declines to remember it at all, rather than falling back
to the raw title it happens to be wearing. That fallback was 86% of a real
store, none of it matchable.
"""
import glob
import os
import re
import shlex
import struct

# THE SLOT KEY, built and recognised in ONE place. Two sites used to spell it
# out (the identity that writes it and the migration that validates it): and
# a store whose writer and checker disagree about a key shape is how this
# codebase has lost placements before. Change the shape here and both follow.
_CHROME_SLOT = "chrome:win:"
_CHROME_SLOT_RE = re.compile(r"^chrome:win:\d+$")


def chrome_slot(win):
    """The kb key for Chrome window id `win`."""
    return f"{_CHROME_SLOT}{win}"


def is_chrome_slot(key):
    """True if `key` is a well-formed Chrome window slot, i.e. one the
    current code could have written. A stored chrome key that is NOT one is a
    raw window title, left over from the identity fallback that no longer
    exists."""
    return bool(_CHROME_SLOT_RE.match(key or ""))


CHROME_APPS = {"google-chrome", "chromium"}


def is_chrome(app):
    """Chrome/Chromium by app-id, case-INSENSITIVELY. A window that comes up
    through XWayland reports `Google-chrome` where the native Wayland one
    reports `google-chrome`, and BOTH turn up in a real store here. Matching
    only the lower-case form left the capitalised windows unclaimed by the
    plugin (no URL identity, and invisible to the browser relaunch) while
    is_browser() (a substring test) still treated them as browsers, so they got
    the settle delay and none of the benefit."""
    return (app or "").lower() in CHROME_APPS


# Seconds between starting one Chrome profile and the next. Long enough for the
# first invocation to become the browser process and open its singleton socket,
# which is what the second one needs to talk to.
CHROME_STAGGER = float(os.environ.get("USHER_CHROME_STAGGER", 4))

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
# Override with USHER_CHROME_FLAGS (space separated), empty to pass none.
_CHROME_FLAGS_DEFAULT = "--restore-last-session --hide-crash-restore-bubble"
CHROME_FLAGS = shlex.split(
    os.environ.get("USHER_CHROME_FLAGS", _CHROME_FLAGS_DEFAULT))
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
    for its open windows: each window's selected tab, at that tab's current
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
    out, ambiguous = {}, set()
    for w, tabs_in_win in wins.items():
        sel = win_sel.get(w)
        active = next((t for t in tabs_in_win if tab_idx.get(t) == sel), None)
        if active is None:
            continue
        entry = nav.get((active, tab_nav.get(active)))
        if not entry:
            continue
        url, title = entry
        if not (title and url):
            continue
        # A TITLE TWO WINDOWS SHARE IS NOT A DISCRIMINATOR, and silently
        # letting the last one win would hand both live windows the same slot.
        # Two "New Tab" windows is all it takes. The same rule learn() applies
        # to its title groups, for the same reason; refusing to answer is the
        # only safe answer, and it matters more now that window_slot REMEMBERS
        # what it resolved.
        if title in out and out[title][0] != w:
            ambiguous.add(title)
        out[title] = (w, url)
    for title in ambiguous:
        del out[title]
    return out


_snss_cache = {"sig": None, "map": {}}


def session_history():
    """{profile dir: [Session_* file, ...]}, NEWEST FIRST, per Chrome profile.

    Browser windows only: PWAs live in a separate Apps session and already
    carry stable app-ids.

    THE OLDER FILES ARE THE POINT. Chrome keeps the PREVIOUS session's file
    beside the new one when it rotates, and that is the only reason a window
    can be followed across a restart at all: the new file says what the
    windows are now, the old one says what they were, and the tabs join them.
    See chrome_bind_windows."""
    byprof = {}
    for f in glob.glob(os.path.expanduser(
            "~/.config/google-chrome/*/Sessions/Session_*")):
        prof = os.path.dirname(os.path.dirname(f))
        try:
            mt = os.path.getmtime(f)
        except OSError:
            continue
        byprof.setdefault(prof, []).append((mt, f))
    return {p: [f for _mt, f in sorted(v, reverse=True)]
            for p, v in byprof.items()}


def browser_started():
    """When the running browser began, as a unix time, or None if none is
    running or /proc cannot be read.

    THE EARLIEST of several, which is the conservative direction: the answer
    is used to DISCARD session files, so an earlier one discards fewer."""
    try:
        hz = os.sysconf("SC_CLK_TCK")
        btime = 0
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    btime = int(line.split()[1])
                    break
    except (OSError, ValueError):
        return None
    if not btime:
        return None
    out = []
    for p in browser_pids():
        try:
            with open(f"/proc/{p}/stat") as f:
                st = f.read()
            # comm can hold spaces and parens, so the fields start after the
            # LAST ')'. starttime is field 22, i.e. index 19 from there.
            out.append(btime + int(st[st.rindex(")") + 2:].split()[19]) / hz)
        except (OSError, ValueError, IndexError):
            continue
    return min(out) if out else None


def session_files():
    """The CURRENT session file per Chrome profile: what the windows are now.

    A FILE UNTOUCHED SINCE BEFORE THE BROWSER STARTED IS DROPPED, and the
    argument is a certainty rather than a heuristic: if this browser run has
    not written the file, nothing in it was written by this run, so its window
    ids belong to a previous one whether or not the profile is loaded.

    WHY IT MATTERS: a profile Chrome has not opened this run still has a
    newest session file, so it contributed phantom windows to the live id set.
    Measured on manifestor 2026-10-09, where Profile 4's month-old file put a
    dead Gmail window in the set, which left claim_by_elimination with two
    free ids for one unresolved view and made it (correctly) refuse. One real
    window went unplaceable for want of excluding a window that did not exist.

    UNFILTERED WHEN NO BROWSER IS RUNNING, which is not a special case so much
    as the same rule with nothing to compare against: every file is then the
    record of the last run, and that is exactly what the login path wants."""
    started = browser_started()
    out = []
    for files in session_history().values():
        if started is not None:
            try:
                if os.path.getmtime(files[0]) < started:
                    continue
            except OSError:
                pass                    # unreadable: keep the old behaviour
        out.append(files[0])
    return out


def session_sig():
    """A cheap signature of the current session files: paths and mtimes, no
    parsing. It changes exactly when Chrome writes one, and the PATHS change
    when it rotates them, which is the moment a restart becomes visible to us.
    One definition, used both to invalidate the title cache and to trigger the
    re-key."""
    try:
        return tuple(sorted((f, os.path.getmtime(f))
                            for f in session_files()))
    except OSError:
        return None


def chrome_session_titles():
    """Merged {page_title: (window_id, raw_url)} across profiles' current
    sessions, cached and re-read only when a session file's mtime changes."""
    files = session_files()
    sig = session_sig()
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
    return chrome_slot(hit[0]) if hit else None


# wayfire view id -> the slot we resolved for it, for the LIFE of that view.
_slot_cache = {}


def window_slot(vid, title):
    """The slot for a LIVE window: resolved ONCE from the title, then
    remembered for as long as the window exists.

    THE TITLE IS A BOOTSTRAP, NOT AN IDENTITY. Of everything wayfire reports
    about a view, the only field that distinguishes two Chrome windows AND
    that Chrome also knows about is the title (app-id and pid are shared,
    geometry is ours to change), so the first join has to go through it.
    RESOLVING ON EVERY LOOKUP WOULD MAKE IDENTITY AS VOLATILE AS THE STRING: a
    Gmail window is `Inbox (1)` in the session file and `Inbox (2)` on screen
    the moment mail arrives, which makes it flicker between known and stranger
    for its whole life.

    A Chrome window's SessionID is fixed for as long as the browser runs, and
    a wayfire view is one Chrome window for its whole life, so the answer
    cannot go stale while the view exists. Cached only on SUCCESS, so a window
    Chrome has not recorded yet is retried until it is.

    Pass vid=None (a stored entry, which has no live view) to get the plain
    lookup with no caching."""
    if vid is None:
        return chrome_window_for(title)
    hit = _slot_cache.get(vid)
    if hit:
        return hit
    hit = chrome_window_for(title)
    if hit:
        _slot_cache[vid] = hit
    return hit


def claim_by_elimination(views):
    """Resolve the ONE view an exact title match cannot, when the id SET
    forces the answer. `views` is [(vid, raw_title)] for every live Chrome
    view. Returns the vid it claimed, or None.

    THE TITLE'S CONTENT IS NOT RELIABLE, which is why this exists. Chrome
    records a tab's title at NAVIGATION time, so a web app that rewrites
    document.title without navigating leaves the session file holding the old
    one indefinitely: measured on manifold, a window read "Google Messages for
    web: Conversations" on screen and "Google Messages for web" in a session
    file rewritten SECONDS earlier, and the two disagreed for two and a half
    hours across many rewrites. Reading the file more often cannot fix that,
    because it is stale by design rather than by lag.

    SO DECIDE BY THE ID SET. Every window Chrome recorded has an id and every
    live view is one of them, so match what the titles DO resolve and look at
    what is left: if exactly one view and exactly one id remain, the pairing
    is FORCED. There is nothing else either could be, which makes this exact
    rather than a guess, and it never compares title content.

    IT REFUSES ON ANY OTHER COUNT, and that is the whole safety argument. Two
    unmatched views against two free ids could pair either way. An INCOGNITO
    window is a live view Chrome never records at all, so it leaves one more
    view than id and this declines, which is the same answer usher gives
    today. Declining costs a placement; pairing wrongly moves someone else's
    window.

    Writes the SAME cache window_slot reads, so the claim is remembered for
    the view's life and dropped by forget_window on unmap."""
    t = chrome_session_titles()
    claimed, unmatched = set(), []
    for vid, raw in views:
        hit = t.get(_chrome_page_title(raw))
        if hit:
            claimed.add(str(hit[0]))
        elif vid is not None and vid not in _slot_cache:
            unmatched.append(vid)
    free = sorted({str(w) for _ti, (w, _u) in t.items()
                   if str(w) not in claimed})
    if len(unmatched) == 1 and len(free) == 1:
        _slot_cache[unmatched[0]] = chrome_slot(free[0])
        return unmatched[0]
    return None


def forget_window(vid):
    """Drop a closed view's cached slot. Wayfire ids are not reused quickly,
    but a cache that only ever grows is a leak in a process that runs for
    weeks."""
    _slot_cache.pop(vid, None)


def chrome_window_tabs(path):
    """{window id: frozenset of the URL each of its open tabs is showing}, for
    one session file. Never raises; a bad file yields {}.

    parse_snss keeps only the ACTIVE tab, which is all an identity needs. This
    keeps the WHOLE SET, because it answers a different question: which window
    in the new session is the one that used to be that window in the old? One
    URL per side is far too thin to decide that; the full tab set is a
    fingerprint.

    A tab's URL is the navigation it has SELECTED. If that record is missing
    (a half-written file, a tab mid-navigation) fall back to its highest
    recorded navigation rather than dropping the tab, since a fingerprint with
    a hole in it still matches and a missing tab weakens it."""
    tabs = _snss_scan(path)
    if tabs is None:
        return {}
    tab_win, tab_idx, win_sel, tab_nav, nav, closed_tabs, closed_wins = tabs
    newest = {}
    for (t, idx), (url, _title) in nav.items():
        if t not in newest or idx > newest[t][0]:
            newest[t] = (idx, url)
    out = {}
    for t, w in tab_win.items():
        if t in closed_tabs or w in closed_wins:
            continue
        entry = nav.get((t, tab_nav.get(t)))
        url = entry[0] if entry else (newest.get(t) or (0, None))[1]
        if url:
            out.setdefault(w, set()).add(url)
    return {w: frozenset(u) for w, u in out.items()}


def chrome_bind_windows(cur, prev):
    """Bind PREVIOUS window ids to the CURRENT ones that restored them, by the
    tabs they have in common: {old id: new id}. Both arguments are
    chrome_window_tabs output.

    WHY THIS HAS TO EXIST. Chrome mints FRESH SessionIDs for every restored
    window: measured twice on 2026-09-29, on the clean-exit and the crash
    path, six windows each time, zero overlap either way, so a slot
    remembered against the old id matches nothing after a restart, and every
    Chrome window comes back a stranger. What survives a restore is the
    CONTENT: the window comes back with its tabs. Chrome leaves the previous
    session file on disk next to the new one, so both sides are readable and
    the join needs no new stored state.

    Greedy by overlap, largest first, each id used once, ties broken by id so
    the answer is deterministic. A pair must ALSO carry MOST OF THE OLD
    window's tabs (more than half) because that is the actual question: is
    most of what that window was showing here again? Measuring the smaller of
    the two instead lets a ten-tab window claim a two-tab one on a single
    shared page, which two unrelated windows can easily have. Unmatched is the
    safe outcome: the slot stays where it was and ages out on the TTL."""
    pairs = []
    for old, ourls in prev.items():
        for new, nurls in cur.items():
            n = len(ourls & nurls)
            if n * 2 > len(ourls):
                pairs.append((n, old, new))
    pairs.sort(key=lambda p: (-p[0], p[1], p[2]))
    used_old, used_new, out = set(), set(), {}
    for _n, old, new in pairs:
        if old in used_old or new in used_new:
            continue
        used_old.add(old)
        used_new.add(new)
        out[old] = new
    return out


_BROWSER_EXES = {"chrome", "chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable"}


def is_browser_cmdline(raw):
    """True if this raw /proc/<pid>/cmdline is a BROWSER process: a browser
    executable with no `--type=` among its arguments. Everything else with the
    same name is a renderer, a gpu process or a zygote (55 of them against 1
    browser, measured), and signalling those achieves nothing useful.

    THERE ARE TWO FRAMINGS AND ONLY ONE IS DOCUMENTED. /proc/<pid>/cmdline is
    meant to be NUL-SEPARATED and for most processes it is, but CHROME
    REWRITES ITS OWN ARGV AREA into a single space-joined string: the large
    majority of its processes carry ONE element, the browser among them.
    Splitting on NUL alone yields one "argv[0]" holding the whole command
    line, whose basename is never a browser name, so this answers False for
    every process on the box and wind-down signals nothing.

    TREAT NUL AS WHITESPACE, which reads both framings. Only the first token
    and the presence of a `--type=` token are read, so an argument that itself
    contains a space (`--profile-directory=Profile 2`) splitting into two
    cannot affect the answer."""
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
    """slot -> the Chrome PROFILE DIRECTORY that has that window open.

    Built from the same SNSS session files the chrome identity is read from, so
    it needs no new state: the profile is simply where each file LIVES
    (.../<Profile>/Sessions/Session_*). The files survive a restart, which is
    how Chrome restores itself, so this is answerable at login before Chrome
    has started.

    Reads the WINDOW table directly rather than going through parse_snss, which
    answers a different question and drops a window whose active-tab title is
    ambiguous or missing. Losing a window here would lose the PROFILE it names,
    and usher would then not start that profile at all."""
    out = {}
    for prof, files in session_history().items():
        name = os.path.basename(prof)
        for win in chrome_window_tabs(files[0]):
            out.setdefault(chrome_slot(win), name)
    return out


def snss_build(tabs, ver=3):
    """Build a minimal SNSS blob from [(window, tab, url, title), ...], for
    selftest: the inverse of the parser, Pickle 4-byte alignment and all.

    Tabs are indexed within their window in the order given, and each window's
    FIRST tab is the selected one, which is the tab parse_snss reads. Takes a
    LIST because the interesting cases are plural: several windows, several
    tabs each, which is what chrome_bind_windows has to tell apart."""
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

    out = b"SNSS" + wi(ver)
    nth = {}
    for window, tab, url, title in tabs:
        i = nth.get(window, 0)
        nth[window] = i + 1
        pk = wi(tab) + wi(0) + ws(url) + ws16(title)
        out += (cmd(_SNSS_SET_TAB_WINDOW, wi(window) + wi(tab))
                + cmd(_SNSS_SET_TAB_INDEX, wi(tab) + wi(i))
                + cmd(_SNSS_SET_SEL_NAV_INDEX, wi(tab) + wi(0))
                + cmd(_SNSS_UPDATE_TAB_NAV, wi(len(pk)) + pk))
    for window in nth:
        out += cmd(_SNSS_SET_SEL_TAB_IN_WIN, wi(window) + wi(0))
    return out
