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
# SetWindowBounds3: int32 window, then x, y, width, height, show state. The
# POSITION is a placeholder (a Wayland client is never told where it is, so
# Chrome writes 0,0 or 10,10), and the SIZE is real.
_SNSS_SET_WINDOW_BOUNDS3 = 14


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


def _snss_records(d):
    """(command id, payload) for each record of a session file's bytes."""
    off = 8                                     # skip magic + int32 version
    while off + 2 <= len(d):
        (size,) = struct.unpack_from("<H", d, off)
        off += 2
        if size == 0 or off + size > len(d):
            break
        yield d[off], d[off + 1:off + size]
        off += size


def _snss_scan(path):
    """Walk one session file's records into raw tables, or None if it is not a
    session file. Split from parse_snss because the two halves fail differently:
    this one must survive a malformed record mid-stream, while resolving the
    tables afterwards is pure dict work that cannot."""
    d = open(path, "rb").read()
    if d[:4] != b"SNSS":
        return None
    tab_win, tab_idx, win_sel, tab_nav = {}, {}, {}, {}
    nav, closed_tabs, closed_wins = {}, set(), set()
    for cid, p in _snss_records(d):
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


def recorded_window_ids():
    """Every Chrome window id that ANY session file on disk still names.

    THAT IS EXACTLY THE SET A STORED SLOT CAN STILL MATCH, which is what
    makes it worth naming. A chrome slot is keyed on a SessionID, and there
    are only two ways one is ever matched again: the id belongs to a window of
    the CURRENT session, or rekey_chrome binds it across a browser restart,
    which it can only do for an id a RETAINED older file still names. An id
    no file on disk names is unreachable, because a SessionID is a monotonic
    counter and no run ever re-mints one (measured four times, 2026-09-29 and
    2026-10-13: every restart hands out a fresh higher block).

    AN EMPTY ANSWER MEANS NO EVIDENCE, NOT "NOTHING IS REACHABLE", and a
    caller must read it that way: with no file parsed, every slot keeps the
    benefit of the doubt. Being wrong the other way would hide a slot that
    was about to be re-keyed, so the empty case costs a report line where the
    alternative costs a placement."""
    ids = set()
    for files in session_history().values():
        for f in files:
            ids |= set(chrome_window_tabs(f))
    return ids


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
        merged, clash = {}, set()
        for f in files:
            try:
                got = parse_snss(f)
            except Exception:
                continue
            for raw, hit in got.items():
                # NORMALISED HERE AS WELL AS ON THE LIVE SIDE, so the two
                # are the same key; two windows that differ only by an
                # unread count collide and are dropped as ambiguous.
                k = _chrome_page_title(raw)
                if k in merged and str(merged[k][0]) != str(hit[0]):
                    clash.add(k)
                merged[k] = hit
        for k in clash:
            merged.pop(k, None)
        _snss_cache["sig"] = sig
        _snss_cache["map"] = merged
    return _snss_cache["map"]


_COUNT_RE = re.compile(r"\(\d+\+?\)")


def _chrome_page_title(title):
    """The page title as a JOIN KEY: the browser-name suffix stripped, and
    every parenthesised NUMBER removed.

    THE NUMBERS ARE UNREAD COUNTS, which a web app rewrites without
    navigating, while Chrome records a title only AT navigation: so the
    session file says "Team Notes | Notion" and the screen says "(2) Team
    Notes | Notion", and the join misses. Measured on dragonfly 2026-11-12:
    five of an account's ten windows unidentified 43s after a login, the
    Team Notes window among them. Applied to BOTH sides, so two windows
    whose titles differ ONLY by such a number collide and are dropped as
    ambiguous (chrome_session_titles) rather than paired wrongly."""
    for suf in CHROME_SUFFIXES:
        if title.endswith(suf):
            title = title[:-len(suf)]
            break
    return " ".join(_COUNT_RE.sub("", title).split())


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


def seed_slots(pairs):
    """Adopt resolutions somebody else made for these views. Returns the
    count taken.

    WHY A ONE-SHOT VERB NEEDS THIS AT ALL: the cache below is per PROCESS and
    is filled by whoever resolved a view FIRST, so the daemon accumulates
    answers a verb cannot have. The title is only a bootstrap and Chrome
    records it at NAVIGATION time, so a window whose title has since drifted
    is unresolvable from scratch while the daemon still holds its slot. The
    daemon is right and the verb is blind, which is the same shape the
    published sources map exists for.

    IT NEVER OVERWRITES, because a resolution this process made itself came
    from the live session file and is at least as good. And it validates the
    SHAPE, so a hand-edited or half-written snapshot cannot put a raw title
    into the cache that identity reads: that fallback is exactly what the
    slot key replaced.

    THE CALLER OWNS THE FRESHNESS TEST. This takes pairs and asks nothing
    about where they came from, which is what keeps this module a leaf."""
    n = 0
    for vid, slot in pairs:
        if vid is None or not is_chrome_slot(slot):
            continue
        if vid not in _slot_cache:
            # THE SLOT VERBATIM. This cache holds the whole `chrome:win:<id>`
            # string, which `window_slot` returns and `claim_by_elimination`
            # reads back with `held[len(_CHROME_SLOT):]`: storing the bare id
            # here would hand every caller a key the matcher never looks up.
            _slot_cache[vid] = slot
            n += 1
    return n


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
    # A TITLE JOIN THE SIZE CONTRADICTS IS REFUSED. The title is the last
    # resort (see claim_by_size), and a stale or shared title can name the
    # wrong window outright; Chrome's record of that window's size is the
    # cheap witness against it.
    if hit and size_disagrees(vid, hit[len(_CHROME_SLOT):]):
        return None
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

    AN ID A LIVE VIEW ALREADY HOLDS IS NOT FREE, and the cache is the only
    honest record of that. A view resolved earlier keeps its slot for life
    while its TITLE goes on changing, so asking the titles alone which ids are
    taken misses exactly the windows this function exists to work around.
    Measured on manifold 2026-10-13: a cached window whose title had gone
    stale was neither matched nor unmatched, its own id read as free, and the
    one genuinely unrecorded window was handed it. Both sides then cached, so
    one slot described two windows until a browser restart carried the wrong
    geometry onto the real one.

    Writes the SAME cache window_slot reads, so the claim is remembered for
    the view's life and dropped by forget_window on unmap."""
    t = chrome_session_titles()
    claimed, unmatched = set(), []
    for vid, raw in views:
        held = _slot_cache.get(vid)
        if held:
            claimed.add(held[len(_CHROME_SLOT):])
            continue
        hit = t.get(_chrome_page_title(raw))
        if hit:
            claimed.add(str(hit[0]))
        elif vid is not None:
            unmatched.append(vid)
    # THE ID SET IS EVERY RECORDED WINDOW, not only those with a usable
    # title: a window whose title it shares with another is dropped from
    # the title map, and was therefore invisible here too, so two windows
    # sharing a title could never be settled even when one was forced.
    ids = {str(w) for _ti, (w, _u) in t.items()}
    ids |= set(chrome_session_sizes())
    free = sorted(i for i in ids if i not in claimed)
    if len(unmatched) == 1 and len(free) == 1:
        _slot_cache[unmatched[0]] = chrome_slot(free[0])
        return unmatched[0]
    return None


def resolved(vid):
    """Has this view already been named, by any means?"""
    return vid in _slot_cache


def forget_window(vid):
    """Drop a closed view's cached slot. Wayfire ids are not reused quickly,
    but a cache that only ever grows is a leak in a process that runs for
    weeks."""
    _slot_cache.pop(vid, None)
    _live_sizes.pop(vid, None)


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


def chrome_window_sizes(path):
    """{window id: (width, height)} for one session file's OPEN windows, as
    Chrome last recorded them. Never raises; a bad file yields {}.

    A window with no open tab is not open, whatever bounds it left behind:
    measured, a session file carries bounds records for windows closed
    minutes earlier."""
    try:
        d = open(path, "rb").read()
    except OSError:
        return {}
    tabs = _snss_scan(path)
    if tabs is None:
        return {}
    tab_win, _ti, _ws, _tn, _nav, closed_tabs, closed_wins = tabs
    open_wins = {w for t, w in tab_win.items()
                 if t not in closed_tabs and w not in closed_wins}
    sizes = {}
    for cid, p in _snss_records(d):
        if cid == _SNSS_SET_WINDOW_BOUNDS3 and len(p) >= 20:
            w, _x, _y, wd, ht = struct.unpack_from("<iiiii", p, 0)
            sizes[w] = (wd, ht)
    return {w: s for w, s in sizes.items()
            if w in open_wins and s[0] > 0 and s[1] > 0}


_size_cache = {"sig": None, "map": {}}


def chrome_session_sizes():
    """{window id (str): (width, height)} across profiles' current sessions,
    cached like chrome_session_titles."""
    sig = session_sig()
    if sig != _size_cache["sig"]:
        merged = {}
        for f in session_files():
            try:
                for w, sz in chrome_window_sizes(f).items():
                    merged[str(w)] = sz
            except Exception:                              # noqa: BLE001
                continue
        _size_cache["sig"] = sig
        _size_cache["map"] = merged
    return _size_cache["map"]


def chrome_frame(live, recorded):
    """The constant (dw, dh) between a live window's size and the size
    Chrome records for it, or None. PURE.

    IT IS THE FRAME, and it is constant per box: measured +44,+71 on
    dragonfly 2026-11-12 for both of a profile's windows, and +44,+71 on
    manifold a month earlier. DERIVED BY VOTE rather than hard-coded, since
    a theme or scale can move it: every live size against every recorded
    one, and the true difference is the only one most pairs agree on. Two
    votes at least, and a clear winner, or the answer is no answer."""
    votes = {}
    for lw, lh in live:
        for rw, rh in recorded:
            d = (int(round(lw)) - int(rw), int(round(lh)) - int(rh))
            votes[d] = votes.get(d, 0) + 1
    ranked = sorted(votes.items(), key=lambda kv: -kv[1])
    if not ranked or ranked[0][1] < 2:
        return None
    if len(ranked) > 1 and ranked[1][1] == ranked[0][1]:
        return None
    return ranked[0][0]


# The frame last derived, for verifying a title join when this pass could
# not derive one (one window, say), and our live chrome views' sizes, by
# view id, as last listed.
_frame = [None]
_live_sizes = {}
SIZE_TOL = 1    # px: Chrome restores and records a window's size exactly


def _fits(a, b, tol=SIZE_TOL):
    return abs(a[0] - b[0]) <= tol and abs(a[1] - b[1]) <= tol


def claim_by_size(views):
    """Name every live Chrome window its SIZE alone identifies. `views` is
    [(view id, (width, height))] for EVERY one of our live Chrome views.
    Returns the view ids it claimed.

    THE SIZE BEFORE THE TITLE. The title is a page's, not a window's: two
    windows showing one page share it, a web app rewrites it without
    navigating, and Chrome records it only at navigation, so the join was
    wrong or refused often enough to cost placements at every login.
    Measured on dragonfly 2026-11-12: two work windows wore one title and
    neither could be named, while their sizes (2527 and 2498
    wide) told them apart outright. The session file records every window's
    size, so a live window whose size, less the frame, matches exactly ONE
    recorded window, and which no other unnamed live window shares, IS that
    window.

    IT REFUSES ON ANY TIE, which is the safety argument, as for
    elimination: two windows of one size are told apart by the title or by
    nothing. Writes the cache `window_slot` reads, so a claim lasts the
    view's life."""
    rec = chrome_session_sizes()
    sizes = {vid: (round(s[0]), round(s[1])) for vid, s in views
             if vid is not None and s and s[0] and s[1]}
    _live_sizes.clear()
    _live_sizes.update(sizes)
    f = chrome_frame(list(sizes.values()), list(rec.values()))
    if f:
        _frame[0] = f
    f = f or _frame[0]
    if not f or not rec:
        return []
    held = {_slot_cache[v][len(_CHROME_SLOT):] for v in sizes
            if v in _slot_cache}
    free = {i: s for i, s in rec.items() if i not in held}
    out = []
    for vid, sz in sizes.items():
        if vid in _slot_cache:
            continue
        want = (sz[0] - f[0], sz[1] - f[1])
        ids = [i for i, s in free.items() if _fits(s, want)]
        twins = [o for o, osz in sizes.items()
                 if o != vid and o not in _slot_cache and _fits(osz, sz)]
        if len(ids) == 1 and not twins:
            _slot_cache[vid] = chrome_slot(ids[0])
            out.append(vid)
    return out


def size_disagrees(vid, wid):
    """Does view `vid`'s live size contradict Chrome's record of window
    `wid`? False when either is unknown: a check with no evidence passes."""
    f, sz = _frame[0], _live_sizes.get(vid)
    rec = chrome_session_sizes().get(str(wid))
    if not (f and sz and rec):
        return False
    return not _fits(rec, (sz[0] - f[0], sz[1] - f[1]), tol=2)


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


def browser_pids(uid=None):
    """Every live browser process OF THIS USER, by is_browser_cmdline.

    THE uid FILTER IS NOT TIDINESS: a window source that is a separate account
    runs its OWN browser on the same display, and `/proc/<pid>/cmdline` is
    readable across uids, so without it this walk returns somebody else's
    browser. Measured 2026-11-02 on a box running both:

        browser_pids() -> [2694384, 2764782]
          2694384  uid 1000   mine
          2764782  uid  997   another account's, and NOT signalable (EPERM)

    BOTH CALLERS WANT THE SAME NARROWING, which is why it belongs here rather
    than in either one:

      wind_down       SIGTERM fails EPERM on a foreign pid, and the engine
                      then cannot tell "I could not signal it" from "it
                      exited", so a logout reports a clean browser stop it
                      did not perform.
      browser_started takes the EARLIEST start, so a foreign browser that
                      started first makes the answer too early, and
                      session_files() then discards FEWER stale files than it
                      should: the 2026-10-09 phantom-window-id bug, back by
                      another road.

    The uid comes from `/proc/<pid>`'s OWNER rather than from `Uid:` in
    status, which is one stat instead of a read and parse, and is the same
    fact for anything not setuid.

    `uid` IS INJECTABLE SO THE FILTER CAN BE PROVEN, and that is the only
    reason it is a parameter: no caller passes it. The alternative was a test
    that monkeypatches `os.getuid`, which is the SHARED module and would have
    changed the answer for every thread in the process, the Watcher's
    included.
    """
    me = os.getuid() if uid is None else uid
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            if os.stat(f"/proc/{d}").st_uid != me:
                continue
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


def snss_build(tabs, ver=3, bounds=None):
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
    for window, (w, h) in (bounds or {}).items():
        out += cmd(_SNSS_SET_WINDOW_BOUNDS3,
                   wi(window) + wi(10) + wi(10) + wi(w) + wi(h) + wi(1))
    return out
