"""Chrome: its session-file format, and the per-window identity read from it.

The DOMAIN KNOWLEDGE, kept apart from the engine that consumes it: how an SNSS
session file is framed, which file belongs to which profile, how a live window
is named by the size Chrome records for it, and which of the fifty-odd chrome
processes is the browser. A LEAF: it imports nothing from the rest of the
package, so the engine can import it at module level with no cycle.

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
no --remote-debugging-port, no new attack surface), name a live window by the
one recorded window its size matches exactly (claim_by_size), and key on the
window id. The title was that join for years and is retired: it is a page's,
not a window's.

IT DOES NOT SURVIVE A RESTART, which an earlier version of this comment claimed
on the strength of one observation. It is a monotonic per-session counter:
every restore mints a fresh block, measured twice on both the clean-exit and
the crash path. chrome_bind_windows, over every window's TABS, is what
carries a window across that boundary, and the id is durable for exactly as
long as the browser runs, which is all identity needs it to be.

A window nothing names exactly has NO identity here: window_slot returns
None and usher declines to remember it at all, rather than falling back to the
raw title it happens to be wearing. That fallback was 86% of a real
store, none of it matchable.
"""
import glob
import hashlib
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


# A CHROME APP WINDOW (a PWA) IS STARTED BY ITS OWN DESKTOP ENTRY, as
# `google-chrome --profile-directory=P --app-id=X`, beside the browser's own
# launch. Two hazards meet in that, measured on dragonfly 2026-11-14:
#
#   ORDER   if an app launch reaches Chrome first it becomes the browser
#           process, without usher's flags. The browser's own launch then
#           hands its request to it, and the session restore it carries
#           reopens the app windows a second time: two of each.
#   PROMPT  without --hide-crash-restore-bubble that first process offers
#           "Chrome didn't shut down correctly. Restore?", and taking it
#           reopens the last session on top of what usher started.
#
# At two earlier unclean logins the browser happened to start first and
# nothing doubled, so the fix is to make that order certain (the engine waits
# for the browser it started) and to suppress the prompt either way.
APP_FLAG = "--app-id="
APP_FLAGS = ["--hide-crash-restore-bubble"]


def is_app_window_argv(argv):
    """Is this a launch of a Chrome APP window rather than the browser? PURE.

    By the program and an `--app-id=` argument, which is what a PWA's own
    desktop entry runs; the browser's launch never carries one."""
    if not argv:
        return False
    return (is_chrome(os.path.basename(argv[0]))
            and any(str(a).startswith(APP_FLAG) for a in argv[1:]))


def app_window_argv(argv):
    """`argv` with the flags an app window's launch needs added, once. PURE.

    NOT CHROME_FLAGS: --restore-last-session on an app launch is a second
    request to reopen the whole session, which is the duplication itself."""
    return list(argv) + [f for f in APP_FLAGS if f not in argv]


def after_browser(launched_at, pids, sleep, now, stagger=None):
    """Hold an app window's launch until the browser usher started this pass
    is running and has had CHROME_STAGGER to open its singleton socket, the
    same interval two profiles are staggered by. Returns the seconds waited.

    Bounded: it polls for a browser process for at most two staggers, then
    lets the launch go anyway, since a missing app window is worse than the
    race. Nothing waits when usher started no browser (launched_at is 0)."""
    stagger = CHROME_STAGGER if stagger is None else stagger
    if not launched_at:
        return 0.0
    t0 = now()
    while not pids() and now() - t0 < 2 * stagger:
        sleep(0.25)
    left = launched_at + stagger - now()
    if left > 0:
        sleep(left)
    return now() - t0
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
# SetTabGroup: a 32-byte struct, int32 tab, pad, the group token (two uint64)
# at 8..24, then a has-group byte at 24 (0 takes the tab OUT of its group,
# with a zero token, so the token alone answers).
# SetTabGroupMetadata2: a Pickle, the token at 4..20, then the group's TITLE
# as a String16. The token is minted afresh at every restart (measured
# 2026-11-20, 0 of 3 shared across one); the TITLE survives (3 of 3).
_SNSS_SET_TAB_GROUP = 25
_SNSS_SET_TAB_GROUP_META = 27


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
    session file. Split from its readers because the two halves fail
    differently: this one must survive a malformed record mid-stream, while
    resolving the tables afterwards is pure dict work that cannot."""
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
    dead window in the set, which left the (since retired) elimination with
    two free ids for one unresolved view and made it (correctly) refuse. One
    real window went unplaceable for want of excluding a window that did not
    exist.

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


_COUNT_RE = re.compile(r"\(\d+\+?\)")


def strip_counts(title):
    """`title` with every parenthesised NUMBER removed and the spacing
    closed up: "(2) Team Notes" and "Signal (1)" are a page and an app
    with an UNREAD COUNT, which changes without the window changing. Used
    by verify's label fallback."""
    return " ".join(_COUNT_RE.sub("", title or "").split())


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
            # string, which `window_slot` returns and `claim_by_size` reads
            # back with `[len(_CHROME_SLOT):]`: storing the bare id here would
            # hand every caller a key the matcher never looks up.
            _slot_cache[vid] = slot
            n += 1
    return n


def window_slot(vid):
    """The slot a LIVE window has been NAMED, or None. A name comes only from
    an exact match against Chrome's own record of that window (claim_by_size)
    or from the daemon's published snapshot (seed_slots), and lasts the
    view's life.

    THE TITLE IS NOT ASKED, AT ALL. It was a bootstrap join for years, and it
    is a page's, not a window's: two windows showing one page share it, a web
    app rewrites it without navigating, and Chrome records it only at
    navigation, so the join named the wrong window or none often enough to
    cost placements at every login. Elimination (the one unnamed window must
    be the one free id) was retired with it: it misbound whenever a window
    Chrome never records was in the pool. A window nothing names is PENDING
    and waits; a wait costs a placement, a guess moves someone else's window.

    vid=None (a stored entry, which has no live view) answers None."""
    if vid is None:
        return None
    return _slot_cache.get(vid)


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

    The WHOLE SET, because it answers the question a restart asks: which
    window in the new session is the one that used to be that window in the
    old? One URL per side is far too thin to decide that; the full tab set is
    a fingerprint (chrome_bind_windows, and the tab record that bridges more
    than one restart).

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


def chrome_window_groups(path):
    """{window id: frozenset of the NAMES of the tab groups it holds}, for
    one session file's open windows. Never raises; a bad or missing file
    yields {}.

    A GROUP NAME IS THE USER'S OWN LABEL, so unlike a tab's address it does
    not change when a page reloads or redirects, and it comes back with the
    window at a restart where the group's token does not. An UNNAMED group
    says nothing about which window it is in, so it is left out. The last
    record for a tab or a group wins, as it does for Chrome."""
    try:
        d = open(path, "rb").read()
        tabs = _snss_scan(path)
    except OSError:
        return {}
    if tabs is None:
        return {}
    tab_win, _ti, _ws, _tn, _nav, closed_tabs, closed_wins = tabs
    tab_tok, title = {}, {}
    for cid, p in _snss_records(d):
        try:
            if cid == _SNSS_SET_TAB_GROUP and len(p) >= 24:
                # taken OUT of a group, Chrome writes an all-zero token
                # (measured, 10 of 10), which no group's metadata names
                t, _o = _snss_i32(p, 0)
                tab_tok[t] = p[8:24]
            elif cid == _SNSS_SET_TAB_GROUP_META and len(p) >= 24:
                title[p[4:20]], _o = _snss_str16(p, 20)
        except Exception:
            pass
    out = {}
    for t, tok in tab_tok.items():
        w = tab_win.get(t)
        name = title.get(tok) if tok else None
        if (w is None or not name or t in closed_tabs
                or w in closed_wins):
            continue
        out.setdefault(w, set()).add(name)
    return {w: frozenset(n) for w, n in out.items()}


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
    cached on the session signature."""
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


# The frame last derived, for a pass that cannot derive one (one window,
# say), and our live chrome views' sizes, by view id, as last listed.
_frame = [None]
_live_sizes = {}
SIZE_TOL = 1    # px: Chrome restores and records a window's size exactly


def _fits(a, b, tol=SIZE_TOL):
    return abs(a[0] - b[0]) <= tol and abs(a[1] - b[1]) <= tol


def claim_by_size(views):
    """Name every live Chrome window its SIZE alone identifies. `views` is
    [(view id, (width, height))] for EVERY one of our live Chrome views.
    Returns the view ids it claimed.

    THE SIZE, AND NOT THE TITLE. The title is a page's, not a window's: two
    windows showing one page share it, a web app rewrites it without
    navigating, and Chrome records it only at navigation, so the title join
    (retired) was wrong or refused often enough to cost placements at every
    login.
    Measured on dragonfly 2026-11-12: two work windows wore one title and
    neither could be named, while their sizes (2527 and 2498
    wide) told them apart outright. The session file records every window's
    size, so a live window whose size, less the frame, matches exactly ONE
    recorded window, and which no other unnamed live window shares, IS that
    window.

    IT REFUSES ON ANY TIE, which is the safety argument: two windows of one
    size are not told apart here at all, and stay PENDING. The size
    uniqueness nudge is what keeps that rare. Writes the cache
    `window_slot` reads, so a claim lasts the view's life."""
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


BIND_MIN_SHARED = 3   # tabs a PARTIAL match must have in common


def _bind_by_groups(cur, prev):
    """{old: new} by tab group names. PURE. Both arguments are {id: frozenset
    of group-name fingerprints}.

    A NAME HELD BY EXACTLY ONE WINDOW ON EACH SIDE links those two windows,
    and a pair binds only if EVERY such name of either window points at the
    other: a window whose names point at two different windows (a group moved
    between windows) binds nothing. A name two windows share on either side
    is no label at all and is simply not used."""
    def owners(side):
        by = {}
        for w, names in side.items():
            for n in names or ():
                by.setdefault(n, []).append(w)
        return {n: ws[0] for n, ws in by.items() if len(ws) == 1}
    po, co = owners(prev), owners(cur)
    links = {n: (po[n], co[n]) for n in po.keys() & co.keys()}
    fwd, back = {}, {}
    for o, w in links.values():
        fwd.setdefault(o, set()).add(w)
        back.setdefault(w, set()).add(o)
    return {o: next(iter(ws)) for o, ws in fwd.items()
            if len(ws) == 1 and back[next(iter(ws))] == {o}}


def chrome_bind_windows(cur, prev, cur_groups=None, prev_groups=None):
    """Bind PREVIOUS window ids to the CURRENT ones that restored them, by
    their tabs: {old id: new id}. Both arguments are {id: frozenset of the
    URL each open tab shows}. PURE.

    WHY THIS HAS TO EXIST. Chrome mints FRESH SessionIDs for every restored
    window (measured twice on 2026-09-29, clean exit and crash, zero overlap),
    so a slot remembered against the old id matches nothing after a restart.
    What survives a restore is the CONTENT: the window comes back with its
    tabs, and a window's tab set is its fingerprint.

    TWO TIERS, AND NEITHER GUESSES:

    EXACT first: the same set of URLs, and no other window on EITHER side
    with that set. A restore brings a window back with exactly its tabs, so
    this is the ordinary case.

    PARTIAL only for what is left, because tabs come and go between the last
    record and the restore: at least BIND_MIN_SHARED tabs in common, MORE
    THAN HALF of the old window's tabs, and each the OTHER'S UNIQUE best. A
    tie on either side binds nothing (it used to be broken by id order, which
    is a guess wearing a sort key). Measuring the old window rather than the
    smaller set is deliberate: a ten-tab window must not claim a two-tab one
    on one shared page.

    TAB GROUP NAMES COME FIRST, when the caller has them (_bind_by_groups):
    a group's name is the user's own label and survives a reload that
    changes a tab's address, which is how a three-tab window with one such
    tab fell below the partial rule at every restart (2026-11-20). The tab
    tiers then decide only the windows the names did not.

    Unbound is the safe outcome: the window is placed by its surface and its
    old slot ages out."""
    out = _bind_by_groups(cur_groups or {}, prev_groups or {})
    used_new = set(out.values())
    sets_new, sets_old = {}, {}
    for w, u in cur.items():
        if u:
            sets_new.setdefault(u, []).append(w)
    for w, u in prev.items():
        if u:
            sets_old.setdefault(u, []).append(w)
    for u, olds in sets_old.items():
        news = sets_new.get(u, [])
        if (len(olds) == 1 and len(news) == 1 and olds[0] not in out
                and news[0] not in used_new):
            out[olds[0]] = news[0]
            used_new.add(news[0])

    def best(scores):
        top = max(scores.values(), default=0)
        hits = [k for k, n in scores.items() if n == top]
        return hits[0] if top and len(hits) == 1 else None

    ok_old = {o: u for o, u in prev.items() if u and o not in out}
    ok_new = {n: u for n, u in cur.items() if u and n not in used_new}
    score = {}
    for o, ou in ok_old.items():
        for n, nu in ok_new.items():
            k = len(ou & nu)
            if k >= BIND_MIN_SHARED and k * 2 > len(ou):
                score[(o, n)] = k
    for o in ok_old:
        n = best({nn: k for (oo, nn), k in score.items() if oo == o})
        if n is None:
            continue
        if best({oo: k for (oo, nn), k in score.items() if nn == n}) == o:
            out[o] = n
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

    Reads every window of the newest file, whatever its titles: losing a
    window here would lose the PROFILE it names, and usher would then not
    start that profile at all."""
    out = {}
    for prof, files in session_history().items():
        name = os.path.basename(prof)
        for win in chrome_window_tabs(files[0]):
            out.setdefault(chrome_slot(win), name)
    return out


def snss_build(tabs, ver=3, bounds=None, groups=None, token_salt="",
                ungroup=()):
    """Build a minimal SNSS blob from [(window, tab, url, title), ...], for
    selftest: the inverse of the parser, Pickle 4-byte alignment and all.

    Tabs are indexed within their window in the order given, and each window's
    FIRST tab is the selected one. Takes a
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
    # groups: {tab: group name}. The token is per FILE (token_salt), as
    # Chrome mints one afresh at every restart.
    named = set()
    for tab, name in (groups or {}).items():
        tok = hashlib.sha256((token_salt + "\0" + name).encode()).digest()[:16]
        out += cmd(_SNSS_SET_TAB_GROUP,
                   wi(tab) + wi(0) + tok + b"\x01" + b"\x00" * 7)
        if name not in named:
            named.add(name)
            pk = tok + ws16(name) + struct.pack("<I", 0)
            out += cmd(_SNSS_SET_TAB_GROUP_META, wi(len(pk)) + pk)
    for tab in ungroup:      # taken back out of its group, as Chrome records
        out += cmd(_SNSS_SET_TAB_GROUP, wi(tab) + wi(0) + b"\x00" * 24)
    return out
