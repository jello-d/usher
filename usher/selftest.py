"""usher's selftest: every check, grouped by area.

Offline and deterministic. No compositor, no network, no real store. Run it
with `usher selftest`, which is also what test/selftest.t drives.

WHY IT IS ITS OWN MODULE: it was 2,134 lines inside engine.py, 38% of the
file, and every reader of the engine had to scroll past it.

HOW IT STUBS THE ENGINE, which is the one thing to get right here. The suite
used to live inside engine.py and wrote `globals()["name"] = ...`. From this
module `globals()` is the SUITE's namespace, so that would create a shadow and
silently stop stubbing anything, and a check that stubs nothing still PASSES.
So every stubbed name is both written AND read through the module:

    engine.load_snapshot = lambda *a: {...}     not globals()[...]
    ... engine.STATE ...                          not a bare STATE

READING ONE BY NAME WOULD BE A SNAPSHOT, which is the same hazard the package
split already records for EXCLUDE_ERRORS and _PLUGINS: an importing module
binds the value it found at import, so a site reading `STATE` directly would
keep seeing the real one after another check had stubbed it. The names the
suite stubs are therefore NEVER in the import list below, and qualifying all
of them uniformly is the rule that cannot be got wrong site by site:

    SESSION_START   _announce       _seated_now     lock_now
    SOCKET_HUNTED   loginctl        _spawn_kitty    logline
    STATE           _owner          _term_cwd       plugins
    _HUNT_WARNED    desktop_entries _term_mux_pending
    runtime_dir     load_snapshot   session_history
    spawn_term      session_locked_hint

Everything else is imported by name, the same way watch.py does it, because
those are constants and functions that are never rebound.
"""
import ast
import contextlib
import inspect
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import date

from . import chrome, engine, toplevels
# FROM chrome ITSELF, not through the engine, which merely re-exports them.
# Importing a name through whoever happened to use it first is how a module's
# real dependency stops being visible in its own header.
from .chrome import (
    CHROME_FLAGS, chrome_bind_windows, chrome_profile_map,
    chrome_session_titles, chrome_window_for, chrome_window_tabs,
    forget_window, is_browser_cmdline, is_chrome, parse_snss, session_files,
    snss_build, window_slot)
from .engine import (
    PLACE_CAP, CONFIG_DIR, EXCLUDE_FILE, IDLE_SETTLE, INCLUDE_FILE,
    KB_SCHEMA, MUX_BIN, MUX_RESUME, PLACE_TOL, PLUGIN_DIR, Resolution,
    START_FLOOR, WindowPlugin, _as_resolution, _derived_id,
    _latch_target_in, _migrate_store, _mux_pending_in, _mux_slot,
    _safe_profile, _single_id, _size_opts, _spec_to_date, _verify_deltas,
    _verify_find,
    chrome_profiles_for, config_path, desktop_launch_for,
    desktop_relaunch_missing, entries_from_snapshot, identity, is_mux_term,
    is_owned, kb_path, kitty_candidates, kitty_live_counts,
    kitty_relaunch_missing, kkey,
    launch_missing, learn, live_keys, load_knowledge, lock_plan,
    lock_summoned_session, match, mux_candidates, mux_cmd_of_saved,
    mux_host_of, mux_relaunch_missing, mux_session_of, mux_session_set,
    pick_socket, place_of, placement_landed, profile_id, pview,
    rekey_chrome, resolution, save_knowledge, saved_sizes, schema_path,
    is_unique, seated_session, target_geometry, unidentified,
    upsert, verify_index, verify_row_name, verify_verdict,
    wayfire_socket)

# THE REAL `logline`, captured at IMPORT before anything can patch it.
# `_quiet_log` replaces `engine.logline` and `watch.logline` for the whole
# area loop, so a check that wants to exercise the production function has
# no other way to reach it, and reaching for the patched one would test the
# stub.
_real_logline = engine.logline


@contextlib.contextmanager
def _tprofile(name):
    """Pin the display profile for a block and put the environment back, so an
    area that changes it cannot leak into the next."""
    prev = os.environ.get("USHER_PROFILE")
    os.environ["USHER_PROFILE"] = name
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("USHER_PROFILE", None)
        else:
            os.environ["USHER_PROFILE"] = prev

@contextlib.contextmanager
def _tblind():
    """Force `doctor` to be unable to see the live session, however selftest
    was invoked.

    UNSETTING WAYFIRE_SOCKET IS NOT ENOUGH ANY MORE, and this helper claimed
    it was for two days. usher gained its own socket DISCOVERY (pick_socket
    searches XDG_RUNTIME_DIR), so with the variable unset it simply FINDS the
    live socket and is not blind at all. The three doctor-blind checks then
    failed for anyone whose python can import pywayfire, which is to say from
    the INSTALLED venv on every box, while `test/run` passed because it uses
    the system python where the import fails for an unrelated reason.

    THE PROXY TRAP, AGAIN, AND IN THE TEST THIS TIME. doctor itself had
    exactly this bug (it read "WAYFIRE_SOCKET is unset" as "I cannot see")
    and it was fixed on 2026-10-01 with the note "grep for the proxy when you
    remove the dependency". This helper was the proxy nobody grepped for.

    So it points the search at an EMPTY runtime dir as well, which is the
    condition that genuinely blinds every branch: no variable to read, and
    nothing to find by searching."""
    import tempfile
    prev = os.environ.pop("WAYFIRE_SOCKET", None)
    prev_rt = os.environ.get("XDG_RUNTIME_DIR")
    empty = tempfile.mkdtemp(prefix="usher-blind-")
    os.environ["XDG_RUNTIME_DIR"] = empty
    try:
        yield
    finally:
        if prev is not None:
            os.environ["WAYFIRE_SOCKET"] = prev
        if prev_rt is not None:
            os.environ["XDG_RUNTIME_DIR"] = prev_rt
        else:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        try:
            os.rmdir(empty)
        except OSError:
            pass

@contextlib.contextmanager
def _tsnss(tabs):
    """A real SNSS file on disk holding `tabs`, removed on the way out. The
    re-key has to read FILES, not dicts, so these checks build the same bytes
    Chrome writes rather than a convenient stand-in."""
    import tempfile
    fd, path = tempfile.mkstemp(prefix="usher-snss-", dir="/var/tmp")
    try:
        os.write(fd, snss_build(tabs))
        os.close(fd)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

@contextlib.contextmanager
def _tsession(cur, prev):
    """Pose as a Chrome profile whose session file has just ROTATED: one
    profile, the new file first and the previous one behind it, which is the
    shape session_history() reports and the only shape the re-key can work
    from."""
    real = engine.session_history
    engine.session_history = lambda: {"P": [cur, prev]}
    try:
        yield
    finally:
        engine.session_history = real

def _tmw(cmd=None, key="term:resume", size=None):
    """A saved terminal window, as a snapshot records one."""
    w = {"app_id": "kitty", "key": key}
    if cmd:
        w["cmd"] = cmd
    if size:
        w["size"] = size
    return w

def _tv(app, title="", pid=-1):
    """A NORMALIZED view, shaped as a plugin hook receives one (see pview)."""
    return {"app": app, "title": title, "pid": pid}

def _under_root(path, root):
    """Is `path` inside `root`? PURE.

    A COMPONENT TEST, not a string prefix: `<root>-other/x` starts with the
    root's characters and is a different directory.
    """
    a, b = os.path.abspath(path), os.path.abspath(root)
    return a.startswith(b + os.sep)


def _raise_it(*_a, **_k):
    """A seam that fails. Named, so a check asserting a
    plugin's raise costs one row rather than the run can say
    so in one word."""
    raise RuntimeError("this seam is broken")


def _trv(app, title="", pid=-1, vid=None, tlid=None):
    """A RAW view, shaped as the compositor reports one. Not interchangeable
    with _tv: anything reached through pview takes either, but app_of and the
    matcher read `app-id` and see nothing in a normalized view.

    `tlid` PUTS THE JOIN KEY ON IT, under `security-context`, which is where
    the compositor reports it (U-W2 R2). A foreign window's per-window
    identity is looked up by that identifier now rather than by a hash of its
    title, so a fixture without one resolves to the source alone: correct
    behaviour, and silent, so the fixture has to supply it deliberately."""
    v = {"app-id": app, "title": title, "pid": pid, "id": vid}
    if tlid is not None:
        v["security-context"] = {"sandbox-engine": "severance",
                                 "app-id": "titan", "instance-id": "titan",
                                 "toplevel-identifier": tlid}
    return v


def _stat_uid(path):
    """The owner of `path`, or None if it is gone. For asking whose process a
    /proc entry is without parsing status."""
    try:
        return os.stat(path).st_uid
    except OSError:
        return None


def _dead_pid():
    """A pid that is NOT running, found rather than guessed: a hardcoded high
    number is a pid somebody else may be using, and this is handed to
    os.kill."""
    for p in range(4194300, 4194000, -1):
        if not os.path.exists(f"/proc/{p}"):
            return p
    raise AssertionError("could not find an unused pid")


_DEAD_PID = _dead_pid()


def _capture_out(fn, *a, **kw):
    """Run `fn` and return what it PRINTED. The wind-down reports to stdout,
    because it talks to a human holding down a power button, so its stdout is
    the thing under test."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*a, **kw)
    return buf.getvalue()

def _t_registry(ck):
    """the plugin registry: who claims which window, and the
    title parsers that feed it."""
    ps = {getattr(p, "name", "?"): p for p in engine.plugins()}
    # the registry loads the three built-ins; each claims the right windows
    ps = {getattr(p, "name", "?"): p for p in engine.plugins()}
    ck("plugins-builtin", all(n in ps for n in ("chrome", "mux", "kitty")))
    ck("owns-chrome", ps["chrome"].owns(_tv("google-chrome")))

    # A PLAIN TERMINAL AT $HOME IS A NORMAL WINDOW, not an exception. It used
    # to be excluded end to end (never captured, never placed, never brought
    # back), which is the same shape as chrome's retired ^New Tab$ rule and is
    # retired for the same reasons: settled state leaves a terminal opened
    # mid-session where it opens, and when usher spawns one at session start it
    # can place it. The cwd IS the key, so drive these by stubbing the one
    # thing that reads it.
    _kp, _home = ps["kitty"], os.path.expanduser("~")
    _kv = {"app": "kitty", "title": "terminal", "pid": 4242, "id": None}
    _real_cwd = engine._term_cwd
    try:
        engine._term_cwd = lambda _pid: _home
        ck("kitty-home-resolves-ready",
           _kp.resolve(_kv).key == f"kitty:{_home}")
        ck("kitty-home-is-ready", _kp.resolve(_kv).is_ready)
        # AN UNREADABLE CWD IS "ASK AGAIN", NOT "NEVER REMEMBER THIS", and
        # this check used to assert the opposite: a test pinning a mistaken
        # belief. transient means never remember; unidentified means cannot say
        # WHICH window yet. Conflating them cost real behaviour: a kitty cannot
        # be identified for its first 0.25s (no shell in /proc yet) so it read
        # as transient, and _place_view tests transient BEFORE identity and
        # returns there, dropping every non-mux terminal in the one 0.15s
        # window it gets.
        engine._term_cwd = lambda _pid: None
        # PENDING, not NEVER: a kitty has no shell in /proc for its first
        # ~0.25s, so this is "ask again", and reading it as "never remember"
        # is what dropped every non-mux terminal once already.
        ck("kitty-unreadable-cwd-is-pending",
           _kp.resolve(_kv).state == Resolution.PENDING)
        ck("kitty-unreadable-cwd-is-unidentified", unidentified(_kv))
        ck("kitty-unreadable-cwd-says-why", bool(_kp.resolve(_kv).why))
    finally:
        engine._term_cwd = _real_cwd
    # The 2026-10-03 shrink bug: a relaunched mux terminal maps BEFORE mux
    # attaches, so its title has no colon and KittyPlugin used to answer with
    # a cwd key, which the placer then resized the window down to. Both argv
    # SHAPES are pinned, because spawn_term wraps the command in `ksh -c`.
    ck("mux-pending-latch-process",
       _mux_pending_in(["/bin/sh", "/x/libexec/mux-latch", "manifold"]))
    ck("mux-pending-wrapped-resume",
       _mux_pending_in(["ksh", "-c", f"{MUX_BIN} resume; exec ksh -i"]))
    ck("mux-pending-wrapped-latch",
       _mux_pending_in(["ksh", "-c", f"{MUX_BIN} latch box; exec ksh -i"]))
    # HOWEVER MUX IS SPELLED, which is the half that broke: mux moved to a
    # machine-wide install, every recorded command named the old
    # `~/.local/bin/mux`, and a window started from the NEW path no longer
    # deferred, so KittyPlugin claimed it with a confident cwd key and the
    # shrink bug came back. Both spellings, pinned as LITERALS so this cannot
    # pass merely by agreeing with whatever MUX_BIN happens to be today.
    ck("mux-pending-the-bare-name",
       _mux_pending_in(["ksh", "-c", "mux resume; exec ksh -i"]))
    ck("mux-pending-an-absolute-path",
       _mux_pending_in(["ksh", "-c",
                        "/usr/local/bin/mux resume; exec ksh -i"]))
    ck("mux-pending-a-retired-absolute-path",
       _mux_pending_in(["ksh", "-c",
                        "/home/u/.local/bin/mux resume; exec ksh -i"]))
    # ANCHORED TO COMMAND POSITION. A command that merely MENTIONS a path
    # ending in `mux` must not defer: deferring forever is the direction that
    # costs a window its memory altogether.
    ck("mux-pending-not-a-path-that-merely-ends-in-mux",
       not _mux_pending_in(["ksh", "-c", "cd /home/u/src/mux && ls"]))
    # AND READING A LIVE argv MUST NOT RAISE. This is arbitrary bytes from
    # /proc on a placement path, and an unbalanced quote is a thing a real
    # command line contains.
    ck("mux-pending-survives-unbalanced-quoting",
       _mux_pending_in(["ksh", "-c", "mux resume 'oops"]) in (True, False))

    # AND THE COMMAND NAME IS A BARE NAME, which is the invariant that makes
    # all of the above survive the NEXT move. It was `~/.local/bin/mux`, and
    # reverting it passed this entire suite until this check existed.
    ck("mux-bin-is-a-bare-name", "/" not in MUX_BIN)
    ck("mux-resume-uses-the-bare-name", MUX_RESUME.split()[0] == MUX_BIN)
    # Host-dependent, so it SAYS which it was rather than asserting silently:
    # the invariant above is the durable claim, this is the live corroboration.
    _mw = shutil.which(MUX_BIN)
    ck(f"mux-bin-resolves-on-PATH ({_mw or 'mux ABSENT here'})",
       _mw is not None or shutil.which("mux") is None)

    # AND IT MUST NOT FIRE ON AN ORDINARY SHELL, or every plain kitty would
    # defer forever and never be remembered at all.
    ck("mux-pending-not-a-plain-shell",
       not _mux_pending_in(["ksh", "-i"]))
    ck("mux-pending-not-bare-tmux",
       not _mux_pending_in(["tmux", "-L", "global", "attach-session"]))
    # The deferral self-clears: `exec ksh -i` replaces the wrapper, so the
    # argv stops naming mux with no timer involved.
    ck("mux-pending-clears-after-exec",
       not _mux_pending_in(["ksh", "-i"]))

    # AND THE WIRING, which the pure checks above cannot see: identity has to
    # CONSULT the predicate. Stubbed with a READABLE cwd on purpose, so the
    # only reason left to decline is the pending mux. With an unreadable one
    # this would pass for the same reason kitty-unreadable-cwd-has-no-identity
    # does, i.e. for the wrong reason, which is the trap this file keeps
    # meeting (see learn-drops-absent-mux).
    _real_pending = engine._term_mux_pending
    try:
        engine._term_cwd = lambda _pid: "/w/proj"
        engine._term_mux_pending = lambda _pid: False
        ck("kitty-keys-normally-when-no-mux-pending",
           _kp.resolve(_kv).key == "kitty:/w/proj")
        engine._term_mux_pending = lambda _pid: True
        ck("kitty-defers-while-mux-pending",
           _kp.resolve(_kv).state == Resolution.PENDING)
        ck("kitty-mux-pending-is-unidentified", unidentified(_kv))
        ck("kitty-mux-pending-says-why",
           "mux" in (_kp.resolve(_kv).why or ""))
    finally:
        engine._term_cwd = _real_cwd
        engine._term_mux_pending = _real_pending

    # predict/verify's matcher. KEY FIRST, LABEL as the fallback, because a
    # chrome window's key is minted fresh by each browser process while its
    # title survives the restart, and a terminal's key survives while its
    # banner title does not. Getting the ORDER wrong would silently verify
    # the wrong window against the wrong expectation.
    # THE ROW'S LABEL HAS TO NAME A DIFFERENT WINDOW FROM ITS KEY, or the
    # ORDER is not exercised at all and the check passes whichever way round
    # the two lookups go. Caught by planting the label-first order against an
    # earlier fixture whose label matched nothing: it fell through to the key
    # either way, so this check had never tested the thing it is named for.
    _vrow = {"app_id": "kitty", "key": "term:resume", "label": "Inbox"}
    _vlive = [{"app_id": "kitty", "key": "term:resume", "title": "a:b"},
              {"app_id": "google-chrome", "key": "chrome:win:9",
               "title": "Inbox"}]
    _lk, _ll = verify_index(_vlive)
    _vhit, _vhow = _verify_find(_vrow, _lk, _ll)
    ck("verify-matches-on-key", _vhow == "key")
    ck("verify-matches-on-key-not-on-a-rival-label",
       _vhit[0]["key"] == "term:resume")
    ck("verify-falls-back-to-label",
       _verify_find({"app_id": "google-chrome", "key": "chrome:win:1",
                     "label": "Inbox"}, _lk, _ll)[1] == "label")
    ck("verify-reports-no-match",
       _verify_find({"app_id": "kitty", "key": "nope", "label": "nope"},
                    _lk, _ll) == (None, None))
    # A row with no slot must NOT be matched by an empty label, which would
    # pair it with whatever window happens to have a blank title.
    ck("verify-ignores-an-empty-label",
       _verify_find({"key": None, "label": ""}, _lk, _ll) == (None, None))

    # THE APP IS HALF THE KEY. Three of one account's apps share the
    # source-alone identity, so an index on the identity alone hands every
    # one of those rows the same window and reports the rows whose app it is
    # not as WRONG against their own correct expectation. Live on manifold
    # 2026-11-06 over a store with no drift: 24 ok, 2 wrong, both false.
    _vsrc = [{"app_id": "slack", "key": "titan", "title": "",
              "workspace": [1, 0], "pos": [376, 48], "size": [2473, 1684]},
             {"app_id": "chrome-aaa-Default", "key": "titan", "title": "",
              "workspace": [1, 0], "pos": [11, 129], "size": [2755, 1509]}]
    _sk, _sl = verify_index(_vsrc)
    ck("verify-index-separates-two-apps-on-one-identity", len(_sk) == 2)
    ck("verify-index-finds-the-row-its-own-app",
       _verify_find({"app_id": "chrome-aaa-Default", "key": "titan",
                     "label": ""}, _sk, _sl)[0][0]["pos"] == [11, 129])
    # A blank title must not become a label key, or every redacted foreign
    # window lands in one group and the fallback pairs them at random.
    ck("verify-index-ignores-a-blank-title", _sl == {})
    # AND THE PAIR IS NOT UNIQUE EITHER: a dict kept whichever was seen last,
    # so which row read ok came down to iteration order.
    _vdup = [{"app_id": "kitty", "key": "kitty:/h", "title": "a",
              "pos": [1, 1]},
             {"app_id": "kitty", "key": "kitty:/h", "title": "b",
              "pos": [9, 9]}]
    _dk, _dl = verify_index(_vdup)
    ck("verify-index-keeps-both-windows-of-a-shared-key",
       len(_dk) == 1 and len(_verify_find(
           {"app_id": "kitty", "key": "kitty:/h", "label": ""},
           _dk, _dl)[0]) == 2)

    # The deltas, and the tolerance that makes a rounded size agreement.
    _vexp = {"expect_workspace": [1, 0], "expect_pos": [10, 10],
             "expect_size": [100, 100]}
    ck("verify-deltas-agree-at-the-slot",
       _verify_deltas({"workspace": [1, 0], "pos": [10, 10],
                       "size": [101, 100]}, _vexp, 2) == [])
    ck("verify-deltas-name-the-field",
       [b.split()[0] for b in _verify_deltas(
           {"workspace": [1, 0], "pos": [80, 10], "size": [100, 100]},
           _vexp, 2)] == ["pos"])

    # A ROW A SHARED KEY LEFT BEHIND IS NOT A FAULT: one slot, N windows, and
    # the slot ledger leaves the rest where they opened. So the row is
    # satisfied if ANY of them is at the remembered place, and requiring ALL
    # would report that design as a fault on every box with two terminals in
    # one directory.
    _vgrp = [{"workspace": [1, 0], "pos": [99, 99], "size": [100, 100]},
             {"workspace": [1, 0], "pos": [10, 10], "size": [100, 100]}]
    ck("verify-one-of-a-shared-key-at-the-slot-is-ok",
       verify_verdict(_vgrp, _vexp, 2) == (True, []))
    _vno, _vbad = verify_verdict(_vgrp[:1], _vexp, 2)
    ck("verify-none-of-a-shared-key-at-the-slot-is-wrong", not _vno)
    ck("verify-a-wrong-row-reports-its-deltas",
       [b.split()[0] for b in _vbad] == ["pos"])

    # THE WIRING, because every check above is about functions do_verify has
    # to CALL, and this package has found that hole eight times.
    _vsrc_txt = inspect.getsource(engine.do_verify)
    ck("verify-indexes-through-the-one-definition",
       "verify_index(live)" in _vsrc_txt)
    ck("verify-does-not-index-on-the-identity-alone",
       'w.get("key"): w' not in _vsrc_txt)
    ck("verify-names-a-row-through-the-one-definition",
       "verify_row_name(r)" in _vsrc_txt)
    ck("verify-judges-a-group-through-the-one-definition",
       "verify_verdict(wins, r, tol)" in _vsrc_txt)
    # A row with no label prints its APP, or three of an account's apps all
    # report as the bare source name.
    ck("verify-row-name-prefers-the-label",
       verify_row_name({"label": "Inbox", "app_id": "a", "key": "b"})
       == "Inbox")
    ck("verify-row-name-falls-back-to-app-and-key",
       verify_row_name({"label": "", "app_id": "slack", "key": "titan"})
       == "slack | titan")

    # A STORED ENTRY IS THE ONE GENUINE `NEVER`: its pid is long dead, so no
    # amount of asking will ever make the cwd readable, and saying so beats
    # retrying forever. Replay uses the key recorded at capture instead.
    _stored = {"app": "kitty", "title": "kitty:/tmp", "pid": -1, "id": None}
    ck("kitty-stored-entry-is-never",
       _kp.resolve(_stored).state == Resolution.NEVER)
    ck("kitty-stored-entry-says-why", bool(_kp.resolve(_stored).why))
    # a constant title is no longer special to anything
    ck("plain-title-is-not-a-mux-term", not is_mux_term("kitty", "terminal"))
    # XWayland reports `Google-chrome`; both forms exist in a real store, and
    # only matching the lower-case one left those windows unclaimed
    ck("owns-chrome-xwayland", ps["chrome"].owns(_tv("Google-chrome")))
    ck("is_chrome-cases", is_chrome("Google-chrome") and is_chrome("chromium")
       and not is_chrome("kitty") and not is_chrome(None))
    ck("is_owned-xwayland", is_owned("Google-chrome"))
    ck("owns-mux", ps["mux"].owns(_tv("kitty", "wf:code")))
    ck("owns-kitty-notmux", not ps["mux"].owns(_tv("kitty", "✳ Claude Code"))
       and ps["kitty"].owns(_tv("kitty", "✳ Claude Code")))
    ck("owner-mux",
       engine._owner(_tv("kitty", "wf:code[manifold]")) is ps["mux"])
    ck("owner-kitty",
       engine._owner(_tv("kitty", "✳ Claude Code")) is ps["kitty"])
    ck("owns-nobody", engine._owner(_tv("slack", "Slack")) is None)
    ck("is_owned", is_owned("google-chrome") and is_owned("kitty")
       and not is_owned("slack"))

    # mux session parse: label-stripped, up to the first ':'; namespaced key
    ck("mux-session", mux_session_of("wf:code⠀[manifold]") == "wf")
    ck("mux-session-label", mux_session_of("[WORK] proj:main") == "proj")
    ck("mux-session-none", mux_session_of("terminal") is None)

    # host parse: the TRAILING tag only. The leading [LABEL] context prefix must
    # never be read as a host, and an untagged title falls back to this box.
    ck("mux-host", mux_host_of("wf:code⠀⠀⠀⠀[manifold]") == "manifold")
    ck("mux-host-label", mux_host_of("[WORK] proj:main") is None)
    ck("mux-host-both",
       mux_host_of("[WORK] proj:main⠀⠀⠀⠀[manifold]") == "manifold")
    # latch detection, the thing that decides replay-exactly vs fall back to
    # `mux resume`. Verified live once; this pins the matching itself.
    ck("latch-argv", _latch_target_in(
       ["/bin/sh", "/home/x/.cache/pkgs/mux/bin/../libexec/mux-latch",
        "manifestor:tackup"]) == "manifestor:tackup")
    ck("latch-argv-host-only",
       _latch_target_in(["/bin/sh", "/opt/mux/libexec/mux-latch",
                         "manifold"]) == "manifold")
    ck("latch-argv-none", _latch_target_in(
       ["tmux", "-L", "global", "attach-session", "-t", "=wf"]) is None)
    # a latch with NO target names no host, so there is nothing to replay
    ck("latch-argv-bare",
       _latch_target_in(["/bin/sh", "/opt/mux/libexec/mux-latch"]) is None)
    # must not match a lookalike basename
    ck("latch-argv-lookalike",
       _latch_target_in(["/opt/mux/libexec/mux-latcher", "box"]) is None)

    # THE USER'S OWN CONFIG LANGUAGE, which had NO checks at all: not the
    # `<app-regex> :: <title-regex>` parser, not either reload, not the
    # plugin drop-in. All three reloads were also in the set of functions
    # the suite never executed, and their whole published promise is that an
    # edit applies ON SAVE with no restart. LOSING THESE RULES IS SILENT,
    # since no rules parses fine and means "place everything", so the
    # symptom is windows moving that should not with nothing reporting a
    # fault.
    _cfg = tempfile.mkdtemp(prefix="usher-cfg-")
    _ex, _in = os.path.join(_cfg, "exclude"), os.path.join(_cfg, "include")
    _pd = os.path.join(_cfg, "plugins")
    os.makedirs(_pd)
    _o_ex, _o_in, _o_pd = (engine.EXCLUDE_FILE, engine.INCLUDE_FILE,
                           engine.PLUGIN_DIR)
    _o_er, _o_ee = engine.EXCLUDE_RULES, engine.EXCLUDE_ERRORS
    _o_ar, _o_ae = engine.ANCHOR_RULES, engine.ANCHOR_ERRORS
    _o_pl = engine._PLUGINS

    def _put(path, text):
        with open(path, "w") as f:
            f.write(text)

    _xv = _tv("zzz-x", "Secret Thing")
    _xo = _tv("zzz-x", "Ordinary")
    try:
        engine.EXCLUDE_FILE, engine.INCLUDE_FILE = _ex, _in
        engine.PLUGIN_DIR = _pd

        _put(_ex, "zzz-x :: ^Secret\n")
        engine.reload_exclude()
        ck("exclude-reload-applies", engine.is_transient(_xv)
           and not engine.is_transient(_xo))
        # A REWRITE MUST TAKE EFFECT, which is the live-edit promise and the
        # only thing distinguishing a reload from a one-time read.
        _put(_ex, "zzz-x :: ^Ordinary\n")
        engine.reload_exclude()
        ck("exclude-reload-picks-up-a-rewrite",
           engine.is_transient(_xo) and not engine.is_transient(_xv))
        # ONE BAD LINE MUST NOT COST THE FILE. A typo in a hand-edited rule
        # file is the ordinary case, and dropping every rule around it would
        # silently stop excluding anything.
        _put(_ex, "zzz-x :: ^Secret\nno separator here\nzzz-x :: ^Ordinary\n")
        engine.reload_exclude()
        ck("exclude-reports-a-bad-line", len(engine.EXCLUDE_ERRORS) == 1)
        ck("exclude-keeps-the-good-rules-either-side",
           len(engine.EXCLUDE_RULES) == 2 and engine.is_transient(_xv)
           and engine.is_transient(_xo))
        _put(_ex, "zzz-x :: ^(unclosed\n")
        engine.reload_exclude()
        ck("exclude-reports-a-bad-regex",
           not engine.EXCLUDE_RULES and len(engine.EXCLUDE_ERRORS) == 1)
        _put(_ex, "# a comment\n\n   \nzzz-x :: ^Secret\n")
        engine.reload_exclude()
        ck("exclude-ignores-comments-and-blanks",
           len(engine.EXCLUDE_RULES) == 1 and not engine.EXCLUDE_ERRORS)
        # NO FILE IS NO RULES AND NO ERRORS, which is the state doctor
        # reports: a missing file is "place everything" rather than a fault.
        os.remove(_ex)
        engine.reload_exclude()
        ck("exclude-with-no-file-is-no-rules",
           not engine.EXCLUDE_RULES and not engine.EXCLUDE_ERRORS)

        # A RULE THAT CAN FREEZE THE DAEMON IS REFUSED, which is stronger
        # than flagged on purpose: the system is protected above any
        # particular rule. CPython's regex engine does not release the GIL,
        # so a catastrophic backtracker stops capture, placer, status and
        # the event loop together, and the process that would report it is
        # the one that stopped. Measured: `^(a+)+$` against a title takes
        # 0.05s at twenty characters and gives NO ANSWER IN EIGHT SECONDS
        # at thirty.
        ck("probe-flags-a-catastrophic-pattern",
           engine.regex_probe(r"^(a+)+$") > engine.REGEX_PROBE_BUDGET)
        # THE MARGIN IS THE CLAIM, not the flagging: a check that refuses a
        # rule somebody legitimately wrote is one that gets switched off.
        # These are the fleet's own patterns plus what a person writes.
        _realistic = [r"org.gnome.Loupe", r"^.*$", r"^New Tab$",
                      r"google-chrome", r"^\[WORK", r"^Settings -.*",
                      r"kitty|foot|alacritty", r"^(Inbox|Sent) ",
                      r"[A-Za-z0-9_.-]+", r"^.{0,200}$", r"(?i)slack",
                      r".*\.(png|jpe?g|gif)$"]
        _worst = max(engine.regex_probe(p) for p in _realistic)
        ck("probe-clears-every-realistic-pattern",
           _worst * 10 < engine.REGEX_PROBE_BUDGET)
        # AND THE PROBE SET IS NOT EMPTY, or every pattern measures 0 and
        # the guard passes over nothing.
        ck("probe-actually-ran", engine.regex_probe(r"^(a+)+$") > 0)

        # THE RULE IS REFUSED AND THE GOOD ONE BESIDE IT SURVIVES, which is
        # the same rule as one bad line not costing the file.
        _put(_ex, "zzz-x :: ^(a+)+$\nzzz-x :: ^Secret\n")
        engine.reload_exclude()
        ck("a-dangerous-rule-is-refused",
           len(engine.EXCLUDE_RULES) == 1
           and len(engine.EXCLUDE_ERRORS) == 1)
        ck("the-rule-beside-a-refused-one-still-applies",
           engine.is_transient(_xv))
        # AND IT SAYS WHY, naming the pattern and the cause, because a
        # refusal a reader cannot act on is a silent loss with extra steps.
        # NOT `[0]`, which turned a plant that refuses NOTHING into an
        # IndexError and aborted the area instead of naming the cell.
        _why = (engine.EXCLUDE_ERRORS[0][2] if engine.EXCLUDE_ERRORS
                else "<nothing was refused>")
        ck("a-refusal-names-the-reason",
           "freeze" in _why and "(a+)+" in _why)
        # THE SAME GUARD ON THE APP SIDE, which runs FIRST and so would
        # freeze on any title at all.
        _put(_ex, "^(a+)+$ :: ^.*$\n")
        engine.reload_exclude()
        ck("a-dangerous-APP-pattern-is-refused-too",
           not engine.EXCLUDE_RULES and len(engine.EXCLUDE_ERRORS) == 1)

        # AND THE ESCALATION, which is the half that makes a refusal
        # reachable by somebody who is not reading watch.log. doctor is the
        # verb these notes say to run FIRST and it reported the rule files
        # NOT AT ALL until now, so a refused rule would have been a line in
        # a log and nothing else. A FAIL rather than a WARN because the box
        # is carrying a fault, and that is what sets doctor's exit code,
        # which is what a script or a provision can act on.
        from . import doctor as _drr

        def _contracts():
            _o = []
            _c = _drr._doctor_contracts(_o.append, None)
            return _c, "\n".join(_o)

        _rc_bad, _out_bad = _contracts()
        _put(_ex, "zzz-x :: ^Secret\n")
        engine.reload_exclude()
        _rc_ok, _out_ok = _contracts()
        ck("doctor-fails-on-a-refused-rule", _rc_bad == 1)
        ck("doctor-is-clean-when-the-rules-are", _rc_ok == 0)
        # PAIRWISE, since one message for both states is how a reader comes
        # to ignore the line: the two must READ differently as well as exit
        # differently.
        ck("doctor-reads-differently-either-way", _out_bad != _out_ok)
        ck("doctor-names-the-refused-rule",
           "bad rule" in _out_bad and "freeze" in _out_bad)
        ck("doctor-says-the-rules-are-clean-when-they-are",
           "rule files load with no errors" in _out_ok)

        _put(_in, "zzz-a :: ^Keep\n")
        engine.reload_anchor()
        ck("anchor-reload-applies", engine.is_anchored("zzz-a", "Keep This")
           and not engine.is_anchored("zzz-a", "Drop This"))
        _put(_in, "zzz-a :: ^Drop\n")
        engine.reload_anchor()
        ck("anchor-reload-picks-up-a-rewrite",
           engine.is_anchored("zzz-a", "Drop This")
           and not engine.is_anchored("zzz-a", "Keep This"))

        # THE PLUGIN DROP-IN, end to end: a file appears, the signature
        # changes (which is what triggers the reload in the daemon), and the
        # plugin then OWNS its app and resolves through the registry.
        engine.reload_plugins()
        _n0, _sig0 = len(engine.plugins()), engine.plugins_sig()
        _put(os.path.join(_pd, "zzzdropin.py"),
             "class P:\n"
             "    name = 'zzz-dropin'\n"
             "    def owns(self, v):\n"
             "        return v['app'] == 'zzz-dropin'\n"
             "    def resolve(self, v):\n"
             "        return ('ready', 'dropin:1')\n"
             "PLUGIN = P()\n")
        ck("plugins-sig-sees-a-new-file", engine.plugins_sig() != _sig0)
        engine.reload_plugins()
        ck("plugin-dropin-is-registered",
           len(engine.plugins()) == _n0 + 1
           and engine.is_owned("zzz-dropin"))
        ck("plugin-dropin-resolves",
           engine.resolution(_tv("zzz-dropin", "x")).key == "dropin:1")
        # AND REMOVING IT UNREGISTERS, or an uninstalled plugin would go on
        # claiming its app for the life of the daemon.
        os.remove(os.path.join(_pd, "zzzdropin.py"))
        engine.reload_plugins()
        ck("plugin-dropin-removal-unregisters",
           len(engine.plugins()) == _n0
           and not engine.is_owned("zzz-dropin"))
    finally:
        engine.EXCLUDE_FILE, engine.INCLUDE_FILE = _o_ex, _o_in
        engine.PLUGIN_DIR = _o_pd
        engine.EXCLUDE_RULES, engine.EXCLUDE_ERRORS = _o_er, _o_ee
        engine.ANCHOR_RULES, engine.ANCHOR_ERRORS = _o_ar, _o_ae
        engine._PLUGINS = _o_pl
        shutil.rmtree(_cfg, ignore_errors=True)

def _t_resolution(ck):
    """THE READINESS CONTRACT, as a table over every registered plugin.

    READ THROUGH _st/_wh BELOW, never off the object directly. If the thing
    under test stops returning a Resolution, `r.state` raises and the
    AttributeError ABORTS the suite before the summary prints, so a correctly
    caught regression reads as "nothing failed". Met for real while planting
    these; it is the same false negative the greeter regression harness hit.

    All four historical readiness bugs were ONE PLUGIN forgetting, so the
    check that matters is not "does chrome behave" but "does every plugin,
    including one a user drops in tomorrow, obey the same rule". A table is
    what catches that; a per-plugin check is what missed it four times."""
    def _st(v):
        """resolution(v).state, or None if it is not even a Resolution."""
        return getattr(resolution(v), "state", None)

    def _wh(v):
        return getattr(resolution(v), "why", None)

    # 1. THE TYPE ITSELF. Three states, exactly one of them ready, and a
    #    reason on both no-answers (doctor prints it; a silent Pending is the
    #    hardcoded-explanation problem coming back).
    ck("resolution-ready-is-ready", Resolution.ready("k").is_ready)
    ck("resolution-ready-carries-the-key", Resolution.ready("k").key == "k")
    ck("resolution-pending-is-not-ready", not Resolution.pending("w").is_ready)
    ck("resolution-never-is-not-ready", not Resolution.never("w").is_ready)
    ck("resolution-pending-has-no-key", Resolution.pending("w").key is None)
    ck("resolution-never-has-no-key", Resolution.never("w").key is None)
    ck("resolution-pending-carries-why", Resolution.pending("w").why == "w")
    ck("resolution-never-carries-why", Resolution.never("w").why == "w")
    ck("resolution-states-are-distinct",
       len({Resolution.READY, Resolution.PENDING, Resolution.NEVER}) == 3)

    # 1b. NO APP-ID AND NO TITLE IS NO HANDLE, so it is NEVER rather than
    #     Ready(""). An empty key matches every other handle-less window, so
    #     remembering one would drag the next onto the last one's geometry.
    #     A real `kkey("", "")` entry was found in the live store, 354x31 at
    #     ws(2,0), aged ten days and matchable by anything.
    _none = _trv("", "")
    ck("resolution-no-handle-is-never", _st(_none) == Resolution.NEVER)
    ck("resolution-no-handle-says-why", bool(_wh(_none)))
    ck("no-handle-is-unidentified", unidentified(_none))
    #     A TITLE IS STILL A HANDLE for an unowned app, and must not be
    #     discarded just because the app-id is missing: is_unique() used to
    #     call the empty app-id unique, which keyed by app_id ALONE and threw
    #     the title away.
    _titled = _trv("", "Volume Control")
    ck("blank-app-with-a-title-is-ready", _st(_titled) == Resolution.READY)
    ck("blank-app-keeps-its-title", not unidentified(_titled))
    ck("blank-app-is-never-appid-keyed",
       not is_unique("", Counter({"": 1})))
    ck("a-real-app-alone-is-still-appid-keyed",
       is_unique("signal", Counter({"signal": 1})))

    # 2. EVERY PLUGIN, including the base and anything a user registered.
    #    A plugin that answers at all must answer with a Resolution, must
    #    carry a key when ready, and must carry a reason when it does not.
    _vs = [_tv("kitty", "terminal"), _tv("kitty", "s:w\u2800[host]"),
           _tv("google-chrome", "Inbox"), _tv("nosuchapp", "x")]
    for _p in list(engine.plugins()) + [WindowPlugin()]:
        for _i, _v in enumerate(_vs):
            _r = _p.resolve(pview(_v))
            # The view index is IN THE NAME so a failure localises to the
            # exact row; a looped check with one name cannot say which input
            # broke it, which is the whole value of naming them.
            _n = f"contract-{_p.name}-v{_i}"
            ck(f"{_n}-returns-a-Resolution", isinstance(_r, Resolution))
            if _r.is_ready:
                ck(f"{_n}-ready-has-a-key", bool(_r.key))
            else:
                ck(f"{_n}-unready-says-why", bool(_r.why))

    # 2b. THE DUCK-TYPED FORM. A user plugin is documented as needing no
    #     import of usher, so a 2-tuple has to be as good as a Resolution or
    #     that promise is quietly broken. The OLD contract's bare string must
    #     NOT be read as a key: that is the fail-safe direction.
    ck("duck-ready-tuple", _as_resolution(("ready", "k"), "t").key == "k")
    ck("duck-pending-tuple",
       _as_resolution(("pending", "w"), "t").state == Resolution.PENDING)
    ck("duck-never-tuple",
       _as_resolution(("never", "w"), "t").state == Resolution.NEVER)
    ck("duck-pending-tuple-keeps-why",
       _as_resolution(("pending", "w"), "t").why == "w")
    ck("duck-ready-tuple-has-no-why",
       _as_resolution(("ready", "k"), "t").why is None)
    for _bad in ("kitty:/tmp", None, ("ready",), ("bogus", "x"), 7, ()):
        ck(f"duck-rejects-{type(_bad).__name__}-{str(_bad)[:8]}",
           _as_resolution(_bad, "t").state == Resolution.PENDING)
    ck("duck-rejection-names-the-fix",
       "2-tuple" in (_as_resolution("k", "t").why or ""))

    # 2d. AND A PLUGIN WITH NO `name`, which is the same promise one step
    #     further out: `name` is in NEITHER PLUGIN_HOOKS nor the README nor
    #     the man page, and appears only as an uncommented line in the
    #     example, so a plugin written from the documented hooks has none.
    #     Reading it bare raised OUT of resolution, so identity,
    #     unidentified, _single_id and SNAPSHOT all raised, leaving the
    #     daemon alive and BLIND: `capture error` every second and nothing
    #     learned or placed again. A LABEL USED TO REPORT A FAILURE MUST NOT
    #     BE ABLE TO CAUSE ONE.
    class _Nameless:                       # deliberately no `name`
        def owns(self, v):
            return v["app"] == "zzz-nameless"

        def resolve(self, v):
            return ("ready", "nameless:1")

    class _NamelessRaises:                 # the worse pair: no name AND it
        def owns(self, v):                 # raises, so the HANDLER reads it
            return v["app"] == "zzz-nameless-raises"

        def resolve(self, v):
            raise RuntimeError("boom")

    _nv = _tv("zzz-nameless", "x")
    _nr = _tv("zzz-nameless-raises", "x")

    def _res(v):
        """GUARDED, so the pre-fix code fails BY NAME. Unguarded, its
        AttributeError aborts the area and is reported as
        `_t_resolution-RAISED-AttributeError`, which localises to five
        hundred checks instead of to the cell. This file's own rule, and
        the plant is what showed my check breaking it."""
        try:
            return engine.resolution(v)
        except Exception as e:                             # noqa: BLE001
            return Resolution.pending(f"RAISED {type(e).__name__}: {e}")

    _real = engine._PLUGINS
    try:
        engine._PLUGINS = [_Nameless(), _NamelessRaises()]
        ck("nameless-plugin-resolves", _res(_nv).key == "nameless:1")
        ck("nameless-plugin-that-raises-is-pending",
           not _res(_nr).is_ready and "boom" in (_res(_nr).why or ""))
        # AND THE CONTROL, or "always print ?" would pass the row above: a
        # plugin that DOES carry a name must still be named in the reason,
        # since that message is the only thing telling a reader whose
        # plugin broke.
        class _NamedRaises:
            name = "zzz-named"

            def owns(self, v):
                return v["app"] == "zzz-named"

            def resolve(self, v):
                raise RuntimeError("boom")

        engine._PLUGINS = [_NamedRaises()]
        ck("a-named-plugin-that-raises-is-still-named",
           "zzz-named" in (_res(_tv("zzz-named", "x")).why or ""))
    finally:
        engine._PLUGINS = _real

    # 2c. DOCTOR'S LABELS. Three states must print as three labels, which is
    #     the reporting payoff of all this and was left unspent for a day:
    #     the first cut said `unjoinable` for any window with a reason, so a
    #     Chrome window that had merely not been written yet read as one that
    #     never would. That is the same overclaim the old hardcoded text made.
    from .doctor import _unmatched_why as _uw
    _real_owner = engine._owner
    try:
        class _P(WindowPlugin):
            name = "labeltest"
            st = Resolution.READY

            def owns(self, v):
                return True

            def resolve(self, v):
                if _P.st == Resolution.READY:
                    return Resolution.ready("k")
                if _P.st == Resolution.PENDING:
                    return Resolution.pending("not yet")
                return Resolution.never("never will")

        engine._owner = lambda _v: _P()
        _lv = _trv("kitty", "x")
        _P.st = Resolution.READY
        ck("doctor-ready-is-unmatched", _uw(_lv)[0] == "unmatched")
        _P.st = Resolution.PENDING
        ck("doctor-pending-is-pending", _uw(_lv)[0] == "pending")
        _P.st = Resolution.NEVER
        ck("doctor-never-is-unjoinable", _uw(_lv)[0] == "unjoinable")
        ck("doctor-labels-are-three-distinct", len({
            _uw(_lv)[0] for _P.st in (Resolution.READY, Resolution.PENDING,
                                      Resolution.NEVER)}) == 3)
        _P.st = Resolution.PENDING
        ck("doctor-prints-the-plugin-reason", "not yet" in _uw(_lv)[1])
    finally:
        engine._owner = _real_owner

    # THE COLLISION REMEDY, three cases that must stay distinct. A chrome
    # slot duplicate is usher mis-resolving (a SessionID names ONE window),
    # NOT a missing plugin, and Chrome already has one: that advice would
    # send the reader nowhere. Asserted PAIRWISE, since collapsing two is
    # exactly how the wrong remedy gets printed.
    from .doctor import collision_fix as _cfix
    # FOUR CASES NOW, PAIRWISE DISTINCT. A window from another account must
    # NOT be told to write a plugin: a plugin could not read that account's
    # app state either, so there is nothing a reader can do and saying so is
    # the only honest answer. Collapsing any two of these sends somebody to
    # fix the wrong thing, which is why they are asserted as a SET.
    ck("collision-fix-names-a-source",
       "titan" in _cfix("titan", "titan")
       and "plugin" not in _cfix("titan", "titan"))
    ck("collision-fix-six-cases-are-pairwise-distinct",
       len({_cfix("titan", "titan"), _cfix("titan", "titan", 6),
            _cfix("titan:abc123", "titan", 6),
            _cfix("chrome:win:1"), _cfix("kitty:/tmp"),
            _cfix("whatever")}) == 6)
    # A REAL COLLISION ON A PER-WINDOW KEY IS NOT BLINDNESS, and it became
    # reachable the moment the daemon started PUBLISHING its map: the report
    # resolves per window now, so two windows landing on one
    # `<source>:<digest>` key share an identity INSIDE that account. Saying
    # "this report cannot see it" there sends a reader to look for a daemon
    # that is working.
    ck("collision-on-a-per-window-key-is-reported-as-real",
       "cannot see" not in _cfix("titan:abc123", "titan", 6)
       and "ONE identity" in _cfix("titan:abc123", "titan", 6))
    # AND IT DOES NOT REPEAT THE OUTER LINE, which already states the
    # consequence: the message's job is the CAUSE and who could fix it.
    ck("collision-on-a-per-window-key-adds-to-the-outer-line",
       "stay where" not in _cfix("titan:abc123", "titan", 6)
       and "only that account" in _cfix("titan:abc123", "titan", 6))
    ck("collision-on-a-per-window-key-names-the-account",
       "titan" in _cfix("titan:abc123", "titan", 6))
    # AND IT STILL OFFERS NO REMEDY HERE, because only that account can make
    # them distinct: a plugin on this side could not read its state either.
    ck("collision-on-a-per-window-key-does-not-say-write-a-plugin",
       "plugin" not in _cfix("titan:abc123", "titan", 6))

    # THE RELAUNCH SECTION ITSELF, driven, because its faults were in the
    # BRANCHING and not in any message function: the suite had never executed
    # it. Reading its real output is what found all three.
    if os.getuid() != 0:
        from . import doctor as _dr
        _d_state = tempfile.mkdtemp(prefix="usher-drep-")
        _d_old, _d_old2 = engine.STATE, _dr.STATE
        # doctor imports STATE BY NAME and holds its own copy, so patching
        # engine's alone leaves its `load_knowledge()` reading the REAL store
        # and the check answering from the host.
        try:
            engine.STATE = _dr.STATE = _d_state
            with _tprofile("drep"):
                save_knowledge({}, "drep")

                def _srow(app, **kw):
                    r = {"app_id": app, "title": kw.pop("title", ""),
                         "key": kw.pop("key", ""), "id": kw.pop("vid", 1),
                         "pid": -1, "cmd": None, "output": "DP-1",
                         "workspace": [0, 0], "pos": [1, 2], "size": [3, 4]}
                    r.update(kw)
                    return r

                def _report(saved, live, hook=None):
                    _rows = []
                    _rh = engine.SOURCE_TRIGGER_HOOK
                    try:
                        if hook is not None:
                            engine.SOURCE_TRIGGER_HOOK = hook
                        _dr._doctor_relaunch(_rows.append,
                                             {"time": 0, "windows": saved},
                                             live)
                    finally:
                        engine.SOURCE_TRIGGER_HOOK = _rh
                    return "\n".join(_rows)

                # ANOTHER ACCOUNT'S SAVED WINDOW. It fell through to the
                # per-window verdicts, resolved its app-id in the OWNER's
                # registry and printed `RELAUNCH slack (/usr/bin/slack)`: an
                # action usher does not take, naming the owner starting
                # somebody's work application, which is the most alarming
                # thing this report could say falsely.
                _theirs = [_srow("slack", key="titan", source="titan",
                                 owner=997)]
                _r1 = _report(_theirs, [], hook=sys.executable)
                ck("doctor-asks-the-account-for-its-own-windows",
                   "ASK" in _r1 and "titan" in _r1)
                ck("doctor-never-offers-to-relaunch-another-accounts-window",
                   "RELAUNCH" not in _r1 and "START" not in _r1)
                # AND WITH NO HOOK IT SAYS SO AND NAMES THE PATH, which is
                # source_trigger's own never-silent rule: nothing starts them
                # and the reader is owed the reason, not a cheerful omission.
                _r2 = _report(_theirs, [],
                              hook=os.path.join(_d_state, "no-such-hook"))
                ck("doctor-says-when-no-hook-will-start-them",
                   "no source-trigger hook" in _r2
                   and "no-such-hook" in _r2)
                ck("doctor-hook-present-and-absent-read-differently",
                   _r1 != _r2)
                # THE OWNER'S CHROME, with ONLY another account's browser
                # live. The engine starts ours (its plugin asks per user and
                # says why); the report counted any live browser and said
                # `self`, so it described a desk coming back that would not.
                _r3 = _report([_srow("google-chrome", key="chrome:win:7")],
                              [_trv("google-chrome", "theirs", pid=1)])
                ck("doctor-a-foreign-browser-does-not-read-as-ours-being-up",
                   "START" in _r3 and "self" not in _r3)
                ck("doctor-our-own-live-browser-still-reads-as-up",
                   "self" in _report(
                       [_srow("google-chrome", key="chrome:win:7")],
                       [_trv("google-chrome", "mine", pid=os.getpid())]))
                # AND A REASON IS NOT CUT MID-SENTENCE. At 30 characters
                # "no desktop entry names this app" lost its last letter and
                # read as a typo, and "<app>.desktop is NoDisplay=true: the
                # registry ..." was cut to a sentence that reads COMPLETE, so
                # a reader never learns the explanation was taken away.
                _r4 = _report([_srow("zzz-no-entry-names-this",
                                     title="Thing", key="Thing")], [])
                ck("doctor-gives-the-whole-reason",
                   "names this app)" in _r4)
        finally:
            engine.STATE, _dr.STATE = _d_old, _d_old2
            shutil.rmtree(_d_state, ignore_errors=True)

    # THE FIFTH CASE: not a collision at all, but THIS REPORT's blindness.
    # `_SOURCE_WINDOWS` is filled by the refresh and so belongs to the
    # DAEMON's process; a one-shot verb resolves every one of a source's
    # windows to the source-alone key and counted them as sharing a slot.
    # Measured on manifold 2026-11-04: seven of one account's Chrome windows
    # gave ONE key in a verb and SEVEN distinct keys once the cache was
    # filled in the same process. So doctor was naming a FAULT that was not
    # happening, which this file rates as worse than naming nothing.
    ck("collision-per-window-slots-say-it-is-not-a-collision",
       "cannot see" in _cfix("titan", "titan", 6)
       and "6" in _cfix("titan", "titan", 6))
    ck("collision-per-window-does-not-claim-usher-cannot-tell",
       "cannot tell" not in _cfix("titan", "titan", 6))
    # AND THE GENUINE FOREIGN COLLISION SURVIVES, which is the terminal case:
    # only chrome-shaped identities pass `parse_source_windows`, so a foreign
    # kitty has no per-window slot and really does share one key.
    ck("collision-no-per-window-slots-is-still-a-collision",
       "cannot tell" in _cfix("titan", "titan", 0))

    # THE COUNT ITSELF, pure, so every cell is reachable with no daemon.
    _pwkb = {engine.kkey("google-chrome", "titan"): {},
             engine.kkey("google-chrome", "titan:chrome:win:11"): {},
             engine.kkey("google-chrome", "titan:chrome:win:22"): {},
             engine.kkey("google-chrome", "other:chrome:win:33"): {},
             engine.kkey("kitty", "titan"): {},
             engine.kkey("google-chrome", "chrome:win:44"): {}}
    ck("per-window-slots-counts-only-this-source",
       engine.source_per_window_slots(_pwkb, "google-chrome", "titan") == 2)
    ck("per-window-slots-ignores-the-source-alone-key",
       engine.source_per_window_slots(_pwkb, "kitty", "titan") == 0)
    ck("per-window-slots-ignores-another-sources-keys",
       engine.source_per_window_slots(_pwkb, "google-chrome", "other") == 1)
    # AN OWNER WINDOW HAS NO SOURCE, and BOTH SPELLINGS OF "none" have to be
    # passed. `""` is what `source_of` answers and is correct by arithmetic
    # even with the guard gone (no identity begins with a colon), so a plant
    # removing the guard was INVISIBLE to a check that passed only `""`.
    # `None` is what a bare `.get("source")` answers and raises TypeError on
    # `None + ":"` without it. So the guard is load-bearing and the usual
    # uncatchable-plant signal would have had it DELETED: that signal reads
    # "dead code" and here it read "the fixture is too narrow".
    ck("per-window-slots-is-zero-for-the-owner",
       engine.source_per_window_slots(_pwkb, "google-chrome", "") == 0)
    # GUARDED, so the guard's removal is a NAMED failure rather than a raise
    # that aborts the area: the sentinel is this file's own idiom for it.
    try:
        _pwn = engine.source_per_window_slots(_pwkb, "google-chrome", None)
    except Exception:                                   # noqa: BLE001
        _pwn = "RAISED"
    ck("per-window-slots-survives-a-None-source", _pwn == 0)

    # AND THE WIRING, because the pure helper's checks say nothing about
    # whether doctor consults it or about the TAG: COLLISION names a fault
    # and invites a reader to act, so the blind case must not wear it.
    import pathlib as _pl
    _dsrc = (_pl.Path(engine.__file__).parent / "doctor.py").read_text()
    ck("doctor-asks-for-the-per-window-count",
       "source_per_window_slots(kb," in _dsrc)
    ck("doctor-does-not-call-the-blind-case-a-collision",
       "NOT RESOLVED HERE" in _dsrc)
    # AND THE BLIND TAG IS GATED ON A SOURCE-ALONE KEY, not merely on the
    # count being non-zero: with the map published a verb resolves per
    # window, so a collision on a `<source>:<digest>` key is REAL and must
    # not wear a tag that tells the reader this report cannot see.
    ck("doctor-reserves-the-blind-tag-for-a-source-alone-key",
       "_pw and _ident == _csrc" in _dsrc)

    # A CHROME ENTRY KEYED BY A RAW TITLE is litter nothing can match, and
    # until this nothing named it: three sat on manifold, found by a content
    # sweep of the dry run rather than by any check.
    _slot = engine.kkey("google-chrome", "chrome:win:17")
    _ttl = engine.kkey("google-chrome", "Inbox (1) - Gmail")
    _only = engine.kkey("google-chrome", "")
    _kbt = {_slot: {}, _ttl: {}, _only: {},
            engine.kkey("signal", "Signal"): {},
            # ANOTHER ACCOUNT'S per-window key is the source name plus an
            # OPAQUE DIGEST, so it is correctly not a slot and reading it as
            # stale would report every one of them.
            engine.kkey("google-chrome", "titan:80a4286f0c64c477"):
                {"source": "titan"}}
    # NOT `_st`, which is already a resolution helper in this area and
    # which a bare assignment shadows: the suite named it at once.
    _stl = engine.stale_chrome_titles(_kbt)
    ck("a-chrome-title-key-is-reported-as-stale", _stl == [_ttl])
    ck("a-chrome-slot-is-not-stale", _slot not in _stl)
    ck("the-app-id-only-chrome-key-is-not-stale", _only not in _stl)
    ck("another-accounts-digest-is-not-read-as-stale",
       not any((_kbt[k].get("source") or "") for k in _stl))
    ck("a-non-chrome-title-key-is-not-stale",
       not any(k.startswith("signal") for k in _stl))
    # AND THE WIRING, the hole this file records ten times over: the pure
    # function's checks say nothing about whether doctor prints it.
    ck("doctor-reports-the-stale-chrome-titles",
       "stale_chrome_titles(kb)" in _dsrc)

    # A DESK UNVISITED FOR LONGER THAN THE TTL used to lose its memory on
    # the first visit back, AFTER placing from it once: the prune is
    # wall-clock and fires on LEARN, never on load, so the order was place,
    # then strip. Measured on manifestor: five dormant stores, 25 entries,
    # 51 to 74 days, and ZERO survivors in a prune today.
    #
    # `forgive_dormancy` shifts the store forward by the gap it was away, so
    # a desk's memory ages only while the desk is in USE. Three stateless
    # cutoff rules were simulated first and all fail, which is why this
    # moves the DATA and not the cutoff.
    _fd = engine.forgive_dormancy
    _ttl = engine.KNOWLEDGE_TTL
    _n0 = time.time()

    def _store(*ages_d):
        return {"a%d\x00x" % i: {"last_seen": _n0 - d * 86400}
                for i, d in enumerate(ages_d)}

    # THE REAL SHAPE: a desk last used 60 days ago, holding one entry seen on
    # its last day, one 10 days before that, and one 40 days before that,
    # which was ALREADY stale when the desk went dormant.
    _dorm = _store(60, 70, 100)
    _gap = _fd(_dorm, _n0)
    ck("dormancy-is-forgiven-by-the-gap-it-was-away",
       abs(_gap - 60 * 86400) < 2)
    # RELATIVE STALENESS SURVIVES EXACTLY, which is the property all three
    # rejected rules lack and the whole reason this is safe to do: every
    # entry moves by the SAME gap, so staleness earned while the desk was in
    # USE is kept and only the dormancy is forgiven.
    _ages = sorted(round((_n0 - e["last_seen"]) / 86400.0)
                   for e in _dorm.values())
    ck("forgiving-dormancy-keeps-relative-staleness", _ages == [0, 10, 40])
    # ...so the entry that was already stale is STILL pruned, and the other
    # two survive, which is what the whole change is for.
    engine.prune_kb(_dorm, _n0)
    ck("the-already-stale-entry-is-still-pruned", len(_dorm) == 2)

    # A LIVE DESK IS UNTOUCHED: its gap is seconds, which is what the floor
    # is for. Asserted byte-for-byte, because a shift of a few seconds would
    # pass a looser test while still rewriting every entry in the store.
    # SECONDS OLD, NOT EXACTLY NOW, which is what a real live store looks
    # like: with the newest entry at age 0 the gap is exactly 0 and a plant
    # removing the floor entirely passed this cell. The fixture has to make
    # the floor load-bearing.
    _live = {"k\x00a": {"last_seen": _n0 - 2.0},
             "k\x00b": {"last_seen": _n0 - 86400.0}}
    _was = json.dumps(_live, sort_keys=True)
    ck("a-live-desk-is-not-shifted", _fd(_live, _n0) == 0.0
       and json.dumps(_live, sort_keys=True) == _was)
    # AND THE FLOOR IS WHAT DECIDES, rather than the TTL or a guess: just
    # under it moves nothing, just over it moves.
    _a = {"k": {"last_seen": _n0 - engine.DORMANT_FLOOR + 10}}
    _b = {"k": {"last_seen": _n0 - engine.DORMANT_FLOOR - 10}}
    ck("the-floor-is-what-separates-a-respawn-from-a-return",
       _fd(_a, _n0) == 0.0 and _fd(_b, _n0) > 0)

    # SELF-LIMITING, so a worker respawn cannot forgive the same gap twice:
    # after the first load `newest` IS now, so every later load computes ~0.
    _s = _store(60)
    _gaps = []
    for _i in range(4):
        _gaps.append(_fd(_s, _n0 + 5.0 * (_i + 1)))
    ck("forgiving-dormancy-is-self-limiting",
       _gaps[0] > 86400 and all(g == 0.0 for g in _gaps[1:]))

    # AN EMPTY STORE, AND ONE WITH NO TIMESTAMPS, CONCLUDE NOTHING rather
    # than shifting by `now`, which would be a gap measured from the epoch.
    ck("an-empty-store-is-not-shifted", _fd({}, _n0) == 0.0)
    ck("a-store-with-no-timestamps-is-not-shifted",
       _fd({"k": {}}, _n0) == 0.0)
    # A NON-DICT ENTRY MUST NOT RAISE HERE either: load_knowledge drops those
    # just above, and this runs on the same pass.
    ck("a-non-dict-entry-does-not-break-the-shift",
       _fd({"k": "not an entry", "j": {"last_seen": _n0 - 60 * 86400}}, _n0)
       > 0)

    # THE RESCUE COUNT, which is what the report must say rather than the
    # store SIZE. An entry counts only if it sat OUTSIDE the cutoff before
    # the shift and INSIDE it after, which makes the line rare and always
    # meaningful with no threshold to tune.
    _dres = engine.dormancy_rescued
    _day = 86400.0
    ck("dormancy-rescue-counts-what-crossed-the-cutoff",
       _dres({"k": {"last_seen": _n0 - (_ttl - 2 * _day)}},
             _n0, 10 * _day) == 1)
    # THE QUIET-DESK CASE, which is the whole defect: an entry nowhere near
    # the cutoff is not rescued by a gap that moved it.
    ck("dormancy-rescue-ignores-what-was-never-at-risk",
       _dres({"k": {"last_seen": _n0 - 60.0}}, _n0, 600.0) == 0)
    # AND ONE STILL STALE AFTERWARDS IS NOT A RESCUE, which is the other half
    # of the shift's own promise: dormancy is forgiven, staleness is not.
    ck("dormancy-rescue-ignores-what-is-still-stale",
       _dres({"k": {"last_seen": _n0 - (_ttl + 2 * _day)}},
             _n0, 60.0) == 0)
    ck("no-gap-rescues-nothing",
       _dres({"k": {"last_seen": _n0 - _ttl + 60}}, _n0, 0.0) == 0)
    ck("a-non-dict-entry-does-not-break-the-rescue-count",
       _dres({"k": "not an entry",
              "j": {"last_seen": _n0 - (_ttl - 2 * _day)}},
             _n0, 10 * _day) == 1)

    # AND THE WIRING: the shift happens at LOAD, which is the only moment
    # before the first capture with the whole store in hand. The function's
    # own cells say nothing about whether anything calls it, which is the
    # hole this file records eleven times.
    _rstate, _rprof = engine.STATE, engine.profile_id
    _tdir = tempfile.mkdtemp(prefix="usher-ttl-", dir="/var/tmp")
    try:
        engine.STATE = _tdir
        engine.profile_id = lambda *a, **k: "DESK"
        # `write_json` takes a BLOB, not an object: it is the atomic rename,
        # and the caller does the encoding.
        engine.write_json(
            os.path.join(_tdir, "knowledge-DESK.json"),
            json.dumps(_store(60, 70)))
        engine.write_json(os.path.join(_tdir, "knowledge-DESK.schema"),
                          str(engine.KB_SCHEMA))
        _loaded = engine.load_knowledge("DESK")
        # AND THEN PRUNE, because `load` does not: the loss is the first
        # CAPTURE after the return, so a cell that only loads passes whether
        # or not the gap was forgiven. The plant that removes the call is
        # caught by this and by nothing else.
        engine.prune_kb(_loaded, time.time())
        ck("load-forgives-a-dormant-desk", len(_loaded) == 2)
        # THE CONTROL: without it this passes over a load that has stopped
        # pruning altogether rather than one that forgave correctly.
        engine.write_json(
            os.path.join(_tdir, "knowledge-DESK.json"),
            json.dumps({"k\x00x": {"last_seen": _n0 - 60 * 86400},
                        "k\x00y": {"last_seen": _n0 - 200 * 86400}}))
        _l2 = engine.load_knowledge("DESK")
        engine.prune_kb(_l2, time.time())
        ck("load-forgiveness-still-prunes-what-was-stale-at-that-desk",
           len(_l2) == 1)

        # AND THE LINE REPORTS THE RESCUE, NOT THE STORE SIZE, which is the
        # defect this closes. Measured on manifestor: NINE lines in one day,
        # four from the real daemon and three inside one second, every one
        # `away 0.0 day(s), so 1 entr(ies) are not aged for it` over a store
        # where nothing was within the TTL's reach.
        _said = []
        _rl = engine.logline
        try:
            engine.logline = _said.append
            # A QUIET DESK: one entry, fresh, and a gap just over the floor.
            # The shift is REAL and saves nothing, so nothing is said. This
            # is the manifestor shape exactly.
            engine.write_json(
                os.path.join(_tdir, "knowledge-DESK.json"),
                json.dumps({"k\x00q": {
                    "last_seen": _n0 - engine.DORMANT_FLOOR - 60}}))
            engine.load_knowledge("DESK")
            _quiet = [m for m in _said if "not aged out" in m]
            _said.clear()
            # ...and a desk away two months, where BOTH entries really are
            # saved from the next capture's prune.
            engine.write_json(
                os.path.join(_tdir, "knowledge-DESK.json"),
                json.dumps(_store(60, 70)))
            engine.load_knowledge("DESK")
            _loud = [m for m in _said if "not aged out" in m]
            _said.clear()
            # AND THE UNITS MUST FIT THE GAP, which was the other half of the
            # noise: `0.0 day(s)` cannot express anything under 72 minutes,
            # and a rescue can be driven by a gap of HOURS. Two entries, so
            # the NEWEST sets a two-hour gap and the other is what it saves.
            #
            # THE OLD ENTRY MUST START OUTSIDE THE CUTOFF, which a first
            # fixture got wrong: at `_ttl - 1800` it was already SAFE, so
            # nothing was rescued, the line was correctly silent, and the
            # cell failed over the product working. Ask what inputs a guard
            # tells apart.
            engine.write_json(
                os.path.join(_tdir, "knowledge-DESK.json"),
                json.dumps({"k\x00new": {"last_seen": _n0 - 2 * 3600},
                            "k\x00old": {"last_seen": _n0 - _ttl - 1800}}))
            engine.load_knowledge("DESK")
            _hours = [m for m in _said if "not aged out" in m]
        finally:
            engine.logline = _rl
        ck("a-trivial-gap-is-forgiven-in-silence", not _quiet)
        # THE CONTROL, or the cell above passes over a line that was deleted
        # outright rather than one that learned when to speak.
        ck("a-real-dormancy-reports-what-it-rescued",
           len(_loud) == 1 and "2 entr" in _loud[0]
           and "day(s)" in _loud[0])
        # AND THE COUNT IS THE RESCUE AND NOT THE STORE SIZE, which this
        # fixture can tell apart where the one above cannot: TWO entries are
        # stored and exactly ONE of them was saved.
        ck("the-gap-is-reported-in-units-that-fit-it",
           len(_hours) == 1 and "hour(s)" in _hours[0]
           and "0.0 day" not in _hours[0] and "1 entr" in _hours[0])
    finally:
        engine.STATE, engine.profile_id = _rstate, _rprof
        shutil.rmtree(_tdir, ignore_errors=True)
    # --- THE TERMINAL NOTE: only a fault when there ARE terminals --------
    # The 2026-09-15 purge compared store KEYS against RAW live titles, so
    # nothing matched and it deleted every terminal entry on the pass that
    # wrote it: 294 entries, ZERO for kitty, WITH TWO MUX TERMINALS ON
    # SCREEN. This line is that signature, and it had NO checks, which is why
    # it was gated on the store alone and fired on every box with no terminal
    # open, naming a fault that was not happening. Fourth doctor message of
    # that class.
    #
    # doctor IMPORTS ITS LOADERS BY NAME, so its own copies are what must be
    # stubbed: patching engine's would leave doctor reading the real store,
    # which is the stale-copy hazard this package documents.
    _dsave = (_dr.load_knowledge, _dr.load_snapshot, _dr._doctor_surfaces,
              _dr.profile_id)
    try:
        _dr._doctor_surfaces = lambda *a, **k: None
        _dr.profile_id = lambda *a, **k: "P"

        def _store_rows(kb, snap):
            _dr.load_knowledge = lambda *a, **k: kb
            _dr.load_snapshot = lambda *a, **k: snap
            rows = []
            _dr._doctor_store(rows.append)
            return [r for r in rows if "NO kitty entries" in r]

        _term = {"app_id": "kitty", "title": "t"}
        _sig = {"windows": [_term, _term], "time": time.time()}
        # THE REAL SIGNATURE: terminals in the last capture, none in the store
        ck("doctor-names-the-missing-terminal-entries",
           len(_store_rows({"signal\x00": {"last_seen": time.time()}},
                           _sig)) == 1)
        # ...AND IT IS SILENT WITH NO TERMINAL OPEN, which is an ordinary
        # state and was the false alarm: a box whose terminals the user
        # closed has no kitty entries CORRECTLY, and the purge dropping them
        # is the fail-safe working.
        ck("doctor-is-silent-when-no-terminal-is-open",
           _store_rows({"signal\x00": {"last_seen": time.time()}},
                       {"windows": [{"app_id": "signal", "title": "S"}],
                        "time": time.time()}) == [])
        # ...and silent when the store DOES remember them, which is the
        # control: without it both cells above pass over a line that has
        # stopped printing at all.
        ck("doctor-is-silent-when-the-terminals-are-remembered",
           _store_rows({"kitty\x00term:resume": {"last_seen": time.time()}},
                       _sig) == [])
        # A MISSING SNAPSHOT CONCLUDES NOTHING rather than reading "no
        # terminals": this section makes no IPC call on purpose, so it is the
        # half that still prints when usher cannot see the compositor.
        ck("doctor-says-nothing-about-terminals-with-no-snapshot",
           _store_rows({"signal\x00": {"last_seen": time.time()}},
                       None) == [])
    finally:
        (_dr.load_knowledge, _dr.load_snapshot, _dr._doctor_surfaces,
         _dr.profile_id) = _dsave

    ck("collision-chrome-blames-usher",
       "mis-resolved" in _cfix("chrome:win:123"))
    ck("collision-chrome-does-not-say-plugin",
       "plugin" not in _cfix("chrome:win:123"))
    # AND IT MUST NOT NAME settitle, which it did on the belief that a named
    # window becomes title-keyed. Measured false and in the harmful
    # direction: any colon in the name hands the window to MuxPlugin, whose
    # `owns` is title-only, and with no latch target `_mux_slot` answers
    # `term:resume`, the real mux terminal's key. The check asserts
    # the
    # ABSENCE because a reader following that advice was worse off than one
    # given none, and a wording change is the whole fix.
    ck("collision-kitty-does-not-name-settitle",
       "settitle" not in _cfix("kitty:/w"))
    ck("collision-kitty-explains-the-cwd-key",
       "directory" in _cfix("kitty:/w"))
    # THE MECHANISM BEHIND THAT, pinned so the advice cannot drift back in
    # while it stays true: a colon-titled kitty with no mux in its tree is
    # handed the key a real `mux resume` terminal holds.
    ck("a-colon-in-a-title-alone-makes-it-a-mux-terminal",
       engine.is_mux_term("kitty", "work:titan"))
    ck("and-with-no-latch-target-that-key-is-term-resume",
       engine._mux_slot(None) == "term:resume")
    ck("collision-other-says-plugin", "plugin" in _cfix("some window title"))
    ck("collision-remedies-are-three-distinct",
       len({_cfix("chrome:win:123"), _cfix("kitty:/w"),
            _cfix("some window title")}) == 3)
    # an app_id-only key is the empty identity, and must not fall into either
    # named branch
    ck("collision-appid-only-says-plugin", "plugin" in _cfix(""))

    # 3. THE GATE. A window that is not ready must be refused by BOTH call
    #    sites, which is the invariant every silent failure in this repo's
    #    history broke: a store written under a key the matcher never looks up.
    _real = engine._owner
    try:
        class _Pend(WindowPlugin):
            name = "pendtest"

            def owns(self, v):
                return True

            def resolve(self, v):
                return Resolution.pending("by construction")

        engine._owner = lambda _v: _Pend()
        _v = _tv("kitty", "anything")
        ck("gate-pending-is-unidentified", unidentified(_v))
        ck("gate-pending-has-no-single-id", _single_id(_v) is None)
        # identity() still ANSWERS, for logs and reports, and must not crash.
        ck("gate-pending-identity-falls-back-to-title",
           identity(_v) == "anything")

        class _Never(_Pend):
            name = "nevertest"

            def resolve(self, v):
                return Resolution.never("by construction")

        engine._owner = lambda _v: _Never()
        ck("gate-never-is-unidentified", unidentified(_v))
        ck("gate-never-has-no-single-id", _single_id(_v) is None)

        # A PLUGIN THAT RAISES, OR RETURNS RUBBISH, MUST NOT GET A WINDOW
        # REMEMBERED. Both degrade to Pending, never to Ready: the fail-safe
        # direction is to forget a window, not to key it on a guess.
        class _Boom(_Pend):
            name = "boomtest"

            def resolve(self, v):
                raise RuntimeError("boom")

        engine._owner = lambda _v: _Boom()
        ck("gate-raising-plugin-is-pending", _st(_v) == Resolution.PENDING)
        ck("gate-raising-plugin-says-so", "boom" in (_wh(_v) or ""))

        class _Junk(_Pend):
            name = "junktest"

            def resolve(self, v):
                return "kitty:/tmp"        # the OLD contract's return type

        engine._owner = lambda _v: _Junk()
        ck("gate-old-contract-return-is-pending",
           _st(_v) == Resolution.PENDING)
        ck("gate-old-contract-is-not-silently-keyed", _single_id(_v) is None)
    finally:
        engine._owner = _real

    # 1c. ANOTHER ACCOUNT'S WINDOW IS NEVER OURS TO IDENTIFY.
    #
    # LIVE DAMAGE, measured 2026-11-02: a work account's Chrome window joined
    # the OWNER's recorded session ids and was LEARNED into a personal
    # window's slot, overwriting its workspace and position. A title is no
    # discriminator between two browsers owned by two users.
    #
    # THE TABLE FIRST, injectable so all four cells are reachable with no
    # second account on the box. Only a POSITIVE read of a different uid is
    # foreign: declining a window that IS ours would break every placement.
    ck("foreign-a-stored-entry-pid-is-ours",
       engine.foreign_owner(-1, uid_of=lambda _p: 999, me=1000) is None)
    ck("foreign-an-unreadable-uid-is-ours",
       engine.foreign_owner(42, uid_of=lambda _p: None, me=1000) is None)
    ck("foreign-my-own-uid-is-ours",
       engine.foreign_owner(42, uid_of=lambda _p: 1000, me=1000) is None)
    ck("foreign-another-uid-is-foreign",
       engine.foreign_owner(42, uid_of=lambda _p: 997, me=1000) == 997)

    # AND THE LIVE-SIDE READER OF THAT TABLE, which is the one definition of
    # "is one of MINE already up". Three relaunch paths answered it with the
    # whole view list, and every consequence was the QUIET direction: the
    # owner's Signal not started while only the work account's ran, two of
    # the owner's shells in one directory coming back as ONE whenever any
    # other account had a terminal on screen, and doctor reporting Chrome as
    # `self` for a window usher would START.
    #
    # pid 1 IS init, so a second account is not needed to drive it; skipped
    # as root, where pid 1 genuinely is ours.
    if os.getuid() != 0:
        _ov_mine = _trv("zzz-app", "Mine", pid=os.getpid(), vid=1)
        _ov_dead = _trv("zzz-app", "Stored", pid=-1, vid=2)
        _ov_them = _trv("zzz-app", "Theirs", pid=1, vid=3)
        ck("our-views-keeps-our-own",
           engine.our_views([_ov_mine]) == [_ov_mine])
        ck("our-views-keeps-a-dead-pid",
           engine.our_views([_ov_dead]) == [_ov_dead])
        ck("our-views-drops-another-accounts",
           engine.our_views([_ov_them]) == [])
        # THE MIXED CASE, which is the only one production ever sees and the
        # one a per-cell check cannot speak for: it must KEEP ours and DROP
        # theirs in the same pass, in order.
        ck("our-views-splits-a-mixed-list",
           engine.our_views([_ov_mine, _ov_them, _ov_dead])
           == [_ov_mine, _ov_dead])

    # AND A FOREIGN WINDOW WITH NO NAME IS STILL NEVER, which is the half that
    # keeps the uid out of the store: with no provider wired the only thing
    # usher has is a number, and a number must not be a key. Driven with the
    # hook absent, which is the state of a box that wired nothing.
    if os.getuid() != 0:
        _rsh3 = engine.SOURCE_HOOK
        engine._SOURCE_CACHE.clear()
        try:
            engine.SOURCE_HOOK = "/nonexistent/window-source"
            _un = engine.resolution(_trv("slack", "x", pid=1, vid=97))
            ck("foreign-unnamed-is-never", not _un.is_ready)
            ck("foreign-unnamed-says-nothing-can-name-it",
               "name its source" in (_un.why or ""))
        finally:
            engine.SOURCE_HOOK = _rsh3
            engine._SOURCE_CACHE.clear()

        # ---- THE JOIN, AND ITS STICKINESS -----------------------------
        # The owner hashes the live title and looks it up in what the account
        # last reported. Driven with a NAMED source so the window resolves,
        # which is the only arrangement where a per-window part can appear.
        _rsh4 = engine.SOURCE_HOOK
        _hookd = tempfile.mkdtemp(prefix="usher-wsrc-", dir="/var/tmp")
        try:
            _hk4 = os.path.join(_hookd, "window-source")
            with open(_hk4, "w") as f:
                f.write("#!/bin/sh\nprintf titan\n")
            os.chmod(_hk4, 0o755)
            engine.SOURCE_HOOK = _hk4
            engine._SOURCE_CACHE.clear()
            engine._SOURCE_WINDOWS.clear()
            engine._SOURCE_SLOT.clear()
            _TT = "Quarterly Plan - Google Chrome"
            _TL1 = "aaaa1111bbbb22"       # a wlroots-shaped identifier
            _jv = _trv("google-chrome", _TT, pid=1, vid=201, tlid=_TL1)
            # NO MAP YET: today's behaviour exactly, the source alone.
            ck("foreign-with-no-report-keys-on-its-source",
               engine.resolution(_jv).key == "titan")
            engine.set_source_windows(
                "titan", {_TL1: engine.identity_digest("chrome:win:11")})
            ck("foreign-with-a-report-keys-per-window",
               engine.resolution(_jv).key
               == "titan:" + engine.identity_digest("chrome:win:11"))
            # STICKY, and the join key is no longer in the view at all:
            # `_jv2` carries a different title AND no identifier, so only the
            # cache can answer. A report that goes briefly absent (the
            # account between captures) therefore costs nothing, which is the
            # same reason chrome's own slot cache exists.
            _jv2 = _trv("google-chrome", "Something Else Entirely",
                        pid=1, vid=201)
            ck("a-joined-identity-survives-a-title-change",
               engine.resolution(_jv2).key
               == "titan:" + engine.identity_digest("chrome:win:11"))
            # AND IS DROPPED WITH THE VIEW, or a cache that only grows is a
            # leak in a process that runs for weeks and a recycled view id
            # inherits somebody else's identity.
            engine.forget_source_window(201)
            ck("a-joined-identity-is-dropped-on-unmap",
               engine.resolution(_jv2).key == "titan")
            # A WINDOW THE ACCOUNT DID NOT REPORT falls back rather than
            # guessing, which is what keeps a partial report safe.
            ck("an-unreported-window-falls-back-to-its-source",
               engine.resolution(
                   _trv("google-chrome", "Never Reported", pid=1,
                        vid=202)).key == "titan")

            # AND THE SNAPSHOT KEEPS AN OPAQUE KEY while still redacting a
            # title-shaped one. This is the privacy boundary meeting the new
            # field: learn() reads `key`, and the title it joins on is
            # blanked in the same row, so blanking the key unconditionally
            # would make the per-window identity unreachable.
            engine._SOURCE_SLOT.clear()
            engine.set_source_windows(
                "titan", {_TL1: engine.identity_digest("chrome:win:11")})

            class _JoinSock:
                @staticmethod
                def list_outputs():
                    return [{"name": "eDP-1",
                             "geometry": {"x": 0, "y": 0, "width": 100,
                                          "height": 100},
                             "workspace": {"x": 0, "y": 0, "grid_width": 1,
                                           "grid_height": 1}}]

                @staticmethod
                def list_views(**_kw):
                    return [_trv("google-chrome", _TT, pid=1, vid=201,
                                 tlid=_TL1)]

            _js = engine.snapshot(_JoinSock)["windows"][0]
            ck("snapshot-keeps-a-resolved-foreign-key",
               _js.get("key")
               == "titan:" + engine.identity_digest("chrome:win:11"))
            ck("snapshot-still-redacts-the-resolved-windows-title",
               _js.get("title") == "")
            ck("a-kept-foreign-key-carries-no-title",
               not any(w in _js.get("key", "")
                       for w in ("Quarterly", "Plan", "Chrome")))
            # AND THE COMPOSITOR'S IDENTIFIER IS RECORDED, which is what lets
            # the DAEMON relay this window's pid: the refresh runs off a
            # snapshot rather than a live view list, so without the field the
            # pid has no handle the far side can join on and the relay works
            # at logoff and never during a session.
            ck("snapshot-records-the-compositors-identifier",
               _js.get("identifier") == _TL1)
            ck("the-recorded-identifier-is-what-the-pid-relay-reads",
               engine.source_pid_lines([_js], "titan")
               == ["pid %s %d" % (_TL1, _js["pid"])])

            # ---- THE RE-KEY ACROSS THAT ACCOUNT'S BROWSER RESTART --------
            # A SessionID is per browser RUN, so at a login every per-window
            # key stored for that account names a dead id. Only the account
            # can do the join, since it needs its own two session files, so
            # it reports the binding and the owner applies it.
            # BOTH SIDES ARE DIGESTS, since that is what a per-window key
            # holds: the account hashes its own identity and the owner never
            # sees the string, so a re-key is digest to digest.
            _D11 = engine.identity_digest("chrome:win:11")
            _D22 = engine.identity_digest("chrome:win:22")
            _D91 = engine.identity_digest("chrome:win:91")
            _D92 = engine.identity_digest("chrome:win:92")
            _rk_txt = ("usher: recorded 1 app(s)\n"
                       "rekey %s %s\n"
                       "rekey %s %s\n"
                       "window abc123def456789a %s\n"
                       % (_D11, _D91, _D22, _D92, _D91))
            ck("source-rekey-parses-the-pairs",
               engine.parse_source_rekey(_rk_txt)
               == {_D11: _D91, _D22: _D92})
            ck("source-rekey-ignores-the-window-lines",
               "abc123def456789a" not in str(
                   engine.parse_source_rekey(_rk_txt)))
            # BOTH SIDES VALIDATED, because these rewrite store KEYS: a
            # source reporting anything else would be editing the owner's
            # store in a shape the owner never chose. A readable identity is
            # exactly what must not arrive, since a mux term's names a work
            # host and session.
            ck("source-rekey-refuses-a-title-on-either-side",
               engine.parse_source_rekey(
                   "rekey Some-Page %s\n"
                   "rekey %s Some-Other-Page\n" % (_D91, _D11)) == {})
            ck("source-rekey-refuses-a-readable-identity-on-either-side",
               engine.parse_source_rekey(
                   "rekey term:latch box:work %s\n"
                   "rekey %s term:latch box:work\n" % (_D91, _D11)) == {})
            ck("source-rekey-refuses-a-pair-that-does-not-move",
               engine.parse_source_rekey("rekey %s %s" % (_D11, _D11)) == {})

            def _e_rk(ident, src, ws):
                e = {"app_id": "google-chrome", "title": ident,
                     "workspace": ws}
                if src:
                    e["source"] = src
                return e

            _rkb = {
                engine.kkey("google-chrome", "titan:chrome:win:11"):
                    _e_rk("titan:chrome:win:11", "titan", [1, 0]),
                engine.kkey("google-chrome", "titan:chrome:win:22"):
                    _e_rk("titan:chrome:win:22", "titan", [2, 0]),
                engine.kkey("google-chrome", "chrome:win:11"):
                    _e_rk("chrome:win:11", "", [0, 0]),
                engine.kkey("google-chrome", "other:chrome:win:11"):
                    _e_rk("other:chrome:win:11", "other", [0, 1]),
            }
            _n_rk = engine.rekey_source(
                _rkb, "titan", {"chrome:win:11": "chrome:win:91",
                                "chrome:win:22": "chrome:win:92"})
            ck("rekey-source-moves-this-sources-slots", _n_rk == 2)
            ck("rekey-source-keys-them-on-the-new-ids",
               engine.kkey("google-chrome", "titan:chrome:win:91") in _rkb
               and engine.kkey("google-chrome",
                               "titan:chrome:win:92") in _rkb)
            ck("rekey-source-carries-the-geometry-across",
               _rkb[engine.kkey("google-chrome",
                                "titan:chrome:win:91")]["workspace"]
               == [1, 0])
            # THE KEY-TITLE IS THE IDENTITY and has to move with the key,
            # which is the trap this file keeps falling into.
            ck("rekey-source-moves-the-key-title-too",
               _rkb[engine.kkey("google-chrome",
                                "titan:chrome:win:91")]["title"]
               == "titan:chrome:win:91")
            ck("rekey-source-leaves-the-OWNERS-slot-alone",
               engine.kkey("google-chrome", "chrome:win:11") in _rkb)
            ck("rekey-source-leaves-ANOTHER-sources-slot-alone",
               engine.kkey("google-chrome", "other:chrome:win:11") in _rkb)
            # ...AND THAT NEEDS ITS OWN FIXTURE, because in the one above the
            # already-known guard masks it: `titan:chrome:win:11` moves
            # first, so the new key exists by the time the other source's row
            # is reached and it is skipped for the WRONG reason. A plant
            # removing the prefix test changed nothing at all until this.
            # Note "other" and "titan" are the same length deliberately, so
            # the slice lands exactly on a binding key.
            _rkb3 = {
                engine.kkey("google-chrome", "other:chrome:win:11"):
                    _e_rk("other:chrome:win:11", "other", [0, 1]),
                engine.kkey("google-chrome", "chrome:win:11"):
                    _e_rk("chrome:win:11", "", [0, 0]),
            }
            _n_rk3 = engine.rekey_source(
                _rkb3, "titan", {"chrome:win:11": "chrome:win:91"})
            ck("rekey-source-moves-nothing-that-is-not-its-own",
               _n_rk3 == 0)
            ck("rekey-source-left-both-foreign-and-owner-keys-intact",
               sorted(_rkb3) == sorted([
                   engine.kkey("google-chrome", "other:chrome:win:11"),
                   engine.kkey("google-chrome", "chrome:win:11")]))
            ck("rekey-source-is-a-no-op-the-second-time",
               engine.rekey_source(
                   _rkb, "titan",
                   {"chrome:win:11": "chrome:win:91"}) == 0)
            ck("rekey-source-with-no-binding-changes-nothing",
               engine.rekey_source(_rkb, "titan", {}) == 0)
            # AND A SLOT THE CURRENT SESSION ALREADY KNOWS IS LEFT ALONE:
            # the store's own answer for it is at least as good as a guess.
            _rkb2 = {
                engine.kkey("google-chrome", "titan:chrome:win:11"):
                    _e_rk("titan:chrome:win:11", "titan", [1, 0]),
                engine.kkey("google-chrome", "titan:chrome:win:91"):
                    _e_rk("titan:chrome:win:91", "titan", [9, 9]),
            }
            engine.rekey_source(_rkb2, "titan",
                                {"chrome:win:11": "chrome:win:91"})
            ck("rekey-source-does-not-overwrite-a-known-slot",
               _rkb2[engine.kkey("google-chrome",
                                 "titan:chrome:win:91")]["workspace"]
               == [9, 9])

            # ---- WHEN TO ASK, which is the part with a trap in it --------
            # The ask is a CAPTURE, and a capture REPLACES that account's
            # roster with what is live, so asking mid-login records a partial
            # desk. The guard must therefore be a PRECONDITION that cannot
            # block forever: the first version required every app the owner
            # had SAVED for that source to be live, and it never fired at a
            # login, because that account's saved set names Wine installers
            # and dialogs that do not come back (9 of 14, measured). The
            # feature was silently off at exactly the event it exists for.
            _P = engine.source_refresh_plan
            _un = [{"app_id": "google-chrome", "source": "titan",
                    "key": "titan"},
                   {"app_id": "slack", "source": "titan", "key": "titan"}]
            # THE CLOCK STARTS ON FIRST SIGHT, so nothing is asked for on the
            # pass that discovers it: that pass is the middle of a login.
            _r, _seen = _P(_un, {}, 1000.0, {})
            ck("refresh-does-not-ask-on-first-sight", _r == [])
            ck("refresh-records-what-it-saw",
               set(_seen) == {"titan"} and _seen["titan"][1] == 1000.0)
            # STILL NOT, while the set has been stable for less than settle.
            ck("refresh-waits-for-the-set-to-settle",
               _P(_un, {}, 1000.0 + engine.SOURCE_SETTLE - 1, _seen)[0] == [])
            # AND THEN IT ASKS.
            ck("refresh-asks-once-the-set-is-stable",
               _P(_un, {}, 1000.0 + engine.SOURCE_SETTLE, _seen)[0]
               == ["titan"])
            # A SET THAT CHANGES RESTARTS THE CLOCK, which is the whole
            # point: a login is a set that keeps growing.
            _grown = _un + [{"app_id": "zoom", "source": "titan",
                             "key": "titan"}]
            _r2, _seen2 = _P(_grown, {}, 1000.0 + engine.SOURCE_SETTLE,
                             _seen)
            ck("refresh-a-changed-set-restarts-the-clock", _r2 == [])
            ck("refresh-asks-after-the-new-set-settles",
               _P(_grown, {}, 1000.0 + 2 * engine.SOURCE_SETTLE,
                  _seen2)[0] == ["titan"])
            # THE REGRESSION THE OLD GUARD WAS: an app that is gone for good
            # must not hold the ask off, because nothing will ever bring it
            # back. There is no `saved` argument now, and this pins that the
            # live set ALONE decides.
            ck("refresh-is-not-blocked-by-an-app-that-never-returns",
               _P(_un, {}, 1000.0 + engine.SOURCE_SETTLE, _seen)[0]
               == ["titan"])
            # RATE LIMITED, or a window that can NEVER be identified
            # (incognito) makes a loop out of asking about it.
            ck("refresh-is-rate-limited",
               _P(_un, {"titan": 1000.0}, 1000.0 + engine.SOURCE_SETTLE,
                  _seen)[0] == [])
            ck("refresh-asks-again-after-the-interval",
               _P(_un, {"titan": 1000.0},
                  1000.0 + engine.SOURCE_REFRESH_EVERY
                  + engine.SOURCE_SETTLE, _seen)[0] == ["titan"])
            # IDENTIFIED ALREADY: never asks, so a settled desk makes no
            # subprocess at all, AND the clock is dropped so a later window
            # starts a fresh one rather than inheriting a stale "stable
            # since" and being asked for immediately.
            _id = [dict(_un[0], key="titan:chrome:win:91"), _un[1]]
            _r3, _seen3 = _P(_id, {}, 2000.0, _seen)
            ck("refresh-does-not-ask-when-everything-is-identified",
               _r3 == [])
            ck("refresh-drops-the-clock-when-nothing-is-wanted",
               "titan" not in _seen3)
            # A NON-CHROME WINDOW NEVER TRIGGERS IT, since the report has
            # nothing to say about one and asking would be a subprocess per
            # interval forever.
            ck("refresh-is-not-triggered-by-a-non-chrome-window",
               _P([{"app_id": "slack", "source": "titan", "key": "titan"}],
                  {}, 1000.0, {})[0] == [])
            # AND THE OWNER'S OWN WINDOWS NEVER DO, or every desk would ask.
            ck("refresh-is-not-triggered-by-our-own-window",
               _P([{"app_id": "google-chrome", "key": "chrome:win:1"}],
                  {}, 1000.0, {})[0] == [])

            # THE DRAIN: applying a binding is a one-shot edit to the store,
            # so one left behind would be re-applied on every pass.
            engine._SOURCE_REKEY["titan"] = {"a": "b"}
            ck("take-source-rekey-returns-it",
               engine.take_source_rekey("titan") == {"a": "b"})
            ck("take-source-rekey-drains-it",
               engine.take_source_rekey("titan") == {})

            # AND THE TRIGGER RECORDS IT FOR THE WORKER, which owns the
            # store. The WIRING, which the parser's own checks say nothing
            # about: that is the hole which passed the whole suite last time.
            def _sr_rk(_argv, **_k):
                class R:
                    returncode = 0
                    stderr = ""
                    stdout = _rk_txt
                return R()

            engine._SOURCE_REKEY.clear()
            # _announce PRINTS as well as logging, and the area quieting only
            # covers logline, so without this the suite's own stdout carries
            # "asked titan to capture".
            _ra_rk = engine._announce
            engine._announce = lambda *_a, **_k: None
            try:
                engine.source_trigger(["titan"], "capture", run=_sr_rk,
                                      hook=_hk4)
            finally:
                engine._announce = _ra_rk
            ck("source-trigger-records-the-rekey-for-the-worker",
               engine.take_source_rekey("titan")
               == {_D11: _D91, _D22: _D92})

            # ---- AN OWNED APP WHOSE PLUGIN CANNOT ACT ON A ROSTER ---------
            # THE BUG: the account's terminal was in its roster, counted
            # missing, and started by NOBODY. KittyPlugin owns kitty so the
            # registry default skipped it, and KittyPlugin acts from a
            # recorded `cmd` that a roster row (an app-id and nothing else)
            # does not carry, so it no-opped. Slack beside it came back
            # because no plugin claims slack, which is the contrast that
            # named the mechanism.
            #
            # DRIVEN THROUGH THE REAL `roster_launch`, because the fix is the
            # interaction between the plugin loop and the default, and each
            # half in isolation looks correct. The spawn is injected, so
            # nothing is started.
            _rl_got = []
            _rl_entries = {"kitty": {"exec": "kitty", "type": "Application"},
                           "slack": {"exec": "/usr/bin/slack",
                                     "type": "Application"}}
            _r_de, _r_an = engine.desktop_entries, engine._announce
            try:
                engine.desktop_entries = lambda *_a, **_k: _rl_entries
                engine._announce = lambda *_a, **_k: None
                _n_rl = engine.roster_launch(["kitty", "slack"], [],
                                             spawn=_rl_got.append)
            finally:
                engine.desktop_entries = _r_de
                engine._announce = _r_an
            _rl_started = {a for argv in _rl_got for a in argv[:1]}
            ck("roster-starts-an-owned-app-its-plugin-could-not",
               "kitty" in _rl_started)
            ck("roster-still-starts-an-unowned-app",
               "/usr/bin/slack" in _rl_started)
            ck("roster-counts-both", _n_rl == 2)
            # AND NOTHING IS STARTED TWICE, which is the expensive direction:
            # two browsers against one profile is the singleton fight.
            ck("roster-starts-each-app-once",
               len(_rl_got) == len({tuple(a) for a in _rl_got}))

            # THE POLICY ITSELF, pure, so every cell is reachable. `started`
            # is keyed by plugin object, which is how roster_launch collects
            # it.
            _kp = next((p for p in engine.plugins()
                        if p.owns({"app": "kitty", "title": "",
                                   "pid": -1})), None)
            ck("roster-claimed-finds-the-kitty-plugin", _kp is not None)
            # THE REGISTRY IS PASSED, which these checks must do or they
            # test a key MISS rather than the policy: `started` is keyed by
            # plugin object, and a fixture handing a different instance
            # reads as "reported nothing" and keeps the claim, so every cell
            # below would pass for the same wrong reason.
            _reg = list(engine.plugins())
            ck("roster-claimed-an-unowned-app-is-never-claimed",
               engine.roster_claimed(["slack"], {}, _reg) == set())
            ck("roster-claimed-an-owner-that-reported-nothing-keeps-its-claim",
               engine.roster_claimed(["kitty"], {_kp: 0}, _reg) == {"kitty"})
            ck("roster-claimed-an-owner-that-started-it-keeps-its-claim",
               engine.roster_claimed(["kitty"], {_kp: {"kitty"}}, _reg)
               == {"kitty"})
            # A NON-OWNER THAT STARTED IT COUNTS, which is a PRODUCT bug the
            # end-to-end terminal check found: the owner of a bare
            # `{kitty, "", -1}` view is always KittyPlugin, because MuxPlugin
            # claims a kitty by its TITLE, so the plugin that actually put
            # two mux terminals back was never the one asked and the default
            # went on to start a THIRD kitty as a bare shell at $HOME.
            _mp = next((p for p in engine.plugins()
                        if getattr(p, "name", "") == "mux"), None)
            ck("roster-claimed-finds-the-mux-plugin", _mp is not None)
            ck("roster-claimed-counts-a-NON-owners-report",
               engine.roster_claimed(
                   ["kitty"], {_mp: {"kitty"}, _kp: set()}, _reg)
               == {"kitty"})
            # AND THE OWNER DECLINING IS STILL THE DEFAULT'S CHANCE when
            # nobody else started it, or the terminal bug comes straight
            # back for every app with one plugin.
            ck("roster-claimed-nobody-started-it-leaves-it-to-the-default",
               engine.roster_claimed(
                   ["kitty"], {_mp: set(), _kp: set()}, _reg) == set())
            ck("roster-claimed-an-owner-that-declined-releases-it",
               engine.roster_claimed(["kitty"], {_kp: set()}, _reg) == set())
            # A RAISE IS NOT A DECLINE: the plugin may have started some of
            # its apps before failing, so its claim stays whole.
            ck("roster-claimed-an-owner-that-raised-keeps-its-claim",
               engine.roster_claimed(["kitty"], {_kp: None}, _reg)
               == {"kitty"})
            # AND A FIXTURE THAT HANDS THE WRONG OBJECT IS THE TRAP ITSELF,
            # pinned so the checks above cannot quietly become vacuous.
            ck("roster-claimed-a-stranger-key-is-not-mistaken-for-a-decline",
               engine.roster_claimed(["kitty"], {object(): set()}, _reg)
               == {"kitty"})

            # THE TWO READERS OF EITHER CONTRACT.
            ck("launched-apps-reads-a-set",
               engine.launched_apps({"a", "b"}) == {"a", "b"})
            ck("launched-apps-reads-a-list",
               engine.launched_apps(["a"]) == {"a"})
            ck("launched-apps-calls-a-count-unknown",
               engine.launched_apps(2) is None
               and engine.launched_apps(0) is None)
            ck("launched-count-counts-either-contract",
               engine.launched_count({"a", "b"}) == 2
               and engine.launched_count(3) == 3
               and engine.launched_count(0) == 0)
            # GARBAGE IS ZERO, NOT A RAISE: this runs on the login path and a
            # third-party plugin returning nonsense must not stop the rest.
            ck("launched-count-survives-garbage",
               engine.launched_count("two") == 0
               and engine.launched_count(None) == 0)

            # ---- THE THREE THINGS PLANTING FOUND, all of them WIRING -----
            # The pure policy had checks and the places that CALL it did
            # not, which is the fourth instance of that hole in this file.

            # 1. A PLUGIN THAT RAISES KEEPS ITS CLAIM. It may have started
            # some of its apps before failing, so letting the default in
            # would double-launch. Driven through the real `roster_launch`,
            # since the plant was in its except arm and the pure function
            # cannot see it.
            class _Boom:
                name = "boom"

                def owns(self, v):
                    return v["app"] == "kitty"

                def relaunch_missing(self, saved, live):
                    raise RuntimeError("plugin exploded mid-launch")

            _bg, _r_pl = [], engine.plugins
            _r_de2, _r_an2, _r_lg = (engine.desktop_entries,
                                     engine._announce, engine.logline)
            try:
                engine.plugins = lambda: [_Boom()]
                engine.desktop_entries = lambda *_a, **_k: {
                    "kitty": {"exec": "kitty", "type": "Application"}}
                engine._announce = lambda *_a, **_k: None
                engine.logline = lambda *_a, **_k: None
                engine.roster_launch(["kitty"], [], spawn=_bg.append)
                # THE PRECONDITION: with the SAME plugin declining rather
                # than raising, the default DOES start it. Without this the
                # check above passes for any reason that stops the launch.
                _bg2 = []
                _Boom.relaunch_missing = (
                    lambda self, saved, live: set())
                engine.roster_launch(["kitty"], [], spawn=_bg2.append)
            finally:
                engine.plugins = _r_pl
                engine.desktop_entries = _r_de2
                engine._announce = _r_an2
                engine.logline = _r_lg
            ck("roster-a-plugin-that-raised-is-not-second-guessed",
               _bg == [])
            ck("roster-raise-check-has-a-working-control",
               _bg2 == [["kitty"]])

            # 2. THE RESTORE PATH MUST NOT GET THE ROSTER'S POLICY. There a
            # plugin owning an app really is what starts it, from a recorded
            # command per window, so bypassing the claim would have the
            # default spawn a BARE kitty at $HOME for a saved terminal whose
            # cwd is unreadable, where today it spawns nothing. Asserted on
            # the SOURCE, because driving `launch_missing` for real spawns
            # real apps: this suite has opened 16 terminals on a live desktop
            # once already.
            import inspect as _isp
            _lm_src = _isp.getsource(engine.launch_missing)
            _rl_src = _isp.getsource(engine.roster_launch)
            ck("restore-calls-the-default-at-all",
               "desktop_relaunch_missing(" in _lm_src)
            ck("restore-does-not-pass-the-roster-policy",
               "claimed=" not in _lm_src)
            ck("roster-does-pass-the-roster-policy",
               "claimed=roster_claimed(" in _rl_src)
            # AND THE RESUME RELAYS THE LIVE VIEWS, which is now REQUIRED
            # rather than merely useful: the terminal relaunch counts per
            # cwd, so the account has to be able to READ its own live
            # terminals or it would ask for every one of them again. The
            # SAVED rows cannot serve, since their identifiers name a
            # previous session and their pids are dead.
            ck("the-resume-trigger-relays-the-LIVE-views",
               'source_trigger(source_trigger_plan(saved), "resume", '
               'views=live)' in _lm_src)

            # 3. CHROME REPORTS EVERY SPELLING IT CLAIMED. XWayland says
            # `Google-chrome` and native Wayland says `google-chrome`, and
            # BOTH are in a real store, so reporting one spelling leaves the
            # default free to start the browser again under the other.
            _chp = next((p for p in engine.plugins()
                         if p.owns({"app": "google-chrome", "title": "",
                                    "pid": -1})), None)
            ck("chrome-plugin-is-findable", _chp is not None)
            _r_cs, _r_an3 = engine.chrome_profiles_for, engine._announce
            _r_sp = engine.app_spawn
            try:
                engine.chrome_profiles_for = lambda _s: ["Default"]
                engine._announce = lambda *_a, **_k: None
                engine.app_spawn = lambda *_a, **_k: None
                _both = _chp.relaunch_missing(
                    [{"app_id": "Google-chrome"},
                     {"app_id": "google-chrome"}], [])
            finally:
                engine.chrome_profiles_for = _r_cs
                engine._announce = _r_an3
                engine.app_spawn = _r_sp
            ck("chrome-reports-both-spellings-it-claimed",
               _both == {"Google-chrome", "google-chrome"})
            engine._SOURCE_REKEY.clear()

            # ---- AND THE ENCLAVE SIDE PRODUCES THE PAIRS -----------------
            # Driven through its three seams, so no session file and no
            # second account are needed. The shape is what the owner parses.
            _fake_hist = {"P": ["cur", "prev"]}
            _fake_tabs = {"cur": {91: frozenset({"u1", "u2"}),
                                  92: frozenset({"u3", "u4"})},
                          "prev": {11: frozenset({"u1", "u2"}),
                                   22: frozenset({"u3", "u4"})}}
            _lines_rk = engine.source_rekey_lines(
                hist=lambda: _fake_hist, tabs=lambda f: _fake_tabs[f])
            ck("source-rekey-lines-pair-old-to-new",
               engine.parse_source_rekey("\n".join(_lines_rk))
               == {_D11: _D91, _D22: _D92})
            # AND THE IDENTITY NEVER CROSSES IN THE CLEAR, which is the
            # whole reason the pairs are digests: a chrome slot is harmless
            # and a terminal's identity names a work host and session, so
            # the rule has to hold for the shape, not per app.
            ck("source-rekey-lines-carry-no-readable-identity",
               not any("chrome:win:" in ln for ln in _lines_rk))
            ck("source-rekey-lines-are-the-shape-the-owner-parses",
               all(len(ln.split()) == 3
                   and ln.split()[0] == engine.SOURCE_REKEY_WORD
                   for ln in _lines_rk))
            # NO PREVIOUS FILE MEANS NO BINDING, which is a first run rather
            # than an error: there is nothing to rebind from.
            ck("source-rekey-lines-need-a-previous-session",
               engine.source_rekey_lines(
                   hist=lambda: {"P": ["cur"]},
                   tabs=lambda f: _fake_tabs[f]) == [])
            ck("source-rekey-lines-tolerate-an-empty-history",
               engine.source_rekey_lines(hist=lambda: {},
                                         tabs=lambda _f: {}) == [])
            # AND NOTHING BINDS WHEN THE TAB SETS DISAGREE, which is
            # chrome_bind_windows own rule and the reason a wrong pair does
            # not quietly move somebody's slot.
            # AND THE VERB PRINTS THEM, which the lines function's own
            # checks say nothing about: removing the print loop from
            # do_source_capture passed the entire suite. THIRD INSTANCE of
            # this hole, after entry_output and the window-map cache.
            def _raiser(*_a, **_k):
                raise RuntimeError("session files are unreadable")

            _rt = engine.toplevels.list_toplevels
            _rsl = engine.source_rekey_lines
            _rsw = engine.source_window_lines
            _rsr = engine.save_roster
            _cap_out = io.StringIO()
            try:
                engine.toplevels.list_toplevels = lambda: (
                    [{"app_id": "google-chrome", "title": "T"}], "")
                engine.source_rekey_lines = lambda: [
                    "rekey %s %s" % (_D11, _D91)]
                engine.source_window_lines = lambda _r, *_a, **_k: []
                engine.save_roster = lambda *_a, **_k: None
                with contextlib.redirect_stdout(_cap_out):
                    _rc_cap = engine.do_source_capture()
            finally:
                engine.toplevels.list_toplevels = _rt
                engine.source_rekey_lines = _rsl
                engine.source_window_lines = _rsw
                engine.save_roster = _rsr
            ck("source-capture-succeeds", _rc_cap == engine.EXIT_OK)
            ck("source-capture-prints-the-rekey-pairs",
               engine.parse_source_rekey(_cap_out.getvalue())
               == {_D11: _D91})
            # AND A FAILURE THERE IS NOT FATAL: the roster is the part a
            # restore cannot do without, and a session-file problem must not
            # cost it.
            _cap_out2, _cap_exc = io.StringIO(), None
            try:
                engine.toplevels.list_toplevels = lambda: (
                    [{"app_id": "google-chrome", "title": "T"}], "")
                engine.source_rekey_lines = _raiser
                engine.source_window_lines = lambda _r, *_a, **_k: []
                engine.save_roster = lambda *_a, **_k: None
                # STDERR TOO: the non-fatal path reports there by design,
                # and the suite's own output is not the place for it.
                # GUARDED, so narrowing that `except` is reported BY NAME
                # here rather than aborting whichever area reaches it first.
                _rc_cap2 = None
                with contextlib.redirect_stdout(_cap_out2), \
                        contextlib.redirect_stderr(io.StringIO()) as _ce2:
                    try:
                        _rc_cap2 = engine.do_source_capture()
                    except Exception as _e_cap:            # noqa: BLE001
                        _cap_exc = _e_cap
            finally:
                engine.toplevels.list_toplevels = _rt
                engine.source_rekey_lines = _rsl
                engine.source_window_lines = _rsw
                engine.save_roster = _rsr
            ck("source-capture-survives-a-rekey-failure",
               _cap_exc is None and _rc_cap2 == engine.EXIT_OK)
            ck("source-capture-still-records-the-roster-then",
               "recorded 1 app" in _cap_out2.getvalue())
            ck("source-capture-says-why-it-could-not-bind",
               _cap_exc is None and "could not bind" in _ce2.getvalue())

            ck("source-rekey-lines-refuse-unrelated-windows",
               engine.source_rekey_lines(
                   hist=lambda: {"P": ["cur", "prev"]},
                   tabs=lambda f: {"cur": {91: frozenset({"x"})},
                                   "prev": {11: frozenset({"y"})}}[f]) == [])

            # ---- THE ORDERING, which only a whole PASS can show ----------
            # `snapshot` STAMPS each window's key, so a refresh that runs
            # after it is built fills a cache the rows were already stamped
            # against: `learn` then records the source-alone key and the
            # per-window identity arrives one capture LATE. In a quiet
            # session nothing dirties the store, so "next capture" can be
            # never, which is the event-driven trap this file records twice.
            #
            # A CHECK ON EITHER TICK ALONE PASSES, so this drives one real
            # `_capture_once` and asserts on what the STORE holds after it.
            # Found live on manifold: the daemon asked, got six windows, and
            # the store still read 0 per-window keys.
            #
            # PATCHED ON `watch`'s OWN NAMES, not engine's. watch.py does
            # `from .engine import save_knowledge, persist, snapshot`, so it
            # holds its own references and patching engine's globals leaves
            # the daemon's copies live. Getting that wrong wrote `{}` over a
            # REAL profile store and put eight fixture rows in the history
            # ring, which is the stale-copy hazard the package split records
            # and the third time this suite has written into real state.
            from . import watch as _word
            _TW = "Confidential Plan - Google Chrome"
            _TL2 = "cccc3333dddd44"

            class _OrdSock:
                def list_outputs(self):
                    return [{"name": "DP-1",
                             "geometry": {"x": 0, "y": 0, "width": 100,
                                          "height": 100},
                             "workspace": {"x": 0, "y": 0, "grid_width": 1,
                                           "grid_height": 1}}]

                def list_views(self, filter_mapped_toplevel=False):
                    # AN OUTPUT AND A GEOMETRY, or `place_of` answers "null"
                    # and `unreadable_placement` refuses to learn the row:
                    # the first version of this fixture had neither, and the
                    # check failed for its own reason while the product was
                    # correct. _trv builds the minimum a plugin needs, which
                    # is less than a capture does.
                    return [dict(_trv("google-chrome", _TW, pid=1,
                                      vid=301, tlid=_TL2),
                                 **{"output-name": "DP-1",
                                    "geometry": {"x": 0, "y": 0,
                                                 "width": 10, "height": 10}})]

            _wo = _word.Watcher(launch=False)
            _wo.place_sock = _OrdSock()
            _wo.kb, _wo.groups = {}, {}
            _wo.saved = {"windows": []}
            _wo.src_asked = {}
            # ALREADY STABLE, or the guard correctly declines on the pass
            # that first SEES the window: the ask waits for a login to stop
            # bringing windows up. The app set must be exactly what the plan
            # computes, or this silently presents a CHANGED set and the
            # clock restarts.
            _wo.src_seen = {"titan": (frozenset({"google-chrome"}),
                                      time.time() - 10 * engine.SOURCE_SETTLE)}
            _wo.st["dirty"] = True
            _wo.st["last"] = 0
            _ord_saved, _ord_persisted = [], []
            _r_sk, _r_pe = _word.save_knowledge, _word.persist
            _r_tr = engine.source_trigger

            _ord_views = []

            def _ord_trigger(sources, action, **_k):
                _ord_views.append(_k.get("views"))
                for s in sources:
                    engine.set_source_windows(
                        s, {_TL2: engine.identity_digest("chrome:win:77")})
                return len(sources)

            try:
                _word.save_knowledge = lambda kb, prof: _ord_saved.append(
                    dict(kb))
                _word.persist = lambda *_a, **_k: _ord_persisted.append(1)
                engine.source_trigger = _ord_trigger
                engine._SOURCE_WINDOWS.clear()
                engine._SOURCE_SLOT.clear()
                # AND THE PANEL MAP, because `entry_output` resolves by PANEL
                # before falling back to the connector name, and another area
                # leaves a stub cached. A leaked SOFT-dependency cache is how
                # this check first failed against correct code.
                engine._PANELS.update({"map": {}, "at": time.time()})
                # THE PRECONDITION, so this cannot pass vacuously: with the
                # cache empty the window stamps the source-alone key.
                ck("ordering-fixture-starts-with-no-identity",
                   engine.snapshot(_OrdSock())["windows"][0].get("key")
                   == "titan")
                _wo._capture_once(_OrdSock())
            finally:
                _word.save_knowledge, _word.persist = _r_sk, _r_pe
                engine.source_trigger = _r_tr
                engine._SOURCE_WINDOWS.clear()
                engine._SOURCE_SLOT.clear()
            _PWK = engine.kkey(
                "google-chrome",
                "titan:" + engine.identity_digest("chrome:win:77"))
            ck("a-refresh-is-spent-on-the-SAME-capture-pass",
               sorted(_wo.kb) == [_PWK])
            # AND THE REFRESH SENDS THE PIDS WITH THE QUESTION. The WIRING,
            # which `source_pid_lines` own checks say nothing about: the
            # snapshot rows carry both halves, and that is the only reason
            # the relay can happen on the capture thread without a second
            # round trip to the compositor. Asserted as the LINES the far
            # side would receive, not as the argument, because passing the
            # wrong row shape is the way this fails.
            ck("the-refresh-relays-this-sources-pids",
               _ord_views and engine.source_pid_lines(
                   _ord_views[-1] or [], "titan") == ["pid %s 1" % _TL2])
            ck("the-ordering-pass-did-not-store-the-source-alone-key",
               engine.kkey("google-chrome", "titan") not in _wo.kb)
            # AND IT REACHED THE SAVE, or the two above could pass over a
            # pass that returned early and learned nothing at all.
            ck("the-ordering-pass-saved-what-it-learned",
               len(_ord_saved) == 1 and sorted(_ord_saved[0]) == [_PWK])
            # AND THE STUBS WERE USED, which is what proves this touched no
            # real state: both are patched on watch's own names.
            ck("the-ordering-pass-wrote-no-real-state",
               len(_ord_persisted) == 1)
        finally:
            engine.SOURCE_HOOK = _rsh4
            engine._SOURCE_CACHE.clear()
            engine._SOURCE_WINDOWS.clear()
            engine._SOURCE_SLOT.clear()
            shutil.rmtree(_hookd, ignore_errors=True)

    # match_keys / entry_matches: ONE definition for the five places that ask
    # which stored keys a window may match. A FOREIGN WINDOW MATCHES EXACTLY
    # ONE, its own source's: the app_id-only key means "every window of this
    # app", which is the OWNER's, so offering it across the boundary would
    # place a work Slack on the owner's Slack slot.
    ck("match-keys-owner-gets-both",
       engine.match_keys("slack", "ident")
       == (engine.kkey("slack", ""), engine.kkey("slack", "ident")))
    ck("match-keys-foreign-gets-only-its-source",
       engine.match_keys("slack", "ident", "titan")
       == (engine.kkey("slack", "titan"),))
    ck("match-keys-foreign-never-offers-the-appid-only-key",
       engine.kkey("slack", "")
       not in engine.match_keys("slack", "ident", "titan"))
    # The ident-first order is a PRE-EXISTING difference, preserved rather
    # than quietly changed inside this work.
    ck("match-keys-ident-first-is-preserved",
       engine.match_keys("slack", "ident", ident_first=True)
       == (engine.kkey("slack", "ident"), engine.kkey("slack", "")))
    _own_e = {"app_id": "slack", "title": "", "appid_only": True}
    # CARRIES `source` AS A FIELD, which is what the matcher asks: inferring
    # it from `title == source` was loose, and the field is also what stops
    # the per-title prune mistaking this for a leftover title key.
    _src_e = {"app_id": "slack", "title": "titan", "appid_only": False,
              "source": "titan"}
    ck("entry-matches-owner-appid-only-claims-an-owner-window",
       engine.entry_matches(_own_e, "slack", "anything"))
    ck("entry-matches-owner-appid-only-REFUSES-a-foreign-window",
       not engine.entry_matches(_own_e, "slack", "anything", "titan"))
    ck("entry-matches-a-source-entry-claims-its-own-window",
       engine.entry_matches(_src_e, "slack", "anything", "titan"))
    ck("entry-matches-a-source-entry-refuses-an-owner-window",
       not engine.entry_matches(_src_e, "slack", "anything"))
    # AND AN ENTRY WITH NO `source` FIELD NEVER CLAIMS A FOREIGN WINDOW, even
    # if its title happens to equal the source name. That is the loose
    # inference this replaced, and a title is user-controlled.
    ck("entry-matches-a-title-that-merely-equals-the-source-does-not-count",
       not engine.entry_matches(
           {"app_id": "slack", "title": "titan", "appid_only": False},
           "slack", "anything", "titan"))

    # ---- A PER-WINDOW KEY FOR ANOTHER ACCOUNT'S WINDOWS ------------------
    # `<source>:<identity>`, so the source name is a PREFIX and the key can
    # never collide with the owner's own `chrome:win:<id>`. The gate is what
    # stops an arbitrary identity becoming a key that is not this account's.
    _PW = "titan:chrome:win:11"
    ck("source-ident-accepts-this-sources-own-key",
       engine.source_ident("titan", _PW) == _PW)
    ck("source-ident-refuses-another-sources-key",
       not engine.source_ident("titan", "other:chrome:win:11"))
    ck("source-ident-refuses-an-owner-shaped-key",
       not engine.source_ident("titan", "chrome:win:11"))
    ck("source-ident-refuses-the-bare-source",
       not engine.source_ident("titan", "titan"))
    ck("match-keys-foreign-gets-the-window-then-the-source",
       engine.match_keys("google-chrome", _PW, "titan")
       == (engine.kkey("google-chrome", _PW),
           engine.kkey("google-chrome", "titan")))
    ck("match-keys-foreign-still-never-offers-the-appid-only-key",
       engine.kkey("google-chrome", "")
       not in engine.match_keys("google-chrome", _PW, "titan"))
    # THE FALLBACK IS WHAT MAKES THIS ADDITIVE: an entry stored under the
    # source alone is that account's app_id-only key and still claims any of
    # its windows, so nothing relearns.
    _pw_e = {"app_id": "google-chrome", "title": _PW, "appid_only": False,
             "source": "titan"}
    _sa_e = {"app_id": "google-chrome", "title": "titan",
             "appid_only": False, "source": "titan"}
    ck("entry-matches-a-per-window-entry-claims-its-own-window",
       engine.entry_matches(_pw_e, "google-chrome", _PW, "titan"))
    ck("entry-matches-a-per-window-entry-refuses-another-window",
       not engine.entry_matches(_pw_e, "google-chrome",
                                "titan:chrome:win:22", "titan"))
    ck("entry-matches-a-source-alone-entry-still-claims-any-of-its-windows",
       engine.entry_matches(_sa_e, "google-chrome", _PW, "titan"))

    # THE IDENTITY SHAPE IS VALIDATED ON ARRIVAL, which is what makes the
    # opacity ours rather than the far side's to honour: these become store
    # keys and reach watch.log, so a source reporting a window TITLE would
    # reinstate the leak the digest exists to avoid.
    _tl = "aaaa1111bbbb22"
    _dg = engine.identity_digest("chrome:win:11")
    ck("source-window-parse-accepts-an-identifier-and-a-digest",
       engine.parse_source_windows("window %s %s" % (_tl, _dg))
       == {_tl: _dg})
    # A READABLE IDENTITY IS REFUSED, which is the whole point of the shape
    # test: a terminal's is `term:latch <host>:<session>` and names a work
    # host and session, so it must never become a store key or a log line.
    ck("source-window-parse-REFUSES-a-readable-identity",
       engine.parse_source_windows(
           "window %s term:latch somehost:somesession" % _tl) == {})
    ck("source-window-parse-REFUSES-a-title-as-an-identity",
       engine.parse_source_windows(
           "window %s Offer-Letter-Google-Chrome" % _tl) == {})
    # AND A NON-IDENTIFIER JOIN KEY IS REFUSED TOO, because the key is now
    # the compositor's handle and a source inventing one would claim a window
    # it does not own.
    ck("source-window-parse-refuses-a-junk-join-key",
       engine.parse_source_windows("window not-hex-at-all %s" % _dg) == {})
    ck("source-window-parse-refuses-an-arbitrary-word",
       engine.parse_source_windows("window %s titan" % _tl) == {})

    # ...AND END TO END ON A REAL FOREIGN PID, needing no stub and no second
    # account: pid 1 is root's, so a view carrying it is genuinely somebody
    # else's on any box this is not run as root on.
    if os.getuid() != 0:
        _fv = _trv("google-chrome", "Settings - Appearance", pid=1, vid=91)
        _r = engine.resolution(_fv)
        ck("foreign-resolution-is-never", _st(_fv) == Resolution.NEVER)
        ck("foreign-resolution-says-whose", "uid 0" in (_r.why or ""))
        # THE CONSEQUENCE THAT MATTERS: `unidentified` is the one predicate
        # both learning and placing ask, so Never there is what actually
        # stops the slot being taken.
        ck("foreign-is-unidentified", engine.unidentified(_fv))
        ck("foreign-has-no-identity-key", _single_id(_fv) is None)
        # AND THE BUG ITSELF: a learn pass over a foreign window must create
        # no slot. This is the check the live damage would have failed.
        # The window shape is a SNAPSHOT row, which is what learn() consumes,
        # built the way the lifecycle harness builds one.
        _kb, _groups = {}, {}
        _fw = {"app_id": "google-chrome", "title": "Settings - Appearance",
               "key": "chrome:win:1", "pid": 1, "id": 91,
               "output": "eDP-1", "workspace": [1, 0],
               "pos": [172, 115], "size": [100, 100]}
        engine.learn(_kb, _groups, [_fw], time.time())
        ck("foreign-is-never-learned", not _kb)
        # AND THE POSITIVE CONTROL, or the check above passes for any reason
        # at all. IT ASSERTS THE REASON RATHER THAN THE OUTCOME, because a
        # CHROME row's readiness is a question about the HOST: its identity
        # joins the title against the live session files, so the same row
        # learns on a box whose Chrome happens to have recorded a window of
        # that title and does not on a box whose Chrome has not. Measured
        # 2026-11-04: it learned on manifestor off a stale session file and
        # was correctly Pending on manifold, so asserting `bool(_kb2)` made
        # this a check on the host. What the gate owes is that OUR pid is not
        # refused FOR BEING SOMEBODY ELSE'S, which is host-free whatever
        # chrome then answers. The learn-level control is the unowned-app
        # pair below, where resolution needs no host state at all.
        _ow = _trv("google-chrome", "Settings - Appearance",
                   pid=os.getpid(), vid=92)
        ck("foreign-check-has-a-working-control",
           "uid 0" not in (engine.resolution(_ow).why or ""))

        # ---- AND THE HEADLINE: TWO of one account's windows, TWO slots ----
        # Seven of titan's Chrome windows shared ONE key on manifold, so one
        # was placed and six landed where Chrome opened them. A fixture with
        # ONE window would pass whatever the code did, so there are two, and
        # the assertion is that the store gained TWO distinct keys.
        #
        # THE ROWS CARRY `key` ALREADY STAMPED, which is what snapshot() does
        # while the window is live: the title this identity joins on is
        # redacted in the row, so learn() must read the stamp rather than
        # re-derive. That is the whole reason the stamp is kept.
        _t0 = time.time()
        _kb3, _g3 = {}, {}
        _w1 = {"app_id": "google-chrome", "title": "", "source": "titan",
               "key": "titan:chrome:win:11", "pid": 1, "id": 101,
               "output": "eDP-1", "workspace": [1, 0], "pos": [10, 10],
               "size": [100, 100]}
        _w2 = dict(_w1, key="titan:chrome:win:22", id=102,
                   workspace=[2, 0], pos=[20, 20])
        engine.learn(_kb3, _g3, [_w1, _w2], _t0)
        _tk = sorted(k for k in _kb3 if "titan" in k)
        ck("two-foreign-windows-get-two-slots", len(_tk) == 2)
        ck("each-foreign-slot-names-its-own-window",
           _tk == sorted([engine.kkey("google-chrome", "titan:chrome:win:11"),
                          engine.kkey("google-chrome",
                                      "titan:chrome:win:22")]))
        ck("foreign-slots-keep-their-own-geometry",
           {tuple(_kb3[k]["workspace"]) for k in _tk} == {(1, 0), (2, 0)})
        ck("a-foreign-slot-carries-its-source-field",
           all(_kb3[k].get("source") == "titan" for k in _tk))
        # AND A KEY THAT IS NOT THIS SOURCE'S IS NEVER STORED, which is the
        # guard in learn: a stamp naming another account, or an owner-shaped
        # one, falls back to the source-alone key rather than cross-filing.
        _kb4, _g4 = {}, {}
        engine.learn(_kb4, _g4,
                     [dict(_w1, key="chrome:win:99", id=103)], _t0)
        ck("a-foreign-window-never-takes-an-owner-shaped-key",
           list(_kb4) == [engine.kkey("google-chrome", "titan")])
        # AND WITH NO PER-WINDOW STAMP IT IS TODAY'S BEHAVIOUR EXACTLY, so a
        # window whose account cannot say which one it is does not regress.
        _kb5, _g5 = {}, {}
        engine.learn(_kb5, _g5, [dict(_w1, key="", id=104)], _t0)
        ck("a-foreign-window-with-no-stamp-keys-on-its-source",
           list(_kb5) == [engine.kkey("google-chrome", "titan")])

        # AND AGAIN WITH AN UNOWNED, SINGLE-WINDOW APP, which is a DIFFERENT
        # PATH THROUGH learn and the one that was actually broken. The check
        # above uses chrome, which a plugin OWNS, so `is_unique` is False and
        # it reaches the gate by the third branch; an app_id-only window takes
        # the FIRST branch, which did not ask. It passed for the wrong reason
        # and a live box found what the suite could not: a work account's
        # Slack kept being learned into `slack\0` with the resolution fix in
        # place. The lesson is the file's own: when a check passes, ask which
        # branch it proved.
        _kb3, _g3 = {}, {}
        _sw = {"app_id": "slack", "title": "Sign in | Slack", "key": "slack",
               "pid": 1, "id": 94, "output": "eDP-1", "workspace": [1, 0],
               "pos": [415, 55], "size": [1244, 1151]}
        engine.learn(_kb3, _g3, [_sw], time.time())
        ck("foreign-appid-only-app-is-never-learned", not _kb3)
        _kb4, _g4 = {}, {}
        engine.learn(_kb4, _g4,
                     [dict(_sw, pid=os.getpid(), id=95)], time.time())
        ck("foreign-appid-only-control-is-learned",
           engine.kkey("slack", "") in _kb4)

        # STEP 1 END TO END: a window with a NAMED source is learned under
        # that source's key, and the OWNER's key shape is untouched by its
        # presence. Driven as learn() receives them, i.e. snapshot rows, with
        # the source already stamped and the title already redacted.
        _kb5, _g5 = {}, {}
        _f_src = {"app_id": "slack", "title": "", "key": "", "cmd": None,
                  "pid": 1, "id": 98, "owner": 0, "source": "titan",
                  "output": "eDP-1", "workspace": [1, 0],
                  "pos": [415, 55], "size": [1244, 1151]}
        _o_slack = {"app_id": "slack", "title": "Slack", "key": "Slack",
                    "pid": os.getpid(), "id": 99,
                    "output": "eDP-1", "workspace": [2, 0],
                    "pos": [10, 20], "size": [800, 600]}
        engine.learn(_kb5, _g5, [_f_src, _o_slack], time.time())
        ck("step1-a-named-source-is-learned-under-its-source-key",
           engine.kkey("slack", "titan") in _kb5)
        # THE KEY-SHAPE HAZARD, which is what `counts` excluding foreign rows
        # fixes: before it, two Slacks made counts["slack"] == 2 and the
        # OWNER's window flipped off its app_id-only key, orphaning its slot.
        ck("step1-the-owners-key-shape-is-unaffected",
           engine.kkey("slack", "") in _kb5)
        ck("step1-the-owner-entry-is-still-appid-only",
           _kb5[engine.kkey("slack", "")].get("appid_only") is True)
        # AND NO LABEL FOR THE FOREIGN ENTRY. `label` is the human title, and
        # a work window's title is that account's content; the snapshot
        # redacts it, and this asserts nothing downstream puts it back.
        ck("step1-a-foreign-entry-carries-no-label",
           _kb5[engine.kkey("slack", "titan")].get("label") == "")
        ck("step1-the-owner-entry-keeps-its-label",
           _kb5[engine.kkey("slack", "")].get("label") == "Slack")

    # 1d. THE WINDOW-SOURCE SEAM: whose window, from a hook, so usher names
    #     no provider and works identically with none.
    #
    # REAL SCRIPTS AND REAL SUBPROCESSES, not a stubbed runner: the access
    # check, the exit code and the stdout parsing are the contract, and a
    # stub would test my idea of them instead.
    _hd = tempfile.mkdtemp(prefix="usher-src-", dir="/var/tmp")
    try:
        def _mkhook(name, body, mode=0o755):
            p = os.path.join(_hd, name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n" + body + "\n")
            os.chmod(p, mode)
            return p

        _h_src = _mkhook("src", 'echo titan\nexit 0')
        _h_mine = _mkhook("mine", "exit 1")
        _h_cannot = _mkhook("cannot", "exit 2")
        _h_prose = _mkhook("prose", 'echo "usage: hook <pid>"\nexit 0')
        _h_empty = _mkhook("empty", "exit 0")
        _h_noexec = _mkhook("noexec", "echo titan", mode=0o644)

        ck("source-hook-names-the-source",
           engine.window_source(1, hook=_h_src) == ("titan", "source"))
        ck("source-hook-exit-1-is-mine",
           engine.window_source(1, hook=_h_mine) == (None, "mine"))
        ck("source-hook-exit-2-is-unknown",
           engine.window_source(1, hook=_h_cannot) == (None, "unknown"))
        # A PROVIDER THAT PRINTS PROSE HAS NOT ANSWERED, and reading its first
        # word as a source name would key windows on a usage block.
        ck("source-hook-prose-is-not-a-name",
           engine.window_source(1, hook=_h_prose) == (None, "unknown"))
        ck("source-hook-silence-is-not-a-name",
           engine.window_source(1, hook=_h_empty) == (None, "unknown"))
        ck("source-hook-not-executable-is-nohook",
           engine.window_source(1, hook=_h_noexec) == (None, "nohook"))
        ck("source-hook-absent-is-nohook",
           engine.window_source(1, hook=os.path.join(_hd, "nope"))
           == (None, "nohook"))
        # A HOOK THAT HANGS MUST NOT HANG PLACEMENT. Driven through the
        # injected runner rather than by actually sleeping, so the suite
        # stays fast while the except arm is still executed.
        def _boom(*_a, **_k):
            raise subprocess.TimeoutExpired("hook", 2)

        # ITS OWN HOOK PATH, so this cannot read a cached answer from the
        # `src` hook above: the cache is keyed on the provider as well as the
        # process, and reusing a path made this depend on call ORDER.
        _h_hang = _mkhook("hang", "exit 0")
        ck("source-hook-timeout-is-unknown",
           engine.window_source(1, run=_boom, hook=_h_hang) == (None,
                                                                "unknown"))
        # FOUR STATES, PAIRWISE DISTINCT. Collapsing two is how a mechanism
        # that distinguishes N cases ends up spending none of it, which this
        # file records twice.
        ck("source-hook-states-are-pairwise-distinct",
           len({engine.window_source(1, hook=_h_src)[1],
                engine.window_source(1, hook=_h_mine)[1],
                engine.window_source(1, hook=_h_cannot)[1],
                engine.window_source(1, hook=_h_noexec)[1]}) == 4)

        # window_origin: THE uid GOES FIRST, and that is observable. A source
        # tuple that WOULD name a source is ignored when the uid says the
        # window is ours, which is what keeps the hook off the hot path.
        ck("origin-our-own-window-does-not-consult-the-hook",
           engine.window_origin(1, source=("titan", "source"),
                                uid_of=lambda _p: 1000, me=1000)
           == (None, None))
        ck("origin-a-foreign-window-carries-the-name",
           engine.window_origin(1, source=("titan", "source"),
                                uid_of=lambda _p: 997, me=1000)
           == ("titan", 997))
        # NO PROVIDER, OR ONE THAT CANNOT ANSWER: the uid answer alone, which
        # is exactly what usher computed before this seam existed.
        for _st in ("nohook", "unknown"):
            ck(f"origin-falls-back-to-the-uid-when-{_st}",
               engine.window_origin(1, source=(None, _st),
                                    uid_of=lambda _p: 997, me=1000)
               == (None, 997))

        # AND THE REASON NAMES THE SOURCE, which is what a human reads in
        # doctor and what a stored key will carry once the source is keyable.
        if os.getuid() != 0:
            _rsh2 = engine.SOURCE_HOOK
            engine._SOURCE_CACHE.clear()
            try:
                engine.SOURCE_HOOK = _h_src
                _fr = engine.resolution(
                    _trv("slack", "Sign in | Slack", pid=1, vid=93))
                # A NAMED SOURCE *IS* THE KEY, which is the whole of step 1:
                # keyed on the NAME, never the uid, because a uid is an
                # allocation that renumbers on a repave and orphans every
                # slot keyed on it.
                ck("foreign-named-source-is-ready", _fr.is_ready)
                ck("foreign-key-is-the-source-name", _fr.key == "titan")
                # THE SOURCE ALONE, with no per-window part, because there is
                # none to add: the app's state is behind the uid wall. So two
                # windows of one foreign app SHARE this key and the slot
                # ledger places the first, which is the honest degradation an
                # app_id-only app has always had.
                _fr2x = engine.resolution(
                    _trv("slack", "Something else entirely", pid=1, vid=96))
                ck("foreign-key-ignores-the-title", _fr2x.key == "titan")
            finally:
                engine.SOURCE_HOOK = _rsh2
                engine._SOURCE_CACHE.clear()

        # THE CACHE KEEPS A SETTLED ANSWER AND NOT AN UNSETTLED ONE: freezing
        # "unknown" would turn a blip into a permanent wrong answer.
        engine._SOURCE_CACHE.clear()
        engine.window_source(os.getpid(), hook=_h_src)
        ck("source-hook-caches-a-settled-answer",
           len(engine._SOURCE_CACHE) == 1)
        engine._SOURCE_CACHE.clear()
        engine.window_source(os.getpid(), hook=_h_cannot)
        ck("source-hook-does-not-cache-unknown",
           not engine._SOURCE_CACHE)
        engine._SOURCE_CACHE.clear()
    finally:
        shutil.rmtree(_hd, ignore_errors=True)

def _t_lock(ck):
    """The lock decision, as the full matrix. PURE, so no session is needed.

    Written as a table because the costs are ASYMMETRIC and every uncertain
    cell has to decline: refusing to lock costs a lock, while believing a lock
    that did not happen costs the console. A per-case check would not have
    made that obvious, and the `None` hint row is the one that matters.
    """
    _S = ("13", "999")        # a resolved (session id, leader)
    lock_now_real = engine.lock_now
    rows = [
        # loginctl, seated, hint,   forced, expected plan
        (False, _S,   "no",  False, "no-loginctl"),
        (False, None, None,  False, "no-loginctl"),
        (True,  None, None,  False, "no-session"),
        (True,  _S,   "yes", False, "already"),
        (True,  _S,   "no",  False, "lock"),
        (True,  _S,   None,  False, "unverifiable"),
        (True,  _S,   None,  True,  "forced-unverifiable"),
        # force must NOT invent a session or a loginctl
        (False, _S,   "no",  True,  "no-loginctl"),
        (True,  None, None,  True,  "no-session"),
        # and must not re-lock what is already locked
        (True,  _S,   "yes", True,  "already"),
    ]
    for have, seated, hint, forced, want in rows:
        got = lock_plan(have, seated, hint, forced=forced)
        ck(f"lock-plan-{int(have)}-{bool(seated) and 1 or 0}-{hint}-"
           f"{int(forced)}", got == want)

    # lock_now()'s ORCHESTRATION, with both seams injected. The live path
    # cannot be exercised here (unlocking from an ssh shell does not take, so
    # a locked box stays locked), and a one-off live lock proves the MECHANISM
    # without proving this function drives it correctly. Note it must VERIFY
    # rather than trust: `loginctl lock-session` exits 0 whether or not
    # anything is listening, which is the same "report the end state, never
    # the call returning" rule the plymouth capture script needed.
    _real_lc, _real_hint = engine.loginctl, engine.session_locked_hint
    try:
        calls = []
        # THE LISTING MUST NAME THE REAL USER, because lock_now resolves the
        # seat with getpass.getuser(): a fixture with a made-up name silently
        # resolves to no-session and every check below then passes or fails
        # for the wrong reason.
        import getpass as _gp
        _me = _gp.getuser()

        def _lc(*a, **k):
            calls.append(a)
            if a[0] == "list-sessions":
                return 0, f"  13 1000 {_me} seat0 999 user tty7 no -\n"
            return 0, ""

        engine.loginctl = _lc

        # the hint flips to yes on the second poll: locked, and confirmed
        seq = iter(["no", "no", "yes", "yes"])
        engine.session_locked_hint = lambda _s: next(seq, "yes")
        ok, plan, _d = engine.lock_now(wait=3)
        ck("lock-now-locks-and-confirms", ok and plan == "locked")
        ck("lock-now-actually-asked-logind",
           any(c[0] == "lock-session" for c in calls))

        # the hint NEVER flips: nothing is handling the Lock signal
        engine.session_locked_hint = lambda _s: "no"
        ok, plan, detail = engine.lock_now(wait=0.6)
        ck("lock-now-detects-an-unhonoured-lock",
           (not ok) and plan == "not-honoured")
        ck("lock-now-says-nothing-is-handling-it",
           "nothing is handling" in detail.lower())

        # already locked: no request at all, which keeps a reload from
        # re-locking a session the user has since unlocked and is using
        calls.clear()
        engine.session_locked_hint = lambda _s: "yes"
        ok, plan, _d = engine.lock_now()
        ck("lock-now-already-locked-is-ok", ok and plan == "already")
        ck("lock-now-already-locked-asks-nothing",
           not any(c[0] == "lock-session" for c in calls))

        # no seated session: must not lock anything, and must not invent one
        def _lc_empty(*a, **k):
            calls.append(a)
            return (0, "") if a[0] == "list-sessions" else (0, "")

        calls.clear()
        engine.loginctl = _lc_empty
        engine.session_locked_hint = lambda _s: "no"
        ok, plan, _d = engine.lock_now()
        ck("lock-now-no-session-declines", (not ok) and plan == "no-session")
        ck("lock-now-no-session-asks-nothing",
           not any(c[0] == "lock-session" for c in calls))
    finally:
        engine.loginctl = _real_lc
        engine.session_locked_hint = _real_hint

    # THE SUMMONED-LOCK MARKER, which must be per SESSION and not per boot.
    # On this fleet the login user LINGERS, so XDG_RUNTIME_DIR survives a
    # logout and a boot-scoped marker suppressed the lock on every summoned
    # login after the first. That leaves a console open for somebody who is
    # not in front of it, and it is the exact shape of a test campaign.
    _rl, _rs, _rln = engine.loginctl, engine._seated_now, engine.logline
    _rt = os.environ.get("USHER_SUMMONED")
    import tempfile as _tf
    _d = _tf.mkdtemp(prefix="usher-mark-")
    _rrd = engine.runtime_dir
    try:
        os.environ["USHER_SUMMONED"] = "1"
        engine.runtime_dir = lambda: _d
        engine.logline = lambda *a, **k: None
        calls = []

        def _lock_stub():
            calls.append(1)
            return True, "locked", "ok"

        engine.lock_now = _lock_stub
        engine._seated_now = lambda: ("13", "999")
        ck("marker-locks-the-first-time",
           lock_summoned_session() is True and len(calls) == 1)
        ck("marker-does-not-relock-the-same-session",
           lock_summoned_session() is None and len(calls) == 1)
        # A NEW LOGIN IS A NEW SESSION ID, and the surviving marker must not
        # suppress it. This is the bug: with a boot-scoped marker this stayed
        # at 1 and the second console was left unlocked.
        engine._seated_now = lambda: ("14", "1000")
        ck("marker-relocks-a-NEW-session",
           lock_summoned_session() is True and len(calls) == 2)
        # not summoned -> never, whatever the marker says
        os.environ.pop("USHER_SUMMONED", None)
        ck("marker-ignores-an-unsummoned-session",
           lock_summoned_session() is None and len(calls) == 2)

        # THE MARKER PATH, which is the half that has to work once the
        # compositor is a UNIT and the daemon no longer inherits greetd's
        # environment. USHER_SUMMONED is unset throughout this block.
        ck("summon-env-absent-and-no-marker-is-not-summoned",
           engine.take_summoned() is False)
        engine.arm_summoned()
        ck("summon-marker-alone-is-enough",
           os.path.exists(engine.summon_marker())
           and engine.take_summoned() is True)
        # CONSUMED, so a login that is declined, or a session that never
        # arrives, cannot hand its lock to the NEXT console login.
        ck("summon-marker-is-consumed-by-the-read",
           not os.path.exists(engine.summon_marker()))
        ck("summon-marker-does-not-fire-twice",
           engine.take_summoned() is False)
        # ...and it drives the real lock path, not just the predicate.
        engine._seated_now = lambda: ("15", "1001")
        engine.arm_summoned()
        ck("summon-marker-locks-a-session-with-no-env-var",
           lock_summoned_session() is True and len(calls) == 3)
        # THE ENV VAR STILL WORKS, which is what lets this land BEFORE the
        # session is recomposed: a box where usher is new and the session is
        # not must keep locking.
        os.environ["USHER_SUMMONED"] = "1"
        engine._seated_now = lambda: ("16", "1002")
        ck("summon-env-var-alone-still-locks",
           not os.path.exists(engine.summon_marker())
           and lock_summoned_session() is True and len(calls) == 4)
        os.environ.pop("USHER_SUMMONED", None)
        # AND A FAILED WRITE IS NOT FATAL. Losing the lock is bad; refusing
        # the login because a marker could not be written is worse, and the
        # warning is what makes it visible.
        engine.runtime_dir = lambda: os.path.join(_d, "nope", "deeper")
        with contextlib.redirect_stderr(io.StringIO()):
            _armed = engine.arm_summoned()
        ck("summon-arm-survives-an-unwritable-runtime-dir", _armed is False)
        ck("summon-take-survives-an-unreadable-marker",
           engine.take_summoned() is False)
        engine.runtime_dir = lambda: _d
        # THE WIRING, which the checks above say nothing about: a correct
        # predicate nobody calls is the shape that cost `entry_output` its
        # own separate check. `cleanly login` must ARM, and the ORDER matters
        # as much as the call, so the refusal and the dry run are checked too.
        import usher.cli as _cl
        _rss, _rlc = _cl.session_start, engine.lock_capability
        try:
            started = []

            class _Exec(Exception):
                "session_start EXECS, so a stub that RETURNS is a liar."

            def _start(a):
                # RECORD AND RAISE, because the real one never comes back: a
                # returning stub falls through to _cleanly_leave and takes a
                # live connect() with it. Same fix the dock harness needed.
                started.append(a)
                raise _Exec()
            _cl.session_start = _start
            engine.lock_capability = lambda: (True, "lock", "ok")
            _q = io.StringIO()
            try:
                with contextlib.redirect_stdout(_q), \
                        contextlib.redirect_stderr(_q):
                    _cl.do_cleanly(["login"])
                _reached = False
            except _Exec:
                _reached = True
            ck("login-arms-the-summon-marker",
               _reached and started == ["login"]
               and os.path.exists(engine.summon_marker()))
            os.remove(engine.summon_marker())
            # A REFUSED LOGIN MUST LEAVE NOTHING. Arming before the refusal
            # would hand a lock to whoever logs in at the console next, which
            # is the one way this marker could do harm.
            engine.lock_capability = lambda: (False, "no-loginctl", "none")
            started.clear()
            with contextlib.redirect_stdout(_q), \
                    contextlib.redirect_stderr(_q):
                _rc = _cl.do_cleanly(["login"])
            ck("a-refused-login-arms-nothing",
               _rc == 1 and started == []
               and not os.path.exists(engine.summon_marker()))
            # ...and a DRY RUN likewise: it starts nothing, so it must leave
            # nothing for the next real login to consume.
            engine.lock_capability = lambda: (True, "lock", "ok")
            with contextlib.redirect_stdout(_q), \
                    contextlib.redirect_stderr(_q):
                _dry = _cl.do_cleanly(["login", "-n"])
            ck("a-dry-run-login-arms-nothing",
               _dry == 0 and started == []
               and not os.path.exists(engine.summon_marker()))
        finally:
            _cl.session_start, engine.lock_capability = _rss, _rlc

    finally:
        engine.loginctl = _rl
        engine._seated_now = _rs
        engine.logline = _rln
        engine.runtime_dir = _rrd
        engine.lock_now = lock_now_real
        if _rt is None:
            os.environ.pop("USHER_SUMMONED", None)
        else:
            os.environ["USHER_SUMMONED"] = _rt
        import shutil as _sh
        _sh.rmtree(_d, ignore_errors=True)

    # THE TWO INVARIANTS WORTH NAMING SEPARATELY, because a future edit that
    # breaks either is the one that costs the console rather than a lock.
    ck("lock-force-cannot-fabricate-a-session",
       lock_plan(True, None, None, forced=True) == "no-session")
    ck("lock-unreadable-hint-is-never-plain-lock",
       lock_plan(True, _S, None) != "lock")
    ck("lock-capability-is-two-plans",
       {"lock", "already"} == {p for p in
                               ("lock", "already", "no-loginctl",
                                "no-session", "unverifiable")
                               if p in ("lock", "already")})

def _t_desktop(ck):
    """The DEFAULT relaunch: any app, from the freedesktop registry.

    Every refusal below is a case measured on a real store rather than an
    invented one, which is why they are worth pinning individually: the two
    NoDisplay rows are a tray applet already in autostart and a portal whose
    window is a transient dialog, and relaunching either at session start is
    the failure this filter exists to prevent."""
    E = {
        "calibre-gui": {"exec": "calibre %U", "type": "Application"},
        "signal-desktop": {"exec": "/bin/sh %U", "startupwmclass": "signal"},
        "nm-applet": {"exec": "/bin/sh", "nodisplay": "true"},
        "portal": {"exec": "/bin/sh", "nodisplay": "TRUE"},
        "oldhidden": {"exec": "/bin/sh", "hidden": "true"},
        # the user's OWN entry, authored to let usher relaunch a CLI app
        # without putting it in the app menu
        "mine": {"exec": "/bin/sh", "nodisplay": "true",
                 "x-usher-user-authored": "True"},
        # ...but Hidden is a TOMBSTONE and outranks authorship
        "minedeleted": {"exec": "/bin/sh", "hidden": "true",
                        "x-usher-user-authored": "True"},
        "alink": {"exec": "/bin/sh", "type": "Link"},
        "needsterm": {"exec": "/bin/sh", "terminal": "true"},
        "gone": {"exec": "/no/such/binary/anywhere"},
        "noexec": {"type": "Application"},
        "dup-a": {"exec": "/bin/sh", "startupwmclass": "twice"},
        "dup-b": {"exec": "/bin/sh", "startupwmclass": "twice"},
        # A PLUGIN-OWNED APP THAT DOES HAVE AN ENTRY, which the owned-app
        # cells need: /usr/share/applications/kitty.desktop is real, and
        # without a row here those checks would pass because the entry was
        # MISSING rather than because the claim was honoured.
        "kitty": {"exec": "kitty", "type": "Application"},
    }

    def go(app):
        return desktop_launch_for(app, E)

    ck("desktop-strips-field-codes", go("calibre-gui")[0] == ["calibre"])
    # the reverse join, and it is not cosmetic: Signal's app-id is `signal`
    # while its entry is `signal-desktop`, so the clearest real case needs it
    ck("desktop-joins-on-startupwmclass", go("signal")[0] == ["/bin/sh"])
    ck("desktop-is-case-insensitive", go("CALIBRE-GUI")[0] == ["calibre"])
    for app, want in (("nm-applet", "NoDisplay"), ("portal", "NoDisplay"),
                      ("oldhidden", "Hidden"), ("alink", "Type=Link"),
                      ("needsterm", "Terminal=true"),
                      ("gone", "not here"), ("noexec", "no usable Exec"),
                      ("twice", "2 desktop entries"),
                      ("nosuchapp", "no desktop entry"),
                      ("", "no app-id")):
        argv, why = go(app)
        ck(f"desktop-refuses-{app or 'empty'}", argv is None)
        ck(f"desktop-says-why-{app or 'empty'}", want in (why or ""))
    # NoDisplay must be read case-insensitively: the spec says the value is a
    # boolean, and a real entry writing TRUE must not slip through.
    ck("desktop-nodisplay-is-case-insensitive", go("portal")[0] is None)

    # AUTHORSHIP DECIDES HOW NoDisplay READS, and the asymmetry is the point.
    # The spec says NoDisplay means "do not show in menus", not "do not
    # launch", so reading it as a launch filter is a REPURPOSING. It is a good
    # one for somebody else's entry (there, hidden correlates with
    # not-an-app) and wrong for the user's own, where the obvious reason to
    # author a NoDisplay entry is to let usher relaunch a CLI-launched app
    # without cluttering the menu. Refusing that second-guesses the only
    # person who knows.
    ck("desktop-user-nodisplay-is-allowed", go("mine")[0] == ["/bin/sh"])
    ck("desktop-system-nodisplay-is-refused", go("nm-applet")[0] is None)
    # HIDDEN OUTRANKS AUTHORSHIP, because the spec calls it a deletion: the
    # user removed the entry at their level, so a launcher must act as though
    # it is not there. Treating it like NoDisplay would resurrect it.
    ck("desktop-hidden-beats-authorship", go("minedeleted")[0] is None)
    ck("desktop-hidden-says-deleted",
       "deleted" in (go("minedeleted")[1] or ""))

    # THE OFF SWITCH must actually stop it, and must not need a restart to
    # read: it is checked per call, like the exclude rules.
    _env = os.environ.get("USHER_NO_DEFAULT_RELAUNCH")
    try:
        os.environ["USHER_NO_DEFAULT_RELAUNCH"] = "1"
        _got = []
        ck("desktop-off-switch-stops-it",
           desktop_relaunch_missing(
               [{"id": 1, "app_id": "calibre-gui", "title": "t", "pid": -1}],
               [], spawn=_got.append) == set() and _got == [])
    finally:
        if _env is None:
            os.environ.pop("USHER_NO_DEFAULT_RELAUNCH", None)
        else:
            os.environ["USHER_NO_DEFAULT_RELAUNCH"] = _env

    # --- the pass itself, with the spawn stubbed --------------------------
    def W(app, title="t"):
        return {"id": 1, "app_id": app, "title": title, "pid": -1,
                "output": "DP-1", "workspace": [1.0, 1.0],
                "pos": [0.0, 0.0], "size": [10.0, 10.0]}

    _re, _rl, _ra = engine.desktop_entries, engine.logline, engine._announce
    try:
        engine.desktop_entries = lambda *a, **k: E
        engine.logline = lambda *a, **k: None
        engine._announce = lambda *a, **k: None
        got = []
        n = desktop_relaunch_missing([W("calibre-gui")], [],
                                     spawn=got.append)
        ck("desktop-pass-launches-a-missing-app",
           n == {"calibre-gui"} and got == [["calibre"]])
        # ALREADY RUNNING: its windows are its own business
        got = []
        n = desktop_relaunch_missing([W("calibre-gui")],
                                     [_trv("calibre-gui", "t")],
                                     spawn=got.append)
        ck("desktop-pass-skips-a-live-app", n == set() and got == [])
        # AN OWNED APP IS NEVER TOUCHED HERE, which is what makes a specific
        # plugin an override rather than a competitor.
        got = []
        n = desktop_relaunch_missing([W("kitty")], [], spawn=got.append)
        ck("desktop-pass-skips-an-owned-app", n == set() and got == [])
        # ...UNLESS THE CALLER SAYS THE OWNER DID NOT START IT, which is the
        # roster path: an app-id-only row gives a plugin keyed on a recorded
        # command nothing to act on, and its claim would then be the only
        # thing stopping the app from coming back. Measured on manifold: an
        # account's terminal was in its roster and started by nobody.
        got = []
        n = desktop_relaunch_missing([W("kitty")], [], spawn=got.append,
                                     claimed=set())
        ck("desktop-pass-starts-an-owned-app-the-owner-declined",
           n == {"kitty"} and got == [["kitty"]])
        # AND AN EXPLICIT CLAIM IS STILL HONOURED, or the bypass would
        # double-launch whatever the plugin really did start.
        got = []
        n = desktop_relaunch_missing([W("kitty")], [], spawn=got.append,
                                     claimed={"kitty"})
        ck("desktop-pass-honours-an-explicit-claim",
           n == set() and got == [])
            # ANOTHER ACCOUNT'S SAVED WINDOW IS NOT OURS TO START. The entry
        # carries an app-id and nothing else, so resolving it in OUR registry
        # and running it would open a second, PERSONAL copy of somebody's
        # work application. `snapshot` stamps `owner` for exactly this, and
        # the control above (same row, no owner) is what makes this non-vacuous.
        got = []
        n = desktop_relaunch_missing([dict(W("calibre-gui"), owner=997)], [],
                                     spawn=got.append)
        ck("desktop-pass-skips-another-accounts-app",
           n == set() and got == [])
        # ONE INVOCATION PER APP, not per window: all six chrome windows
        # report one pid and a desktop entry describes an APP.
        got = []
        n = desktop_relaunch_missing([W("calibre-gui", "a"),
                                      W("calibre-gui", "b")], [],
                                     spawn=got.append)
        ck("desktop-pass-is-per-app-not-per-window",
           n == {"calibre-gui"} and got == [["calibre"]])
        # a refusal is silent-but-logged, never a crash, and never a spawn
        got = []
        n = desktop_relaunch_missing([W("nm-applet")], [], spawn=got.append)
        ck("desktop-pass-honours-a-refusal", n == set() and got == [])
    finally:
        engine.desktop_entries = _re
        engine.logline = _rl
        engine._announce = _ra

def _t_slots(ck):
    """ONE WINDOW PER SLOT, driven through the real Watcher.

    THE WART THIS CLOSES: ten kitty windows in one directory were all seated
    at the identical geometry, stacked perfectly, and with no taskbar you
    would never find out. Not a new rule either: match() has been
    consume-once since it was written, so `usher restore` could never
    double-place; only the DAEMON's per-window path had never learned it."""
    from .watch import Watcher, PLACE_GRACE
    import time as _t

    # THE RULE, PURE, and every WORD proven: live_holder dispatches on which
    # of three it answers, so one returning the wrong word would still be
    # "non-empty" and match no arm. Asserting the exact word is the only
    # thing that catches that.
    ck("holder-nobody-is-free", engine.live_holder(None, 7, {7}) == "free")
    ck("holder-ourselves-is-free", engine.live_holder(7, 7, {7}) == "free")
    ck("holder-alive-is-held", engine.live_holder(5, 7, {5, 7}) == "held")
    ck("holder-gone-is-stale", engine.live_holder(5, 7, {7}) == "stale")
    # NO EVIDENCE REFUSES: an unreadable view list is not proof the holder
    # died, and reading it that way would hand a held slot away on an IPC
    # blip and bring back the stacking the ledger exists to prevent.
    ck("holder-no-evidence-is-held", engine.live_holder(5, 7, set()) == "held")
    # ...but a window with no rival is never refused for want of a list.
    ck("holder-no-evidence-still-frees-an-unheld-slot",
       engine.live_holder(None, 7, set()) == "free")

    w = Watcher(launch=False)
    now = _t.time()

    # place, and inside the grace, so placement is actually attempted
    w.st["armed_at"] = now
    w.st["last_map"] = now

    seated = []

    class _Sock:
        # `live` is what the compositor would report as mapped toplevels, and
        # it has to be here rather than absent: without list_views the ledger
        # check falls to live_holder's NO-EVIDENCE arm and every check below
        # would pass for the wrong reason, which is this file's oldest trap.
        live = {1, 2, 3}

        def list_outputs(self):
            return [{"name": "DP-1", "geometry": {"x": 0, "y": 0,
                                                  "width": 100, "height": 100}}]

        def list_views(self, filter_mapped_toplevel=False):
            return [{"id": i} for i in sorted(self.live)]

    w.place_sock = _Sock()
    w._seat_view = lambda v, e, o: (seated.append(v["id"]) or True)
    w.kb = {kkey("signal", ""):
            {"app_id": "signal", "title": "", "appid_only": True,
             "label": "x", "output": "DP-1", "workspace": [1.0, 1.0],
             "pos": [1.0, 1.0], "size": [10.0, 10.0], "last_seen": now,
             "sticky": False, "inverted": False, "fullscreen": False}}

    def V(vid):
        return {"id": vid, "app-id": "signal", "title": "Signal",
                "pid": -1, "parent": -1, "geometry": {"x": 0, "y": 0,
                                                      "width": 1, "height": 1}}

    try:
        for vid in (1, 2, 3):
            w.deadline[vid] = now + PLACE_GRACE
            w.identified.add(vid)
            w._try_place(V(vid))
        # THE WHOLE POINT: the first window gets the slot, the others are left
        # exactly where they opened rather than stacked on top of it.
        ck("slot-first-window-is-placed", seated == [1])
        ck("slot-second-window-is-not-stacked", 2 not in seated)
        ck("slot-third-window-is-not-stacked", 3 not in seated)
        ck("slot-ledger-records-the-holder",
           w.slot_held.get(kkey("signal", "")) == 1)

        # STEP 2: A WINDOW FROM ANOTHER ACCOUNT IS PLACED FROM ITS OWN
        # SLOT, AND NEVER FROM THE OWNER'S. Both slots exist here on purpose:
        # `signal\0` is the owner's app_id-only key and matches every window
        # of that app, so an ungated placer would seat the foreign window on
        # the owner's geometry. That is the mis-bind the whole area exists to
        # prevent, and it is the one thing step 2 could get wrong.
        if os.getuid() != 0:
            _hd2 = tempfile.mkdtemp(prefix="usher-slot-src-", dir="/var/tmp")
            _rh2, _rc2 = engine.SOURCE_HOOK, dict(engine._SOURCE_CACHE)
            try:
                _hp = os.path.join(_hd2, "src")
                with open(_hp, "w") as f:
                    f.write("#!/bin/sh\necho titan\nexit 0\n")
                os.chmod(_hp, 0o755)
                engine.SOURCE_HOOK = _hp
                engine._SOURCE_CACHE.clear()
                w.kb[kkey("signal", "titan")] = {
                    "app_id": "signal", "title": "titan", "appid_only": False,
                    "source": "titan", "label": "", "output": "DP-1",
                    "workspace": [2.0, 2.0], "pos": [9.0, 9.0],
                    "size": [10.0, 10.0], "last_seen": now, "sticky": False,
                    "inverted": False, "fullscreen": False}
                _got = []
                w._seat_view = lambda v, e, o: (_got.append((v["id"], e))
                                                or True)
                _Sock.live = {1, 2, 3, 9}
                _fv9 = {"id": 9, "app-id": "signal", "title": "Signal",
                        "pid": 1, "parent": -1,
                        "geometry": {"x": 0, "y": 0, "width": 1, "height": 1}}
                w.deadline[9] = now + PLACE_GRACE
                w.identified.add(9)
                w._try_place(_fv9)
                ck("step2-a-foreign-window-is-placed", [i for i, _ in _got]
                   == [9])
                ck("step2-placed-from-its-own-source-slot",
                   bool(_got) and _got[0][1].get("source") == "titan")
                # AND NOT FROM THE OWNER'S SLOT, which is the assertion that
                # would have caught an ungated lookup: the owner's entry sits
                # at ws(1,1) and the source's at ws(2,2).
                ck("step2-not-placed-from-the-owners-slot",
                   bool(_got) and list(_got[0][1].get("workspace")) == [2.0,
                                                                        2.0])
                ck("step2-the-ledger-uses-the-source-key",
                   w.slot_held.get(kkey("signal", "titan")) == 9)
            finally:
                engine.SOURCE_HOOK = _rh2
                engine._SOURCE_CACHE.clear()
                engine._SOURCE_CACHE.update(_rc2)
                shutil.rmtree(_hd2, ignore_errors=True)
                _Sock.live = {1, 2, 3}
                w._seat_view = lambda v, e, o: (seated.append(v["id"]) or True)

        # CLOSING THE HOLDER RELEASES THE SLOT, or its place would be
        # permanently unusable and every later window of that app adrift.
        w._on_event({"event": "view-unmapped", "view": {"id": 1}})
        ck("slot-released-on-unmap",
           kkey("signal", "") not in w.slot_held)
        w.placed.discard(2)
        w.deadline[2] = _t.time() + PLACE_GRACE
        w.identified.add(2)
        w._try_place(V(2))
        ck("slot-reusable-after-the-holder-closes", 2 in seated)

        # THE COMPOSITOR DOES NOT TELL US AN OUTPUT ARRIVED, measured on
        # wayfire 0.11.0 by subscribing to usher's own fourteen events in a
        # nested compositor: creating an output emits ZERO events, destroying
        # it emits `output-removed`. So the DOCK direction had no signal, and
        # `_profile_drift` could not cover it either, because capture is
        # event-driven and an idle session never dirtied the store.
        #
        # ITS OWN WATCHER, because the slot fixture below shares place_sock
        # and swapping it here broke two ledger checks on the first attempt.
        wp, _tr = Watcher(launch=False), []
        wp._begin_transition = lambda why: _tr.append(why)
        wp._capture_failed = lambda e, c, n: c

        def _outs(*names):
            class _O:
                def list_outputs(self):
                    if names and names[0] is None:
                        raise RuntimeError("planted: ipc down")
                    return [{"name": n} for n in names]
            return _O()

        one = _outs("DP-1")
        ck("outputs-first-poll-is-not-a-change",
           wp._poll_outputs(one) is one and not _tr)
        ck("outputs-first-poll-remembers-the-set",
           wp.outputs_seen == frozenset({"DP-1"}))
        ck("outputs-unchanged-is-silent",
           wp._poll_outputs(one) is one and not _tr)
        wp._poll_outputs(_outs("DP-1", "HEADLESS-1"))
        ck("outputs-an-ARRIVAL-starts-a-transition",
           len(_tr) == 1 and "+HEADLESS-1" in _tr[0])
        wp._poll_outputs(one)
        ck("outputs-a-DEPARTURE-does-too",
           len(_tr) == 2 and "-HEADLESS-1" in _tr[1])
        # NO EVIDENCE CHANGES NOTHING: an IPC failure must not read as every
        # output having vanished, or a blip starts a transition.
        wp._poll_outputs(_outs(None))
        ck("outputs-an-ipc-failure-is-not-a-display-change", len(_tr) == 2)
        ck("outputs-an-ipc-failure-keeps-the-remembered-set",
           wp.outputs_seen == frozenset({"DP-1"}))

        # THE WORKER'S STDERR REACHES watch.log, which is the one place a
        # reader looks: a worker that dies before it can log left `rc 1` with
        # no cause, and tackup lost a VM run to exactly that. BOUNDED BOTH
        # WAYS, because this runs on every respawn and a crash loop would
        # otherwise write a traceback into the log every two seconds.
        import tempfile as _tf2
        from . import watch as _wt
        _ed = _tf2.mkdtemp(prefix="usher-werr-")
        try:
            _ep = os.path.join(_ed, "err")
            ck("worker-stderr-missing-file-is-silent",
               _wt.worker_error_tail(_ep) == [])
            with open(_ep, "w") as f:
                f.write("\n")
            ck("worker-stderr-blank-is-silent",
               _wt.worker_error_tail(_ep) == [])
            with open(_ep, "w") as f:
                f.write("".join(f"line{i}\n" for i in range(40)))
            _tail = _wt.worker_error_tail(_ep)
            ck("worker-stderr-keeps-only-the-last-lines",
               len(_tail) == _wt.WORKER_ERR_LINES and _tail[-1] == "line39")
            with open(_ep, "w") as f:
                f.write("x" * 5000 + "\n")
            ck("worker-stderr-truncates-a-long-line",
               len(_wt.worker_error_tail(_ep)[0]) == _wt.WORKER_ERR_WIDTH)
            # The shape that matters: the LAST frame and the exception, which
            # is what names the cause.
            with open(_ep, "w") as f:
                f.write("Traceback (most recent call last):\n"
                        '  File "x", line 1, in <module>\n'
                        "Exception: Event not found: \"output-added\"\n")
            ck("worker-stderr-keeps-the-exception",
               any("output-added" in ln
                   for ln in _wt.worker_error_tail(_ep)))

            # DEGRADE ON A MISSING EVENT, never die. Before this, wayfire
            # refusing the whole call on the first unknown name killed the
            # worker rc 1 forever at one death per 30s with no cause logged
            # (tackup T8, from the distro's 0.10.0 which has no
            # `output-added`).
            class _Sub:
                """A compositor that knows only `good`. Mirrors the two facts
                measured on 0.11.0: it refuses the WHOLE call on one unknown
                name, and a refusal leaves the connection USABLE."""

                def __init__(self, good):
                    self.good, self.took = set(good), None

                def watch(self, evs=None):
                    if evs is None:
                        return {"result": "ok"}
                    missing = [e for e in evs if e not in self.good]
                    if missing:
                        raise Exception(
                            'Event not found: "%s"' % missing[0])
                    self.took = list(evs)
                    return {"result": "ok"}

            _all = ["view-mapped", "output-added", "output-removed"]
            s = _Sub(_all)
            ck("subscribe-healthy-takes-one-call",
               _wt.subscribe(s, _all) == _all and s.took == _all)
            s = _Sub(["view-mapped", "output-removed"])
            # GUARDED, so the PRE-FIX code reports as one named failure
            # instead of a raise that aborts the area: this is the plant that
            # matters most and it should say which check caught it.
            try:
                got = _wt.subscribe(s, _all, connect_one=lambda: _Sub(s.good))
            except Exception:                                  # noqa: BLE001
                got = "RAISED"
            ck("subscribe-drops-only-the-missing-event",
               got == ["view-mapped", "output-removed"])
            ck("subscribe-still-subscribes-to-the-rest", s.took == got)
            # NOTHING AT ALL is not a degradation, it is a broken compositor,
            # and pretending to watch would be worse than dying.
            s = _Sub([])
            try:
                _wt.subscribe(s, _all, connect_one=lambda: _Sub(set()))
                _raised = False
            except RuntimeError:
                _raised = True
            ck("subscribe-raises-when-nothing-is-accepted", _raised)

            # THE RESPAWN REPORT: it stops SHOUTING, never stops working,
            # because an early-death streak is exactly what a slow login
            # produces and this repo has the recovering counter-example.
            _r = _wt.respawn_report
            ck("respawn-first-deaths-carry-the-cause",
               [_r(n) for n in (1, 2, 3)] == ["detail"] * 3)
            ck("respawn-says-it-once-at-the-threshold",
               _r(_wt.LOOP_SHOUT_AT) == "shout")
            ck("respawn-then-goes-quiet",
               {_r(n) for n in range(_wt.LOOP_SHOUT_AT + 1,
                                     _wt.LOOP_SHOUT_AT + 20)} == {"quiet"})
            ck("respawn-three-outcomes-are-distinct",
               len({_r(1), _r(_wt.LOOP_SHOUT_AT),
                    _r(_wt.LOOP_SHOUT_AT + 1)}) == 3)
        finally:
            import shutil as _sh2
            _sh2.rmtree(_ed, ignore_errors=True)

        # THE HOLDER WENT AND ITS UNMAP NEVER ARRIVED. No view-unmapped event
        # here, deliberately: that is the whole fault. The ledger says 2 and
        # the compositor no longer lists it, so 3 must get the slot. Pre-fix
        # this was refused for the life of the generation, which cost calibre
        # its place on manifold and let the capture loop learn the cascade.
        w.place_sock.live = {3}
        w.placed.discard(3)
        w.deadline[3] = _t.time() + PLACE_GRACE
        w.identified.add(3)
        w._try_place(V(3))
        ck("slot-taken-from-a-holder-that-is-gone", 3 in seated)
        ck("slot-ledger-moves-to-the-new-holder",
           w.slot_held.get(kkey("signal", "")) == 3)

        # AND A LIVE HOLDER IS STILL A HOLDER, which is the half that must not
        # regress: the fix changes LIVENESS, never precedence.
        w.place_sock.live = {3, 4}
        w.deadline[4] = _t.time() + PLACE_GRACE
        w.identified.add(4)
        w._try_place(V(4))
        ck("slot-still-refused-while-the-holder-lives", 4 not in seated)

        # AND IT SAYS SO ONCE, NOT PER EVENT. _try_place runs from every map
        # AND every rename, and a browser renames constantly, so an
        # unconditional line here turned one standing condition into 126 rows
        # in an hour on manifold (seven windows over one key). The refusal
        # must still be SAID, since silently not placing is this repo's
        # recurring failure, so the assertion is EXACTLY ONE rather than none.
        # BOTH SPELLINGS ARE CAPTURED, since watch.py imports logline BY NAME
        # and holds its own reference: patching engine's alone leaves the
        # daemon's copy writing into the real log, which is the stale-copy
        # hazard the package split is careful about. Restored to whatever the
        # area quieting installed rather than to the real function.
        from . import watch as _wslot
        _rl_e, _rl_w = engine.logline, _wslot.logline
        _slog = []
        engine.logline = _wslot.logline = _slog.append
        try:
            w.slot_said.clear()
            w._try_place(V(4))
            _n1 = len([m for m in _slog if "slot taken" in m])
            for _ in range(5):
                w._try_place(V(4))
            _n2 = len([m for m in _slog if "slot taken" in m])
            ck("slot-refusal-is-said-at-all", _n1 == 1)
            ck("slot-refusal-is-said-once-not-per-event", _n2 == _n1)
            # A NEW WINDOW REUSING THE vid MUST BE SAID AGAIN, or quietening
            # it becomes a permanent silence as view ids are recycled.
            w._on_event({"event": "view-unmapped", "view": {"id": 4}})
            w.place_sock.live = {3, 4}
            w.deadline[4] = _t.time() + PLACE_GRACE
            w.identified.add(4)
            w._try_place(V(4))
            ck("slot-refusal-is-said-again-for-a-new-window",
               len([m for m in _slog if "slot taken" in m]) == _n2 + 1)
        finally:
            engine.logline, _wslot.logline = _rl_e, _rl_w

        # AND A DEAD HOLDER IS DROPPED EVEN WHERE THE PLACEMENT CANNOT GO ON,
        # or the ledger keeps asserting a window we have just proved is gone,
        # which is the asserted-vs-actual drift that caused this in the first
        # place. Reachable: the entry names an output nobody has, so
        # _place_view returns before seating anything.
        w.place_sock.live = {5}
        w.slot_held[kkey("signal", "")] = 3          # 3 is no longer live
        w.kb[kkey("signal", "")]["output"] = "GONE-1"
        w.deadline[5] = _t.time() + PLACE_GRACE
        w.identified.add(5)
        w._try_place(V(5))
        ck("slot-dead-holder-dropped-even-with-nowhere-to-place",
           kkey("signal", "") not in w.slot_held)
        ck("slot-nowhere-to-place-seats-nothing", 5 not in seated)
        w.kb[kkey("signal", "")]["output"] = "DP-1"   # later blocks share kb

        # ONE LATE CHANCE, and the distinction it encodes. In SETTLED, past the
        # PLACE_CAP (so nothing can re-enter place), a window that MAPPED
        # while place was in force is still placed the first time it
        # becomes identifiable; one opened mid-session is not. Conflating
        # those cost a Chrome window its slot for 2.5 hours on manifold: it
        # logged `recognised late, re-graced` and was then refused.
        from .engine import PLACE_CAP as _CAP
        def _settled_watcher():
            x = Watcher(launch=False)
            x.st["armed_at"] = _t.time() - _CAP - 1    # settled, past the cap
            x.st["last_map"] = _t.time()               # cannot rescue it
            x.place_sock = _Sock()
            x.kb = w.kb
            return x
        ck("cap-really-defeats-the-regrace",
           not _settled_watcher()._placing_now())
        s1 = []
        x = _settled_watcher()
        x._seat_view = lambda v, e, o: (s1.append(v["id"]) or True)
        x.deadline[7] = _t.time() + PLACE_GRACE
        x.late_ok.add(7)                               # mapped at login
        x._try_place(V(7))
        ck("late-chance-places-a-login-window", s1 == [7])
        s2 = []
        y = _settled_watcher()
        y._seat_view = lambda v, e, o: (s2.append(v["id"]) or True)
        y.deadline[8] = _t.time() + PLACE_GRACE        # NOT in late_ok
        y._try_place(V(8))
        ck("settled-still-leaves-a-new-window-alone", s2 == [])
        # ...and the chance is spent: identified, so not a first look again.
        s3 = []
        z = _settled_watcher()
        z._seat_view = lambda v, e, o: (s3.append(v["id"]) or True)
        z.deadline[9] = _t.time() + PLACE_GRACE
        z.late_ok.add(9)
        z.identified.add(9)                            # already had its look
        z._try_place(V(9))
        ck("late-chance-is-only-the-first-look", s3 == [])

        # ---- THE LEARN GATE COVERS A WINDOW THE LEDGER REFUSED ---------
        # Several windows can share ONE store key. The ledger gives the slot
        # to one and leaves the rest where they opened, and those are never
        # placed, so the place-mode clause above released them the moment
        # place mode ended and the capture loop learned a CASCADE position
        # into a key the window does not own, OVERWRITING the holder's
        # geometry. Self-worsening: the next login restores the cascade.
        #
        # MEASURED on manifold 2026-11-06 from the pre-logoff pair, which is
        # the first time this was diagnosable at all. Ten of one account's
        # Chrome windows shared `google-chrome NUL titan`, one was placed to
        # ws[0,1] and nine were refused, and the slot went
        # ws[0,1] pos[128,155] -> ws[2,0] pos[172,150], which is exactly
        # where one of the refused windows sat. THE FIXTURE USES THOSE
        # NUMBERS so the check reads as the incident.
        #
        # A FOREIGN WINDOW IS THE RIGHT SHAPE and the owner's app is NOT:
        # two windows of one of the owner's apps are TITLE-keyed, because
        # `is_unique` needs a count of one, so they would not share a key and
        # the fixture would not model the bug. A foreign window keys on its
        # SOURCE ALONE whatever the count, which is why ten of them collided.
        # The first attempt got this wrong and would have tested nothing.
        #
        # SETTLED ON PURPOSE: the damage happens AFTER place mode ends, so a
        # fixture in place mode passes over the bug entirely.
        _SK = kkey("google-chrome", "titan")
        _base = {"app_id": "google-chrome", "title": "titan",
                 "appid_only": False, "label": "", "output": "DP-1",
                 "workspace": [0.0, 1.0], "pos": [128.0, 155.0],
                 "size": [10.0, 10.0], "last_seen": _t.time(),
                 "source": "titan", "sticky": False, "inverted": False,
                 "fullscreen": False}

        def _fw(vid, ws, pos):
            return {"id": vid, "app_id": "google-chrome", "title": "",
                    "key": "titan", "source": "titan", "owner": 997,
                    "workspace": ws, "pos": pos, "size": [10.0, 10.0],
                    "output": "DP-1"}

        _wins = [_fw(1, [0.0, 1.0], [128.0, 155.0]),
                 _fw(2, [2.0, 0.0], [172.0, 150.0])]
        g = _settled_watcher()
        g.kb = {_SK: dict(_base)}
        ck("gate-fixture-is-really-settled", not g._placing_now())
        ck("gate-fixture-really-shares-one-key",
           engine.matched_key(g.kb, "google-chrome", "titan", "titan") == _SK)

        g.slot_held[_SK] = 1
        _h = g._held(_wins)
        ck("gate-a-refused-window-is-held-even-when-settled", 2 in _h)
        ck("gate-the-holder-itself-is-not-held", 1 not in _h)
        # A HOLDER THAT IS NOT LIVE IS NOT A HOLDER, or a closed window would
        # freeze its slot forever. The live set is the SNAPSHOT's, which is
        # what makes this answerable on the capture thread at all:
        # `_live_ids()` reads the placer's socket, whose one writer is the
        # placer.
        g.slot_held[_SK] = 99
        ck("gate-a-dead-holder-holds-nothing", g._held(_wins) == frozenset())
        # AND AN UNSHARED KEY IS UNTOUCHED, which is every window on an
        # ordinary desk: this must not become a general brake on learning.
        g.slot_held.clear()
        ck("gate-an-unheld-key-is-not-held", g._held(_wins) == frozenset())

        # THE DAMAGE ITSELF, which only a LEARN pass expresses: a check on
        # `_held` alone says nothing about what reaches the store.
        _kb4 = {_SK: dict(_base)}
        g.slot_held[_SK] = 1
        engine.learn(_kb4, {}, _wins, _t.time(), hold=g._held(_wins))
        ck("gate-the-slot-keeps-the-HOLDER-geometry",
           (_kb4.get(_SK) or {}).get("pos") == [128.0, 155.0])
        ck("gate-the-slot-did-not-take-the-cascade",
           (_kb4.get(_SK) or {}).get("workspace") == [0.0, 1.0])
        # AND THE CONTROL, or both of those pass over a learn that wrote
        # nothing at all: with no holder the pass DOES reach the store, and
        # with the measured cascade values.
        _kb5 = {_SK: dict(_base)}
        g.slot_held.clear()
        engine.learn(_kb5, {}, _wins, _t.time(), hold=g._held(_wins))
        ck("gate-control-a-learn-with-no-holder-does-write",
           (_kb5.get(_SK) or {}).get("pos") == [172.0, 150.0])
    finally:
        pass

def _t_verify(ck):
    """A PLACEMENT IS A REQUEST, and nothing used to read the result back.

    THE MEASURED BUG (manifold, 2026-10-05): wayfire's own `place` plugin
    (cascade) assigned a relaunched calibre window its position AFTER usher
    had asked for the remembered slot, usher logged `placed ws(0,1)` twice,
    and the window sat on ws(0,0) for five minutes until a human moved it.
    Replaying the identical configure-view by hand applied exactly, so the
    request, the arithmetic and the client were all fine; only the knowing
    was missing. `placed` dedups, so the lost race was locked in for the life
    of the window."""
    from . import watch as _w
    from .watch import Watcher, PLACE_VERIFY

    # THE SUITE'S OWN FIXTURE LINES MUST NOT REACH watch.log. Asserted
    # BEHAVIOURALLY rather than by checking that _quiet_log patched something:
    # comparing the two module attributes for identity would pass just as
    # happily if NEITHER had been patched, which is the "check passes for the
    # wrong reason" shape this suite keeps meeting. Looking for the marker
    # rather than for a size change also survives the live daemon writing a
    # real line in the same instant.
    # A NONCE, so the check asks "did THIS run leak" rather than "has
    # anything ever leaked". Met immediately: a planted-regression run that
    # deliberately broke the patching wrote one probe line into the real log,
    # and a fixed marker then failed every subsequent run over a leak that
    # had already been fixed. A check that cannot be cleared by fixing the
    # fault is a check that gets switched off.
    _probe = f"selftest probe, never for watch.log: {os.getpid()}-{time.time()}"
    _w.logline(_probe)
    engine.logline(_probe)
    _tail = ""
    _lf = os.path.join(engine.STATE, "watch.log")
    if os.path.exists(_lf):
        with open(_lf, errors="replace") as _fh:
            _tail = _fh.read()[-4000:]
    ck("quiet-log-keeps-fixtures-out-of-watch-log", _probe not in _tail)

    # A LINE FROM A DEV TREE SAYS SO. watch.log is the forensic record this
    # package leans on, and nothing marked a line that did not come from the
    # installed code: five such lines sat in manifestor's log, including a
    # NameError NO COMMIT EVER HAD, from a half-edited working tree run
    # against the live session. `_quiet_log` cannot help, because it patches
    # this function for the SUITE and a hand probe is not the suite.
    #
    # THE PURE HALF FIRST, including the shape a substring test gets wrong.
    for _p, _want in (
            ("/opt/usher/venv/lib/python3.14/site-packages/usher/engine.py",
             False),
            ("/home/jello/.local/share/usher/venv/lib/python3.12/"
             "site-packages/usher/engine.py", False),
            ("/home/jello/src/usher/usher/engine.py", True),
            ("/var/tmp/plantX/usher/engine.py", True),
            # a DEV tree whose path merely CONTAINS the words
            ("/home/jello/src/site-packages-notes/usher/engine.py", True)):
        ck("dev-path-%s" % _p.strip("/").replace("/", "-")[-40:],
           engine.is_dev_path(_p) is _want)
    # AND THE WIRING, host-free: the cache is the seam, so the mark is
    # asserted BOTH WAYS without caring where this suite happens to run
    # from. Asserting the mark's presence directly would be a check on the
    # host, since `test/selftest.t` runs the suite from the installed venv
    # AND from the dev tree.
    _rdev, _rll = engine._DEV_TREE, engine.logline
    _ldir = tempfile.mkdtemp(prefix="usher-dev-", dir="/var/tmp")
    _rst = engine.STATE
    try:
        engine.STATE = _ldir
        engine.logline = _real_logline
        for _dev, _tag in ((True, "[dev] "), (False, "")):
            engine._DEV_TREE = _dev
            _n = f"devmark-{_dev}-{os.getpid()}"
            _real_logline(_n)
            with open(os.path.join(_ldir, "watch.log")) as _fh:
                _lines = [x for x in _fh if _n in x]
            ck("logline-marks-a-dev-tree-line" if _dev
               else "logline-leaves-an-installed-line-bare",
               len(_lines) == 1
               and _lines[0].split(" ", 2)[2].startswith(_tag + _n))
    finally:
        engine._DEV_TREE, engine.logline = _rdev, _rll
        engine.STATE = _rst
        shutil.rmtree(_ldir, ignore_errors=True)

    _o = {"name": "DP-1", "id": 1,
          "geometry": {"x": 0, "y": 0, "width": 100, "height": 100},
          "workspace": {"x": 0, "y": 0, "grid_width": 3, "grid_height": 3}}
    _e = {"output": "DP-1", "workspace": [1, 1], "pos": [10, 20],
          "size": [30, 40]}

    def _v(x, y, w=30, h=40, out="DP-1"):
        return {"id": 7, "app-id": "calibre-gui", "title": "calibre",
                "output-name": out,
                "geometry": {"x": x, "y": y, "width": w, "height": h}}

    # ws(1,1) with the viewport at (0,0) puts the slot at 100+10, 100+20
    ck("verify-landed-exactly", placement_landed(_v(110, 120), _e, _o))
    ck("verify-landed-within-tolerance",
       placement_landed(_v(110 + PLACE_TOL, 120 - PLACE_TOL), _e, _o))
    ck("verify-rejects-just-outside-tolerance",
       not placement_landed(_v(110 + PLACE_TOL + 1, 120), _e, _o))
    # THE ONE THAT MATTERS: the cascade position, a whole workspace off.
    ck("verify-catches-the-cascade-position",
       not placement_landed(_v(10, 20), _e, _o))
    # A SIZE THE CLIENT REFUSED IS NOT A FAILED PLACEMENT. kitty rounds to
    # whole cells and adds padding, so comparing the size would report every
    # terminal placement as lost and re-place it until the budget ran out.
    ck("verify-ignores-a-refused-size",
       placement_landed(_v(110, 120, w=44, h=51), _e, _o))
    ck("verify-rejects-the-wrong-output",
       not placement_landed(_v(110, 120, out="DP-2"), _e, _o))
    ck("verify-rejects-a-gone-window", not placement_landed(None, _e, _o))

    logged = []
    _real_log = _w.logline
    _w.logline = lambda m: logged.append(m)
    try:
        def _wat(fresh, tries=1):
            w = Watcher(launch=False)
            w.placed.add(7)
            w.place_tries[7] = tries
            w._fresh_view = lambda vid: fresh
            return w

        w = _wat(_v(10, 20))
        w._verify_one(7, {"e": _e, "o": _o})
        # CLEARING `placed` IS THE FIX: it is the dedup that locked the
        # original failure in, so a miss has to reopen the window.
        ck("verify-miss-reopens-the-window", 7 not in w.placed)
        ck("verify-miss-requeues-for-another-go", 7 in w.pending)
        ck("verify-miss-is-logged", any("did not take" in m for m in logged))

        # A HIT IS SILENT AND CHANGES NOTHING, which is the common case.
        logged[:] = []
        w = _wat(_v(110, 120))
        w._verify_one(7, {"e": _e, "o": _o})
        ck("verify-hit-leaves-it-placed", 7 in w.placed)
        ck("verify-hit-is-silent", logged == [])

        # BOUNDED: at the end of the budget the window is left where it is
        # rather than fought over for the whole 120s grace.
        logged[:] = []
        w = _wat(_v(10, 20), tries=len(PLACE_VERIFY))
        w._verify_one(7, {"e": _e, "o": _o})
        ck("verify-gives-up-after-the-budget",
           7 in w.placed and 7 not in w.pending)
        ck("verify-gives-up-out-loud", any("after" in m for m in logged))

        # A WINDOW THAT CLOSED IS NOT A FAILED PLACEMENT.
        logged[:] = []
        w = _wat(None)
        w._verify_one(7, {"e": _e, "o": _o})
        ck("verify-ignores-a-closed-window", 7 in w.placed and logged == [])

        # THE VERIFY RUNS UNDER THE PLACER'S ERROR POLICY. It is driven
        # straight from _placer_loop, which has no guard of its own, so a
        # raise here would kill the placer thread and placement would stop
        # for the rest of the session with nothing in the log saying why.
        logged[:] = []
        w = _wat(_v(10, 20))
        def _boom(*a):
            raise RuntimeError("probe")
        ck("verify-raise-does-not-escape-the-placer",
           w._guarded("verify", _boom) is None)
        ck("verify-raise-is-logged", any("verify error" in m for m in logged))

        # AND THE ARMING IS WIRED, DRIVEN THROUGH THE REAL _seat_view rather
        # than by calling _verify_later directly. Testing the arming function
        # on its own would pass just as happily with the CALL removed from
        # _seat_view, which is the whole feature dead and nothing saying so:
        # the same "a check that passes for the wrong reason" shape this
        # suite has now been bitten by four times.
        _real_place = _w.place
        _w.place = lambda sock, vid, e, o: {}
        try:
            def _seated(tries=0):
                """One real _seat_view, with its per-window announcement kept
                out of the suite's own output: it prints the placement to
                stdout as well as logging it, and a fixture line is
                indistinguishable from a real one to anybody reading
                either."""
                w = Watcher(launch=False)
                w._restate = lambda vid, e: None
                w.place_sock = object()
                if tries:
                    w.place_tries[7] = tries
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    moved = w._seat_view(_v(10, 20), _e, _o)
                return w, moved

            w, moved = _seated()
            ck("verify-is-armed-by-a-real-place", moved and 7 in w.verify)
            ck("verify-counts-the-attempt", w.place_tries.get(7) == 1)
            # AND NOT ARMED PAST THE BUDGET, or a window could be dragged
            # around for the whole 120s grace.
            w, _ = _seated(tries=len(PLACE_VERIFY))
            ck("verify-arms-nothing-past-the-budget", 7 not in w.verify)
        finally:
            _w.place = _real_place
    finally:
        _w.logline = _real_log

def _t_lifecycle(ck):
    """A WINDOW'S LIFE, TICK BY TICK, driven through the real decision code.

    THE GAP THIS CLOSES, and it is a structural one rather than a missing
    case: every other check in this file hands a plugin or the store ONE
    frozen view, so the suite could not see a SEQUENCE at all. The 2026-10-03
    shrink bug was a sequence and nothing else. The window was handled
    correctly at tick 2 and ruinously at tick 1, and the damage was that
    tick 1's answer got WRITTEN and carried forward. A per-tick check on
    either tick alone passes.

    So the shape is: script the states a window really moves through, run the
    real `resolution()` and the real `learn()` at each one, and assert on the
    TRACE. What matters is not only the final answer but that no wrong answer
    was ever committed on the way to it."""
    def drive(ticks, when0=1_800_000_000):
        """Run a scripted lifecycle. Each tick is (label, window, cwd, mux):
        `cwd` is what the shell's /proc cwd would answer and `mux` whether a
        mux command is still starting in the tree, which are the two things
        that make a terminal's identity arrive LATE.

        Returns (trace, store). learn() applies the readiness gate itself, so
        calling it every tick is what production does rather than a
        simplification: a window that is not ready simply does not land."""
        kb, groups, trace = {}, {}, []
        _rc, _rp = engine._term_cwd, engine._term_mux_pending
        try:
            for i, (label, win, cwd, mux) in enumerate(ticks):
                engine._term_cwd = lambda _p, _c=cwd: _c
                engine._term_mux_pending = lambda _p, _m=mux: _m
                r = resolution(win)
                learn(kb, groups, [win], when0 + i)
                trace.append({"label": label, "state": r.state, "key": r.key,
                              "store": sorted(k.split("\0")[1] for k in kb)})
        finally:
            engine._term_cwd = _rc
            engine._term_mux_pending = _rp
        return trace, kb

    def W(vid, title, app="kitty", pid=4242):
        return {"id": vid, "app_id": app, "title": title, "pid": pid,
                "output": "DP-1", "workspace": [1.0, 1.0],
                "pos": [0.0, 0.0], "size": [800.0, 600.0]}

    # === TIMELINE 1: THE SHRINK BUG =======================================
    # usher spawns `kitty ... ksh -c "mux latch host; exec ksh -i"`. The
    # window MAPS BEFORE mux attaches, because a latch has to ssh first, so
    # for a moment it is a kitty titled `ksh` with a mux command in its tree.
    # Pre-fix, KittyPlugin answered `kitty:<cwd>` here, the placer resized the
    # window onto that slot, and the capture loop learned the shrunken size
    # back into the terminal's own slot.
    BANNER = "vigilance:main\u2800\u2800\u2800\u2800[manifold]"
    trace, kb = drive([
        ("maps as a bare shell, mux still starting", W(1, "ksh"), "/h", True),
        ("mux still starting",                       W(1, "ksh"), "/h", True),
        ("the banner lands",                      W(1, BANNER), "/h", False),
        ("settled",                                W(1, BANNER), "/h", False),
    ])
    ck("life-shrink-t0-is-pending", trace[0]["state"] == Resolution.PENDING)
    ck("life-shrink-t1-is-pending", trace[1]["state"] == Resolution.PENDING)
    ck("life-shrink-t2-is-ready", trace[2]["state"] == Resolution.READY)
    ck("life-shrink-t2-keys-a-terminal",
       str(trace[2]["key"]).startswith("term:"))
    # THE INVARIANT, and the actual bug: nothing may be committed while the
    # answer is still arriving. A cwd key written at t0 is what the placer
    # then aimed at.
    ck("life-shrink-nothing-learned-while-pending",
       trace[0]["store"] == [] and trace[1]["store"] == [])
    ck("life-shrink-no-cwd-key-EVER",
       not any(k.startswith("kitty:") for t in trace for k in t["store"]))
    ck("life-shrink-ends-with-one-terminal-slot",
       trace[-1]["store"] == [trace[2]["key"]])

    # === TIMELINE 2: A PLAIN KITTY, whose cwd arrives late ================
    # The same LATENESS without any mux: a kitty has no shell in /proc for its
    # first ~0.25s. It must be held, not dropped (reading this as "never
    # remember" is what killed every non-mux terminal once), and then learned
    # under the cwd key once it is readable.
    trace, kb = drive([
        ("maps, no shell in /proc yet", W(2, "terminal"), "", False),
        ("cwd readable",                W(2, "terminal"), "/w/p", False),
        ("settled",                      W(2, "terminal"), "/w/p", False),
    ])
    ck("life-cwd-t0-is-pending", trace[0]["state"] == Resolution.PENDING)
    ck("life-cwd-t0-learns-nothing", trace[0]["store"] == [])
    ck("life-cwd-settles-on-the-cwd-key", trace[-1]["store"] == ["kitty:/w/p"])

    # === TIMELINE 3: THE SWITCH, which must NOT mint a second slot ========
    # A terminal that changes what it DISPLAYS keeps its slot: that is the
    # whole point of keying on the command rather than the session, and the
    # regression it guards made a window a stranger every time you switched.
    trace, kb = drive([
        ("showing one session",     W(3, BANNER), "/h", False),
        ("switched to another",
         W(3, "tackup:main\u2800\u2800\u2800\u2800[manifold]"), "/h", False),
    ])
    ck("life-switch-keeps-one-slot", len(trace[-1]["store"]) == 1)
    ck("life-switch-keeps-the-same-slot",
       trace[0]["store"] == trace[1]["store"])

    # === TIMELINE 4: A NEVER, which must never be committed ===============
    # A stored entry's pid is dead, so its cwd can never be read. Unlike a
    # PENDING this will not resolve by waiting, and the distinction matters:
    # the store must not grow a guessed key for it either way.
    trace, kb = drive([
        ("a replayed entry, pid long dead",
         W(4, "terminal", pid=-1), "", False),
    ])
    ck("life-never-is-never", trace[0]["state"] == Resolution.NEVER)
    ck("life-never-learns-nothing", trace[0]["store"] == [])

def _t_terminals(ck):
    """a terminal's SLOT, and which windows need respawning."""
    ps = {getattr(p, "name", "?"): p for p in engine.plugins()}
    # THE SLOT. A terminal owns its place by the COMMAND it runs, so the two
    # windows below are the same slot despite showing different sessions:
    # which is the entire point of the change, and what the session-shaped key
    # could not do.
    ck("slot-local", _mux_slot(None) == "term:resume")
    ck("slot-latch",
       _mux_slot("manifestor:tackup") == "term:latch manifestor:tackup")
    ck("slot-survives-session-switch",
       ps["mux"].resolve(_tv("kitty", "vigilance:1\u2800\u2800[manifold]")).key
       == ps["mux"].resolve(_tv("kitty", "tackup:1\u2800\u2800[manifold]")).key)
    ck("slot-latch-differs-from-local",
       _mux_slot("manifestor:tackup") != _mux_slot(None))

    # live_keys resolves a real on-screen title through to its identity
    ck("live-keys", live_keys([_tv("kitty", "live:1⠀⠀⠀⠀[manifestor]")])
       == {"term:resume"})

    # relaunch candidate selection, driven with fixtures (no mux, no
    # compositor). The per-session matching this replaced is covered by the
    # command checks above; what matters here is the kitty half.
    def S(key, app="kitty"):
        return {"app_id": app, "key": key, "title": ""}

    # COUNTED PER CWD, not deduped. THE OLD CHECK ENCODED THE BUG: it
    # asserted that two `kitty:/tmp` rows yield ONE cwd, so N windows sharing
    # a directory came back as one, and the enclave made it visible (four
    # roster rows, one key, one terminal started of four). Third time a check
    # in this file has pinned a mistaken belief.
    def LV(key, app="kitty"):
        """A LIVE view whose identity resolves to `key` with no /proc read:
        the title path, which is what an unowned app and a mux banner use."""
        return {"app-id": app, "title": key, "pid": -1}

    ck("kitty-candidates-counts-per-cwd",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp"),
                         S("kitty:/nonexistent-" + "z" * 12),
                         S("mux@manifestor:wf")], []) == ["/tmp", "/tmp"])
    ck("kitty-candidates-live",
       kitty_candidates([S("kitty:/tmp")],
                        [LV("kitty:/tmp", app="zzz-unowned")]) == [])
    # ONE OF TWO UP MEANS ONE TO START, which is the whole point and is the
    # cell neither the old behaviour nor a naive count gets right.
    ck("kitty-candidates-starts-only-the-shortfall",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp")],
                        [LV("kitty:/tmp", app="zzz-unowned")]) == ["/tmp"])
    ck("kitty-candidates-starts-nothing-when-every-window-is-up",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp")],
                        [LV("kitty:/tmp", app="zzz-unowned"),
                         LV("kitty:/tmp", app="zzz-unowned")]) == [])
    # AND AN UNREADABLE LIVE SIDE CAPS THE ASK AT ONE PER CWD, which is the
    # old behaviour: over-spawning puts four terminals on screen at every
    # login, where under-spawning costs a window the human reopens. A live
    # KITTY whose identity resolves to neither a cwd nor a term slot is
    # exactly that state (a dead pid, or a relay that dropped the pids).
    ck("kitty-candidates-will-not-multiply-against-an-unreadable-live-side",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp")],
                        [{"app-id": "kitty", "title": "", "pid": -1}])
       == ["/tmp"])
    # AND THE READABILITY TEST ITSELF, both answers.
    ck("kitty-live-counts-reads-a-cwd-window",
       kitty_live_counts([LV("kitty:/tmp", app="zzz-unowned")])
       == (Counter({"/tmp": 1}), True))
    # A MUX TERMINAL IS A kitty, which is what makes that branch
    # load-bearing: dropping it sends `term:resume` to the unreadable arm and
    # caps every cwd at one. The fixture has to say app="kitty" or it tests
    # nothing (the first version said `zzz-unowned` and the plant passed).
    ck("kitty-live-counts-accounts-for-a-mux-terminal",
       kitty_live_counts([LV("term:resume", app="kitty")])
       == (Counter(), True))
    # AND A REAL MUX TERMINAL BESIDE A PLAIN ONE STILL COUNTS THE PLAIN ONE,
    # which is the arrangement every box here actually has.
    ck("kitty-candidates-counts-past-a-live-mux-terminal",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp")],
                        [LV("term:resume", app="kitty")]) == ["/tmp", "/tmp"])
    ck("kitty-live-counts-says-so-when-a-kitty-cannot-be-read",
       kitty_live_counts([{"app-id": "kitty", "title": "", "pid": -1}])[1]
       is False)

    # the relaunch command. A latch is REPLAYED (it is the one mux verb that
    # survives in the process tree); anything else was a local mux, and the
    # default is `mux resume`, which rebuilds the whole set rather than the one
    # session a titlebar happened to name.
    ck("cmd-default-is-resume",
       mux_cmd_of_saved({"app_id": "kitty"}) == MUX_RESUME)
    ck("cmd-recorded-wins",
       mux_cmd_of_saved({"app_id": "kitty", "cmd": "X latch manifestor"})
       == "X latch manifestor")
    ck("resume-names-no-session",
       " go " not in MUX_RESUME and MUX_RESUME.endswith(" resume"))

    # candidates are COUNTED per command, not matched per session
    ck("cand-one-per-missing-window",
       mux_candidates([_tmw(), _tmw()], []) == [(MUX_RESUME, None)] * 2)
    ck("cand-counts-live-down",
       len(mux_candidates([_tmw(), _tmw()],
                          [_tv("kitty", "a:1\u2800\u2800[manifold]")])) == 1)
    ck("cand-distinct-commands",
       sorted(c for c, _ in mux_candidates(
           [_tmw(), _tmw(cmd="L latch manifestor")], []))
       == sorted([MUX_RESUME, "L latch manifestor"]))
    ck("cand-carries-size",
       mux_candidates([_tmw(size=[2132.0, 1674.0])], [])
       == [(MUX_RESUME, [2132, 1674])])
    ck("cand-ignores-non-mux",
       mux_candidates([{"app_id": "kitty", "key": "kitty:/tmp"}], []) == [])

def _t_launch_source(ck):
    """launch_missing must use the snapshot it is GIVEN, not re-read one.

    THE RACE THIS PINS: the worker starts its capture loop before it reaches
    the relaunch, and at session start that loop writes a snapshot with ZERO
    windows, because nothing has mapped yet. A launch_missing that reads the
    file therefore relaunched nothing, and a whole session came back empty.
    Whether it happened at all was a thread race, which is why it survived
    several logins.
    """
    import contextlib
    import io
    real = (engine.load_snapshot, engine.plugins,
            engine.desktop_relaunch_missing, engine.ipc,
            engine.source_trigger, engine.logline)
    seen, desk, asked, logs = [], [], [], []

    class _P:
        def relaunch_missing(self, saved, live):
            seen.append([w.get("cmd") for w in saved])
            return 0

    class _Sock:
        def list_views(self, **k):
            return []

    try:
        # THE LIVE SET IS THE FIXTURE'S, NOT THE HOST'S. This area called the
        # REAL ipc(), so every cell below behaved differently depending on
        # whether the box had a compositor: with one it read the developer's
        # own windows, and without one the read raised and fell back to an
        # empty list. Both happen in this fleet's own suite, which runs it
        # under the system python3 (no pywayfire) AND under the venv against
        # a live socket.
        engine.ipc = lambda *a, **k: _Sock()
        engine.source_trigger = lambda *a, **k: asked.append(k) or 0
        # STUBBED HERE rather than left to _quiet_log, which silences the log
        # for the whole area loop: an area that wants to ASSERT what was
        # logged stubs for itself, which is what that helper's own docstring
        # says and what restoring to whatever we found keeps working.
        engine.logline = lambda s: logs.append(s)
        engine.load_snapshot = lambda *a: {
            "windows": [{"app_id": "kitty", "cmd": "FROM THE FILE"}]}
        engine.plugins = lambda: [_P()]
        # THE DEFAULT REGISTRY RELAUNCH NEEDS STUBBING TOO, and forgetting it
        # OPENED TWO REAL TERMINALS on the developer's desktop per run, which
        # the capture loop then learned as `kitty:<cwd>` slots the terminal
        # purge does not cover. launch_missing calls BOTH the plugin hooks and
        # desktop_relaunch_missing, and the latter is not a plugin, so
        # stubbing `plugins` does not reach it. Worse: stubbing `plugins`
        # HIDES the real kitty plugin, so is_owned("kitty") goes False and the
        # registry claims this fixture's kitty window, which it would never do
        # in production.
        engine.desktop_relaunch_missing = \
            lambda *a, **k: desk.append(a) or 0
        given = {"windows": [{"app_id": "kitty", "cmd": "FROM THE CALLER"}]}
        with contextlib.redirect_stdout(io.StringIO()):
            launch_missing(given)
        ck("launch-uses-the-snapshot-it-is-given",
           seen and seen[-1] == ["FROM THE CALLER"])
        # ...and a one-shot verb with no daemon running still gets a snapshot.
        with contextlib.redirect_stdout(io.StringIO()):
            launch_missing()
        ck("launch-falls-back-to-reading-when-given-nothing",
           bool(seen) and seen[-1] == ["FROM THE FILE"])
        # AN EMPTY SNAPSHOT MUST NOT BE MISTAKEN FOR "nothing was saved": it is
        # what the caller hands us at a cold start, and relaunching from it is
        # the bug. Passing it through unchanged is what lets the caller decide.
        with contextlib.redirect_stdout(io.StringIO()):
            launch_missing({"windows": []})
        ck("launch-passes-an-empty-snapshot-through",
           bool(seen) and seen[-1] == [])
        # ASSERT THE STUB WAS REACHED, or a future launch_missing that stops
        # calling the registry default would make this silently vacuous and
        # the spawn could come back unnoticed.
        ck("launch-reaches-the-registry-default", len(desk) == 3)

        # --- AND A FAILED LIVE READ MUST START NOTHING OF OURS ----------
        # Every owner-side path asks "is mine already up?", so an empty live
        # set answers "no" for everything: a failed read does not degrade the
        # relaunch, it INVERTS it. Measured on a real 26-window desk where
        # every saved window WAS live: 0 launches became 4 apps and 6 spawns.
        def _boom(*a, **k):
            raise OSError("planted: the compositor is not answering")
        engine.ipc = _boom
        _n0, _d0, _a0 = len(seen), len(desk), len(asked)
        with contextlib.redirect_stdout(io.StringIO()):
            _blind_n = launch_missing(given)
        ck("launch-starts-nothing-of-ours-when-the-live-read-fails",
           _blind_n == 0 and len(seen) == _n0 and len(desk) == _d0)
        # AND IT STILL ASKS THE OTHER ACCOUNTS, which is the one place an
        # empty live set is already the SAFE answer: the account decides what
        # of its own is missing against its own compositor view, and the
        # relayed views only sharpen its per-command terminal count, so a
        # failed read makes it ask for LESS. Skipping it would cost that
        # account its whole desk for no gain.
        ck("launch-still-asks-the-sources-when-the-live-read-fails",
           len(asked) == _a0 + 1)
        # AND IT SAYS SO, CARRYING THE CAUSE. Refusing silently is worse than
        # the bug for a reader: a login would come up with an empty desk and
        # nothing anywhere to explain it, which is this package's most
        # repeated failure shape. Asserted on the planted exception's own
        # text rather than on our wording, so the message stays free to be
        # reworded and a generic line cannot satisfy it.
        ck("launch-says-why-it-started-nothing",
           any("not answering" in s for s in logs))
        # THE CONTROL, without which both cells above pass over a
        # launch_missing that has simply stopped calling anything: the SAME
        # fixture with a working read must still reach the owner's paths.
        engine.ipc = lambda *a, **k: _Sock()
        with contextlib.redirect_stdout(io.StringIO()):
            launch_missing(given)
        ck("launch-blindness-has-a-working-control",
           len(seen) == _n0 + 1 and len(desk) == _d0 + 1)
    finally:
        (engine.load_snapshot, engine.plugins,
         engine.desktop_relaunch_missing, engine.ipc,
         engine.source_trigger, engine.logline) = real

def _raises(exc, fn):
    """True when fn() raises exc. A GUARDED call rather than letting it
    propagate, so a check that stops holding reports as one clean FAIL
    instead of aborting its area before the summary line."""
    try:
        fn()
    except exc:
        return True
    except Exception:                                         # noqa: BLE001
        return False
    return False


def _fake_compositor(path, offer=True, rows=(), stop_after_bind=False):
    """A thread speaking just enough of the protocol to answer one client.

    A REAL UNIX SOCKET AND REAL WIRE BYTES, not a stubbed `list_toplevels`.
    The thing under test is a hand-written protocol client, so a fixture that
    stands in for the conversation tests nothing: every framing, padding and
    opcode decision has to actually go over a socket. Same reason the chrome
    checks write real SNSS files to disk instead of passing dicts.

    `rows` is [(app_id, title, identifier)]; `offer=False` advertises only
    wl_shm, which is the "this compositor has no window list" case.
    """
    import socket as _s
    import struct as _st
    import threading

    srv = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def hdr(obj, opcode, body):
        return _st.pack("<II", obj, ((8 + len(body)) << 16) | opcode) + body

    def wstr(s):
        b = s.encode() + b"\0"
        return _st.pack("<I", len(b)) + b + b"\0" * (-len(b) % 4)

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        buf = b""
        bound = False
        try:
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
                while len(buf) >= 8:
                    obj, hi = _st.unpack_from("<II", buf, 0)
                    size, opcode = hi >> 16, hi & 0xFFFF
                    if size < 8 or len(buf) < size:
                        break
                    body, buf = buf[8:size], buf[size:]
                    if obj == 1 and opcode == toplevels.RQ_GET_REGISTRY:
                        (reg,) = _st.unpack_from("<I", body, 0)
                        names = ([(7, toplevels.PROTOCOL, 1)] if offer
                                 else []) + [(9, "wl_shm", 2)]
                        for nm, iface, ver in names:
                            conn.sendall(hdr(
                                reg, toplevels.EV_GLOBAL,
                                _st.pack("<I", nm) + wstr(iface)
                                + _st.pack("<I", ver)))
                    elif obj != 1 and opcode == toplevels.RQ_BIND:
                        (_nm,) = _st.unpack_from("<I", body, 0)
                        _iface, off = toplevels._read_string(body, 4)
                        _ver, lst = _st.unpack_from("<II", body, off)
                        bound = True
                        if stop_after_bind:
                            conn.close()
                            return
                        handle = 0xFF000001
                        for app, title, ident in rows:
                            conn.sendall(hdr(
                                lst, toplevels.EV_LIST_TOPLEVEL,
                                _st.pack("<I", handle)))
                            for op, val in ((toplevels.EV_H_TITLE, title),
                                            (toplevels.EV_H_APP_ID, app),
                                            (toplevels.EV_H_IDENTIFIER,
                                             ident)):
                                conn.sendall(hdr(handle, op, wstr(val)))
                            conn.sendall(hdr(handle, toplevels.EV_H_DONE, b""))
                            handle += 1
                    elif obj == 1 and opcode == toplevels.RQ_SYNC:
                        (cb,) = _st.unpack_from("<I", body, 0)
                        conn.sendall(hdr(cb, toplevels.EV_CALLBACK_DONE,
                                         _st.pack("<I", 0)))
                        if bound:
                            return
        except OSError:
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, t


def _t_toplevels(ck):
    """The hand-written wayland client: framing, discovery, three states.

    WHY THIS AREA EXISTS AT ALL: an enclave account cannot reach the wayfire
    IPC (it lives in the session user's 0700 runtime dir) and no wayland
    protocol carries a window's position anyway, so the only way it can be
    told which windows are its own is this protocol. That makes
    a hand-written client load-bearing for the enclave restore, and an opcode
    is declaration order, so a wrong one reports plausible nonsense rather
    than failing. `test/tools.t` re-derives every opcode from the installed
    XMLs; this area proves the conversation those opcodes drive.
    """
    # THE WIRE STRING, where the padding is the easy thing to get wrong: the
    # length INCLUDES the NUL and the whole field is padded to 4 bytes.
    ck("wire-string-length-counts-the-nul",
       toplevels._string("ab")[:4] == b"\x03\x00\x00\x00")
    ck("wire-string-is-padded-to-four",
       len(toplevels._string("ab")) == 8
       and len(toplevels._string("abc")) == 8
       and len(toplevels._string("abcd")) == 12)
    ck("wire-string-round-trips",
       toplevels._read_string(toplevels._string("hello"), 0) == ("hello", 12))
    # AN EMPTY STRING IS LENGTH 0 WITH NO BYTES, not length 1 with a NUL, and
    # reading it as the latter walks the offset into the next argument.
    ck("wire-empty-string-has-no-bytes",
       toplevels._read_string(b"\x00\x00\x00\x00", 0) == ("", 4))
    ck("wire-truncated-string-raises", _raises(
        toplevels.ProtocolError,
        lambda: toplevels._read_string(b"\x40\x00\x00\x00ab", 0)))

    # DISCOVERY MIRRORS pick_socket, refusal included.
    with tempfile.TemporaryDirectory() as d:
        env = {"XDG_RUNTIME_DIR": d}
        ck("socket-none-present-is-a-reason",
           toplevels.wayland_socket(env)[0] == ""
           and "no wayland socket is in" in toplevels.wayland_socket(env)[1])
        open(os.path.join(d, "wayland-1"), "w").close()
        open(os.path.join(d, "wayland-1.lock"), "w").close()
        ck("socket-lock-file-is-not-a-candidate",
           toplevels.wayland_socket(env)[0] == os.path.join(d, "wayland-1"))
        open(os.path.join(d, "wayland-9"), "w").close()
        got, why = toplevels.wayland_socket(env)
        # TWO REFUSE RATHER THAN GUESS: a stale socket from a previous session
        # would answer, with somebody else's windows, which is worse than an
        # error. The same call `pick_socket` makes for the same reason.
        ck("socket-two-candidates-refuse", got == "" and "ambiguous" in why)
        ck("socket-absolute-wins-over-discovery",
           toplevels.wayland_socket(
               {"WAYLAND_DISPLAY": os.path.join(d, "wayland-1"),
                "XDG_RUNTIME_DIR": "/nonexistent"})[0]
           == os.path.join(d, "wayland-1"))
        ck("socket-absolute-but-missing-says-so",
           toplevels.wayland_socket({"WAYLAND_DISPLAY": "/no/such"})[1]
           .startswith("WAYLAND_DISPLAY names /no/such"))
        ck("socket-relative-with-no-runtime-dir-says-so",
           "XDG_RUNTIME_DIR is unset"
           in toplevels.wayland_socket({"WAYLAND_DISPLAY": "wayland-1"})[1])

    # THE WHOLE CONVERSATION, against a real socket.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "wl")
        srv, _t = _fake_compositor(p, rows=[
            ("google-chrome", "Inbox", "aa"), ("slack", "Alex", "bb")])
        try:
            rows, why = toplevels.list_toplevels(p, timeout=5.0)
        finally:
            srv.close()
        ck("toplevels-reads-a-roster", why == "" and len(rows) == 2)
        ck("toplevels-carries-app-id-title-identifier",
           sorted((r["app_id"], r["title"], r["identifier"]) for r in rows)
           == [("google-chrome", "Inbox", "aa"), ("slack", "Alex", "bb")])
        # NO GEOMETRY, EVER, and that is the point rather than a limitation:
        # the protocol has no positional argument, so a caller cannot come to
        # believe a roster is a layout.
        ck("toplevels-report-no-geometry",
           all(set(r) == {"app_id", "title", "identifier"} for r in rows))

    # THREE STATES AND NOT TWO, which this tree has shipped collapsed twice.
    # An empty roster with no reason is a real answer; every failure carries
    # one. A caller must not read "no windows" as "could not look".
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "wl")
        srv, _t = _fake_compositor(p, rows=[])
        try:
            rows, why = toplevels.list_toplevels(p, timeout=5.0)
        finally:
            srv.close()
        ck("toplevels-empty-session-is-a-real-answer",
           rows == [] and why == "")

        p2 = os.path.join(d, "wl2")
        srv, _t = _fake_compositor(p2, offer=False)
        try:
            rows, why = toplevels.list_toplevels(p2, timeout=5.0)
        finally:
            srv.close()
        ck("toplevels-missing-protocol-is-a-reason",
           rows == [] and toplevels.PROTOCOL in why)
        ck("toplevels-three-states-are-pairwise-distinct",
           len({"", why, "the compositor closed the connection"}) == 3)

        ck("toplevels-no-socket-is-a-reason",
           toplevels.list_toplevels(os.path.join(d, "absent"))[1]
           .startswith("cannot reach the wayland display"))

        p3 = os.path.join(d, "wl3")
        srv, _t = _fake_compositor(p3, rows=[("x", "y", "z")],
                                   stop_after_bind=True)
        try:
            rows, why = toplevels.list_toplevels(p3, timeout=5.0)
        finally:
            srv.close()
        ck("toplevels-disconnect-mid-answer-is-a-reason",
           rows == [] and why != "")

    # A SHORT HEADER IS REFUSED rather than looped on: size < 8 cannot be a
    # message, and treating it as one spins forever on the same bytes.
    class _Sock:
        def __init__(self, data):
            self.data = data

        def settimeout(self, _t):
            pass

        def recv(self, _n):
            d, self.data = self.data, b""
            return d

    import struct as _st
    ck("framing-short-header-raises", _raises(
        toplevels.ProtocolError,
        lambda: toplevels._Reader(_Sock(_st.pack("<II", 1, (4 << 16) | 0)))
        .message(time.monotonic() + 1)))
    # AND A MESSAGE SPLIT ACROSS READS IS REASSEMBLED, which is the normal
    # case on a stream socket and the one a naive reader gets wrong once.
    whole = _st.pack("<II", 5, ((8 + 4) << 16) | 2) + _st.pack("<I", 99)

    class _Split:
        def __init__(self):
            self.parts = [whole[:3], whole[3:]]

        def settimeout(self, _t):
            pass

        def recv(self, _n):
            return self.parts.pop(0) if self.parts else b""

    ck("framing-reassembles-a-split-message",
       toplevels._Reader(_Split()).message(time.monotonic() + 1)
       == (5, 2, _st.pack("<I", 99)))


def _quiet_launch(apps, live, spawned):
    """roster_launch with its announcements swallowed. `_announce` prints as
    well as logging, and the suite's `_quiet_log` only covers the log."""
    with contextlib.redirect_stdout(io.StringIO()):
        return engine.roster_launch(apps, live, spawn=spawned.append)


def _t_roster(ck):
    """The enclave's own two verbs: its roster, and starting from it.

    THE AUTHORITY IS THE POINT. The owner triggers these and supplies no
    content, so the record of what an account had open is written by that
    account in its own home. Everything here pins the cases where getting it
    wrong would either lose a desk or let the owner start something.
    """
    # ELIMINATION'S POOL IS THE OWNER'S VIEWS ONLY.
    #
    # PRODUCT, LIVE: the call site filtered on `is_chrome` alone, so a work
    # account's Chrome view was a candidate for an id out of the OWNER's
    # session files, and one second after a capture the owner's store held
    # `chrome:win:<owner id>` labelled with the WORK window's title and no
    # `source` field. `window_slot` caches that for the view's life, so it is
    # a sticky wrong slot and a disclosure at once.
    _ours = _trv("google-chrome", "mine", pid=os.getpid())
    _theirs = dict(_trv("google-chrome", "theirs", pid=os.getpid()))
    _theirs["source"] = "titan"
    _pool = engine.chrome_elimination_pool([_ours, _theirs])
    ck("elimination-pool-keeps-our-own-chrome-view",
       any(t == "mine" for _v, t in _pool))
    ck("elimination-pool-excludes-a-foreign-chrome-view",
       not any(t == "theirs" for _v, t in _pool))
    # AND IT STILL EXCLUDES NON-CHROME, or the pool would offer owner session
    # ids to windows that were never in a session file at all.
    ck("elimination-pool-excludes-non-chrome",
       engine.chrome_elimination_pool([_trv("kitty", "term")]) == [])

    # A SOURCE NAME IS HALF A KEY, and needs the app-id as the other half.
    #
    # FOUND LIVE on manifold as a `'\x00titan'` entry sitting beside the five
    # legitimate source keys: an app-id-less foreign window keyed on the
    # source ALONE, which matches every handle-less window of that whole
    # account and would drag the next one onto the last one's geometry. Fifth
    # instance of a rule scoped to one category meeting something outside it:
    # `is_unique` has refused an empty app-id since the `'\0'` wildcard fix,
    # and the source branch runs FIRST and never asked it.
    _fw = {"app_id": "", "title": "SOMETHING", "source": "titan", "pid": -1}
    ck("a-source-key-needs-an-app-id",
       not engine.resolution(_fw).is_ready
       and "no app-id" in (engine.resolution(_fw).why or ""))
    ck("a-source-key-with-an-app-id-is-still-ready",
       engine.resolution({"app_id": "slack", "title": "x",
                          "source": "titan", "pid": -1}).key == "titan")
    # AND THE GATE BOTH SIDES READ MUST AGREE, which is the whole reason the
    # fix went into `resolution` rather than into the keying branch: a store
    # written under a key the matcher never looks up is the fault that
    # predicate exists to prevent.
    ck("an-app-id-less-foreign-window-is-not-learned",
       engine.unidentified(_fw))

    # PURE, so the decision needs no compositor and no other account.
    ck("roster-plan-is-the-difference",
       engine.roster_plan(["a", "b", "c"], ["b"]) == ["a", "c"])
    ck("roster-plan-empty-when-all-live",
       engine.roster_plan(["a"], ["a", "z"]) == [])
    ck("roster-plan-ignores-blanks",
       engine.roster_plan(["a", ""], ["", "z"]) == ["a"])

    # ---- THE PER-WINDOW ROWS, which is what brings a TERMINAL back ------
    # THE BUG THE USER REPORTED: an app-id alone resolves to a bare shell at
    # $HOME, so the account's terminals came back having forgotten both their
    # directory and the mux session they were showing. A row carries the
    # subset of a snapshot row the relaunchers already read.
    ck("roster-saved-prefers-a-window-row-over-an-app-id",
       engine.roster_saved(
           ["kitty", "slack"], [],
           [{"app_id": "kitty", "key": "term:resume",
             "cmd": "mux resume"}])
       == [{"app_id": "kitty", "key": "term:resume", "cmd": "mux resume"},
           {"app_id": "slack"}])
    # TWO ROWS FOR ONE APP STAY TWO, which is the whole point for terminals:
    # the relaunchers count per COMMAND, so collapsing them to one app-id
    # would bring back one of two windows.
    ck("roster-saved-keeps-one-row-per-window",
       len(engine.roster_saved(
           ["kitty"], ["kitty"],
           [{"app_id": "kitty", "key": "term:resume", "cmd": "mux resume"},
            {"app_id": "kitty", "key": "term:latch b:s",
             "cmd": "mux latch b:s"}])) == 2)
    # AND A WINDOW ROW IS NOT FILTERED BY LIVENESS while an app-id row is:
    # "kitty is running" cannot answer "which of my two terminals is up", and
    # the relaunchers ask the sharper question themselves.
    ck("roster-saved-app-id-rows-drop-when-the-app-is-up",
       engine.roster_saved(["slack"], ["slack"], []) == [])
    ck("roster-saved-window-rows-survive-their-app-being-up",
       engine.roster_saved(
           ["kitty"], ["kitty"],
           [{"app_id": "kitty", "key": "term:resume", "cmd": "mux resume"}])
       == [{"app_id": "kitty", "key": "term:resume", "cmd": "mux resume"}])
    ck("roster-saved-with-nothing-to-do-is-empty",
       engine.roster_saved([], [], []) == [])

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state", "roster.json")
        ck("roster-round-trips-sorted-and-deduped",
           engine.save_roster(["slack", "google-chrome", "slack", ""],
                              path=p) == ["google-chrome", "slack"]
           and engine.load_roster(p) == (["google-chrome", "slack"], ""))
        # THREE STATES AND NOT TWO: a captured account with nothing open is a
        # real answer, and must not read the same as a roster that cannot be
        # read at all. Collapsing those is how a resume would start nothing
        # and report success.
        empty = os.path.join(d, "empty.json")
        engine.save_roster([], path=empty)
        ck("roster-captured-but-empty-is-a-real-answer",
           engine.load_roster(empty) == ([], ""))
        ck("roster-absent-is-a-reason",
           engine.load_roster(os.path.join(d, "none.json"))[1]
           .startswith("no roster at"))
        bad = os.path.join(d, "bad.json")
        open(bad, "w").write("{not json")
        ck("roster-unreadable-is-a-reason",
           engine.load_roster(bad)[1].startswith("cannot read the roster"))
        ver = os.path.join(d, "ver.json")
        open(ver, "w").write('{"version": 99, "apps": ["x"]}')
        got, why = engine.load_roster(ver)
        ck("roster-wrong-version-is-a-reason-not-an-app-list",
           got == [] and "version 99" in why)
        ck("roster-three-states-are-pairwise-distinct",
           len({"", engine.load_roster(os.path.join(d, "none.json"))[1],
                engine.load_roster(bad)[1]}) == 3)
        shape = os.path.join(d, "shape.json")
        open(shape, "w").write('{"version": 1, "apps": "slack"}')
        ck("roster-app-list-must-be-a-list",
           engine.load_roster(shape)[1].endswith("carries no app list"))
        # A HAND-WRITTEN OR HALF-WRITTEN ROSTER IS THE CASE THE FILTER IS FOR,
        # and checking only the round trip tested nothing: save_roster already
        # normalises, so load_roster could return the list raw and still
        # agree. A planted regression doing exactly that passed the whole
        # suite. This is the file as a human or an interrupted write leaves it.
        raw = os.path.join(d, "raw.json")
        open(raw, "w").write(
            '{"version": 1, "apps": ["b", "", "a", 7, "a", null]}')
        ck("roster-normalises-what-it-reads-off-disk",
           engine.load_roster(raw) == (["a", "b"], ""))

        # ---- AND THE PER-WINDOW ROWS, ON DISK ----------------------------
        wp = os.path.join(d, "win.json")
        _wsaved = engine.save_roster(
            ["kitty", "slack"], path=wp,
            windows=[{"app_id": "kitty", "key": "term:latch b:s",
                      "cmd": "mux latch b:s"},
                     {"app_id": "kitty", "key": "kitty:/tmp", "cmd": None},
                     {"app_id": "slack", "key": ""}])   # no key, no row
        ck("roster-still-writes-the-app-list", _wsaved == ["kitty", "slack"])
        ck("roster-writes-a-row-per-describable-window",
           engine.roster_windows(wp)
           == [{"app_id": "kitty", "key": "term:latch b:s",
                "cmd": "mux latch b:s"},
               {"app_id": "kitty", "key": "kitty:/tmp", "cmd": None}])
        # ADDITIVE, so no version bump and nothing relearns: a roster written
        # before this existed reads exactly as it did, and a bump would cost
        # one login where this account's desk does not come back at all.
        ck("an-older-roster-has-no-window-rows-and-is-not-an-error",
           engine.roster_windows(p) == []
           and engine.load_roster(p)[1] == "")
        ck("no-window-rows-means-the-key-is-absent-rather-than-empty",
           "windows" not in json.load(open(p)))
        # A TITLE MUST NEVER REAPPEAR HERE. It is redacted in the snapshot,
        # in the log and in every report, and a roster row is one more place
        # it could come back under another name.
        # THE COUNT IS PART OF THE ASSERTION, not a separate check: `all()`
        # over an empty list is True, so a missing `windows` key would pass
        # this silently and a sentinel fallback was merely redundant with
        # the row-count check above. A plant removing that sentinel was
        # UNCATCHABLE, which is this file's own signal for dead code.
        _wblob = json.load(open(wp)).get("windows") or []
        ck("a-roster-row-carries-no-title-field",
           len(_wblob) == 2
           and all(set(r) == {"app_id", "key", "cmd"} for r in _wblob))
        # A HAND-WRITTEN FILE, which is the case the filter is for: fed only
        # its own writer's output it tests nothing, and that exact hole let a
        # plant through once already.
        rawin = os.path.join(d, "rawin.json")
        open(rawin, "w").write(
            '{"version": 1, "apps": ["kitty"], "windows": ['
            '"not-a-dict", '
            '{"app_id": "kitty"}, '                      # no key
            '{"key": "term:resume"}, '                   # no app_id
            '{"app_id": "kitty", "key": "k", "cmd": ["a", "b"]}, '
            '{"app_id": "kitty", "key": "k2", "cmd": ""}, '
            '{"app_id": "kitty", "key": "term:resume", "cmd": null}]}')
        ck("roster-windows-normalises-what-it-reads-off-disk",
           engine.roster_windows(rawin)
           == [{"app_id": "kitty", "key": "term:resume", "cmd": None}])
        ck("roster-windows-is-empty-when-the-file-cannot-be-read",
           engine.roster_windows(bad) == []
           and engine.roster_windows(os.path.join(d, "none.json")) == [])

    # ---- END TO END: THE ACCOUNT'S TERMINALS COME BACK ------------------
    # THE USER'S REPORT, driven through the REAL `roster_launch` because the
    # whole fault was the interaction between a roster row and the plugins:
    # each half read correctly on its own. BOTH terminal spawns are stubbed,
    # since this path is what opened 16 real kitty windows on a live desktop
    # once already.
    _rt_cmds, _rt_kitty, _rt_desk = [], [], []
    _r_st, _r_sk2 = engine.spawn_term, engine._spawn_kitty
    _r_de2, _r_an2 = engine.desktop_entries, engine._announce
    try:
        engine.spawn_term = lambda cmd, size=None: (
            _rt_cmds.append(cmd) or True)
        engine._spawn_kitty = lambda cwd, size=None: _rt_kitty.append(cwd)
        engine.desktop_entries = lambda *_a, **_k: {
            "kitty": {"exec": "kitty", "type": "Application"},
            "slack": {"exec": "/usr/bin/slack", "type": "Application"}}
        engine._announce = lambda *_a, **_k: None
        _n_e2e = engine.roster_launch(
            ["kitty", "slack"], [], spawn=_rt_desk.append,
            windows=[{"app_id": "kitty", "key": "term:latch box:work",
                      "cmd": "mux latch box:work"},
                     {"app_id": "kitty", "key": "term:resume",
                      "cmd": "mux resume"}])
    finally:
        engine.spawn_term, engine._spawn_kitty = _r_st, _r_sk2
        engine.desktop_entries, engine._announce = _r_de2, _r_an2
    ck("a-remembered-mux-latch-comes-back-as-its-own-command",
       "mux latch box:work" in _rt_cmds)
    ck("a-remembered-local-mux-comes-back-too",
       "mux resume" in _rt_cmds)
    # AND NOT AS A BARE SHELL, which is exactly what it used to do: the
    # registry default resolved `kitty.desktop` and started a shell at $HOME,
    # forgetting the directory and the session the window was showing.
    ck("a-remembered-terminal-is-not-started-from-the-registry",
       not any(argv and argv[0] == "kitty" for argv in _rt_desk))
    ck("an-unowned-app-beside-it-still-starts-from-the-registry",
       any(argv and argv[0] == "/usr/bin/slack" for argv in _rt_desk))
    ck("roster-launch-counts-the-terminals-and-the-app",
       _n_e2e == 2)
    # TWO TERMINALS MEANS TWO SPAWNS, which is the per-COMMAND counting the
    # app-id path cannot express: one `kitty` app-id would have brought back
    # one of the two windows.
    ck("two-remembered-terminals-are-two-spawns", len(_rt_cmds) == 2)

    # AND `source_roster_rows` IS WHERE THE ROWS COME FROM, over this
    # account's own /proc, through the same seams the identity uses.
    _srr = engine.source_roster_rows(
        [{"app_id": "kitty", "title": "t", "identifier": "aabbccdd1122"},
         {"app_id": "kitty", "title": "u", "identifier": "bbccddee2233"},
         {"app_id": "kitty", "title": "v", "identifier": "ccddeeff3344"},
         {"app_id": "kitty", "title": "w"}],          # no identifier
        resolve=lambda v: {"t": "term:latch b:s", "u": "kitty:/tmp"}.get(
            v["title"]),
        cmd_of=lambda v: "mux latch b:s" if v["title"] == "t" else None)
    ck("source-roster-rows-carry-the-key-and-the-command",
       _srr == [{"app_id": "kitty", "key": "term:latch b:s",
                 "cmd": "mux latch b:s"},
                {"app_id": "kitty", "key": "kitty:/tmp", "cmd": None}])
    # A KEY IS REQUIRED AND A COMMAND IS NOT: `saved_key` is what every
    # relauncher reads, so a row without one describes nothing, while a plain
    # kitty legitimately has no command (it comes back from its cwd).
    ck("source-roster-rows-skip-a-window-with-no-key", len(_srr) == 2)
    ck("source-roster-rows-refuse-a-pid-that-is-not-ours",
       engine.source_roster_rows(
           [{"app_id": "kitty", "title": "t", "identifier": "aabbccdd1122"}],
           {"aabbccdd1122": os.getpid()},
           resolve=lambda _v: "term:resume", cmd_of=lambda _v: "mux resume",
           uid=os.geteuid() + 1) == [])
    # AND A RESOLVER THAT RAISES COSTS ONE ROW, not the whole capture.
    ck("source-roster-rows-survive-a-resolver-that-raises",
       engine.source_roster_rows(
           [{"app_id": "kitty", "title": "t", "identifier": "aabbccdd1122"}],
           resolve=_raise_it, cmd_of=lambda _v: "x") == [])

    # WHAT A LOG LINE OR A REPORT MAY SAY ABOUT A FOREIGN WINDOW.
    #
    # THE SECOND ROUTE FOR THE SAME DISCLOSURE. The snapshot redaction was
    # fixed first and this was still live afterwards: measured on manifold a
    # minute after the fixed daemon started, `recognised late, re-graced:
    # google-chrome | Inbox (23) - jello@...` in the session user's own
    # watch.log. So the title is not the only thing to redact; every site
    # that renders a window FOR A HUMAN has to ask.
    ck("log-title-passes-our-own-window-through",
       engine.log_title({"app_id": "signal", "title": "Signal", "pid": -1})
       == "Signal")
    ck("log-title-gives-a-foreign-window-its-source-not-its-title",
       engine.log_title({"app_id": "slack", "title": "SECRET SUBJECT",
                         "source": "titan"}) == "[titan]")
    # AND IT MUST NOT LEAK VIA A MISSING TITLE either: no title at all is
    # still "" rather than None, because every caller slices it.
    ck("log-title-is-always-a-string",
       engine.log_title({"app_id": "x", "pid": -1}) == "")
    # A RECORDED SOURCE WINS, which is what makes a REPLAYED row safe: its
    # pid is long dead, so re-deriving would call it ours.
    ck("log-title-trusts-a-recorded-source-over-a-dead-pid",
       engine.log_title({"app_id": "slack", "title": "SECRET",
                         "source": "titan", "pid": -1}) == "[titan]")

    # AND THE WIRING, because the helper's own checks say nothing about
    # whether the log sites call it. Matched against the exact pattern the
    # pre-fix code used, with a vacuity guard so an emptied scan cannot pass.
    import pathlib
    _wd = pathlib.Path(engine.__file__).parent
    _watch = (_wd / "watch.py").read_text()
    _doc = (_wd / "doctor.py").read_text()
    ck("no-log-site-reads-a-raw-view-title",
       'v.get("title", "")' not in _watch
       and "lv.get('title','')" not in _doc)
    ck("the-log-sites-do-call-the-redactor",
       _watch.count("engine.log_title(") >= 3
       and _doc.count("engine.log_title(") >= 1)

    # AND THE REPORTS, WHICH THIS CHECK USED TO MISS ENTIRELY: it scanned
    # watch.py and doctor.py and never engine.py, where `_restore_report`
    # lives, so `usher restore --dry-run` printed SIX of the work account's
    # window titles in full on manifold (2026-11-04) with every other
    # redaction check green. Driven BEHAVIOURALLY rather than by grepping a
    # literal, because a pattern scan is what went stale: it asks what the
    # report PRINTS, which cannot be satisfied by code that merely mentions
    # the helper.
    _secret = "ACQUISITION-TERMS-DO-NOT-LEAK"

    def _report_of(row):
        _b = io.StringIO()
        with contextlib.redirect_stdout(_b):
            engine._restore_report([], [row], [row], [], [], {}, True, 0)
        return _b.getvalue()

    # NAMED, which is this fleet today.
    _named = {"app-id": "google-chrome", "title": _secret, "pid": 1,
              "id": 301, "source": "titan"}
    _out = _report_of(_named)
    ck("the-dry-run-report-redacts-a-foreign-title", _secret not in _out)
    ck("the-dry-run-report-still-names-the-source", "[titan]" in _out)
    # AND UNNAMED, which is any box with no provider wired and is the half
    # `log_title` itself was missing: pid 1 is root's, so the uid says foreign
    # while no hook can supply a name.
    _out2 = _report_of({"app-id": "google-chrome", "title": _secret,
                        "pid": 1, "id": 303})
    ck("the-dry-run-report-redacts-an-UNNAMED-foreign-title",
       _secret not in _out2)
    ck("the-dry-run-report-says-whose-when-it-cannot-name-it",
       "[uid 0]" in _out2)
    # THE CONTROL, or the check above passes for a report that prints nothing
    # at all: OUR OWN title must still come through, since the whole value of
    # these reports is being readable.
    _ol = _trv("signal", _secret, pid=os.getpid(), vid=302)
    _buf2 = io.StringIO()
    with contextlib.redirect_stdout(_buf2):
        engine._restore_report([], [_ol], [_ol], [], [], {}, True, 0)
    ck("the-dry-run-report-keeps-our-own-title",
       _secret in _buf2.getvalue())

    # AND doctor's SECOND site, which parses a LIVE title to print what a
    # terminal is SHOWING. Redacted, the parse finds no colon, so a foreign
    # terminal's session and host are never narrated. LATENT when fixed (that
    # account's terminals are titled `terminal`), so the invariant is what is
    # pinned rather than an observed line.
    _ft = {"app_id": "kitty", "title": "work:main[somehost]", "pid": 1}
    ck("a-redacted-title-cannot-be-read-as-a-mux-banner",
       not engine.is_mux_term("kitty", engine.log_title(_ft)))
    ck("the-same-banner-IS-read-for-our-own-window",
       engine.is_mux_term("kitty", engine.log_title(
           dict(_ft, pid=os.getpid()))))
    ck("doctor-does-not-parse-a-raw-live-title",
       'lv.get("title") or ""' not in _doc)
    # AND THE ELIMINATION POOL IS ACTUALLY USED, because the pool function's
    # own checks say nothing about whether the caller consults it: a planted
    # bypass restoring the old inline expression passed every one of them.
    # Same lesson `entry_output` already carries, matched against the exact
    # pre-fix pattern with a vacuity guard so an emptied scan cannot pass.
    ck("elimination-is-fed-from-the-pool",
       "engine.chrome_elimination_pool(" in _watch)
    ck("elimination-does-not-build-its-own-list",
       "if chrome.is_chrome(app_of(v))]" not in _watch)
    # AND THE WIND-DOWN REPORT MUST REACH THE LOG, not only stdout. The power
    # menu runs `usher cleanly <verb>; systemctl <verb>` through /bin/sh, so
    # this process's stdout goes NOWHERE: on that path the log is the only
    # copy, which is `_announce`'s own stated reason for existing.
    # `captured 0 window(s)` is the signature of the failure the step
    # ordering exists to prevent, so it is the one line that must survive.
    _eng = (_wd / "engine.py").read_text()
    _ww = _eng[_eng.index("def _wind_down_wait("):]
    _ww = _ww[:_ww.index("\ndef ")]
    ck("the-wind-down-outcomes-are-announced-not-just-printed",
       'print("usher:' not in _ww and 'print(f"usher:' not in _ww
       and _ww.count("_announce(") >= 5)
    ck("the-wind-down-logs-the-capture-count",
       "wind-down captured %d window(s)" in _eng)

    # WHAT doctor SAYS ABOUT THE SEAM, as a pure table. The lines matter as
    # much as the mechanism: the symptom of a missing hook is "my work apps
    # did not come back" with nothing anywhere saying why.
    from .doctor import source_seam_report as _seam
    ck("seam-reports-a-source-it-can-ask",
       _seam(["titan"], True, [], "no roster")
       == [("OK", "source-trigger present; 1 other account(s) can be asked: "
                  "titan")])
    _unreachable = _seam(["titan"], False, [], "no roster", hook="/h")
    ck("seam-warns-when-a-source-cannot-be-asked",
       _unreachable[0][0] == "WARN" and "titan" in _unreachable[0][1]
       and "/h" in _unreachable[0][1])
    ck("seam-says-what-that-costs",
       _unreachable[1] == ("", "their windows are placed, and their apps "
                               "are never started"))
    # SILENCE IS ONE OF THE ANSWERS and it is the common one. Every ordinary
    # box has neither a hook nor another account, and a line that is always
    # there and never actionable is the kind that gets skimmed past.
    ck("seam-says-nothing-on-a-box-with-neither",
       _seam([], False, [], "no roster") == [])
    ck("seam-reports-this-accounts-own-roster",
       _seam([], False, ["slack"], "")
       == [("OK", "this account's own roster: slack")])
    # AND CAPTURED-BUT-EMPTY MUST NOT READ LIKE NOT-AN-ENCLAVE. One is a desk
    # that will come back as nothing; the other is an ordinary box. Three
    # states again, and collapsing two is how the wrong remedy prints.
    # COMPARED AS A LIST OF LEVELS, not by indexing: with the branch removed
    # the rows are empty, and `[0][0]` then raises instead of failing by name.
    # The area guard does report that, so it is not silent, but a named FAIL
    # is what a reader can act on.
    ck("seam-empty-roster-and-no-roster-differ",
       [r[0] for r in _seam([], False, [], "")] == ["WARN", ""]
       and _seam([], False, [], "no roster") == [])

    # ---- THE PRE-LOGOFF PAIR, which closes a FORENSIC gap -------------
    # MEASURED 2026-11-05: Signal came back on the wrong workspace and the
    # question "what did the store say just before the logoff?" could not be
    # answered. The history ring is 20 files and covered SEVEN AND A HALF
    # MINUTES on that box, and the milestones are daily, so nothing spans a
    # session boundary, which is exactly where this package's failures live.
    _rs = engine.STATE
    try:
        with tempfile.TemporaryDirectory() as _d:
            engine.STATE = _d
            # A FOREIGN WINDOW IN THE FIXTURE, because the invariant that
            # matters is not that the copy exists but that it adds no
            # disclosure: `snapshot()` blanks a foreign title and `learn()`
            # its label, and this must copy them AS THEY ARE. A copy of a
            # redaction has been the leak three times here.
            json.dump({"time": 1, "windows": [
                {"app_id": "google-chrome", "title": "", "source": "titan",
                 "key": "titan:chrome:win:1", "workspace": [1, 0]},
                {"app_id": "signal", "title": "Signal", "workspace": [2, 0]}]},
                open(os.path.join(_d, "current.json"), "w"))
            _kbf = engine.kb_path()
            json.dump({engine.kkey("signal", ""): {"workspace": [2, 0]}},
                      open(_kbf, "w"))

            _dst = os.path.join(_d, "logoff")
            _w1 = engine.retain_logoff(_dst)
            ck("logoff-retains-the-snapshot",
               os.path.exists(os.path.join(_dst, "current.json")))
            ck("logoff-retains-the-loaded-store",
               os.path.exists(os.path.join(_dst,
                                           os.path.basename(_kbf))))
            ck("logoff-retains-exactly-the-pair", len(_w1) == 2)
            # ONE GENERATION, so it is bounded: a second logoff overwrites
            # rather than accumulating a file per session forever.
            _w2 = engine.retain_logoff(_dst)
            ck("logoff-keeps-one-generation",
               len(os.listdir(_dst)) == 2 and len(_w2) == 2)
            # THE REDACTION SURVIVES THE COPY, asserted rather than assumed.
            _got = json.load(open(os.path.join(_dst, "current.json")))
            _fw = [w for w in _got["windows"] if w.get("source")]
            ck("logoff-copy-has-a-foreign-window-at-all", len(_fw) == 1)
            ck("logoff-copy-carries-no-foreign-title",
               all(not w.get("title") for w in _fw))
            ck("logoff-copy-keeps-our-own-title",
               any(w.get("title") == "Signal" for w in _got["windows"]))

        # NOTHING TO COPY IS NOT A FAILURE: a wind-down whose capture refused
        # has no snapshot, and this must not raise on the path whose whole
        # doctrine is that usher is never the reason a machine will not go
        # down.
        with tempfile.TemporaryDirectory() as _d2:
            engine.STATE = _d2
            try:
                _w3 = engine.retain_logoff(os.path.join(_d2, "logoff"))
                _ok = _w3 == []
            except Exception:                           # noqa: BLE001
                _ok = False
            ck("logoff-with-nothing-to-copy-is-not-a-failure", _ok)
    finally:
        engine.STATE = _rs

    # AND THE WIRING, because the helper's own checks say nothing about
    # whether wind-down calls it: the fourth instance of that hole here.
    _wd = inspect.getsource(engine.do_wind_down)
    ck("wind-down-retains-the-pair", "retain_logoff()" in _wd)
    # INSIDE THE CAPTURE'S `try`, so a retention failure can never strand
    # somebody at a machine that will not shut down. GUARDED, because a plant
    # that removes the call turns a bare `.index()` into a ValueError that
    # aborts the area: a named failure beats a raise, which is this file's own
    # rule and which I broke writing the check for it.
    _i_ret = _wd.find("retain_logoff()")
    _i_exc = _wd.find("except Exception")
    ck("wind-down-retention-cannot-stop-a-reboot",
       _i_ret >= 0 and _i_exc >= 0 and _i_ret < _i_exc)
    # AND IT RE-CAPTURES ONCE THE SOURCES HAVE REPORTED, which is the fix for
    # the logoff capture being BLIND: it runs in the CLI process, so the
    # per-window map is empty when the first capture stamps each window's
    # key. Measured on manifold: seventeen of one account's windows stamped
    # ONE key blind, twelve sighted.
    _i_cap = _wd.find("do_capture()")
    _i_trg = _wd.find('source_trigger(source_trigger_plan(_lv), "capture"')
    _i_re = _wd.rfind("do_capture()")
    ck("wind-down-captures-FIRST-while-the-session-is-certainly-intact",
       _i_cap >= 0 and _i_trg >= 0 and _i_cap < _i_trg)
    ck("wind-down-re-captures-after-the-sources-report",
       _i_re > _i_trg)
    # AND RETAINS THE PAIR AGAIN, or the kept snapshot is the BLIND one and
    # the forensic record this exists for describes a desk nobody had.
    ck("the-re-capture-retains-the-pair-too",
       _wd.rfind("retain_logoff()") > _i_trg)
    # CONDITIONAL ON SOMETHING HAVING BEEN LEARNED, so a box with no other
    # account pays nothing: a second snapshot on every logoff for nothing is
    # the kind of cost that gets a safety step deleted.
    ck("the-re-capture-only-fires-when-a-source-reported",
       "if _win:" in _wd)

    # THE VERBS, with the wayland client and the spawn both stubbed.
    real_list = toplevels.list_toplevels
    real_state = engine.STATE
    real_src = engine.source_trigger
    try:
        with tempfile.TemporaryDirectory() as d:
            engine.STATE = d
            rows = [{"app_id": "google-chrome", "title": "t",
                     "identifier": "1"},
                    {"app_id": "slack", "title": "u", "identifier": "2"}]
            toplevels.list_toplevels = lambda *a, **k: (rows, "")
            out = _capture_out(engine.do_source_capture)
            ck("capture-records-its-own-apps",
               engine.load_roster()[0] == ["google-chrome", "slack"]
               and "2 app(s)" in out)

            # A FAILING CLIENT MUST NOT WRITE. "Could not look" is not "there
            # was nothing", and writing an empty roster on a failed read is
            # exactly how a desk is lost.
            toplevels.list_toplevels = lambda *a, **k: ([], "no socket here")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = engine.do_source_capture()
            ck("capture-refuses-when-it-cannot-look",
               rc == engine.EXIT_CANNOT
               and "no socket here" in buf.getvalue()
               and engine.load_roster()[0] == ["google-chrome", "slack"])

            # AND AN EMPTY OBSERVATION NEVER OVERWRITES A REMEMBERED DESK.
            # This is September's browser-less capture one account over: an
            # enclave captured AFTER its apps are killed records an empty desk
            # and the next login restores nothing from a record that looks
            # perfectly valid.
            toplevels.list_toplevels = lambda *a, **k: ([], "")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = engine.do_source_capture()
            ck("capture-empty-does-not-clobber-a-remembered-desk",
               rc == engine.EXIT_CANNOT
               and engine.load_roster()[0] == ["google-chrome", "slack"]
               and "NOT being overwritten" in buf.getvalue())

            # IT STILL SELF-CORRECTS, which is what keeps that rule narrow:
            # any observation with a window REPLACES the roster wholesale, so
            # an app really closed stops coming back.
            toplevels.list_toplevels = lambda *a, **k: ([rows[1]], "")
            _capture_out(engine.do_source_capture)
            ck("capture-a-smaller-desk-replaces-the-roster",
               engine.load_roster()[0] == ["slack"])

            # ---- THE RELAYED PIDS REACH THE REPORTER --------------------
            # The WIRING, which `parse_source_pids` own checks say nothing
            # about: a capture that parses stdin and then never passes the
            # map would leave every /proc-derived identity computed against
            # -1, with the whole relay inert and every pure check passing.
            _TLP = "abcdef0123456789"
            _got_pids = []
            _r_swl, _r_rs = engine.source_window_lines, engine._read_stdin
            try:
                toplevels.list_toplevels = lambda *a, **k: (
                    [{"app_id": "kitty", "title": "t",
                      "identifier": _TLP}], "")
                engine._read_stdin = lambda *_a: (
                    "pid %s %d\n" % (_TLP, os.getpid()))

                def _swl(rows_, pids=None, **_k):
                    _got_pids.append(dict(pids or {}))
                    return []

                engine.source_window_lines = _swl
                _capture_out(engine.do_source_capture)
            finally:
                engine.source_window_lines = _r_swl
                engine._read_stdin = _r_rs
            ck("capture-passes-the-relayed-pids-to-the-reporter",
               _got_pids == [{_TLP: os.getpid()}])
            # AND A PID THAT IS NOT OURS IS REFUSED AND SAID OUT LOUD.
            # COUNTED rather than per window, because the state that causes
            # it (a proxy, or a pid namespace) causes it for every window at
            # once, and saying nothing would leave a silently reduced
            # capture: this package's most repeated failure shape.
            _got_pids.clear()
            _buf_p = io.StringIO()
            try:
                engine._read_stdin = lambda *_a: (
                    "pid %s 1\npid %s %d\n"
                    % (_TLP, "99" + _TLP[2:], os.getpid()))
                engine.source_window_lines = _swl
                with contextlib.redirect_stderr(_buf_p):
                    _capture_out(engine.do_source_capture)
            finally:
                engine.source_window_lines = _r_swl
                engine._read_stdin = _r_rs
            ck("capture-drops-a-pid-that-is-not-this-accounts",
               _got_pids == [{"99" + _TLP[2:]: os.getpid()}])
            ck("capture-says-how-many-relayed-pids-it-refused",
               "1 of 2 relayed pid(s)" in _buf_p.getvalue())
            # AND SAYS NOTHING WHEN THEY ARE ALL OURS, or a line fires at
            # every capture on a working box and then gets ignored.
            _buf_q = io.StringIO()
            try:
                engine._read_stdin = lambda *_a: (
                    "pid %s %d\n" % (_TLP, os.getpid()))
                engine.source_window_lines = _swl
                with contextlib.redirect_stderr(_buf_q):
                    _capture_out(engine.do_source_capture)
            finally:
                engine.source_window_lines = _r_swl
                engine._read_stdin = _r_rs
            ck("capture-is-quiet-when-every-relayed-pid-is-ours",
               "relayed pid(s)" not in _buf_q.getvalue())

            # ---- AND THE ROSTER GETS A ROW PER WINDOW -------------------
            # The WIRING for the user's own report: without this the roster
            # is app-ids only, `kitty` resolves to a bare shell at $HOME, and
            # the terminal comes back having forgotten its session.
            _r_srr = engine.source_roster_rows
            try:
                toplevels.list_toplevels = lambda *a, **k: (
                    [{"app_id": "kitty", "title": "t",
                      "identifier": _TLP}], "")
                engine._read_stdin = lambda *_a: (
                    "pid %s %d\n" % (_TLP, os.getpid()))
                engine.source_roster_rows = lambda _r, _p=None, **_k: [
                    {"app_id": "kitty", "key": "term:latch b:s",
                     "cmd": "mux latch b:s"}]
                engine.source_window_lines = lambda _r, *_a, **_k: []
                _out_w = _capture_out(engine.do_source_capture)
            finally:
                engine.source_roster_rows = _r_srr
                engine.source_window_lines = _r_swl
                engine._read_stdin = _r_rs
            ck("capture-writes-the-window-rows-into-the-roster",
               engine.roster_windows()
               == [{"app_id": "kitty", "key": "term:latch b:s",
                    "cmd": "mux latch b:s"}])
            ck("capture-says-how-many-windows-it-can-bring-back",
               "1 of 1 window(s)" in _out_w)
            ck("capture-still-records-the-app-list",
               engine.load_roster()[0] == ["kitty"])
            # AND IT IS ASKED WITH THE RELAYED PIDS, or every /proc-derived
            # command is computed against -1 and the roster carries nothing.
            _seen_srr = []
            try:
                engine._read_stdin = lambda *_a: (
                    "pid %s %d\n" % (_TLP, os.getpid()))
                engine.source_roster_rows = lambda _r, _p=None, **_k: (
                    _seen_srr.append(dict(_p or {})) or [])
                engine.source_window_lines = lambda _r, *_a, **_k: []
                _capture_out(engine.do_source_capture)
            finally:
                engine.source_roster_rows = _r_srr
                engine.source_window_lines = _r_swl
                engine._read_stdin = _r_rs
            ck("capture-asks-for-the-rows-with-the-relayed-pids",
               _seen_srr == [{_TLP: os.getpid()}])
            toplevels.list_toplevels = lambda *a, **k: ([rows[1]], "")

            # ---- AND THE READ CANNOT BLOCK ------------------------------
            # A plain read() returns at once on the relay's closed pipe and
            # HANGS FOR EVER on an inherited one nobody will close, which is
            # what a miswired shim or a hand-run from a pipeline gives it.
            # The owner's own 30s timeout would mask that as a refused
            # trigger with no cause; from a terminal there is no bound.
            # DRIVEN ON A THREAD, because the thing under test is whether
            # it RETURNS: called inline, a blocking implementation hangs the
            # whole suite and reports nothing, which is a plant caught in the
            # one way a check cannot see. Measured: restoring the plain
            # `read()` ran the suite past 400 seconds with no verdict.
            _rd, _wr = os.pipe()
            _r_in = sys.stdin
            _res_in = {}

            def _rd_call():
                try:
                    _res_in["txt"] = engine._read_stdin(0.3)
                except Exception as _e:                    # noqa: BLE001
                    _res_in["err"] = _e

            try:
                os.write(_wr, b"pid %s 7\n" % _TLP.encode())
                sys.stdin = os.fdopen(_rd, "r")
                _th = threading.Thread(target=_rd_call, daemon=True)
                _t0 = time.time()
                _th.start()
                _th.join(5.0)
                _el = time.time() - _t0
                _alive = _th.is_alive()      # the writer stays OPEN
            finally:
                sys.stdin = _r_in
                try:
                    os.close(_wr)            # releases a blocked reader
                except OSError:
                    pass
            ck("read-stdin-returns-on-an-open-pipe-rather-than-blocking",
               not _alive)
            ck("read-stdin-keeps-what-was-already-written",
               engine.parse_source_pids(_res_in.get("txt") or "")
               == {_TLP: 7})
            ck("read-stdin-waited-for-the-deadline-it-was-given",
               _alive or 0.25 <= _el < 3.0)

        with tempfile.TemporaryDirectory() as d:
            engine.STATE = d
            spawned = []
            asked = []
            engine.source_trigger = \
                lambda *a, **k: asked.append(a) or 0

            # NO ROSTER MEANS NOTHING WAS ASSESSED, not nothing to do.
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = engine.do_source_resume()
            ck("resume-with-no-roster-cannot-rather-than-fails",
               rc == engine.EXIT_CANNOT and "never been captured"
               in buf.getvalue())

            engine.save_roster([])
            ck("resume-with-an-empty-roster-is-ok-and-starts-nothing",
               "nothing to start" in _capture_out(engine.do_source_resume))

            engine.save_roster(["google-chrome", "slack"])
            # LIVENESS IS REQUIRED. Unable to tell a cold start from a second
            # trigger, starting a second copy of everything is worse than
            # starting nothing, and this is the only path here that acts.
            toplevels.list_toplevels = lambda *a, **k: ([], "cannot look")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = engine.do_source_resume()
            ck("resume-refuses-rather-than-start-blind",
               rc == engine.EXIT_CANNOT and not spawned
               and "not starting any" in buf.getvalue())

            # THE ORCHESTRATION IS TESTED WITH THE LAUNCHER STUBBED, and that
            # is not tidiness: `roster_launch` with no spawn hands
            # ChromePlugin a missing `google-chrome` and it runs the real
            # browser. This suite has opened 16 real terminals on the
            # developer's desktop once already, for the same reason, and the
            # capture loop then learned them as slots. So the decision and
            # the launching are checked separately, each with the stub its own
            # path needs.
            toplevels.list_toplevels = lambda *a, **k: (
                [{"app_id": "slack", "title": "", "identifier": "2"}], "")
            real_launch = engine.roster_launch
            try:
                wanted = []
                engine.roster_launch = \
                    lambda apps, live, spawn=None, **_k: (
                        wanted.append((sorted(apps), sorted(live)))
                        or len(engine.roster_plan(apps, live)))
                out = _capture_out(engine.do_source_resume)
            finally:
                engine.roster_launch = real_launch
            ck("resume-passes-the-roster-and-the-live-set",
               wanted == [(["google-chrome", "slack"], ["slack"])])

            # ---- AND IT HANDS OVER THE PER-WINDOW ROWS AND THE PIDS ------
            # The WIRING, which `roster_windows` and `source_views` own
            # checks say nothing about: a resume that never reads the rows
            # brings a terminal back as a bare shell, and one that never
            # relays the pids counts per APP instead of per COMMAND, so one
            # of two mux terminals comes back.
            _rl_kw = []
            _r_rs2 = engine._read_stdin
            try:
                engine.save_roster(
                    ["kitty"],
                    windows=[{"app_id": "kitty", "key": "term:resume",
                              "cmd": "mux resume"}])
                toplevels.list_toplevels = lambda *a, **k: (
                    [{"app_id": "kitty", "title": "",
                      "identifier": "aabbccdd1122"}], "")
                engine._read_stdin = lambda *_a: (
                    "pid aabbccdd1122 %d\n" % os.getpid())
                engine.roster_launch = \
                    lambda apps, live, spawn=None, **kw: (
                        _rl_kw.append(kw) or 0)
                _capture_out(engine.do_source_resume)
            finally:
                engine.roster_launch = real_launch
                engine._read_stdin = _r_rs2
            ck("resume-hands-over-the-remembered-window-rows",
               _rl_kw and _rl_kw[-1].get("windows")
               == [{"app_id": "kitty", "key": "term:resume",
                    "cmd": "mux resume"}])
            ck("resume-hands-over-the-live-views-with-their-pids",
               _rl_kw and [v.get("pid") for v in (_rl_kw[-1].get("seen") or [])]
               == [os.getpid()])
            # AND A PID THAT IS NOT OURS NEVER REACHES THE RELAUNCHERS.
            _rl_kw.clear()
            try:
                engine._read_stdin = lambda *_a: "pid aabbccdd1122 1\n"
                engine.roster_launch = \
                    lambda apps, live, spawn=None, **kw: (
                        _rl_kw.append(kw) or 0)
                _capture_out(engine.do_source_resume)
            finally:
                engine.roster_launch = real_launch
                engine._read_stdin = _r_rs2
            ck("resume-drops-a-relayed-pid-that-is-not-this-accounts",
               _rl_kw and [v.get("pid")
                           for v in (_rl_kw[-1].get("seen") or [])] == [-1])
            ck("resume-names-only-what-is-missing",
               out.rstrip().endswith(": google-chrome")
               and "1 missing app(s)" in out)

            # AND THE LAUNCHER ITSELF, with no plugin able to claim the app
            # and the spawn injected, so nothing real can start. An app-id no
            # desktop entry matches would be refused before spawning, so this
            # uses one the fixture registry does answer.
            real_plugins = engine.plugins
            real_entries = engine.desktop_entries
            try:
                engine.plugins = lambda: []
                engine.desktop_entries = lambda *a, **k: {
                    "zzz-probe": {"exec": "true", "terminal": "false",
                                  "name": "probe", "nodisplay": "false",
                                  "hidden": "false"}}
                # _announce PRINTS as well as logging, and _quiet_log only
                # covers the log, so without this every run prints
                # `launch  true` into the suite's own output.
                with contextlib.redirect_stdout(io.StringIO()):
                    n = engine.roster_launch(["zzz-probe"], [],
                                             spawn=spawned.append)
            finally:
                engine.plugins = real_plugins
                engine.desktop_entries = real_entries
            # THE LOOP GUARD: an account reached through the source seam must
            # not reach back through it. One enclave triggering another is a
            # loop, and nothing on this side is the owner.
            ck("roster-launch-never-asks-another-source", asked == [])
            # AN INJECTED SPAWN MUST WIN over the stderr-watching one, or the
            # suite would launch for real. This is the condition I got
            # backwards first, and the two checks below caught it at once.
            ck("an-injected-spawn-is-not-replaced-by-the-watcher",
               spawned == [["true"]])
            # AN INJECTED SPAWN MUST ALSO LEAVE THE SESSION POLICY DISARMED,
            # or the suite would start shelling out to systemd-run. The flag
            # is a module global precisely because the two launch sites are
            # shared with the owner's restore, so its default matters.
            ck("an-injected-spawn-leaves-the-session-policy-off",
               engine._SESSION_LAUNCH is False)
            # AND THE OWNER'S PATH IS UNCHANGED: app_spawn with nothing armed
            # is the direct child it has always been, which is the half that
            # must not regress on a working restore.
            _popen = engine.subprocess.Popen
            _calls = []
            try:
                engine.subprocess.Popen = (
                    lambda *a, **k: _calls.append(a[0]) or _popen(
                        ["/bin/true"], **k))
                engine.app_spawn(["/bin/true"])
            finally:
                engine.subprocess.Popen = _popen
            ck("app-spawn-is-direct-when-nothing-is-armed",
               _calls == [["/bin/true"]])
            # AND A FAST DEATH IS REPORTED WITH ITS STDERR, which is the
            # whole point: four enclave apps died in under 0.3s with nothing
            # in the journal, and DEVNULL'd stderr left no way to see why.
            _said = []
            _rl = engine.logline
            try:
                engine.logline = _said.append
                _w = []
                # _announce PRINTS as well, so redirect or the suite's own
                # output carries fixture lines.
                with contextlib.redirect_stdout(io.StringIO()):
                    engine._spawn_watched(_w)(["/bin/sh", "-c",
                                               "echo BOOM >&2; exit 3"])
                    engine._report_quick_deaths(_w, grace=0.6)
            finally:
                engine.logline = _rl
            ck("a-fast-death-is-logged-with-its-return-code",
               any("DIED rc=3" in m for m in _said))

            ck("a-fast-death-relays-its-stderr",
               any("its stderr: BOOM" in m for m in _said))
            # AND IT MUST REACH STDOUT, because on the enclave side the log
            # is inside a 0700 home the session user cannot read: only stdout
            # crosses, via the trigger's relay. Asserted by CAPTURING stdout,
            # since `logline` alone would satisfy the check above.
            _out2 = io.StringIO()
            _said.clear()
            try:
                engine.logline = _said.append
                _w2 = []
                with contextlib.redirect_stdout(_out2):
                    engine._spawn_watched(_w2)(
                        ["/bin/sh", "-c", "echo LOUD >&2; exit 4"])
                    engine._report_quick_deaths(_w2, grace=0.6)
            finally:
                engine.logline = _rl
            ck("a-fast-death-reaches-stdout-not-only-the-log",
               "DIED rc=4" in _out2.getvalue()
               and "its stderr: LOUD" in _out2.getvalue())
            # AND A SURVIVOR SAYS NOTHING, or every login would log a line
            # per app that started perfectly well.
            _said.clear()
            try:
                engine.logline = _said.append
                _w = []
                with contextlib.redirect_stdout(io.StringIO()):
                    engine._spawn_watched(_w)(["/bin/sh", "-c", "sleep 30"])
                    engine._report_quick_deaths(_w, grace=0.4)
            finally:
                engine.logline = _rl
            ck("a-surviving-app-is-not-reported", _said == [])
            for _pr, _pa, _ in _w:
                _pr.kill()
            ck("roster-launch-spawns-through-the-registry",
               n == 1 and spawned == [["true"]])
            ck("roster-launch-starts-nothing-already-live",
               _quiet_launch(["zzz-probe"], ["zzz-probe"], spawned) == 0
               and len(spawned) == 1)
    finally:
        toplevels.list_toplevels = real_list
        engine.STATE = real_state
        engine.source_trigger = real_src


def _t_cli_split(ck):
    """The two front ends: one table, and each refuses the other's verbs.

    usher-mgr is the service (autostart, systemd, hooks) and usher is the human
    CLI. The split is the AUDIENCE column of cli.VERBS, so the failure this
    guards is the table and the usage text drifting apart, or a verb becoming
    undispatchable because nobody said who it was for.
    """
    from . import cli
    # EVERY VERB THE DISPATCH HANDLES MUST BE IN THE TABLE, or it is unreachable
    # and the usage text cannot mention it. Read the dispatch's own source for
    # the literals rather than trusting a second list here.
    import inspect
    import re
    src = inspect.getsource(cli._dispatch)
    handled = set(re.findall(r'verb == "([a-z_-]+)"', src))
    handled |= set(re.findall(r'"([a-z_-]+)"',
                             " ".join(re.findall(r'verb in \(([^)]*)\)', src))))
    missing = sorted(handled - set(cli.VERBS))
    ck("every-dispatched-verb-is-in-the-table", not missing)
    # ...and every table entry is actually dispatched, so the usage text cannot
    # advertise a verb that does nothing.
    undispatched = sorted(v for v in cli.VERBS if v not in handled)
    ck("every-table-verb-is-dispatched", not undispatched)
    # THE AUDIENCES ARE THE THREE WE MEAN, so a typo cannot silently make a verb
    # reachable from neither front end.
    ck("audiences-are-known",
       {a for a, _h in cli.VERBS.values()} <= {"mgr", "cli", "both"})
    # The service verbs stay off the CLI and vice versa: this is the split.
    ck("watch-is-the-services", cli.VERBS["watch"][0] == "mgr")
    ck("cleanly-is-the-humans", cli.VERBS["cleanly"][0] == "cli")
    ck("selftest-is-for-both", cli.VERBS["selftest"][0] == "both")
    # AND `save` MUST GO THROUGH do_save, which is the one thing every
    # do_save check cannot say: reverting this one line to `do_capture()`
    # restores the blindness in full and passed the ENTIRE suite. Read from
    # the dispatch's own source, the same way the verb table above is.
    _save_body = re.search(
        r'verb in \("capture", "save"\):\n(.*?)\n    elif', src, re.S)
    ck("the-save-verb-is-dispatched-at-all", _save_body is not None)
    ck("save-does-not-capture-straight-from-the-client",
       _save_body is not None and "do_save" in _save_body.group(1)
       and "do_capture" not in _save_body.group(1))
    # An internal verb carries no help, so it never appears in usage.
    ck("internal-verbs-are-hidden",
       cli.VERBS["_worker"][1] is None and cli.VERBS["_super"][1] is None)
    # THE PERMISSIVE ENTRY MUST ACCEPT EVERY VERB, and this is the check that
    # the autostart needed. A verb's audience ("who is it for") and an entry's
    # audience ("what will it accept") are different things; the first version
    # used "both" for each, so the gate refused `usher-mgr watch` and
    # `usher-mgr _super`. That killed the daemon on its next reload, because
    # the supervisor re-execs itself through _super, and would have killed the
    # autostart at the next login. Nothing offline caught it.
    for _v, (_who, _h) in cli.VERBS.items():
        ck(f"legacy-entry-accepts-{_v}", not cli.gate_blocks(_who, "any"))
    ck("the-mgr-entry-still-refuses-a-cli-verb", cli.gate_blocks("cli", "mgr"))
    ck("the-cli-entry-still-refuses-a-mgr-verb", cli.gate_blocks("mgr", "cli"))
    ck("a-both-verb-passes-either-front-end",
       not cli.gate_blocks("both", "mgr")
       and not cli.gate_blocks("both", "cli"))

    # THE PLACEMENT-MODE REQUESTS, as a table, because the cell that was wrong
    # is the one nobody looks at: with NO daemon the arm file is written, the
    # worker baselines its mtime and never adopts it, and the old code printed
    # `placing every window that maps` over that. Pure, so no daemon, no
    # runtime dir and no compositor are needed.
    for _act in ("place", "settle", "toggle"):
        _a, _m = cli.arm_plan(_act, None, None)
        ck(f"arm-{_act}-is-refused-with-no-daemon", _a == "none")
        ck(f"arm-{_act}-says-why", "no daemon" in _m)
    # with a daemon, each means itself and toggle reads the LIVE mode
    ck("arm-place-arms", cli.arm_plan("place", 99, "settled")[0]
       == "place")
    ck("arm-settle-settles", cli.arm_plan("settle", 99, "place")[0]
       == "settle")
    ck("arm-toggle-from-place-settles",
       cli.arm_plan("toggle", 99, "place")[0] == "settle")
    ck("arm-toggle-from-settled-arms",
       cli.arm_plan("toggle", 99, "settled")[0] == "place")
    # AN UNREADABLE MODE WITH THE DAEMON UP still arms, deliberately: one
    # `settle` undoes it, where declining would leave the tray click dead.
    ck("arm-toggle-with-no-status-arms",
       cli.arm_plan("toggle", 99, None)[0] == "place")
    # the two messages are distinct, or a reader cannot tell which happened
    ck("arm-messages-are-distinct",
       len({cli.arm_plan("place", 99, "settled")[1],
            cli.arm_plan("settle", 99, "settled")[1],
            cli.arm_plan("settle", None, None)[1]}) == 3)
    # THE SEAM: usher must not hardcode how a session starts. It reads one
    # path, and the path is beside the other user config rather than in a
    # second config dir.
    # FINDING THE COMPOSITOR SOCKET. pywayfire reads WAYFIRE_SOCKET and
    # otherwise gives up, and its own manual search looks in /tmp while this
    # compositor uses XDG_RUNTIME_DIR, so usher has to pick. A shell often has
    # no WAYFIRE_SOCKET (a tmux server outlives whatever set it, so no pane
    # under it has the variable), which is where `usher cleanly logoff` was
    # told the compositor could not be reached.
    _s = "/run/user/1000/wayfire-wayland-1-.socket"
    ck("an-explicit-socket-always-wins",
       pick_socket(["/run/a.socket"], {"WAYFIRE_SOCKET": _s}) == _s)
    ck("one-candidate-is-picked", pick_socket([_s], {}) == _s)
    # NOTHING FOUND is not an error here: pywayfire reports it, and its message
    # is the one a reader already knows.
    ck("no-candidate-answers-none", pick_socket([], {}) is None)
    # TWO IS AMBIGUOUS, and guessing would talk to the wrong compositor or fail
    # in a way that reads like a bug.
    try:
        pick_socket([_s, "/run/user/1000/wayfire-wayland-2-.socket"], {})
        ck("two-candidates-refuse-rather-than-guess", False)
    except RuntimeError as e:
        ck("two-candidates-refuse-rather-than-guess",
           "ambiguous" in str(e) and "WAYFIRE_SOCKET" in str(e))
    ck("and-an-explicit-one-resolves-the-ambiguity",
       pick_socket([_s, "/run/b.socket"], {"WAYFIRE_SOCKET": _s}) == _s)
    # THE FALLBACK MUST ANNOUNCE ITSELF. Working silently is precisely how the
    # missing discovery hid: everything kept functioning, so nobody fixed the
    # shell. A warning that can be removed without a test failing will be.
    import contextlib
    import io
    _real_env, _real_hunted = dict(os.environ), engine.SOCKET_HUNTED
    _real_warned = engine._HUNT_WARNED
    try:
        engine._HUNT_WARNED = False
        engine.SOCKET_HUNTED = None
        os.environ.pop("WAYFIRE_SOCKET", None)
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            wayfire_socket()
        _said = _err.getvalue()
        # It only warns when it actually HUNTED, which on a box with no
        # compositor socket it will not have done.
        if engine.SOCKET_HUNTED:
            ck("a-hunted-socket-warns-on-stderr",
               "WAYFIRE_SOCKET is unset" in _said
               and engine.SOCKET_HUNTED in _said)
            ck("and-names-the-socket-it-chose", "using " in _said)
            # ONCE per process: a verb that connects repeatedly must not shout
            # repeatedly.
            _err2 = io.StringIO()
            with contextlib.redirect_stderr(_err2):
                wayfire_socket()
            ck("but-only-once-per-process", _err2.getvalue() == "")
        else:
            ck("a-hunted-socket-warns-on-stderr (no socket here: skipped)",
               _said == "")
        # AND IT IS SILENT WHEN THE ENVIRONMENT IS CLEAN, or the warning
        # becomes noise and gets removed.
        engine._HUNT_WARNED = False
        engine.SOCKET_HUNTED = None
        os.environ["WAYFIRE_SOCKET"] = "/run/nowhere.sock"
        _err3 = io.StringIO()
        with contextlib.redirect_stderr(_err3):
            _got = wayfire_socket()
        ck("a-clean-environment-is-silent",
           _err3.getvalue() == "" and _got == "/run/nowhere.sock"
           and engine.SOCKET_HUNTED is None)
    finally:
        os.environ.clear()
        os.environ.update(_real_env)
        engine.SOCKET_HUNTED = _real_hunted
        # Left ARMED rather than restored: this process genuinely has warned
        # now, and a later check that connects would otherwise print the five
        # lines into the suite's output. Honest and quiet.
        engine._HUNT_WARNED = True
        del _real_warned

    from . import cli as _c
    # ENDING THE SESSION MEANS SIGNALLING THE PART OF IT WE OWN. The process
    # map is the REAL chain measured on this box, because the thing that made
    # the first attempt wrong was an assumption about who owns what:
    #
    #   3423     root   greetd
    #    661839  root   greetd --session-worker 13      <- logind's Leader
    #     662787 jello  /bin/sh /usr/local/bin/startwayfire
    #      662894 jello wayfire
    #
    # {pid: (ppid, uid)}; 0 is root, 1000 is us.
    _CHAIN = {1: (0, 0), 3423: (1, 0), 661839: (3423, 0),
              662787: (661839, 1000), 662894: (662787, 1000)}
    ck("the-session-top-is-the-leaders-child-not-the-leader",
       _c.session_tops(_CHAIN, 661839, 1000) == [662787])
    # NOT the compositor, which is BELOW the top: signalling the session command
    # is what runs its own teardown, where killing the compositor skips it.
    ck("and-not-the-compositor-below-it",
       662894 not in _c.session_tops(_CHAIN, 661839, 1000))
    # A MANAGER THAT KEEPS NO ROOT WORKER hands us the leader itself.
    _OURS = {1: (0, 0), 500: (1, 1000), 501: (500, 1000)}
    ck("a-leader-we-own-is-the-top-itself",
       _c.session_tops(_OURS, 500, 1000) == [500])
    # NOTHING OURS AT ALL is a refusal, not a guess: a session belonging to
    # someone else must never be signalled.
    ck("a-session-with-nothing-of-ours-yields-nothing",
       _c.session_tops(_CHAIN, 661839, 4242) == [])
    # TWO SIBLINGS below the handover are both tops, since either could be the
    # session command and neither is below the other.
    _TWO = dict(_CHAIN); _TWO[662999] = (661839, 1000)
    ck("two-siblings-are-both-tops",
       _c.session_tops(_TWO, 661839, 1000) == [662787, 662999])
    # ENDING THE SESSION IS BY ITS LEADER, not by the compositor's name. The
    # parse is pure so it can be driven with real `loginctl list-sessions`
    # output, which is the only way to test it without a session to destroy.
    _AT_GREETER = """    1 1003 manifest-runner -     3296   manager  -    no -
25099  113 _greetd         seat0 1570194 greeter  tty7 yes 1d ago
   13 1000 jello           -     7665   user     -    no  -
    2 1000 jello           -     3294   manager  -    no  -"""
    _LOGGED_IN = _AT_GREETER + """
13537 1000 jello           seat0 846241 user     tty7 yes 1h ago"""
    # AT THE GREETER jello already has TWO sessions and _greetd holds a SEATED
    # one, so "does jello have a session" is true while nobody is logged in.
    ck("no-seated-session-at-the-greeter",
       seated_session("jello", _AT_GREETER) is None)
    ck("the-greeters-own-seated-session-is-not-ours",
       seated_session("_greetd", _AT_GREETER) is None)
    # AND THE LEADER COMES BACK WITH IT, because that is what gets signalled.
    ck("a-seated-login-yields-its-id-and-leader",
       seated_session("jello", _LOGGED_IN) == ("13537", "846241"))
    ck("another-users-login-is-not-ours",
       seated_session("root", _LOGGED_IN) is None)
    # THIS IS WHAT DECIDES WHETHER `cleanly reboot` REFUSES, so it is pinned
    # from both sides. "Cannot reach the compositor" is TWO facts: a session
    # running that we cannot see (refuse, a layout would be lost) and NO
    # session at all (nothing to lose, so refusing only blocks the reboot).
    # Met live 2026-10-02 on a box whose greeter had failed, where usher made
    # itself the reason the machine would not go down.
    ck("no-session-means-nothing-to-lose",
       seated_session("jello", _AT_GREETER) is None)
    ck("a-live-session-is-what-makes-a-refusal-right",
       seated_session("jello", _LOGGED_IN) is not None)
    # AND THE SEATLESS ssh CONNECTION ASKING THE QUESTION IS NOT A SESSION,
    # which is the one that would invert the whole decision: read it as a
    # login and usher refuses to reboot a box that has no session at all.
    ck("the-asking-ssh-connection-is-not-a-session",
       seated_session("jello", "   12 1000 jello  -  7041  user  -  no -")
       is None)
    # THE WHOLE MATRIX, as a pure function, because the cell that was wrong
    # could not be checked while the decision was two `if`s around a
    # `connect()`. A reachable compositor always winds down; unreachable with
    # a session is the refusal this protection exists for; unreachable with NO
    # session has nothing to lose, so blocking the power action protects
    # nothing and only strands the machine.
    for _v in ("reboot", "shutdown", "logoff"):
        ck(f"reachable-{_v}-winds-down",
           _c._leave_plan(_v, True, True) == "wind-down")
        ck(f"unreachable-with-a-session-refuses-{_v}",
           _c._leave_plan(_v, False, True) == "refuse")
    # SEEING NO SESSION IS NOT THE SAME FACT AS THERE BEING NONE, and the
    # capture is the whole job, so the benefit of the doubt goes to the
    # layout. An earlier version of this proceeded here, trading an
    # unrecoverable loss for the convenience of one less word.
    ck("no-session-still-refuses-rather-than-guessing",
       _c._leave_plan("reboot", False, False) == "no-session")
    ck("no-session-shutdown-also-refuses",
       _c._leave_plan("shutdown", False, False) == "no-session")
    # --force IS THE EXPLICIT OVERRIDE, and it works from BOTH refusals: the
    # one where a session was found (you are choosing to lose it) and the one
    # where none was (there should be nothing to lose). Same verb either way.
    ck("force-overrides-the-no-session-refusal",
       _c._leave_plan("reboot", False, False, True) == "forced")
    ck("force-overrides-a-known-session-too",
       _c._leave_plan("reboot", False, True, True) == "forced")
    # AND FORCE NEVER SKIPS A CAPTURE THAT WAS POSSIBLE: reachable always
    # winds down, so --force cannot be used to avoid the thing it exists for.
    ck("force-does-not-skip-a-capture-it-could-have-made",
       _c._leave_plan("reboot", True, True, True) == "wind-down")
    # logoff is the one verb with nothing to do when there is no session, so
    # it needs no force and must NOT fall through to a power action.
    ck("no-session-logoff-does-nothing-and-needs-no-force",
       _c._leave_plan("logoff", False, False) == "nothing"
       and _c._leave_plan("logoff", False, False, True) == "nothing")
    # THE EXIT CONTRACT, which is the half the matrix above says nothing about
    # and the half a CALLER has to match. Asked for by tackup (T1 in
    # `_usher-requests-tackup.md`) after its power menu carried a wrong belief
    # about the control flow for as long as the menu had existed: `reboot` and
    # `shutdown` exec and never return, `logoff` returns, and nothing said so
    # outside this source.
    #
    # THE RULE IS ONE-DIRECTIONAL and that is deliberate: NON-ZERO means usher
    # did NOT hand over, so the caller must act. Zero does NOT prove a
    # handover happened, because a logoff with no session and any --dry-run
    # also exit 0 with nothing to do. Non-zero is the direction a caller
    # needs, and it is the safe one.
    _saved = (engine.connect, engine.do_wind_down,
              _c._no_session_here, _c._end_session, _c._hand_over_power)

    def _leave(verb, reachable, present, force=False, sid=7, dry=False):
        """The REAL _cleanly_leave with only its terminal actions stubbed, so
        the gating, the plan and the return paths are production's own."""
        gone, ended = [], []

        def _no_connect(*a, **k):
            raise RuntimeError("planted: no compositor")

        def _end(dry=False):
            ended.append(dry)
            return (sid, "stub")
        engine.connect = (lambda *a, **k: object()) if reachable \
            else _no_connect
        engine.do_wind_down = lambda: 0
        _c._no_session_here = lambda: not present
        _c._end_session = _end
        # The real one execs and never returns; returning 0 is what a
        # successful exec is indistinguishable from, for a caller.
        _c._hand_over_power = lambda v: (gone.append(v) or 0)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(buf):
                rc = _c._cleanly_leave(verb, dry, force)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
        # OBSERVED, NOT INFERRED, and the first version got this wrong in the
        # one way that matters: it derived the handover from the arguments
        # (`verb == "logoff" and sid is not None`), which calls the
        # nothing-to-do cell a handover and so failed the very check that
        # cell exists for. Ask what the code DID.
        did_end = bool(ended) and sid is not None and not ended[0]
        return rc or 0, bool(gone) or did_end

    try:
        cells = [
            # verb      reach  present force  sid   dry
            ("reboot",   True,  True,  False, 7,    False),
            ("shutdown", True,  True,  False, 7,    False),
            ("logoff",   True,  True,  False, 7,    False),
            ("logoff",   True,  True,  False, None, False),
            ("reboot",   False, True,  False, 7,    False),
            ("logoff",   False, True,  False, 7,    False),
            ("reboot",   False, False, False, 7,    False),
            ("logoff",   False, False, False, 7,    False),
            ("reboot",   False, False, True,  7,    False),
            ("reboot",   False, True,  True,  7,    False),
            ("reboot",   True,  True,  False, 7,    True),
            ("logoff",   True,  True,  False, 7,    True),
        ]
        bad = []
        for _v, _r, _p, _f, _s, _d in cells:
            rc, handed = _leave(_v, _r, _p, _f, _s, _d)
            if rc != 0 and handed:
                bad.append((_v, _r, _p, _f, _s, _d, rc))
        # THE INVARIANT, over every cell at once: nothing may both hand over
        # and report failure, or a caller running its fallback on non-zero
        # would double-fire the terminal action.
        ck("leave-nonzero-never-means-a-handover-happened", not bad)

        # The cells a caller's control flow actually turns on, named one by
        # one because collapsing them is how the wrong one gets missed.
        ck("leave-reachable-reboot-hands-over-and-is-zero",
           _leave("reboot", True, True) == (0, True))
        ck("leave-reachable-logoff-is-zero-when-it-signalled",
           _leave("logoff", True, True) == (0, True))
        # THE GAP A CALLER'S BACKSTOP IS FOR: wound down, capture taken, and
        # no process found to signal. _end_session reports 0 when it
        # SIGNALLED something, not when the session demonstrably ended.
        ck("leave-logoff-with-no-target-is-nonzero-so-the-caller-acts",
           _leave("logoff", True, True, sid=None) == (1, False))
        # A REFUSAL IS `EXIT_CANNOT`, NOT `EXIT_FAIL`, and the difference is
        # the published taxonomy rather than taste: usher could not SEE the
        # session, so nothing was assessed, which the man page names for 2
        # in as many words ("no visible session"). Asserted against the
        # CONSTANTS, so a later change to their values cannot make this
        # check quietly describe something else.
        for _v in ("reboot", "logoff"):
            ck(f"leave-refusal-is-nonzero-and-hands-over-nothing-{_v}",
               _leave(_v, False, True) == (engine.EXIT_CANNOT, False))
        ck("leave-no-session-reboot-is-nonzero-and-hands-over-nothing",
           _leave("reboot", False, False) == (engine.EXIT_CANNOT, False))
        # AND THE TWO NON-ZERO CELLS ARE DIFFERENT CODES, which is the whole
        # point of having two: a logoff that wound down, captured, and found
        # nothing to signal DID the work and the answer is bad (1), where a
        # refusal never looked (2). Collapsing them is how a caller loses
        # the ability to tell "usher is blind" from "usher tried".
        ck("leave-blind-and-tried-are-different-codes",
           _leave("reboot", False, True)[0]
           != _leave("logoff", True, True, sid=None)[0])
        # ...and the one zero WITHOUT a handover, which is why the rule only
        # runs one way: there is nothing to end, so a caller must NOT act.
        ck("leave-no-session-logoff-is-zero-with-nothing-done",
           _leave("logoff", False, False) == (0, False))
        ck("leave-force-hands-over", _leave("reboot", False, False, True)
           == (0, True))
        # A DRY RUN NEVER HANDS OVER AND NEVER REPORTS FAILURE, or `-n` would
        # trip a caller's fallback into doing the real thing.
        ck("leave-dry-run-reboot-is-zero-and-does-nothing",
           _leave("reboot", True, True, dry=True) == (0, False))
        ck("leave-dry-run-logoff-is-zero-and-does-nothing",
           _leave("logoff", True, True, dry=True) == (0, False))
    finally:
        (engine.connect, engine.do_wind_down, _c._no_session_here,
         _c._end_session, _c._hand_over_power) = _saved

    # NO COMPOSITOR NAME IN THE CODE of the leaving path: that is the whole
    # point, and a reappearing `killall <compositor>` is how it would come back.
    #
    # VIA THE AST, over string literals that are NOT docstrings. The first
    # version matched text and stripped ONE known phrase, so the second
    # docstring explaining what `killall wayfire` got wrong failed the check
    # that exists to keep it gone. That is the same way a name-based check turns
    # into noise and then gets switched off; prose must be able to discuss what
    # the code may not do.
    import ast as _ast
    import inspect as _i
    _tree = _ast.parse(_i.getsource(_c))
    _docs = set()
    for _n in _ast.walk(_tree):
        if isinstance(_n, (_ast.Module, _ast.FunctionDef, _ast.ClassDef)):
            _b = getattr(_n, "body", None)
            if (_b and isinstance(_b[0], _ast.Expr)
                    and isinstance(_b[0].value, _ast.Constant)
                    and isinstance(_b[0].value.value, str)):
                _docs.add(id(_b[0].value))
    _lits = [n.value for n in _ast.walk(_tree)
             if isinstance(n, _ast.Constant) and isinstance(n.value, str)
             and id(n) not in _docs]
    ck("the-leaving-path-names-no-compositor",
       not [x for x in _lits if "killall" in x or "wayfire" in x])

    # WHAT THE TWELVE CELLS ABOVE CANNOT SEE: they stub `_end_session`
    # wholesale, which is right (it signals a real session) and leaves the one
    # function on this path that talks to the world untested. It had neither a
    # bound nor a catch while the two other sites asking logind the same
    # question had both, so a missing `loginctl` RAISED out of `cleanly` and a
    # wedged one never returned, which defeats the integrator's
    # `usher cleanly reboot; systemctl reboot` outright: the `;` fallback only
    # runs once usher RETURNS.
    #
    # DRIVEN THROUGH THE STUBBED `engine.loginctl`, which is also the point of
    # routing both through it: the seam that makes them bounded is the seam
    # that makes them checkable.
    _real_lc2 = engine.loginctl
    try:
        engine.loginctl = lambda *a, **k: (None, "")

        def _g(fn):
            """The pre-fix code RAISES, and a raise aborts the area: these are
            the plants that matter most, so each must name its own cell."""
            try:
                return fn()
            except Exception as e:                             # noqa: BLE001
                return f"RAISED {type(e).__name__}"
        _es = _g(lambda: _c._end_session(dry=True))
        _ns = _g(_c._no_session_here)
        ck("end-session-survives-a-loginctl-it-cannot-run",
           _es == (None, "cannot ask logind which session to end"))
        ck("no-session-here-survives-it-too", _ns is False)
        # PAIRWISE, because the whole content of the fix is that ONE value
        # reads in OPPOSITE directions at the two sites: for `_end_session`
        # "cannot ask" is the same fact as a bad answer, and for
        # `_no_session_here` it must NOT be, since its True authorises
        # skipping a capture. Collapsing them is the one way to get this
        # wrong while both cells above still pass individually.
        ck("the-two-read-a-missing-loginctl-in-opposite-directions",
           _ns is False and _es[0] is None)
        engine.loginctl = lambda *a, **k: (1, "")
        ck("a-failing-loginctl-is-not-a-session-to-end",
           _g(lambda: _c._end_session(dry=True))
           == (None, "cannot ask logind which session to end"))
    finally:
        engine.loginctl = _real_lc2

    # AND NO WAITING EXTERNAL COMMAND IS UNBOUNDED, which is the general form
    # of the above and the only thing that can see a FOURTH spelling being
    # added. A hung provider is the same hazard as a regex that backtracks for
    # ever: the system must be protected above any particular provider.
    #
    # POPEN IS EXCLUDED DELIBERATELY, not overlooked: it is fire and forget
    # (a window, a worker, a relaunched app) and a timeout means nothing to a
    # call that never waits. The waiting forms are the ones a stuck bus or a
    # wedged hook can hold for ever.
    #
    # THE FUNC IS WALKED, NOT MATCHED, because `window_source` calls
    # `(subprocess.run if run is None else run)(...)` so the attribute is
    # nested inside the callee rather than being it. A matcher that only
    # looked at `node.func` would report that call as not existing.
    from . import doctor as _dr2
    from . import watch as _wt2
    _WAIT = {"run", "check_output", "call", "check_call", "getoutput"}
    _unbounded, _waiting, _nested = [], 0, 0
    for _mod in (engine, _c, _dr2, _wt2):
        _t2 = _ast.parse(_i.getsource(_mod))
        for _n in _ast.walk(_t2):
            if not isinstance(_n, _ast.Call):
                continue
            _hit = any(isinstance(_s, _ast.Attribute) and _s.attr in _WAIT
                       and isinstance(_s.value, _ast.Name)
                       and _s.value.id == "subprocess"
                       for _s in _ast.walk(_n.func))
            if not _hit:
                continue
            _waiting += 1
            if not (isinstance(_n.func, _ast.Attribute)
                    and _n.func.attr in _WAIT):
                _nested += 1
            if "timeout" not in {k.arg for k in _n.keywords if k.arg}:
                _unbounded.append(f"{_mod.__name__}:{_n.lineno}")
    if _unbounded:                     # named on stderr, since ck takes none
        print(f"selftest: unbounded external commands: {_unbounded}",
              file=sys.stderr)
    ck("every-waiting-external-command-is-bounded", not _unbounded)
    # A VACUITY GUARD CAN ONLY BE SHOWN TO MATTER BY EMPTYING THE THING IT
    # GUARDS, so this is the cell the plant that breaks the scrape hits.
    ck("waiting-external-commands-were-found", _waiting >= 5)
    # AND THE NESTED SHAPE IS REACHED, which the floor above cannot say: a
    # matcher reading `node.func` alone still clears it, because the one call
    # it would miss happens to be bounded TODAY. This is the cell that fails
    # when the walk is narrowed, so a future nested call cannot be invisible.
    ck("the-callee-is-walked-not-matched", _nested >= 1)

    # THE SEAM HANDS THE PROVIDER THE ACTION, and this is the caller's half of
    # that contract. Both halves were written here and never run against each
    # other: usher exec'd `<provider> login` while the provider's parser took no
    # positional, so the one invocation that matters died on "unrecognized
    # arguments: login" and every hand-typed dry run worked. tackup's test now
    # pins the other half.
    #
    # os.execv REPLACES the process, so it is captured rather than called.
    import tempfile as _tf
    _real_exec, _real_seam = os.execv, engine.SESSION_START
    _seen = []
    try:
        with _tf.TemporaryDirectory() as _d:
            _prov = os.path.join(_d, "session-start")
            with open(_prov, "w") as _f:
                _f.write("#!/bin/sh\nexit 0\n")
            os.chmod(_prov, 0o755)
            engine.SESSION_START = _prov
            os.execv = lambda path, argv: _seen.append((path, list(argv)))
            from . import cli as _cli
            _cli.session_start("login")
        ck("the-seam-execs-the-provider-with-the-action",
           _seen == [(_prov, [_prov, "login"])])
    finally:
        os.execv = _real_exec
        engine.SESSION_START = _real_seam
    # A PROVIDER THAT IS NOT EXECUTABLE IS A SILENT NO-OP, the same class as a
    # 0644 hook, so it must be refused rather than run.
    with _tf.TemporaryDirectory() as _d:
        _dud = os.path.join(_d, "session-start")
        open(_dud, "w").close()
        os.chmod(_dud, 0o644)
        _real_seam = engine.SESSION_START
        try:
            engine.SESSION_START = _dud
            from . import cli as _cli
            # BOTH HALVES, because `die_cannot` prints the reason and exits
            # a CODE: `str(SystemExit(2))` is "2", so reading the exception
            # alone would say nothing about whether a human was told. It
            # also means the message lands on stderr the moment it is
            # raised rather than at interpreter exit, so a check that
            # catches the exit has to capture it or the suite prints it.
            _pb = io.StringIO()
            try:
                with contextlib.redirect_stderr(_pb):
                    _cli.session_start("login")
                ck("a-non-executable-provider-is-refused", False)
            except SystemExit as _e:
                ck("a-non-executable-provider-is-refused",
                   _e.code == engine.EXIT_CANNOT)
                ck("a-non-executable-provider-says-why",
                   "not executable" in _pb.getvalue())
        finally:
            engine.SESSION_START = _real_seam

    # TWO DOORS TO THE COMPOSITOR AND NO OTHERS. Five call sites once built a
    # WayfireSocket directly, so they skipped the discovery above and could not
    # reach a compositor the daemon was talking to happily. The guard is a
    # source scan, because the failure is a NEW call site rather than a wrong
    # value, and nothing else can see that.
    #
    # VIA THE AST, NOT A GREP. The first version matched text and flagged two
    # DOCSTRINGS that merely discuss WayfireSocket, which is the usual way a
    # name-based check turns into noise and then gets switched off. ast sees
    # calls only.
    import ast
    import inspect
    from . import chrome as _ch
    from . import doctor as _doc
    from . import watch as _w
    _bad = []
    for _m in (engine, _doc, _w, _ch):
        _tree = ast.parse(inspect.getsource(_m))
        for _node in ast.walk(_tree):
            if not isinstance(_node, ast.FunctionDef):
                continue
            for _sub in ast.walk(_node):
                if (isinstance(_sub, ast.Call)
                        and getattr(_sub.func, "id", None) == "WayfireSocket"
                        and _node.name not in ("ipc", "connect")):
                    _bad.append(f"{_m.__name__}.{_node.name}")
    ck("only-ipc-and-connect-build-a-socket", not _bad)

    # NO MODULE IMPORTS A REBOUND ENGINE GLOBAL BY VALUE, which the package
    # split named as THE one real hazard in splitting this program: the
    # importer gets a SNAPSHOT and goes silently stale at the next reload,
    # with the daemon then running rules a user has edited away. That split
    # left behind an instruction to "grep for `global` before any further
    # split", which is a decision recorded only in prose, and the set has
    # since grown from THREE rebound names to eleven with nothing asking.
    #
    # DERIVED FROM BOTH SIDES, so neither a new rebinding nor a new import
    # can slip past: the rebound set is every name under a `global`
    # statement inside an engine function, and the imports are every
    # `from .engine import` elsewhere in the package.
    _reb = {_nm for _n in ast.walk(ast.parse(inspect.getsource(engine)))
            if isinstance(_n, ast.Global) for _nm in _n.names}
    _byval = []
    for _m in (_doc, _w, _ch, cli, sys.modules[__name__]):
        for _n in ast.walk(ast.parse(inspect.getsource(_m))):
            if (isinstance(_n, ast.ImportFrom)
                    and (_n.module or "").endswith("engine")):
                for _a in _n.names:
                    if _a.name in _reb:
                        _byval.append(f"{_m.__name__}:{_n.lineno} {_a.name}")
    # A VACUITY GUARD, because an AST change or a rename could leave the
    # rebound set EMPTY and the assertion would then pass over nothing. Four
    # is well under the eleven measured, so it reports a collapse and not a
    # normal edit.
    ck("rebound-globals-were-found", len(_reb) >= 4)
    ck("no-module-imports-a-rebound-engine-global-by-value", not _byval)

    # AND THE WIRING, DERIVED FROM THE SOURCE, which is the only thing that
    # stops a seventh instance: a NEW reader is the failure, not a wrong
    # value, and nothing else can see one being added. Every function that
    # calls json.load must either BE json_object or test the type itself.
    _loads = []
    for _m in (engine, cli, _doc, _w):
        _tree = ast.parse(inspect.getsource(_m))
        for _fn in ast.walk(_tree):
            if not isinstance(_fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            _body = ast.get_source_segment(inspect.getsource(_m), _fn) or ""
            if not [n for n in ast.walk(_fn)
                    if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr in ("load", "loads")
                    and getattr(n.func.value, "id", "") == "json"]:
                continue
            _loads.append((_m.__name__, _fn.name,
                           _fn.name == "json_object"
                           or "isinstance" in _body))
    # A VACUITY GUARD FIRST: an AST change that found no call sites would
    # pass the assertion below over an empty list.
    ck("json-readers-were-found", len(_loads) >= 3)
    ck("every-json-reader-establishes-its-shape",
       all(ok for _mod, _fn, ok in _loads))

    # --- EVERY STATEMENT IN A DAEMON THREAD'S LOOP IS GUARDED ------------
    # A thread whose target raises exits THAT THREAD alone. The process
    # lives, the status file may keep ticking, and whatever the thread was
    # for stops dead: for the placer that is NOTHING IS EVER PLACED AGAIN
    # this session, with no line anywhere.
    #
    # MEASURED BY CLASSIFYING EACH LOOP STATEMENT, which is how this was
    # found: the capture thread's `_poll_files`, `_poll_outputs` and
    # `_write_status` all sat OUTSIDE its try, and the placer's
    # `_recheck_all` guards its own `list_views` and its own place loop but
    # not the elimination step between them.
    #
    # THE CHECK IS THE POINT, not the two fixes: a FUTURE statement added
    # outside the guard is the failure mode, and auditing every callee's
    # raise paths by hand is an invariant nobody can hold.
    # IMPORTED HERE: `_wt` is an area-LOCAL import in another function, and
    # using it across the boundary is a NameError this file has recorded
    # twice.
    from . import watch as _wt
    _wsrc = _i.getsource(_wt)
    _wtree = _ast.parse(_wsrc)
    _wfuncs = {n.name: n for n in _ast.walk(_wtree)
               if isinstance(n, _ast.FunctionDef)}
    # the thread TARGETS, derived rather than listed, so a third thread is
    # covered the day it is started
    _tgts = []
    for _n in _ast.walk(_wtree):
        if isinstance(_n, _ast.Call) and getattr(
                _n.func, "id", getattr(_n.func, "attr", "")) == "Thread":
            for _kw in _n.keywords:
                if _kw.arg == "target":
                    _v = _kw.value
                    _tgts.append(getattr(_v, "attr", getattr(_v, "id", "?")))
    _bare = []
    for _tg in _tgts:
        _node = _wfuncs.get(_tg)
        if _node is None:
            _bare.append(f"{_tg}: no such function")
            continue
        for _lp in [s for s in _node.body if isinstance(s, _ast.While)]:
            for _s in _lp.body:
                if isinstance(_s, _ast.Try):
                    continue
                _txt = _ast.unparse(_s)
                # TWO ALLOWED SHAPES, each with its reason. A `sleep` cannot
                # meaningfully raise, and a `with self.lock` block that only
                # reads keys set in __init__ is as close to non-raising as
                # this gets; anything else must be inside the guard.
                if _txt.startswith("time.sleep("):
                    continue
                if (_txt.startswith("with self.lock:")
                        and "self.st[" in _txt and "(" not in
                        _txt.split("self.st[")[1][:20]):
                    continue
                if isinstance(_s, (_ast.Assign, _ast.If)) and not [
                        c for c in _ast.walk(_s)
                        if isinstance(c, _ast.Call)]:
                    continue
                _bare.append(f"{_tg}: {_txt.splitlines()[0][:50]}")
    if _bare:
        print("selftest: statements outside a daemon thread's loop guard: "
              f"{_bare}", file=sys.stderr)
    ck("every-thread-loop-statement-is-guarded", not _bare)
    # A VACUITY GUARD, since an AST change that found no threads would pass
    # the assertion over an empty list.
    ck("the-thread-targets-were-found", len(_tgts) >= 2)

    # THE DESK MUST BE POLLED BY THE LOOP THAT ALWAYS RUNS, not only by the
    # capture step. `_poll_outputs` compares output NAMES, so a desk change
    # that keeps them is invisible to it: same connector, same resolution, a
    # DIFFERENT monitor, which is two docks reached through one port. Nothing
    # moves, so nothing dirties the store, so `_capture_once` is never due and
    # the wrong desk's store stays loaded AND goes on being written. Measured
    # by test/rigs/dock-profile, which saw nothing noticed in 30s.
    #
    # NO SEPARATE VACUITY GUARD, deliberately: a broken scrape yields an
    # empty list and BOTH assertions below fail loudly, so a third would be
    # code no plant could catch.
    _drift_in = sorted(
        f for f, n in _wfuncs.items()
        if [c for c in _ast.walk(n) if isinstance(c, _ast.Call)
            and getattr(c.func, "attr", "") == "_profile_drift"])
    ck("the-desk-is-polled-and-not-only-captured",
       "_capture_loop" in _drift_in)
    # AND THE CAPTURE STEP KEEPS ITS OWN CALL, which is the one that GATES
    # the capture: noticing promptly and suppressing a mid-change capture are
    # two jobs, and losing the second writes the collapse into a store.
    ck("the-capture-step-still-gates-on-the-desk",
       "_capture_once" in _drift_in)
    # AND IT YIELDS TO A TRANSITION, ordered exactly as `_capture_once`
    # orders them, or an arriving monitor is adopted before it is laid out.
    _yields = False
    for _n in _ast.walk(_wfuncs["_capture_loop"]):
        if not isinstance(_n, _ast.If):
            continue
        if "_in_transition" not in _ast.unparse(_n.test):
            continue
        if [c for c in _ast.walk(_n) if isinstance(c, _ast.Call)
                and getattr(c.func, "attr", "") == "_profile_drift"]:
            _yields = True
    ck("the-desk-poll-yields-to-a-transition", _yields)

    # AND THE ESCALATION IS THE CAPTURE STEP'S, not a second policy: log
    # with the streak, and at the limit EXIT so the supervisor does a clean
    # full respawn. A guard that merely continued for ever would trade a
    # dead thread for a silent one.
    _rexit, _rlog = os._exit, _wt.logline
    _said, _exited = [], []
    try:
        os._exit = lambda c: _exited.append(c)
        _wt.logline = lambda s: _said.append(s)
        _w = _wt.Watcher.__new__(_wt.Watcher)
        _w._loop_failed("placer", RuntimeError("planted"), 1)
        ck("a-loop-error-is-logged-with-its-streak",
           any("placer loop error" in s and "streak 1" in s for s in _said))
        ck("a-single-loop-error-does-not-exit", not _exited)
        _w._loop_failed("placer", RuntimeError("planted"),
                        _wt.CAPTURE_FAIL_LIMIT)
        ck("a-sustained-loop-failure-exits-for-respawn", _exited == [1])
        ck("and-it-says-so-before-exiting",
           any("exit for respawn" in s for s in _said))
    finally:
        os._exit, _wt.logline = _rexit, _rlog

    # --- WHO STAMPS A FIELD EVERY DOWNSTREAM READ TRUSTS -----------------
    # Twelve sites read `w.get("source")` bare, and whether that is
    # hand-rolling the question or consuming a single-sourced answer depends
    # on exactly one thing: WHO WRITES IT. One writer makes every read safe
    # by construction; two on the same record type make every read a coin
    # toss, which is the "two sites with a different idea of one fact" family
    # that every silent failure in this package has come from.
    #
    # MEASURED RATHER THAN ASSUMED, and the answer was nuanced: most
    # multi-writer fields are DIFFERENT RECORD TYPES (a snapshot row, a
    # prediction row and a roster row each carry their own `key` and `cmd`),
    # which is fine. The pairs worth naming are the ones on the SAME type.
    #
    # PINNED BY NAME, because the point is that a third writer has to be a
    # DECISION. A new stamper of `owner`, or of a store entry's `panel`, is
    # exactly the defect this cannot be allowed to acquire quietly.
    _STAMPERS = {
        # a live snapshot row's facts: one writer, which is the capture
        "owner": {"snapshot"},
        # a store entry's own: kb_entry stamps it, and surface_seed CLEARS
        # it deliberately, because another desk's panel id names a monitor
        # that may not be attached here and entry_output would fall back to
        # the connector NAME and place the old panel's rect on a new one
        "panel": {"kb_entry", "surface_seed"},
        "surface": {"kb_entry"},
        # snapshot stamps the live fact; kb_entry CARRIES it into the store
        # rather than re-deriving, since a replayed row's pid is long dead
        "source": {"snapshot", "kb_entry"},
    }
    _seen_w = {f: set() for f in _STAMPERS}
    for _mn, _mod in (("engine", engine),):
        _tr = _ast.parse(_i.getsource(_mod))
        _ow = {}
        for _n in _ast.walk(_tr):
            if isinstance(_n, _ast.FunctionDef):
                for _s in _ast.walk(_n):
                    if hasattr(_s, "lineno"):
                        _ow.setdefault(_s.lineno, _n.name)
        for _n in _ast.walk(_tr):
            if isinstance(_n, _ast.Dict):
                for _k in _n.keys:
                    if (isinstance(_k, _ast.Constant)
                            and _k.value in _seen_w):
                        _seen_w[_k.value].add(_ow.get(_n.lineno, "<module>"))
            if isinstance(_n, _ast.Assign):
                for _tg in _n.targets:
                    if (isinstance(_tg, _ast.Subscript)
                            and isinstance(_tg.slice, _ast.Constant)
                            and _tg.slice.value in _seen_w):
                        _seen_w[_tg.slice.value].add(
                            _ow.get(_n.lineno, "<module>"))
    for _f, _want in sorted(_STAMPERS.items()):
        if _seen_w[_f] != _want:
            print(f"selftest: `{_f}` is stamped by {sorted(_seen_w[_f])}, "
                  f"not {sorted(_want)}", file=sys.stderr)
        ck(f"only-the-named-writers-stamp-{_f}", _seen_w[_f] == _want)
    # A VACUITY GUARD, because an AST change that matched nothing would pass
    # all four assertions over four empty sets.
    ck("the-field-stampers-were-found",
       all(_seen_w[_f] for _f in _STAMPERS))

    # THE CONFIG DIR. One place, named for the command, and every config name
    # resolves under it. The per-file fallback to the pre-rename directory is
    # gone: both machines are migrated, so it could only ever resurrect a stale
    # file someone restored by accident.
    ck("the-config-dir-is-named-for-the-command",
       os.path.basename(CONFIG_DIR) == "usher")
    for _n in ("exclude", "include", "plugins", "session-start"):
        ck(f"config-{_n}-sits-in-the-config-dir",
           config_path(_n) == os.path.join(CONFIG_DIR, _n))
    ck("the-state-dir-is-named-for-the-command",
       os.path.basename(engine.STATE) == "usher")
    # AND NOTHING READS THE OLD LOCATIONS ANY MORE, which is the assertion that
    # keeps a fallback from creeping back in under a different name.
    ck("no-path-points-at-the-pre-rename-dirs",
       not any(p.endswith("/session") or "/session/" in p
               or p.endswith("session-layout")
               for p in (CONFIG_DIR, engine.STATE, EXCLUDE_FILE, INCLUDE_FILE,
                         PLUGIN_DIR)))

def _t_relaunch(ck):
    """the relaunch paths, RUN with the spawn stubbed."""
    # RUN the relaunch paths end to end with the spawn stubbed. Checking
    # mux_candidates alone is not enough: a NameError in the announce after the
    # spawn shipped undetected precisely because nothing executed these
    # functions, only the pure helper inside them.
    import io
    import contextlib
    _real = (engine.spawn_term, engine._spawn_kitty, engine.logline)
    _spawned, _logged = [], []
    try:
        # RETURNS TRUE, because spawn_term's contract is now "did it
        # actually start": it REFUSES a recorded command whose program is
        # gone, and the caller must not count or announce a refusal. A stub
        # returning None reads as a refusal, which is what caught this.
        def _st_ok(*a, **k):
            _spawned.append(("mux", a))
            return True

        engine.spawn_term = _st_ok
        engine._spawn_kitty = lambda *a, **k: _spawned.append(("kitty",
                                                                     a))
        # CAPTURE THE LOG instead of writing it. _announce appends to the REAL
        # $STATE/watch.log, so every `./test/run` used to add three fixture
        # rows to the one file that records what usher did to a LIVE session,
        # indistinguishable from real relaunches to anyone reading it later.
        # Capturing loses no coverage (_announce is still CALLED, which is
        # the whole point of running these paths) and lets us assert what it
        # said, which the old version did not.
        engine.logline = _logged.append
        with contextlib.redirect_stdout(io.StringIO()):
            n_mux = mux_relaunch_missing([_tmw(), _tmw(cmd="L latch box")], [])
            n_kit = kitty_relaunch_missing(
                [{"app_id": "kitty", "key": "kitty:/tmp", "title": ""}], [])
        # THE RETURN NAMES THE APP, and the per-window count lives in
        # the spawn tally below. mux reopened TWO terminals and both are
        # kitty windows, so one app-id is the honest answer: the unit of
        # this contract is "which apps did you start", which is the only
        # question the registry default can act on.
        ck("relaunch-mux-runs", n_mux == {"kitty"})
        ck("relaunch-kitty-runs", n_kit == {"kitty"})
        ck("relaunch-spawned", len(_spawned) == 3)
        ck("relaunch-announced",
           len(_logged) == 3 and all(m.startswith("launch") for m in _logged))
    finally:
        (engine.spawn_term, engine._spawn_kitty,
         engine.logline) = _real

    # A RECORDED COMMAND WHOSE PROGRAM IS GONE IS REFUSED, LOUDLY. This is the
    # general form of "usher resume stopped working when mux moved install
    # mode": usher tracks where a window WAS and did not notice that the
    # command to recreate it had been replaced. Unrefused, kitty starts,
    # `ksh -c` finds nothing, the window closes, and watch.log says `launch`.
    #
    # THE REAL spawn_term, not a stub: it returns before Popen, so nothing is
    # spawned and the refusal itself is what is under test.
    _rl2 = engine.logline
    _said2 = []
    try:
        engine.logline = _said2.append
        ck("spawn-term-refuses-a-missing-program",
           engine.spawn_term("/nonexistent/bin/mux resume") is False)
        ck("spawn-term-says-which-program-is-missing",
           any("/nonexistent/bin/mux" in m and "not on PATH" in m
               for m in _said2))
        # AND A PROGRAM THAT DOES EXIST IS NOT REFUSED, or the check above
        # would pass against a function that refuses everything. Asserted
        # WITHOUT SPAWNING by stopping at the Popen seam.
        _rp = engine.subprocess.Popen
        try:
            engine.subprocess.Popen = lambda *a, **k: None
            ck("spawn-term-accepts-a-program-that-exists",
               engine.spawn_term("/bin/sh -c true") is True)
        finally:
            engine.subprocess.Popen = _rp
    finally:
        engine.logline = _rl2

    # AND THE CALLER MUST NOT COUNT OR ANNOUNCE A REFUSAL, which is the half
    # that keeps watch.log honest: `launch <cmd>` is the line a reader trusts
    # to mean a window was opened.
    _rst, _ran2 = engine.spawn_term, engine._announce
    _ann = []
    try:
        engine.spawn_term = lambda *a, **k: False
        engine._announce = _ann.append
        ck("relaunch-does-not-count-a-refused-spawn",
           engine.mux_relaunch_missing(
               [_tmw()], []) == set() and not _ann)
    finally:
        engine.spawn_term, engine._announce = _rst, _ran2

    # STEP 3: ANOTHER ACCOUNT IS ASKED TO ACT, and is handed NO CONTENT.
    #
    # THE PLAN IS PURE, so the decision is checkable with no hook, no
    # compositor and no second account.
    _sv = [{"app_id": "slack", "source": "titan"},
           {"app_id": "google-chrome", "source": "titan"},
           {"app_id": "signal"}]
    ck("source-plan-names-the-sources-present",
       engine.source_trigger_plan(_sv) == ["titan"])
    ck("source-plan-ignores-the-owners-own-windows",
       engine.source_trigger_plan([{"app_id": "signal"}]) == [])
    ck("source-plan-is-one-entry-per-source-not-per-window",
       engine.source_trigger_plan(_sv + [{"app_id": "x", "source": "titan"},
                                         {"app_id": "y", "source": "other"}])
       == ["other", "titan"])

    # AND THE HOOK IS HANDED A SOURCE AND AN ACTION, NOTHING ELSE. This is the
    # whole security content of the seam and it was the SECOND design: the
    # first handed over app-ids, which is an escalation, because a recognised
    # terminal app-id resolves to a terminal on the far side and the owner
    # would then have arbitrary code running as the other account.
    _asked_sr = []

    def _sr_ok(argv, **_k):
        _asked_sr.append(argv)

        class R:
            returncode = 0
            stderr = ""
            stdout = "recorded 2 app(s) for this account: a b"
        return R()

    _rsrh, _rl3 = engine.SOURCE_TRIGGER_HOOK, engine.logline
    _said3 = []
    _hd3 = tempfile.mkdtemp(prefix="usher-sr-", dir="/var/tmp")
    try:
        engine.logline = _said3.append
        _hk = os.path.join(_hd3, "source-trigger")
        with open(_hk, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(_hk, 0o755)
        _ra = engine._announce
        engine._announce = lambda *a, **k: None
        try:
            _n_sr = engine.source_trigger(["titan"], "resume", run=_sr_ok,
                                          hook=_hk)
            ck("source-trigger-asks-once-per-source", len(_asked_sr) == 1)
            ck("source-trigger-passes-the-source-and-the-action",
               _asked_sr == [[_hk, "titan", "resume"]])
            ck("source-trigger-counts-what-accepted", _n_sr == 1)
            # THE FAR SIDE'S OWN WORDS REACH THIS LOG, which is the only
            # record the session user can read: the enclave writes its own
            # watch.log inside a home this user cannot open, so a bare
            # "asked titan to resume" is indistinguishable from a resume
            # that found no roster or refused every app.
            ck("source-trigger-relays-what-the-far-side-said",
               any("recorded 2 app(s)" in m for m in _said3))
            ck("source-trigger-names-the-source-and-action-on-the-relay",
               any(m.strip().startswith("titan resume:") for m in _said3))
            # A FOUR-APP RESUME IS EIGHT LINES, and a cap of four relayed the
            # first two apps: the log then read as two launches while four
            # windows came back. The roster bounds stdout, so the cap has to
            # be above anything a real one can say.
            _said4 = []
            engine.logline = _said4.append
            _apps4 = ["app%d" % i for i in range(4)]
            _rep4 = "\n".join("launch %s\nvia session: started" % a
                              for a in _apps4)

            def _sr_many(argv, **_k):
                class R:
                    returncode = 0
                    stderr = ""
                    stdout = _rep4
                return R()

            engine.source_trigger(["titan"], "resume", run=_sr_many, hook=_hk)
            ck("source-trigger-relays-every-app-of-a-real-roster",
               all(any(a in m for m in _said4) for a in _apps4))
            ck("source-trigger-relays-no-truncation-note-when-it-fits",
               not any("more line(s)" in m for m in _said4))
            # AND SAYS SO WHEN IT DOES TRUNCATE, because a report cut off
            # without a word is the fault above wearing a bigger number.
            _said5 = []
            engine.logline = _said5.append
            _over = engine.SOURCE_RELAY_LINES + 3

            def _sr_flood(argv, **_k):
                class R:
                    returncode = 0
                    stderr = ""
                    stdout = "\n".join("line %d" % i for i in range(_over))
                return R()

            engine.source_trigger(["titan"], "resume", run=_sr_flood,
                                  hook=_hk)
            ck("source-trigger-caps-a-flood",
               sum(1 for m in _said5 if "line " in m)
               == engine.SOURCE_RELAY_LINES)
            ck("source-trigger-says-how-much-it-dropped",
               any("and 3 more line(s)" in m for m in _said5))
            engine.logline = _said3.append
            # EXACTLY THREE WORDS, and the argv length is the check rather
            # than a scan of its contents: a scan can be satisfied by content
            # that merely looks harmless, where a fixed arity cannot carry a
            # list of anything.
            ck("source-trigger-hands-over-no-content",
               len(_asked_sr[0]) == 3
               and _asked_sr[0][2] in engine.SOURCE_ACTIONS)

            # ---- WHICH WINDOW IS WHICH, across the boundary ----------------
            # Several windows of one app share one key on the owner's side,
            # because the handle lives in the app's own state inside a home
            # the owner may not read. The source reports a DIGEST of each
            # live title plus an opaque id, and the owner hashes the title it
            # already reads off the compositor. Nothing readable crosses.
            _T1 = "Quarterly Revenue Plan - Google Chrome"
            _T2 = "Offer Letter - Google Chrome"
            _TL1 = "aaaa1111bbbb22"
            _TL2 = "cccc3333dddd44"
            # EVERY ROW CARRIES THE COMPOSITOR'S IDENTIFIER, which is the
            # join key now. A row WITHOUT one is skipped, and that has its
            # own check below: a source that cannot name which window it is
            # looking at must report nothing rather than guess.
            _rows_w = [
                {"app_id": "google-chrome", "title": _T1,
                 "identifier": _TL1},
                {"app_id": "google-chrome", "title": _T2,
                 "identifier": _TL2},
                {"app_id": "kitty", "title": _T1,     # same title, not chrome
                 "identifier": "eeee5555ffff66"},
                {"app_id": "google-chrome", "title": "",
                 "identifier": "1111aaaa2222bb"},
                {"app_id": "google-chrome", "title": "Unrecorded - Google "
                                                     "Chrome",
                 "identifier": "3333cccc4444dd"},
                {"app_id": "google-chrome", "title": _T1},   # NO identifier
            ]
            _ids_w = {_T1: "chrome:win:11", _T2: "chrome:win:22"}
            # THE SEAM IS `_single_id` NOW, which takes a VIEW rather than a
            # title: that is what makes this generic, since a terminal's
            # identity is its cwd or its mux command and neither is in any
            # window protocol. The stub stands in for it and keeps the app
            # gate, which in production is structural (a plugin is only ever
            # asked about windows it owns).
            def _res_w(v):
                if v.get("app-id") != "google-chrome":
                    return None
                return _ids_w.get(v.get("title") or "")

            _lines_w = engine.source_window_lines(_rows_w, resolve=_res_w)
            ck("source-window-reports-one-line-per-resolved-window",
               len(_lines_w) == 2)
            # A ROW WITH NO IDENTIFIER IS SKIPPED, not guessed at: the last
            # fixture row is resolvable and nameless, so without this the
            # count above would be three.
            ck("source-window-skips-a-row-with-no-join-key",
               len(_lines_w) == 2)
            ck("source-window-line-is-three-words",
               all(len(ln.split()) == 3
                   and ln.split()[0] == engine.SOURCE_WINDOW_WORD
                   for ln in _lines_w))
            # THE PRIVACY PROPERTY, and it gets its own check because it is
            # the whole reason this shape was chosen over shipping titles: a
            # readable title must never appear in anything that crosses, and
            # the relay LOGS what crosses into the owner's watch.log.
            ck("source-window-discloses-no-title",
               not any(w in " ".join(_lines_w)
                       for w in ("Quarterly", "Revenue", "Offer", "Letter")))
            # AND THE APP GATE IS LOAD-BEARING: the resolver joins against
            # ONE app's recorded state, so a terminal wearing a browser's
            # title must not be handed to it. A coincidence here is a wrong
            # slot that sticks for the life of the view.
            ck("source-window-skips-an-app-the-resolver-does-not-own",
               len([ln for ln in _lines_w
                    if engine.identity_digest("chrome:win:11") in ln]) == 1)
            ck("source-window-skips-what-it-cannot-resolve",
               not any("Unrecorded" in ln for ln in _lines_w))
            # THE PARSE IS LENIENT, because this shares a channel with prose.
            # GUARDED, so a parser that RAISES on a short line is reported by
            # name here rather than aborting whichever area happens to reach
            # it first: `len(parts) == 3` is both the shape filter and the
            # index bound, and the two are left fused deliberately.
            _parsed_w, _mal_w = {}, None
            try:
                _parsed_w = engine.parse_source_windows(
                    "usher: recorded 2 app(s) for this account: a b\n"
                    + "\n".join(_lines_w)
                    + "\nwindow not-three\nvia session: started in its own\n")
            except Exception as _e_w:                      # noqa: BLE001
                _mal_w = _e_w
            ck("source-window-parse-survives-a-malformed-line",
               _mal_w is None)
            ck("source-window-parse-keeps-only-the-shape",
               _parsed_w == {_TL1: engine.identity_digest("chrome:win:11"),
                             _TL2: engine.identity_digest("chrome:win:22")})
            ck("source-window-parse-ignores-prose-on-the-same-channel",
               len(_parsed_w) == 2)
            # ---- THE MAP IS PUBLISHED, so a one-shot verb can see ------
            # THE MEASURED GAP: the map is per PROCESS and filled only by a
            # trigger, so `restore`, `restore --dry-run`, `predict` and
            # `verify` all read another account's windows as the source
            # ALONE. On manifold 2026-11-06, with eleven per-window slots in
            # the store, a blind verb matched ZERO of them.
            _sdir2 = tempfile.mkdtemp(prefix="usher-pub-", dir="/var/tmp")
            _sf = os.path.join(_sdir2, "usher.sources")
            _r_sfile, _r_adopt = engine.SOURCES_FILE, engine._SOURCES_ADOPTED
            try:
                engine.SOURCES_FILE = _sf
                engine._SOURCE_WINDOWS.clear()
                engine._SOURCE_SLOT.clear()
                engine._SOURCES_ADOPTED = False
                ck("publishing-nothing-writes-an-empty-map",
                   engine.publish_sources() is True
                   and engine.load_published_sources() == {})
                engine.set_source_windows("titan", {
                    _TL1: engine.identity_digest("chrome:win:11")})
                ck("the-daemon-publishes-what-it-knows",
                   engine.publish_sources() is True
                   and engine.load_published_sources() == {"titan": {
                       _TL1: engine.identity_digest("chrome:win:11")}})
                # CONTENT-COMPARED, so a poll that changed nothing neither
                # rewrites the file nor moves the mtime a reader would have
                # to reason about.
                ck("publishing-the-same-map-twice-writes-nothing",
                   engine.publish_sources() is False)
                # AND AN EMPTY MAP NEVER OVERWRITES A KNOWN ONE. Found by
                # DEPLOYING the publish: a reload's first capture runs before
                # the refresh, so the map is empty, and that poll's publish
                # wrote `{}` over a good file. Live on manifold, `published
                # the per-window map for 0 source(s)`.
                engine._SOURCE_WINDOWS.clear()
                ck("an-empty-map-does-not-overwrite-a-known-one",
                   engine.publish_sources() is False
                   and engine.load_published_sources() == {"titan": {
                       _TL1: engine.identity_digest("chrome:win:11")}})
                # ...AND IT IS NOT A BLANKET REFUSAL TO WRITE NOTHING: with
                # no file, or one already empty, publishing nothing is right.
                os.remove(_sf)
                ck("an-empty-map-is-published-when-there-is-no-file",
                   engine.publish_sources() is True
                   and engine.load_published_sources() == {})
                engine.set_source_windows("titan", {
                    _TL1: engine.identity_digest("chrome:win:11")})
                engine.publish_sources()
                # AND A VERB ADOPTS IT, which is the half that closes the
                # gap: an EMPTY process map plus the file resolves the window
                # per window, where before it answered the source alone.
                engine._SOURCE_WINDOWS.clear()
                engine._SOURCE_SLOT.clear()
                engine._SOURCES_ADOPTED = False
                _pv_q = dict(_trv("google-chrome", "Anything At All",
                                  pid=os.getpid(), vid=909, tlid=_TL1),
                             **{"source": "titan"})
                ck("a-verb-with-an-empty-map-adopts-the-published-one",
                   engine.resolution(_pv_q).key
                   == "titan:" + engine.identity_digest("chrome:win:11"))
                # ONCE, because resolution runs on every event and the answer
                # only changes when the daemon publishes.
                # ONCE MEANS ONE FILE READ, and that is what the check has
                # to count: asserting the RETURN is 0 passes with the guard
                # removed too, because the second read finds the source
                # already known and skips it. `resolution` runs on every
                # window event, so the guard is a read per event.
                _reads = []
                _rlps = engine.load_published_sources
                try:
                    engine.load_published_sources = (
                        lambda *a, **k: _reads.append(1) or {})
                    engine.adopt_published_sources()
                    engine.adopt_published_sources()
                    engine.resolution(_pv_q)
                finally:
                    engine.load_published_sources = _rlps
                ck("the-published-map-is-read-once-per-process",
                   _reads == [])
                engine._SOURCES_ADOPTED = False
                _reads.clear()
                try:
                    engine.load_published_sources = (
                        lambda *a, **k: _reads.append(1) or {})
                    engine.adopt_published_sources()
                    engine.adopt_published_sources()
                finally:
                    engine.load_published_sources = _rlps
                ck("a-reset-process-reads-the-published-map-exactly-once",
                   _reads == [1])
                # A LIVE TRIGGER BEATS THE FILE, or a reload would be stuck
                # with whatever was published however stale.
                engine._SOURCES_ADOPTED = False
                engine.set_source_windows("titan", {_TL2: "0" * 16})
                ck("a-known-source-is-not-overwritten-by-the-file",
                   engine.adopt_published_sources() == 0
                   and engine._SOURCE_WINDOWS["titan"] == {_TL2: "0" * 16})
                # AND THE OPACITY IS STILL OURS: a hand-edited file must not
                # be able to put a READABLE identity into a store key, which
                # is the whole reason the digest exists.
                with open(_sf, "w") as _f:
                    _f.write(json.dumps({
                        "titan": {_TL1: "chrome:win:11",
                                  "not-hex": "a" * 16,
                                  _TL2: engine.identity_digest("x")}}))
                ck("the-published-map-is-validated-on-the-way-in",
                   engine.load_published_sources()
                   == {"titan": {_TL2: engine.identity_digest("x")}})
                for _bad in ("[]", "{\"titan\": 7}", "not json"):
                    with open(_sf, "w") as _f:
                        _f.write(_bad)
                    ck("a-malformed-published-map-is-simply-no-map-%s"
                       % _bad[:6],
                       engine.load_published_sources() == {})
                os.remove(_sf)
                ck("a-missing-published-map-is-simply-no-map",
                   engine.load_published_sources() == {})
            finally:
                engine.SOURCES_FILE = _r_sfile
                engine._SOURCES_ADOPTED = _r_adopt
                engine._SOURCE_WINDOWS.clear()
                engine._SOURCE_SLOT.clear()
                engine.set_source_windows(
                    "titan", _parsed_w)
                shutil.rmtree(_sdir2, ignore_errors=True)

            # THE TITLE IS NOT CONSULTED, asserted BEHAVIOURALLY in both
            # directions rather than by reading the code, because that is
            # the whole claim of this protocol and the one a reader will
            # doubt. The previous version hashed the live title on both
            # sides, so a title collision was a shared key and a title drift
            # was a lost join; neither is reachable now.
            engine._SOURCE_WINDOWS.clear()
            engine._SOURCE_SLOT.clear()
            engine.set_source_windows("titan", {
                _TL1: engine.identity_digest("chrome:win:11"),
                _TL2: engine.identity_digest("chrome:win:22")})
            _SAME = "Inbox - Google Chrome"
            ck("two-windows-wearing-ONE-title-get-different-identities",
               engine.source_window_identity(
                   "titan", {"title": _SAME, "id": 401}, _TL1)
               != engine.source_window_identity(
                   "titan", {"title": _SAME, "id": 402}, _TL2))
            ck("one-window-under-TWO-titles-gets-one-identity",
               engine.source_window_identity(
                   "titan", {"title": "Before", "id": 403}, _TL1)
               == engine.source_window_identity(
                   "titan", {"title": "After", "id": 404}, _TL1))
            engine._SOURCE_WINDOWS.clear()
            engine._SOURCE_SLOT.clear()

            # THE DIGEST NO LONGER CARRIES THE JOIN, so what it owes is
            # only opacity and distinctness: the compositor's identifier is
            # what both sides agree on, which is why these assert the hash
            # and not any agreement between the two ends.
            ck("digest-is-stable",
               engine.identity_digest("term:resume")
               == engine.identity_digest("term:resume"))
            ck("digest-separates-two-identities",
               engine.identity_digest("term:resume")
               != engine.identity_digest("term:latch h:s"))
            ck("digest-is-fixed-width",
               len(engine.identity_digest("x")) == engine.DIGEST_LEN
               and len(engine.identity_digest("")) == engine.DIGEST_LEN)
            # AND IT HIDES THE THING IT IS HASHING, asserted rather than
            # assumed: a mux latch identity names a work host and session.
            ck("digest-hides-a-readable-identity",
               "somehost" not in
               engine.identity_digest("term:latch somehost:plan"))
            # THE JOIN RATE IS REPORTED, NOT ASSUMED. The two ends read the
            # identifier independently through two different protocols, so
            # whether they agree is a measurement; 0 of N must read
            # differently from no windows. `_v2` carries an identifier the
            # account never reported, which is the honest miss: a window it
            # could not name, rather than one it named differently.
            _v1 = {"app-id": "google-chrome", "title": _T1,
                   "source": "titan", "pid": -1,
                   "security-context": {"toplevel-identifier": _TL1}}
            _v2 = {"app-id": "google-chrome", "title": "Drifted - Google "
                                                       "Chrome",
                   "source": "titan", "pid": -1,
                   "security-context": {
                       "toplevel-identifier": "9999eeee8888dd"}}
            _rep_w = engine.source_window_report([_v1, _v2],
                                                 {"titan": _parsed_w})
            ck("source-window-report-counts-the-join",
               _rep_w == ["titan: 1 of 2 window(s) identified "
                          "(2 reported)"])
            ck("source-window-report-says-zero-of-n-rather-than-nothing",
               engine.source_window_report([_v2], {"titan": _parsed_w})
               == ["titan: 0 of 1 window(s) identified (2 reported)"])
            ck("source-window-report-is-empty-with-no-sources",
               engine.source_window_report([_v1, _v2], {}) == [])
            # AND THE TRIGGER COLLECTS IT, which the resolver's own checks say
            # nothing about: a caller that never passes `windows` gets the
            # old behaviour and one that does must be filled in.
            _got_w = {}

            def _sr_win(argv, **_k):
                class R:
                    returncode = 0
                    stderr = ""
                    stdout = "usher: recorded 1 app(s)\n" + "\n".join(
                        _lines_w)
                return R()

            engine.source_trigger(["titan"], "capture", run=_sr_win,
                                  hook=_hk, windows=_got_w)
            ck("source-trigger-collects-the-window-map",
               _got_w.get("titan") == _parsed_w)
            # AND IT FILLS THE CACHE `resolution` READS, which the resolver's
            # own checks say nothing about: a planted trigger that collected
            # for its caller and recorded nothing passed the ENTIRE suite,
            # while in production the daemon would never learn a single
            # identity and every window would keep the source-alone key.
            # ASSERTED THROUGH THE CONSUMER rather than by reading the dict,
            # because comparing the cache to what was parsed would pass just
            # as happily if something else had filled it.
            engine._SOURCE_WINDOWS.clear()
            engine._SOURCE_SLOT.clear()
            ck("the-cache-starts-empty-so-the-next-check-is-not-vacuous",
               engine.source_window_identity(
                   "titan", {"title": _T1, "id": 301}, _TL1) is None)
            engine.source_trigger(["titan"], "capture", run=_sr_win,
                                  hook=_hk)
            ck("source-trigger-fills-the-cache-resolution-reads",
               engine.source_window_identity(
                   "titan", {"title": _T1, "id": 302}, _TL1)
               == engine.identity_digest("chrome:win:11"))
            engine._SOURCE_WINDOWS.clear()
            engine._SOURCE_SLOT.clear()
            ck("source-trigger-without-the-out-param-still-works",
               engine.source_trigger(["titan"], "capture", run=_sr_win,
                                     hook=_hk) == 1)
            # AN ACTION OUTSIDE THE CLOSED SET IS A PROGRAMMING ERROR, not
            # something to pass through: the far side validates nothing, so
            # this side is where it has to stop.
            ck("source-trigger-refuses-an-unknown-action", _raises(
                ValueError,
                lambda: engine.source_trigger(["titan"], "rm", run=_sr_ok,
                                              hook=_hk)))
            ck("source-trigger-capture-is-a-known-action",
               engine.source_trigger(["titan"], "capture", run=_sr_ok,
                                     hook=_hk) == 1
               and _asked_sr[-1] == [_hk, "titan", "capture"])

            # ---- THE PID RELAY ------------------------------------------
            # THE ONE FACT THE ACCOUNT CANNOT HAVE. Its only window protocol
            # carries no pid, so it cannot map one of its OWN toplevels to
            # one of its OWN processes, and a terminal's identity (a cwd, a
            # mux command) lives nowhere else.
            _pv_a = dict(_trv("kitty", "x", pid=4242, vid=11, tlid=_TL1),
                         **{"source": "titan"})
            _pv_b = dict(_trv("kitty", "y", pid=4243, vid=12, tlid=_TL2),
                         **{"source": "other"})
            _pv_c = _trv("kitty", "mine", pid=4244, vid=13)   # the OWNER's
            _pv_d = dict(_trv("kitty", "z", pid=0, vid=14, tlid="99aabbccdd11"),
                         **{"source": "titan"})               # no usable pid
            _pv_e = dict(_trv("kitty", "w", pid=4245, vid=15),
                         **{"source": "titan"})                # no identifier
            _pl = engine.source_pid_lines(
                [_pv_a, _pv_b, _pv_c, _pv_d, _pv_e], "titan")
            ck("source-pid-lines-name-this-sources-windows-only",
               _pl == ["pid %s 4242" % _TL1])
            ck("source-pid-line-is-three-words",
               all(len(ln.split()) == 3
                   and ln.split()[0] == engine.SOURCE_PID_WORD
                   for ln in _pl))
            # A SNAPSHOT ROW IS THE OTHER SHAPE, and it is the one the DAEMON
            # has: the refresh runs off a snapshot rather than a live view
            # list, so reading only `security-context` would make the relay
            # work at logoff and never during a session.
            ck("source-pid-lines-read-a-snapshot-rows-identifier",
               engine.source_pid_lines(
                   [{"app_id": "kitty", "title": "x", "pid": 4242,
                     "source": "titan", "identifier": _TL1}], "titan")
               == ["pid %s 4242" % _TL1])
            # ARRIVAL IS VALIDATED IN THIS DIRECTION TOO, because these pids
            # are about to be used to read /proc.
            ck("parse-source-pids-keeps-the-shape",
               engine.parse_source_pids(
                   "usher: prose\npid %s 4242\npid %s 7\n" % (_TL1, _TL2))
               == {_TL1: 4242, _TL2: 7})
            ck("parse-source-pids-refuses-a-non-numeric-pid",
               engine.parse_source_pids("pid %s notanumber" % _TL1) == {})
            ck("parse-source-pids-refuses-a-non-positive-pid",
               engine.parse_source_pids("pid %s 0" % _TL1) == {}
               and engine.parse_source_pids("pid %s -3" % _TL1) == {})
            ck("parse-source-pids-refuses-a-junk-identifier",
               engine.parse_source_pids("pid not-hex 4242") == {})
            ck("parse-source-pids-ignores-prose-on-the-same-channel",
               engine.parse_source_pids(
                   "placed kitty eDP-1 | [titan]\n"
                   "pid line too long here") == {})
            # IS IT OURS. A proxy or a pid namespace between the app and the
            # compositor turns every relayed pid foreign, and the account
            # must refuse loudly rather than read somebody else's process.
            ck("own-pid-says-yes-to-our-own-process",
               engine.own_pid(os.getpid()))
            ck("own-pid-says-no-to-root",
               engine.own_pid(os.getpid(), uid=os.geteuid() + 1) is False)
            ck("own-pid-says-no-to-a-dead-pid",
               engine.own_pid(4000000) is False)
            # AND THE REPORTER REFUSES A PID THAT IS NOT OURS, which is what
            # makes the check above load-bearing rather than decorative.
            _seen_res = []

            def _res_pid(v):
                _seen_res.append(v.get("pid"))
                return "kitty:/home/x"

            _rows_p = [{"app_id": "kitty", "title": "t",
                        "identifier": _TL1}]
            ck("source-window-lines-resolve-a-pid-that-is-ours",
               len(engine.source_window_lines(
                   _rows_p, {_TL1: os.getpid()}, resolve=_res_pid)) == 1)
            _seen_res.clear()
            ck("source-window-lines-refuse-a-pid-that-is-not-ours",
               engine.source_window_lines(
                   _rows_p, {_TL1: os.getpid()}, resolve=_res_pid,
                   uid=os.geteuid() + 1) == []
               and not _seen_res)
            # AND THE PID REACHES THE RESOLVER, or every /proc-derived
            # identity is computed against -1 and the whole relay is inert
            # while every check above still passes.
            _seen_res.clear()
            engine.source_window_lines(_rows_p, {_TL1: os.getpid()},
                                       resolve=_res_pid)
            ck("source-window-lines-hand-the-relayed-pid-to-the-resolver",
               _seen_res == [os.getpid()])
            # THE DEFAULT SEAM IS THE REAL DISPATCH, which is what makes this
            # generic: an app NO plugin owns reports nothing, because one
            # window of it is already fully keyed by app-id plus the account
            # name and a title-derived part would move with the title.
            ck("source-window-lines-report-nothing-for-an-unowned-app",
               engine.source_window_lines(
                   [{"app_id": "spotify", "title": "Some Song",
                     "identifier": _TL1}]) == [])
            # AND THE TRIGGER SENDS THEM ON STDIN, not in the argv: the
            # arity is exactly three words, which is what lets the
            # integrator's sudoers rule name a FIXED command with no
            # wildcard, and a wildcard there is execution as the account.
            _sent_in = []

            def _sr_in(argv, **kw):
                _sent_in.append((list(argv), kw.get("input")))

                class R:
                    returncode = 0
                    stderr = ""
                    stdout = ""
                return R()

            engine.source_trigger(["titan"], "capture", run=_sr_in,
                                  hook=_hk, views=[_pv_a, _pv_b])
            ck("source-trigger-sends-the-pids-on-stdin",
               _sent_in[-1][1] == "pid %s 4242\n" % _TL1)
            ck("source-trigger-keeps-the-argv-at-three-words",
               _sent_in[-1][0] == [_hk, "titan", "capture"])
            # A CLOSED STDIN EVEN WITH NOTHING TO SAY, or a far side that
            # reads stdin inherits OURS and blocks the capture loop.
            _sent_in.clear()
            engine.source_trigger(["titan"], "capture", run=_sr_in,
                                  hook=_hk, views=[])
            ck("source-trigger-closes-stdin-with-no-pids-to-send",
               _sent_in[-1][1] == "")
            _sent_in.clear()
            engine.source_trigger(["titan"], "capture", run=_sr_in,
                                  hook=_hk)
            ck("source-trigger-without-views-still-closes-stdin",
               _sent_in[-1][1] == "")

            # A REFUSAL IS REPORTED AND NOT COUNTED.
            def _sr_no(argv, **_k):
                class R:
                    returncode = 3
                    stderr = "nope"
                    stdout = ""
                return R()
            _said3.clear()
            ck("source-trigger-a-refusal-is-not-counted",
               engine.source_trigger(["titan"], "resume", run=_sr_no,
                                     hook=_hk) == 0)
            ck("source-trigger-a-refusal-is-reported",
               any("refused" in m for m in _said3))
        finally:
            engine._announce = _ra
        # NO HOOK, BUT SOMETHING TO ASK: reported, because the reason nothing
        # came back must not be silent.
        _said3.clear()
        ck("source-trigger-no-hook-asks-nothing",
           engine.source_trigger(["titan"], "resume",
                                 hook=os.path.join(_hd3, "nope")) == 0)
        ck("source-trigger-no-hook-says-why",
           any("no source-trigger hook" in m for m in _said3))
        # ...AND NOTHING TO ASK STAYS QUIET, or a box with no other account
        # gains a line at every login and the line gets ignored.
        _said3.clear()
        ck("source-trigger-quiet-when-there-is-nothing-to-do",
           engine.source_trigger([], "resume",
                                 hook=os.path.join(_hd3, "nope")) == 0
           and not _said3)
    finally:
        engine.SOURCE_TRIGGER_HOOK, engine.logline = _rsrh, _rl3
        shutil.rmtree(_hd3, ignore_errors=True)


def _t_chrome(ck):
    """chrome identity, profiles, and the restore flags."""
    ps = {getattr(p, "name", "?"): p for p in engine.plugins()}
    # chrome identity is the WINDOW, not the tab. These run against the real
    # session files when present, which is the only place the join can be
    # tested honestly.
    _wins = {w for w, _u in chrome_session_titles().values()}
    ck("chrome-slots-are-windows",
       all(chrome_window_for(t + " - Google Chrome").startswith("chrome:win:")
           for t in list(chrome_session_titles())[:5]))
    ck("chrome-slot-count-matches-windows",
       len({chrome_window_for(t + " - Google Chrome")
            for t in chrome_session_titles()}) == len(_wins))
    ck("chrome-unknown-title", chrome_window_for("nothing like this") is None)

    # THE TITLE IS A BOOTSTRAP, NOT AN IDENTITY: resolve once, then remember
    # for the life of the view. A Gmail window is `Inbox (1)` in the session
    # file and `Inbox (2)` on screen the moment mail arrives, so re-deriving
    # every time made it flicker between known and stranger for its whole life.
    _t0 = next(iter(chrome_session_titles()), None)
    if _t0:
        _want = chrome_window_for(_t0 + " - Google Chrome")
        ck("slot-resolves-for-a-view",
           window_slot(90001, _t0 + " - Google Chrome") == _want)
        # ...and now survives the title changing under it, which is the bug
        ck("slot-survives-a-title-change",
           window_slot(90001, "Inbox (99) - nothing like this") == _want)
        # a DIFFERENT view is not given the first one's answer
        ck("slot-is-per-view",
           window_slot(90002, "Inbox (99) - nothing like this") is None)
        # a stored entry (no live view) never caches and never reads the cache
        ck("slot-uncached-without-a-view",
           window_slot(None, "Inbox (99) - nothing like this") is None)
        forget_window(90001)
        ck("slot-forgotten-on-unmap",
           window_slot(90001, "Inbox (99) - nothing like this") is None)
        forget_window(90002)

    # A TITLE TWO WINDOWS SHARE IS NOT A DISCRIMINATOR, and it matters more
    # now that the answer STICKS: two "New Tab" windows would otherwise both
    # be handed the same slot, permanently. Same rule learn() applies to its
    # title groups.
    with _tsnss([(31, 1, "https://a/", "Same Title"),
                 (32, 2, "https://b/", "Same Title"),
                 (33, 3, "https://c/", "Unique Title")]) as _dupf:
        _d = parse_snss(_dupf)
        ck("chrome-drops-ambiguous-titles", "Same Title" not in _d)
        ck("chrome-keeps-unambiguous-titles",
           _d.get("Unique Title", (None,))[0] == 33)
    # the profile map is keyed by slot now, so a saved window still resolves
    ck("chrome-profile-map-by-slot",
       all(k.startswith("chrome:win:") for k in chrome_profile_map()))

    # FOLLOWING A WINDOW ACROSS A RESTART. Chrome mints fresh SessionIDs for
    # every restored window, so the bind is the only thing standing between a
    # reboot and losing every Chrome placement. Built as two real SNSS blobs,
    # an "old session" and the "new session" that restored it with different
    # ids: window 7 (two tabs) and window 8 (one tab) come back as 91 and 92.
    with _tsnss([(7, 70, "https://a.example/", "A"),
                 (7, 71, "https://b.example/", "B"),
                 (8, 80, "https://c.example/", "C")]) as _oldf, \
         _tsnss([(91, 10, "https://a.example/", "A"),
                 (91, 11, "https://b.example/", "B"),
                 (92, 12, "https://c.example/", "C")]) as _newf:
        _old, _new = chrome_window_tabs(_oldf), chrome_window_tabs(_newf)
        ck("chrome-tabs-whole-set",
           _old == {7: frozenset({"https://a.example/", "https://b.example/"}),
                    8: frozenset({"https://c.example/"})})
        ck("chrome-bind-across-restart",
           chrome_bind_windows(_new, _old) == {7: 91, 8: 92})
        # a window sharing ONE page with a big one is not that window
        ck("chrome-bind-declines-a-coincidence",
           chrome_bind_windows(
               {93: frozenset({"https://a.example/"}
                              | {f"https://x{i}/" for i in range(9)})},
               {7: _old[7]}) == {})
        ck("chrome-bind-declines-strangers",
           chrome_bind_windows({93: frozenset({"https://zzz/"})}, _old) == {})
        ck("chrome-bind-empty", chrome_bind_windows({}, _old) == {}
           and chrome_bind_windows(_new, {}) == {})

        # and the store move itself: a stale slot follows its window, one the
        # CURRENT session still knows is untouched, a second run is a no-op.
        _kb = {kkey("google-chrome", "chrome:win:7"):
               {"title": "chrome:win:7", "pos": [1, 2]},
               kkey("google-chrome", "chrome:win:8"):
               {"title": "chrome:win:8", "pos": [3, 4]},
               kkey("kitty", "kitty:/tmp"): {"title": "kitty:/tmp"}}
        with _tsession(_newf, _oldf):
            _n1 = rekey_chrome(_kb)
            _n2 = rekey_chrome(_kb)
        ck("chrome-rekey-moves-stale", _n1 == 2)
        ck("chrome-rekey-is-idempotent", _n2 == 0)
        ck("chrome-rekey-keeps-placement",
           _kb.get(kkey("google-chrome", "chrome:win:91"),
                   {}).get("pos") == [1, 2]
           and _kb.get(kkey("google-chrome", "chrome:win:92"),
                       {}).get("pos") == [3, 4])
        ck("chrome-rekey-moves-the-key-title",
           _kb[kkey("google-chrome", "chrome:win:91")]["title"]
           == "chrome:win:91")
        ck("chrome-rekey-leaves-others",
           kkey("kitty", "kitty:/tmp") in _kb and len(_kb) == 3)

    # chrome is started with the flags that make it RESTORE: naming the right
    # profile is not enough, since "On startup" is unset on these profiles and
    # unset means the New Tab page.
    ck("chrome-restore-flag", "--restore-last-session" in CHROME_FLAGS)
    ck("chrome-flags-overridable",
       shlex.split("") == [] and isinstance(CHROME_FLAGS, list))

    # chrome relaunch: only when the last session had Chrome and none is up
    _ch = ps["chrome"]
    ck("chrome-no-saved", _ch.relaunch_missing([], []) == set())
    # PER USER ON BOTH SIDES. Another account's browser answers neither
    # question for us, and the second half is the quiet direction: without it
    # a personal Chrome simply would not come back on any login where the work
    # one was already running.
    if os.getuid() != 0:
        ck("chrome-skips-another-accounts-saved-window",
           _ch.relaunch_missing([{"app_id": "google-chrome", "owner": 997}],
                                []) == set())
        # THE LIVE SIDE, WITHOUT EVER LAUNCHING A BROWSER. relaunch_missing
        # spawns internally, so the seam is the executable lookup: it is
        # reached only if BOTH guards passed, and answering None stops it
        # before any spawn. So "did it ask for the exe" IS the decision.
        _asked = []

        class _NoExe:
            @staticmethod
            def which(c):
                _asked.append(c)
                return None

        _rsh = engine.shutil
        try:
            engine.shutil = _NoExe
            _asked.clear()
            _ch.relaunch_missing([{"app_id": "google-chrome"}],
                                 [_trv("google-chrome", "theirs", pid=1)])
            ck("chrome-a-foreign-live-browser-does-not-suppress-ours",
               bool(_asked))
            # THE CONTROL, which is what makes the line above mean anything:
            # OUR OWN live browser must still suppress it.
            _asked.clear()
            _ch.relaunch_missing(
                [{"app_id": "google-chrome"}],
                [_trv("google-chrome", "mine", pid=os.getpid())])
            ck("chrome-our-own-live-browser-still-suppresses", not _asked)
        finally:
            engine.shutil = _rsh

        # THE SAME CLAIM FOR THE OTHER TWO RELAUNCH PATHS, which asked it
        # with the whole view list while only Chrome's plugin asked it per
        # user. Both measured on real code before the fix.
        #
        # THE REGISTRY DEFAULT covers every app no plugin claims, which is
        # most of a desk: the owner's Signal was not started while only the
        # work account's was running.
        _saved_1 = [{"app_id": "signal", "title": "Signal", "key": "Signal",
                     "pid": -1, "cmd": None, "id": 1}]

        def _started(live):
            _got = []
            # STDOUT CAPTURED, because `_announce` deliberately prints as
            # well as logging (a person running `usher launch` by hand reads
            # the print; `_quiet_log` only takes the log half). Left loose it
            # puts a `launch` line into the suite's own output, which is the
            # record this package reads to tell its noise from a daemon's.
            with contextlib.redirect_stdout(io.StringIO()):
                engine.desktop_relaunch_missing(
                    _saved_1, live,
                    spawn=lambda *a, **k: (_got.append(a[0]), 1)[1])
            return _got

        ck("default-relaunch-ignores-another-accounts-copy",
           bool(_started([_trv("signal", "Theirs", pid=1)])))
        # THE CONTROL: our own live copy must still suppress it, or the
        # check above would pass over a path that double-starts everything.
        ck("default-relaunch-still-skips-our-own-live-copy",
           not _started([_trv("signal", "Mine", pid=os.getpid())]))

        # AND THE TERMINAL COUNT, where the cost was subtler: a foreign kitty
        # matched neither the `kitty:<cwd>` nor the `term:` branch, so it read
        # as a terminal that could not be placed and flipped the whole pass
        # to UNREADABLE, and the candidate list then fell back to one per
        # cwd. Two of the owner's shells in one directory came back as one
        # whenever any other account had a terminal on screen: the bug the
        # per-window counting exists to fix, reintroduced through a flag.
        _saved_2 = [{"app_id": "kitty", "title": "a", "id": 1, "pid": -1,
                     "cmd": None, "key": "kitty:/var/tmp"},
                    {"app_id": "kitty", "title": "b", "id": 2, "pid": -1,
                     "cmd": None, "key": "kitty:/var/tmp"}]
        ck("terminal-count-survives-another-accounts-terminal",
           engine.kitty_candidates(_saved_2,
                                   [_trv("kitty", "", pid=1)])
           == engine.kitty_candidates(_saved_2, []) == ["/var/tmp"] * 2)
        # THE CONTROL, and it is the reason the flag exists at all: one of
        # OUR OWN kitty windows that resolves to neither set really is
        # unaccountable, and must still force the conservative fallback.
        ck("terminal-count-still-falls-back-on-an-unreadable-own-kitty",
           engine.kitty_candidates(
               _saved_2, [_trv("kitty", "", pid=os.getpid())])
           == ["/var/tmp"])
    ck("chrome-already-live",
       _ch.relaunch_missing([{"app_id": "google-chrome"}],
                            [_tv("google-chrome", "x")]) == set())

    # WIND-DOWN FINDS THE BROWSER, in both of the framings /proc/<pid>/cmdline
    # actually comes in. These are real captures: Chrome rewrites its own argv
    # into ONE space-joined string, so the NUL-separated form the kernel
    # documents is the MINORITY here, and reading only that form made
    # browser_pids() return [] on both boxes: wind-down signalling nothing,
    # which is the whole of what it is for.
    ck("browser-cmdline-space-joined",
       is_browser_cmdline(
           b"/opt/google/chrome/chrome --restore-last-session"
           b" --hide-crash-restore-bubble --profile-directory=Profile 2\0"))
    ck("browser-cmdline-nul-separated",
       is_browser_cmdline(
           b"/opt/google/chrome/chrome\0--restore-last-session\0"))
    ck("browser-cmdline-skips-renderer",
       not is_browser_cmdline(
           b"/opt/google/chrome/chrome --type=renderer --top-chrome-webui\0"))
    ck("browser-cmdline-skips-nul-renderer",
       not is_browser_cmdline(
           b"/opt/google/chrome/chrome\0--type=zygote\0"))
    ck("browser-cmdline-skips-other-apps",
       not is_browser_cmdline(b"/usr/bin/kitty --title x\0")
       and not is_browser_cmdline(b"")
       and not is_browser_cmdline(
           b"/opt/google/chrome/chrome_crashpad_handler\0--monitor-self\0"))

    # ...AND IT MUST FIND ONLY *THIS USER'S* BROWSER, which became reachable
    # the day a second account ran its own Chrome on the same display.
    # Measured 2026-11-02: browser_pids() returned [mine, theirs] and the
    # foreign one is not signalable, so wind-down counted a process it could
    # not touch as having exited.
    #
    # THE INVARIANT OVER THE REAL WALK, and the count is stated because with
    # no browser running this half is vacuous and a bare ok would hide that.
    _bp = chrome.browser_pids()
    _notmine = [p for p in _bp
                if _stat_uid(f"/proc/{p}") not in (os.getuid(), None)]
    ck(f"browser-pids-only-this-user ({len(_bp)} found)", not _notmine)

    # ...AND THE FILTER PROVED IN BOTH DIRECTIONS, which the invariant above
    # cannot do on a box with no second account's browser running. A REAL
    # process that `is_browser_cmdline` matches, with no browser installed and
    # no second uid needed: `Popen(args, executable=...)` runs /bin/sleep
    # while argv[0] says chrome, which is what the walk reads.
    _fake = subprocess.Popen(["/opt/google/chrome/chrome", "30"],
                             executable="/bin/sleep",
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        ck("browser-pids-finds-my-own-browser",
           _fake.pid in chrome.browser_pids())
        # Now ask the SAME walk as somebody else: every /proc entry fails the
        # owner test, so a filtered walk finds nothing and an unfiltered one
        # still finds the process above.
        ck("browser-pids-excludes-another-users-browser",
           _fake.pid not in chrome.browser_pids(uid=999999))
    finally:
        _fake.kill()
        _fake.wait()

    # wind_down RETURNS ONLY WHAT IT SIGNALLED, because the caller WAITS on
    # that list: a pid we could not signal would be waited for and then read
    # as exited. Driven with pids that cannot be signalled for the two
    # different reasons.
    # STUBBED ON `engine`, NOT ON `chrome`: engine does `from .chrome import
    # browser_pids`, so it holds its OWN binding and patching chrome's leaves
    # the real /proc walk in place. Written the other way first, and both
    # checks below passed over an empty list for that reason, which the
    # message check caught.
    _rbp2 = engine.browser_pids
    _rlog = engine.logline
    _said = []
    try:
        engine.logline = lambda m: _said.append(m)
        engine.browser_pids = lambda: [_DEAD_PID]
        ck("wind-down-drops-a-pid-that-is-already-gone",
           _ch.wind_down([]) == [])
        # EPERM, not ESRCH: pid 1 is alive and root's. SIGTERM to it is
        # REFUSED for a non-root caller and delivers nothing; skipped
        # outright if this ever runs as root, where it would not be.
        if os.getuid() != 0:
            _said.clear()
            engine.browser_pids = lambda: [1]
            ck("wind-down-drops-a-pid-it-cannot-signal",
               _ch.wind_down([]) == [])
            ck("wind-down-says-what-it-could-not-signal",
               any("could not signal browser 1" in m for m in _said))
    finally:
        engine.browser_pids, engine.logline = _rbp2, _rlog

    # _wind_down_wait MUST NOT READ EPERM AS "EXITED", which is the overclaim
    # that made a logout report a clean browser stop it had not performed.
    _rwt = engine.WIND_DOWN_TIMEOUT
    try:
        engine.WIND_DOWN_TIMEOUT = 0.3        # the loop must stay bounded
        ck("wind-down-wait-nothing-asked",
           "nothing asked" in _capture_out(engine._wind_down_wait, []))
        ck("wind-down-wait-a-gone-pid-is-clean",
           "all exited cleanly"
           in _capture_out(engine._wind_down_wait, [_DEAD_PID]))
        if os.getuid() != 0:
            _out = _capture_out(engine._wind_down_wait, [1])
            # THE THREE CLAIMS, PAIRWISE: it must NOT say the clean line, it
            # must name the pid, and it must say whose problem it is. Checking
            # only the first would pass over a message that said nothing.
            ck("wind-down-wait-foreign-is-not-clean",
               "all exited cleanly" not in _out)
            ck("wind-down-wait-foreign-is-named",
               "another user" in _out and "(1)" in _out)
            ck("wind-down-wait-foreign-still-reports-what-went",
               "everything this session owns exited cleanly" in _out)
    finally:
        engine.WIND_DOWN_TIMEOUT = _rwt

    # A PROFILE CHROME HAS NOT OPENED THIS RUN MUST CONTRIBUTE NO WINDOWS.
    # Its newest session file is still on disk, so the live id set gained
    # windows that do not exist, and elimination then had two free ids for one
    # unresolved view and refused. Measured on manifestor 2026-10-09: Profile
    # 4's month-old file, one dead Gmail window, one real window unplaceable.
    _rbp, _rsh = chrome.browser_pids, chrome.session_history
    _sdir = tempfile.mkdtemp(prefix="usher-sess-", dir="/var/tmp")
    try:
        chrome.browser_pids = lambda: []
        ck("browser-started-none-without-a-browser",
           chrome.browser_started() is None)
        chrome.browser_pids = lambda: [os.getpid()]
        _mine = chrome.browser_started()
        ck("browser-started-reads-the-process",
           _mine is not None and _mine <= time.time())
        # THE EARLIEST OF SEVERAL. pid 1 began at boot, so including it must
        # move the answer BACK, which is the conservative direction given the
        # answer is used to discard files.
        chrome.browser_pids = lambda: [os.getpid(), 1]
        ck("browser-started-takes-the-earliest",
           chrome.browser_started() < _mine)

        _fresh = os.path.join(_sdir, "Session_fresh")
        _stale = os.path.join(_sdir, "Session_stale")
        open(_fresh, "w").close()
        open(_stale, "w").close()
        os.utime(_stale, (1, 1))
        chrome.session_history = lambda: {"loaded": [_fresh],
                                          "dormant": [_stale]}
        chrome.browser_pids = lambda: [os.getpid()]
        ck("session-files-drops-a-profile-older-than-the-browser",
           chrome.session_files() == [_fresh])
        # ...and with NO browser running every file is the record of the last
        # run, which is exactly what the login path reads.
        chrome.browser_pids = lambda: []
        ck("session-files-unfiltered-without-a-browser",
           sorted(chrome.session_files()) == sorted([_fresh, _stale]))
    finally:
        chrome.browser_pids, chrome.session_history = _rbp, _rsh
        shutil.rmtree(_sdir, ignore_errors=True)

    # recorded_window_ids MUST READ THE RETAINED OLDER FILES TOO, not just
    # the current one. Those ids are precisely what rekey_chrome can bind
    # across a restart, so a set built from the newest file alone would call
    # them unreachable and the dry run would hide the slots that matter most
    # during exactly the event they exist for.
    _rsh2 = chrome.session_history
    try:
        with _tsnss([(11, 1, "https://a/", "A")]) as _curf, \
                _tsnss([(22, 2, "https://b/", "B")]) as _prevf:
            chrome.session_history = lambda: {"P": [_curf, _prevf]}
            _rids = chrome.recorded_window_ids()
            ck("recorded-ids-have-the-current-file", 11 in _rids)
            ck("recorded-ids-have-a-retained-older-file", 22 in _rids)
            ck("recorded-ids-are-only-what-a-file-names",
               _rids == {11, 22})
    finally:
        chrome.session_history = _rsh2

    # END TO END, through the title map and elimination, which is where the
    # live fault actually showed: a dormant profile's window is one the file
    # records and nothing can be, so leaving it in the set is what forced the
    # refusal. Two REAL session files, since both halves read bytes.
    with _tsnss([(41, 1, "https://live/", "Live Window")]) as _lf, \
            _tsnss([(42, 2, "https://dead/", "Dead Window")]) as _df:
        _rbp, _rsh = chrome.browser_pids, chrome.session_history
        _rsig = dict(chrome._snss_cache)
        try:
            os.utime(_df, (1, 1))
            chrome.session_history = lambda: {"live": [_lf], "dormant": [_df]}
            chrome.browser_pids = lambda: [os.getpid()]
            chrome._snss_cache["sig"] = None
            _tm = chrome.chrome_session_titles()
            ck("titles-exclude-a-dormant-profile",
               "Live Window" in _tm and "Dead Window" not in _tm)
            # the view whose title the file cannot match is now FORCED, where
            # the phantom id made this refuse
            chrome._slot_cache.clear()
            ck("elim-claims-once-the-phantom-id-is-gone",
               chrome.claim_by_elimination(
                   [(1, "something the file never recorded - Google Chrome")])
               == 1)
            ck("elim-claimed-the-live-window",
               chrome._slot_cache.get(1) == "chrome:win:41")
            # and WITH the dormant profile back in, it refuses: the fixture
            # proves the exclusion is what decides, not the fixture's shape
            chrome.browser_pids = lambda: []
            chrome._snss_cache["sig"] = None
            chrome._slot_cache.clear()
            ck("elim-refuses-while-the-phantom-id-remains",
               chrome.claim_by_elimination(
                   [(1, "something the file never recorded - Google Chrome")])
               is None)
        finally:
            chrome.browser_pids, chrome.session_history = _rbp, _rsh
            chrome._snss_cache.update(_rsig)
            chrome._snss_cache["sig"] = None
            chrome._slot_cache.clear()

def _t_learn(ck):
    """what a learn pass keeps, replaces and purges."""
    # learn() must KEEP the entry it just wrote for a live terminal. Its mux
    # purge once compared kb keys (identities) against raw window titles, so it
    # deleted every terminal entry on the same pass that created it, and
    # terminals were never placed at all. Nothing else here would catch that.
    def LW(vid, title, app="kitty"):
        return {"id": vid, "app_id": app, "title": title, "pid": -1,
                "output": "DP-1", "workspace": [1.0, 1.0],
                "pos": [0.0, 0.0], "size": [800.0, 600.0]}

    _kb, _groups = {}, {}
    learn(_kb, _groups, [LW(1, "usher:main⠀⠀⠀⠀[manifestor]")], 1_800_000_000)
    ck("learn-keeps-live-mux",
       [v["title"] for v in _kb.values()] == ["term:resume"])
    # THE REGRESSION THIS GUARDS: the same window, now showing a DIFFERENT
    # session. Under the session-shaped key that made it a stranger and purged
    # the slot it owned, which is how a terminal lost its remembered place.
    learn(_kb, _groups, [LW(1, "tackup:main⠀⠀⠀⠀[manifold]")], 1_800_000_001)
    ck("learn-survives-session-switch",
       [v["title"] for v in _kb.values()] == ["term:resume"])
    # AN OWNED WINDOW ITS PLUGIN CANNOT IDENTIFY IS NOT LEARNED AT ALL. A
    # Chrome window whose title is in no session file has no slot, and the
    # title it happens to be wearing is not one: storing it was 86% of a real
    # 333-entry store, none of it ever matchable again. An UNOWNED app still
    # keys by title, which for it is the only handle there is.
    _kbc, _gc = {}, {}
    learn(_kbc, _gc, [LW(9, "Nothing Like This - Google Chrome",
                         app="google-chrome"),
                      LW(8, "Nothing Like This", app="Google-chrome"),
                      LW(7, "Some Document", app="libreoffice"),
                      LW(6, "Other Document", app="libreoffice")],
          1_800_000_000)
    ck("learn-skips-unidentified-chrome",
       not any(k.split("\x00")[0].lower() == "google-chrome" for k in _kbc))
    ck("learn-keeps-unowned-title-keys",
       sorted(k.split("\x00")[1] for k in _kbc)
       == ["Other Document", "Some Document"])

    # A HELD WINDOW IS NOT LEARNED, but is still LIVE for everything else.
    # Holding is how the capture loop stops overwriting the slot the placer is
    # about to aim at; pushing it any further would drop the very entry it
    # exists to protect, since the terminal purge asks "is this window still
    # here" and a held window plainly is.
    _kbh, _gh = {}, {}
    learn(_kbh, _gh, [LW(1, "usher:main\u2800\u2800\u2800\u2800[manifestor]")],
          1_800_000_000)
    learn(_kbh, _gh, [LW(1, "usher:main\u2800\u2800\u2800\u2800[manifestor]")],
          1_800_000_001, hold={1})
    ck("learn-hold-keeps-the-entry",
       [v["title"] for v in _kbh.values()] == ["term:resume"])
    ck("learn-hold-does-not-restamp",
       all(v["last_seen"] == 1_800_000_000 for v in _kbh.values()))
    _kbh2, _gh2 = {}, {}
    learn(_kbh2, _gh2, [LW(2, "Some Document", app="libreoffice"),
                        LW(3, "Other Document", app="libreoffice")],
          1_800_000_000, hold={2})
    ck("learn-hold-skips-only-the-held",
       [k.split("\x00")[1] for k in _kbh2] == ["Other Document"])

    # THE TWO HALVES OF "GONE", which one boolean used to answer for both and
    # got the login case exactly backwards. The old check here demonstrated the
    # purge with an EMPTY window list and no memory, which is the one input
    # where nothing can be concluded: that is the shape of every session start,
    # and it deleted both terminal slots seconds before their windows mapped.
    #
    # NOT YET SEEN, absent: could be closed, could be still starting. KEEP.
    _kbs = {"kitty\x00term:resume": dict(_kb["kitty\x00term:resume"])}
    learn(_kbs, {}, [], 1_800_000_002, seen=set())
    ck("learn-keeps-a-terminal-never-seen-alive",
       "kitty\x00term:resume" in _kbs)
    # WATCHED GO: observed alive on an earlier pass, absent now. DROP.
    _seen = set()
    learn(_kbs, {}, [LW(1, "usher:main⠀⠀⠀⠀[manifestor]")], 1_800_000_002,
          seen=_seen)
    ck("learn-remembers-a-live-terminal", "term:resume" in _seen)
    learn(_kbs, {}, [], 1_800_000_003, seen=_seen)
    ck("learn-drops-a-terminal-we-watched-go",
       not any(v["title"].startswith("term:") for v in _kbs.values()))
    # AND A CALLER THAT KEEPS NO MEMORY PURGES NOTHING, rather than purging
    # everything, which is the fail-safe direction: one phantom relaunch costs
    # less than a lost slot.
    _kbn = {"kitty\x00term:resume": dict(_kb["kitty\x00term:resume"])}
    learn(_kbn, {}, [], 1_800_000_002)
    ck("learn-without-a-memory-purges-nothing",
       "kitty\x00term:resume" in _kbn)
    # ...but a kitty:<cwd> entry is NOT swept by the mux purge (it merely has a
    # colon in it, which is all is_mux_term ever tested for)
    _kb["kitty\x00kitty:/tmp"] = {"app_id": "kitty", "title": "kitty:/tmp",
                                  "last_seen": 1_800_000_001,
                                  "appid_only": False}
    learn(_kb, _groups, [LW(1, "usher:main⠀⠀⠀⠀[manifestor]")],
          1_800_000_002)
    ck("learn-keeps-kitty-cwd", "kitty\x00kitty:/tmp" in _kb)

    # THE TWO WRITERS AGREE, which is the INVARIANT rather than nine separate
    # assertions: upsert() and learn() are the only things that write the
    # store, so a shape one remembers and the other declines is two sites
    # with a different idea of what may be keyed, and that disagreement is
    # every silent failure this file records. Asserted as a table because the
    # fault was found by building one: three shapes diverged, each a bug
    # already fixed in learn and never in upsert.
    _OUT = [{"name": "DP-1", "geometry": {"x": 0, "y": 0,
                                          "width": 1920, "height": 1080}}]

    def _uw(app, title, vid=11, **kw):
        w = dict(LW(vid, title, app), output="DP-1")
        w.update(kw)
        return w

    #                                           windows                outputs
    _SHAPES = [
        ("unowned, one window",   [_uw("zzz-unowned", "Thing")],         _OUT),
        ("unowned, two windows",  [_uw("zzz-unowned", "One", 11),
                                   _uw("zzz-unowned", "Two", 12)],       _OUT),
        # AN OWNED APP ITS PLUGIN DECLINED: upsert took the raw TITLE, which
        # is the chrome spam schema 7 purged and which the matcher never
        # looks up for an owned app, so it was unmatchable from birth.
        ("owned, plugin declined", [_uw("google-chrome",
                                        "Nothing Like This - Google Chrome")],
         _OUT),
        ("no app-id and no title", [_uw("", "")],                        _OUT),
        ("no app-id, with title",  [_uw("", "A Picture.png")],           _OUT),
        # ANOTHER uid NO PROVIDER CAN NAME: upsert took `kkey(app, "")`,
        # the OWNER's key, which matches every window of that app. pid 1 is
        # init, so this needs no second account to drive.
        ("another uid, unnamable", [_uw("zzz-unowned", "Thing", pid=1)],  _OUT),
        ("foreign, per-window key", [_uw("slack", "", source="titan",
                                         owner=997, key="titan:aabbccdd")],
         _OUT),
        # PARKED BETWEEN AN UNDOCK AND A REDOCK: upsert wrote a slot naming
        # an output nobody has, which nothing can ever place.
        ("parked on a lost output", [_uw("zzz-unowned", "T", output="DP-9")],
         _OUT),
        # ...and NO OUTPUT LIST CONCLUDES NOTHING, so both still learn.
        ("parked, no output list",  [_uw("zzz-unowned", "T", output="DP-9")],
         None),
    ]
    _rows = []
    for _label, _ws, _outs in _SHAPES:
        _ku, _kl = {}, {}
        upsert(_ku, _ws, 1_800_000_000, _outs)
        learn(_kl, {}, _ws, 1_800_000_000, set(), None, _outs)
        _rows.append((_label, sorted(_ku), sorted(_kl)))
    for _n, _u, _l in _rows:
        if _u != _l:   # named, so a failure says WHICH shape and both answers
            print("  %s: upsert %s vs learn %s" % (_n, _u, _l),
                  file=sys.stderr)
    ck("upsert-and-learn-agree", all(u == l for _, u, l in _rows))
    # AND THE TABLE IS NOT VACUOUS: without this, a table whose every row
    # wrote NOTHING would agree perfectly and assert nothing at all. Five
    # shapes must be learned and four refused, by both.
    ck("upsert-and-learn-agree-is-not-vacuous",
       sum(1 for _, u, _l in _rows if u) == 5
       and sum(1 for _, u, _l in _rows if not u) == 4)

    # --- AND THE DECISION IS ONE FUNCTION, not two copies ----------------
    # The table above catches a divergence AFTER it exists. `stamp_key` makes
    # it impossible: the two writers had been brought into agreement by
    # COPYING three times, and the third time was a divergence found in
    # production. Measured before extracting: a ten-line identical run, 46%
    # of the smaller function, carrying the cross-file guard.
    _c = engine.own_app_counts
    _one = {"app_id": "zzz-unowned", "title": "T", "pid": os.getpid()}

    def _sk(w, key=""):
        return engine.stamp_key(w, w["app_id"], key,
                                _c([dict(_one), w] if w is not _one else
                                   [w]))
    # THE SOURCE IS ASKED FIRST, which is the branch ORDER with teeth: this
    # window is the only one of its app, so `is_unique` would hand it
    # `kkey(app, "")`, the OWNER's key, which matches every window of that
    # app. Reversing the two is the bug that keyed a work Slack as the
    # owner's.
    _f = {"app_id": "slack", "title": "", "source": "acct", "key": "acct",
          "owner": 997}
    # THE FIXTURE IS THE MEASURED SHAPE: ONE SLACK OF EACH ACCOUNT. With the
    # foreign row alone `own_app_counts` excludes it, so `is_unique` is
    # already False and the branch ORDER cannot matter: a plant reordering
    # the two passed this cell until the owner's row was added. That is the
    # real bug's input, and asking what a guard DISTINGUISHES is how to pick
    # a fixture rather than what it merely reaches.
    _mine = {"app_id": "slack", "title": "Slack"}
    _both = engine.own_app_counts([_mine, _f])
    ck("stamp-key-fixture-makes-the-order-matter",
       _both == {"slack": 1} and engine.is_unique("slack", _both))
    ck("stamp-key-asks-the-source-before-app-id-only",
       engine.stamp_key(_f, "slack", "", _both) == ("acct", "acct", False))
    # ...and the OWNER's own window of that same app still gets the
    # app-id-only key, which is the control: without it the cell above passes
    # over a stamp_key that has stopped returning that shape at all.
    ck("stamp-key-still-gives-the-owner-the-app-id-only-key",
       engine.stamp_key(_mine, "slack", "", _both)
       == ("", "Slack", True))
    # AND A STAMPED KEY NAMING ANOTHER SOURCE IS REFUSED, falling back to the
    # one this window actually belongs to: cross-filing it would put one
    # account's window under another's prefix.
    _x = dict(_f, key="elsewhere:deadbeef")
    ck("stamp-key-never-cross-files-a-source",
       engine.stamp_key(_x, "slack", "", engine.own_app_counts([_x]))
       == ("acct", "acct", False))
    # ...while the source's OWN per-window identity is kept, or the per-window
    # work is thrown away at the one place it is stored.
    _p = dict(_f, key="acct:abc123")
    ck("stamp-key-keeps-a-per-window-identity",
       engine.stamp_key(_p, "slack", "", engine.own_app_counts([_p]))[0]
       == "acct:abc123")
    # A TITLE IS THE CALLER'S OWN CASE, so this says so rather than guessing:
    # learn has title GROUPS where upsert has one row and one title.
    _two = [{"app_id": "zzz-unowned", "title": "A"},
            {"app_id": "zzz-unowned", "title": "B"}]
    ck("stamp-key-falls-through-for-a-title",
       engine.stamp_key(_two[0], "zzz-unowned", "",
                        engine.own_app_counts(_two)) is None)
    # AND THE COUNT EXCLUDES FOREIGN ROWS, which is the fact the branch above
    # depends on: counting them made the OWNER's app look non-unique and
    # flipped it off its app-id-only key.
    ck("own-app-counts-excludes-another-account",
       engine.own_app_counts([{"app_id": "slack", "title": "x"},
                              {"app_id": "slack", "title": "y",
                               "source": "acct", "owner": 997}])
       == {"slack": 1})

    # THE WIRING, which the function's own cells say nothing about: neither
    # writer may still decide for itself. Eleventh instance of that hole in
    # this package, so it is asserted rather than trusted.
    import ast as _ast2
    import inspect as _i2
    _esrc = _i2.getsource(engine)
    _etree = _ast2.parse(_esrc)
    _own2 = {}
    for _n2 in _ast2.walk(_etree):
        if isinstance(_n2, _ast2.FunctionDef):
            for _s2 in _ast2.walk(_n2):
                if hasattr(_s2, "lineno"):
                    _own2.setdefault(_s2.lineno, _n2.name)
    _hand, _calls = [], []
    for _n2 in _ast2.walk(_etree):
        if not isinstance(_n2, _ast2.Call):
            continue
        _f2 = _n2.func
        _nm = (_f2.id if isinstance(_f2, _ast2.Name)
               else getattr(_f2, "attr", ""))
        _in = _own2.get(_n2.lineno, "?")
        if _nm == "stamp_key":
            _calls.append(_in)
        # the owner's app-id-only key, built anywhere but the definitions
        if (_nm == "kkey" and len(_n2.args) == 2
                and isinstance(_n2.args[1], _ast2.Constant)
                and _n2.args[1].value == ""
                and _in not in ("match_keys", "stamp_key", "entry_matches",
                                "matched_key", "is_unique",
                                "source_per_window_slots")):
            _hand.append(f"{_in}:{_n2.lineno}")
    if _hand:
        print("selftest: the owner's app-id-only key is built outside the "
              f"definitions: {_hand}", file=sys.stderr)
    ck("no-writer-builds-the-owner-key-for-itself", not _hand)
    ck("both-writers-decide-through-stamp-key",
       {"upsert", "_learn_stamp"} <= set(_calls))

def _t_placement(ck):
    """place_of and target_geometry: the two halves of WHERE a window goes.

    They are inverses, and both were completely untested, which is a strange
    place for this repo to have a hole: a bug in either misplaces every
    window, and the note in place_of already says "if a restored window ever
    lands one workspace off, this offset is the thing to re-check first"."""
    _o = {"DP-1": {"id": 1, "geometry": {"x": 0, "y": 0, "width": 1000,
                                         "height": 800},
                   "workspace": {"x": 1, "y": 1}}}

    def _view(x, y, w=300, h=200, out="DP-1"):
        return {"output-name": out,
                "geometry": {"x": x, "y": y, "width": w, "height": h}}

    # on the CURRENT workspace: the offset is zero, so absolute == current
    ck("place-of-current-workspace",
       place_of(_view(40, 50), _o)["workspace"] == [1, 1])
    ck("place-of-keeps-the-position", place_of(_view(40, 50), _o)["pos"]
       == [40, 50])
    # one workspace right and one down
    ck("place-of-offset-workspace",
       place_of(_view(1040, 850), _o)["workspace"] == [2, 2])
    ck("place-of-position-is-within-the-workspace",
       place_of(_view(1040, 850), _o)["pos"] == [40, 50])
    # FLOOR, NOT ROUND, which is the documented trap: a window in the lower
    # half of a workspace is still ON it, and rounding would report the next
    # one down and put pos out of range.
    ck("place-of-floors-not-rounds",
       place_of(_view(600, 600), _o)["workspace"] == [1, 1]
       and place_of(_view(600, 600), _o)["pos"] == [600, 600])
    # a NEGATIVE offset is a workspace up/left of the current one
    ck("place-of-negative-offset",
       place_of(_view(-960, -750), _o)["workspace"] == [0, 0])
    # an output the compositor no longer reports must not throw
    ck("place-of-unknown-output",
       place_of(_view(5, 6, out="GONE-1"), _o)["workspace"] == [0, 0])

    # target_geometry is the inverse: it lands a stored entry back, expressed
    # relative to whatever workspace the output is showing NOW.
    _e = {"workspace": [2, 2], "pos": [40, 50], "size": [300, 200]}
    ck("target-offsets-from-the-current-workspace",
       target_geometry(_e, _o["DP-1"])
       == {"x": 1040, "y": 850, "width": 300, "height": 200})
    ck("target-on-the-current-workspace-is-the-position",
       target_geometry({"workspace": [1, 1], "pos": [40, 50],
                        "size": [300, 200]}, _o["DP-1"])
       == {"x": 40, "y": 50, "width": 300, "height": 200})
    # ROUND TRIP, which is the property that actually matters: capture a view,
    # restore it, and it must land exactly where it was.
    for _x, _y in ((0, 0), (40, 50), (1040, 850), (-960, -750), (600, 600)):
        _p = place_of(_view(_x, _y), _o)
        _t = target_geometry({"workspace": _p["workspace"], "pos": _p["pos"],
                              "size": _p["size"]}, _o["DP-1"])
        ck(f"placement-round-trips-at-{_x}-{_y}",
           (_t["x"], _t["y"]) == (_x, _y))

    # MATCH: consume-once, so two live windows cannot claim the same slot.
    # Deliberately an app NO plugin owns, so identity() is the raw title and
    # the matcher is what is under test rather than the plugin registry. (A
    # kitty titled "kitty:/a" would be claimed by MuxPlugin, which owns any
    # kitty whose title has a colon, which is why that fixture is wrong.)
    _en = [{"app_id": "libreoffice", "title": "A.odt", "appid_only": False},
           {"app_id": "libreoffice", "title": "B.odt", "appid_only": False},
           {"app_id": "slack", "title": "anything", "appid_only": True}]
    _lv = [_trv("slack", "Slack (3)"), _trv("libreoffice", "A.odt")]
    _pairs, _unlive, _unent = match(_lv, _en)
    ck("match-appid-only-ignores-the-title",
       any(e["app_id"] == "slack" for _l, e in _pairs))
    ck("match-exact-identity", any(e["title"] == "A.odt"
                                   for _l, e in _pairs))
    ck("match-reports-the-leftovers",
       len(_unlive) == 0 and [e["title"] for e in _unent] == ["B.odt"])
    # a live window with no entry is reported, not silently dropped
    _pairs2, _unlive2, _ = match([_trv("libreoffice", "Z.odt")], _en)
    ck("match-unmatched-live", not _pairs2 and len(_unlive2) == 1)
    # CONSUME-ONCE: two live windows resolving to one identity get one slot
    # between them, or they would both be moved onto the same spot.
    _dup = [{"app_id": "libreoffice", "title": "A.odt", "appid_only": False}]
    _pairs3, _unlive3, _ = match([_trv("libreoffice", "A.odt"),
                                  _trv("libreoffice", "A.odt")], _dup)
    ck("match-consumes-an-entry-once",
       len(_pairs3) == 1 and len(_unlive3) == 1)

def _t_geometry(ck):
    """respawn geometry and the chrome profile fallback."""
    # respawn geometry: ask kitty for the size the window had, so it does not
    # map at kitty.conf's default and sit wrong until placement catches up
    ck("saved-sizes", saved_sizes([{"app_id": "kitty", "key": "kitty:/tmp",
                                    "size": [2132.0, 1690.0]}])
       == {"kitty:/tmp": [2132, 1690]})
    ck("saved-sizes-skips-junk",
       saved_sizes([{"app_id": "kitty", "key": "k", "size": [0, 0]},
                    {"app_id": "kitty", "key": "j"}]) == {})
    ck("size-opts", _size_opts([2132, 1690])
       == ["-o", "initial_window_width=2132",
           "-o", "initial_window_height=1690"])
    ck("size-opts-none", _size_opts(None) == [])

    # chrome: with nothing resolvable, fall back to one unnamed launch
    ck("chrome-profiles-fallback",
       chrome_profiles_for([{"app_id": "google-chrome",
                             "key": "nowhere.example/x"}]) == [None])
    ck("chrome-profiles-ignores-others",
       chrome_profiles_for([{"app_id": "kitty", "key": "kitty:/tmp"}])
       == [None])

    # FORGET: the selector, and the NUL-key trap that is most of its reason
    # for existing. A store key is `app_id` NUL `identity`, so `term:` is NOT
    # a prefix of it and `startswith('term:')` answers [] whether or not a
    # terminal slot exists. That cost an investigation here, and doing the
    # split in ONE place is what the verb buys over a hand edit.
    _fe = {"workspace": [1, 0], "pos": [0, 0], "size": [10, 10]}
    _fkb = {engine.kkey("google-chrome", "chrome:win:111"): dict(_fe),
            engine.kkey("google-chrome", "chrome:win:222"): dict(_fe),
            engine.kkey("kitty", "term:resume"): dict(_fe),
            engine.kkey("kitty", "kitty:/src/usher"): dict(_fe),
            engine.kkey("signal", ""): dict(_fe)}
    _fm = engine.forget_matches
    ck("forget-globs-the-identity",
       _fm(_fkb, ["chrome:win:*"])
       == sorted([engine.kkey("google-chrome", "chrome:win:111"),
                  engine.kkey("google-chrome", "chrome:win:222")]))
    ck("forget-matches-an-exact-identity",
       _fm(_fkb, ["term:resume"]) == [engine.kkey("kitty", "term:resume")])
    # THE TRAP ITSELF: a prefix selector must find the terminal slot, which a
    # naive startswith over the KEYS never does.
    ck("forget-finds-a-term-slot-the-naive-filter-misses",
       _fm(_fkb, ["term:*"]) == [engine.kkey("kitty", "term:resume")]
       and [k for k in _fkb if k.startswith("term:")] == [])
    # AN APP-ID-ONLY KEY has no identity, so the glob falls to the app-id.
    ck("forget-matches-an-appid-only-entry",
       _fm(_fkb, ["signal"]) == [engine.kkey("signal", "")])
    ck("forget-does-not-match-an-app-with-an-identity",
       _fm(_fkb, ["kitty"]) == [])
    ck("forget-no-match-is-empty", _fm(_fkb, ["nothing-like-this"]) == [])
    ck("forget-several-selectors-union",
       len(_fm(_fkb, ["chrome:win:111", "signal"])) == 2)
    # CASE IS NOT FOLDED: chrome has two app-id spellings and a store holds
    # both, so a selector must mean exactly what it says.
    ck("forget-is-case-sensitive", _fm(_fkb, ["CHROME:WIN:*"]) == [])
    # ...and a preview must not mutate anything, which is the whole default.
    _snap = dict(_fkb)
    _fm(_fkb, ["*"])
    ck("forget-matching-mutates-nothing", _fkb == _snap)
    ck("forget-star-selects-everything", len(_fm(_fkb, ["*"])) == len(_fkb))

    # PREVIEW BY DEFAULT IS THE WHOLE SAFETY STORY, so it is asserted rather
    # than trusted: a planted regression that made the preview APPLY passed
    # the entire suite until these existed. Three outcomes, and which one
    # happens depends on the daemon, because only it may write the store while
    # it runs.
    _rlk, _rwp = engine.load_knowledge, engine.watcher_pid
    _rfa, _rff = engine.forget_apply, engine.FORGET_FILE
    _fdir = tempfile.mkdtemp(prefix="usher-dofg-", dir="/var/tmp")
    try:
        engine.load_knowledge = lambda: dict(_fkb)
        engine.FORGET_FILE = os.path.join(_fdir, "usher.forget")
        _applied = []
        engine.forget_apply = (lambda kb, sel, prof=None:
                               _applied.append(sel) or sel)
        # 1. a preview must touch NOTHING, with or without a daemon
        for _who, _pid in (("no-daemon", None), ("daemon-up", 99)):
            _applied.clear()
            engine.watcher_pid = lambda: _pid
            with contextlib.redirect_stdout(io.StringIO()):
                _rc = engine.do_forget(["chrome:win:*"], apply=False)
            ck(f"forget-preview-{_who}-applies-nothing", _applied == [])
            ck(f"forget-preview-{_who}-writes-no-request",
               not os.path.exists(engine.FORGET_FILE))
            ck(f"forget-preview-{_who}-succeeds", _rc == engine.EXIT_OK)
        # 2. --apply with NO daemon edits here, because nothing else writes
        _applied.clear()
        engine.watcher_pid = lambda: None
        with contextlib.redirect_stdout(io.StringIO()):
            engine.do_forget(["chrome:win:*"], apply=True)
        ck("forget-apply-without-a-daemon-edits-here",
           _applied == [["chrome:win:*"]])
        ck("forget-apply-without-a-daemon-writes-no-request",
           not os.path.exists(engine.FORGET_FILE))
        # 3. --apply WITH a daemon hands it over instead of editing
        _applied.clear()
        engine.watcher_pid = lambda: 99
        with contextlib.redirect_stdout(io.StringIO()):
            engine.do_forget(["chrome:win:*"], apply=True)
        ck("forget-apply-with-a-daemon-does-not-edit-here", _applied == [])
        ck("forget-apply-with-a-daemon-writes-the-request",
           open(engine.FORGET_FILE).read().split() == ["chrome:win:*"])
        # 4. and the degenerate inputs
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            ck("forget-no-selector-fails",
               engine.do_forget([], apply=True) == engine.EXIT_FAIL)
            _applied.clear()
            ck("forget-no-match-succeeds",
               engine.do_forget(["nothing-like-this"], apply=True)
               == engine.EXIT_OK)
            ck("forget-no-match-applies-nothing", _applied == [])
    finally:
        engine.load_knowledge, engine.watcher_pid = _rlk, _rwp
        engine.forget_apply, engine.FORGET_FILE = _rfa, _rff
        shutil.rmtree(_fdir, ignore_errors=True)

    # THE DRY RUN COLLAPSES ONLY WHAT CANNOT MATCH. 185 UNMATCHED-LAYOUT rows
    # against 12 of signal (manifold, 2026-10-13) buries the one row that
    # means something. What must NOT be collapsed is the whole point, so most
    # of these assert something STAYS.
    def _ue(app, ident):
        return {"app_id": app, "title": ident}
    _dead = _ue("google-chrome", "chrome:win:111")       # no file names it
    _alive = _ue("google-chrome", "chrome:win:222")      # a file still does
    _title = _ue("loupe", "holiday.png")                 # opens again anytime
    _kit = _ue("kitty", "kitty:/src/x")                  # likewise
    _appid = _ue("signal", "")                           # app-id only
    _all = [_dead, _alive, _title, _kit, _appid]
    _keep, _gone = engine._unlayout_split(_all, recorded={222})
    ck("unlayout-collapses-an-unreachable-chrome-slot", _gone == [_dead])
    ck("unlayout-keeps-a-chrome-id-a-file-still-names", _alive in _keep)
    ck("unlayout-keeps-a-title-key", _title in _keep)
    ck("unlayout-keeps-a-kitty-cwd", _kit in _keep)
    ck("unlayout-keeps-an-appid-only-key", _appid in _keep)
    ck("unlayout-loses-nothing", len(_keep) + len(_gone) == len(_all))
    # NO EVIDENCE COLLAPSES NOTHING: an unparsed session file must not read as
    # "every slot is dead", which would hide the slots a browser about to
    # start is going to claim.
    _keep2, _gone2 = engine._unlayout_split(_all, recorded=set())
    ck("unlayout-no-evidence-collapses-nothing",
       _gone2 == [] and len(_keep2) == len(_all))

def _t_snapshots(ck):
    """restoring from a stored milestone."""
    # --from spec resolution (pure half; the file lookup is driven by `list`)
    _t = date(2026, 3, 1)
    ck("spec-today", _spec_to_date("today", _t) == "2026-03-01")
    ck("spec-yesterday",     # crosses a month boundary, which is the point
       _spec_to_date("yesterday", _t) == "2026-02-28")
    ck("spec-date", _spec_to_date("2025-12-31", _t) == "2025-12-31")
    ck("spec-junk", _spec_to_date("lastweek", _t) is None)

    # EVERY EXTERNAL READER ESTABLISHES THE SHAPE IT PROMISES. Six readers
    # asked "is this a JSON object" separately and four got it wrong the
    # same way, because `except (OSError, ValueError)` is the obvious guard
    # and it is HALF of one: `null`, `[1,2]`, `"x"` and `42` all parse.
    _o_js = engine.json_object
    _jsdir = tempfile.mkdtemp(prefix="usher-jsobj-")
    try:
        _p = os.path.join(_jsdir, "x.json")
        for _lbl, _blob in (("null", "null"), ("a-list", "[1,2]"),
                            ("a-string", '"x"'), ("a-number", "42"),
                            ("unparseable", "{oops")):
            engine.write_json(_p, _blob)
            ck(f"json-object-refuses-{_lbl}", engine.json_object(_p) is None)
        ck("json-object-refuses-a-missing-file",
           engine.json_object(os.path.join(_jsdir, "nope.json")) is None)
        # THE CONTROL, or every row above passes over a reader that answers
        # None for everything.
        engine.write_json(_p, json.dumps({"a": 1}))
        ck("json-object-reads-an-object",
           engine.json_object(_p) == {"a": 1})
        # AND IT IS ONLY THE CONTAINER: what the object must CONTAIN is the
        # caller's business, so an EMPTY one is a perfectly good answer.
        engine.write_json(_p, "{}")
        ck("json-object-reads-an-empty-object", engine.json_object(_p) == {})
    finally:
        shutil.rmtree(_jsdir, ignore_errors=True)


    # ADVERSARIAL current.json, which is the file the RELAUNCH reads, so
    # anything raising out of its single reader is "nothing came back at the
    # login". Measured per shape: `null`, a list, a string and a number each
    # raised on load_snapshot's own `.get` and took the kb seed,
    # launch_missing and entries_from_snapshot with them. These notes
    # prescribe hand-seeding this file to recover an unreachable slot, so a
    # wrong shape here is a state that really happens.
    _snapdir = tempfile.mkdtemp(prefix="usher-snapshape-")
    _o_state = engine.STATE
    _W = {"id": 1, "app_id": "zzz", "title": "t", "key": "t", "cmd": None,
          "pid": -1, "output": "DP-1", "workspace": [0, 0], "pos": [1, 2],
          "size": [3, 4]}

    def _snap(blob):
        # GUARDED, so the pre-fix code fails BY NAME: without the shape
        # guard the reader RAISES rather than answering badly, and an
        # unguarded call here aborts the area instead of naming the cell.
        engine.write_json(os.path.join(engine.STATE, "current.json"), blob)
        try:
            return engine.load_snapshot()
        except Exception:                                  # noqa: BLE001
            return "RAISED"

    def _ok_snap(**kw):
        s = {"version": engine.SNAPSHOT_VERSION, "time": 1.0, "host": "h",
             "outputs": [], "windows": [dict(_W)]}
        s.update(kw)
        return json.dumps(s)

    try:
        engine.STATE = _snapdir
        for _lbl, _blob in (("null", "null"), ("list", "[1,2]"),
                            ("string", '"x"'), ("number", "42")):
            ck(f"a-snapshot-that-is-{_lbl}-is-refused", _snap(_blob) is None)
        # THE CONTROL, or every row above passes over a reader that answers
        # None for everything.
        ck("a-well-formed-snapshot-is-read",
           len((_snap(_ok_snap()) or {}).get("windows", [])) == 1)
        # `time` IS AS FUNDAMENTAL AS `version`: a snapshot that cannot be
        # DATED is refused, since every consumer that reasons about age does
        # arithmetic on it.
        ck("a-snapshot-with-no-usable-time-is-refused",
           _snap(_ok_snap(time="yesterday")) is None)
        # AND A BOOL IS NOT A NUMBER, which Python disagrees with: `True` is
        # an int, so an unguarded isinstance would date a snapshot to 1970.
        ck("a-boolean-time-is-refused", _snap(_ok_snap(time=True)) is None)
        # SHAPE, NOT FIELDS. `windows` and `outputs` are what every consumer
        # iterates, so the single reader owns them.
        # A NUMBER IS THE INPUT THAT DISTINGUISHES THE LIST GUARD from the
        # row filter below it: a string and a dict are both ITERABLE, so the
        # filter answers [] either way and a plant removing the guard is
        # invisible. Only a non-iterable reaches the TypeError the guard
        # exists for. This file's own rule, met again: ask what inputs a
        # guard tells apart, not whether the fixture reaches it.
        for _lbl, _kw in (("a-string", {"windows": "abc"}),
                          ("a-dict", {"windows": {"a": 1}}),
                          ("a-number", {"windows": 42})):
            _sn = _snap(_ok_snap(**_kw))
            ck(f"windows-that-is-{_lbl}-names-no-windows",
               isinstance(_sn, dict) and _sn.get("windows") == [])
        _mixed = _snap(_ok_snap(windows=[dict(_W), "x", None, 7]))
        # READ THE ROWS DEFENSIVELY, or the pre-fix code's surviving junk
        # rows make this an area-aborting TypeError instead of a named cell.
        _rows = (_mixed or {}).get("windows", []) if isinstance(_mixed, dict) \
            else []
        ck("a-window-row-that-is-not-an-object-is-dropped",
           [w.get("app_id") for w in _rows if isinstance(w, dict)] == ["zzz"]
           and len(_rows) == 1)
        ck("outputs-that-is-not-a-list-is-emptied",
           (_snap(_ok_snap(outputs="DP-1")) or {}).get("outputs") == [])
    finally:
        engine.STATE = _o_state
        shutil.rmtree(_snapdir, ignore_errors=True)
    ck("spec-not-a-date", _spec_to_date("2026-3-1", _t) is None)

    # a milestone becomes placement entries keyed by the RECORDED identity
    _snap = {"time": 1_800_000_000, "windows": [
        {"app_id": "kitty", "title": "usher:1⠀⠀⠀⠀[manifestor]",
         "key": "mux@manifestor:usher", "output": "DP-1",
         "workspace": [1.0, 1.0], "pos": [0.0, 0.0], "size": [800.0, 600.0]},
        {"app_id": "kitty", "title": "x:1⠀⠀⠀⠀[manifold]",
         "key": "mux@manifold:x", "output": "DP-1",
         "workspace": [1.0, 1.0], "pos": [0.0, 0.0], "size": [800.0, 600.0]},
        {"app_id": "signal", "title": "Signal", "key": "Signal",
         "output": "DP-1", "workspace": [1.0, 1.0], "pos": [0.0, 0.0],
         "size": [800.0, 600.0]}]}
    # snapshot() STAMPS WHOSE WINDOW IT IS, and only when it is not ours, so
    # the field's PRESENCE is the fact and our own snapshots are byte-for-byte
    # what they were. The relaunch paths read it.
    if os.getuid() != 0:
        class _SnapSock:
            @staticmethod
            def list_outputs():
                return [{"name": "DP-1",
                         "geometry": {"x": 0, "y": 0, "width": 100,
                                      "height": 100},
                         "workspace": {"x": 0, "y": 0, "grid_width": 1,
                                       "grid_height": 1}}]

            @staticmethod
            def list_views(**_kw):
                return [_trv("signal", "Signal", pid=os.getpid(), vid=1),
                        _trv("google-chrome", "Theirs", pid=1, vid=2)]

        _snapped = engine.snapshot(_SnapSock)["windows"]
        _by = {w["app_id"]: w for w in _snapped}
        # AND IT SURVIVES A PLUGIN WITH NO `name`, which is the BLAST RADIUS
        # rather than the fault: resolution reading that label bare raised
        # all the way out through identity into here, and a capture that
        # raises is a daemon that never learns or places again. The
        # resolution checks prove the degradation; only driving snapshot
        # proves what it was protecting.
        class _Nameless:
            def owns(self, v):
                return True

            def resolve(self, v):
                return ("ready", "nameless:1")

        _rp = engine._PLUGINS
        try:
            engine._PLUGINS = [_Nameless()]
            # GUARDED, so the pre-fix code fails BY NAME rather than
            # aborting the area: the whole point of this cell is that a
            # capture must not raise, so a raise here IS the finding and
            # wants reporting as one.
            try:
                _n = len(engine.snapshot(_SnapSock)["windows"])
            except Exception:                              # noqa: BLE001
                _n = -1
            ck("snapshot-survives-a-plugin-with-no-name", _n == len(_snapped))
        finally:
            engine._PLUGINS = _rp
        ck("snapshot-records-another-accounts-window",
           _by.get("google-chrome", {}).get("owner") == 0)
        ck("snapshot-leaves-our-own-window-unstamped",
           "owner" not in _by.get("signal", {}))
        # AND IT REDACTS THE CONTENT-BEARING FIELDS, which is a privacy
        # boundary and not tidiness: usher's state lives in the OWNER's home
        # where every one of their processes can read it, and `history/` is a
        # rolling ring, so a work window's TITLE recorded here is work content
        # in the owner's filesystem. Measured on a live box before this
        # existed: a Slack DM's correspondent, a meeting invitation naming a
        # person, and a calendar week, in current.json and two history files.
        _fr2 = _by.get("google-chrome", {})
        ck("snapshot-redacts-a-foreign-title", _fr2.get("title") == "")
        # `key` IS identity(), which falls back to the RAW TITLE for a window
        # nothing can identify, so leaving it would reinstate the leak under
        # another field name.
        ck("snapshot-redacts-the-foreign-key", _fr2.get("key") == "")
        ck("snapshot-drops-the-foreign-command", _fr2.get("cmd") is None)
        # WHAT usher STILL NEEDS SURVIVES, or the redaction has taken the
        # relaunch skip and a future restore with it.
        ck("snapshot-keeps-the-foreign-app-id",
           _fr2.get("app_id") == "google-chrome")
        ck("snapshot-keeps-the-foreign-geometry",
           _fr2.get("pos") is not None and _fr2.get("size") is not None)
        # AND OUR OWN WINDOW IS UNTOUCHED, or this would pass by redacting
        # everything.
        ck("snapshot-does-not-redact-our-own-title",
           _by.get("signal", {}).get("title") == "Signal")

    _e = entries_from_snapshot(_snap)
    ck("milestone-entries", len(_e) == 3)
    ck("milestone-keys",
       sorted(x["title"] for x in _e if x["app_id"] == "kitty")
       == ["mux@manifestor:usher", "mux@manifold:x"])
    # signal is the only window of its app here, so it keys by app_id alone
    ck("milestone-unique",
       [x["appid_only"] for x in _e if x["app_id"] == "signal"] == [True])

    # THE TWO WRITE PATHS ARE WIRED TO THE GATES, which only driving them can
    # say: upsert's own checks prove the refusal and say NOTHING about whether
    # its callers hand it the outputs the refusal needs. Both plants that drop
    # that argument passed the whole suite until these existed, which is the
    # wiring hole this package has now met eleven times.
    if os.getuid() != 0:
        def _pv(app, title, out, vid):
            v = _trv(app, title, pid=os.getpid(), vid=vid)
            v["output-name"] = out
            v["geometry"] = {"x": 10, "y": 20, "width": 300, "height": 200}
            return v

        class _CapSock:
            """One output attached, and a view parked on one that is not:
            the state between an undock and a redock, which is where a
            captured slot naming a lost output can never be placed."""
            @staticmethod
            def list_outputs():
                return [{"name": "DP-1",
                         "geometry": {"x": 0, "y": 0, "width": 1920,
                                      "height": 1080},
                         "workspace": {"x": 0, "y": 0, "grid_width": 1,
                                       "grid_height": 1}}]

            @staticmethod
            def list_views(**_kw):
                return [_pv("zzz-here", "Attached", "DP-1", 1),
                        _pv("zzz-parked", "Parked", "DP-9", 2)]

        _cap_dir = tempfile.mkdtemp(prefix="usher-capture-")
        _cap_state, _cap_ipc = engine.STATE, engine.ipc
        try:
            engine.STATE = _cap_dir
            engine.ipc = lambda: _CapSock
            with _tprofile("capwire"):
                with contextlib.redirect_stdout(io.StringIO()):
                    engine.do_capture()
                _capped = engine.load_knowledge("capwire")
            _apps = sorted(k.partition("\0")[0] for k in _capped)
            ck("capture-learns-an-attached-window", "zzz-here" in _apps)
            ck("capture-refuses-a-parked-window", "zzz-parked" not in _apps)
            # AND THE SEED PATH, the other caller: a store that does not exist
            # yet is seeded from the last snapshot, so a new desk's FIRST
            # store is written by upsert. The snapshot do_capture just wrote
            # names a lost output, so seeding must refuse it too.
            os.remove(os.path.join(_cap_dir, "knowledge-capwire.json"))
            with _tprofile("capwire"):
                _seeded = engine.load_knowledge("capwire")
            _sapps = sorted(k.partition("\0")[0] for k in _seeded)
            ck("seed-learns-an-attached-window", "zzz-here" in _sapps)
            ck("seed-refuses-a-parked-window", "zzz-parked" not in _sapps)
        finally:
            engine.STATE, engine.ipc = _cap_state, _cap_ipc
            shutil.rmtree(_cap_dir, ignore_errors=True)

def _t_profiles(ck):
    """the display-profile id and its paths."""
    # display profiles: the id is a filename, and a monitor set must map to the
    # SAME id every time or a layout is lost on every replug.
    _o = lambda n, w, h: {"name": n, "geometry": {"width": w, "height": h}}
    _a = {"outputs": [_o("DP-1", 1920, 1080), _o("DP-2", 2560, 1440)]}
    _b = {"outputs": [_o("DP-2", 2560, 1440), _o("DP-1", 1920, 1080)]}
    ck("profile-stable", _derived_id(_a) == _derived_id(_b))   # order-blind
    ck("profile-geometry-matters",
       _derived_id(_a) != _derived_id({"outputs": [_o("DP-1", 1920, 1080),
                                                   _o("DP-2", 3840, 2160)]}))
    ck("profile-subset-differs",
       _derived_id(_a) != _derived_id({"outputs": [_o("DP-1", 1920, 1080)]}))
    ck("profile-none", _derived_id({"outputs": []}) is None)
    ck("profile-safe", _safe_profile("../../etc/passwd") == ".._.._etc_passwd")
    ck("profile-safe-empty", _safe_profile("") == "default")
    with _tprofile("testset"):
        ck("profile-env", profile_id() == "testset")
        ck("profile-paths", kb_path().endswith("knowledge-testset.json")
           and schema_path().endswith("knowledge-testset.schema"))

def _t_migration(ck):
    """store migration: stamping, and the legacy merge."""
    with _tprofile("testset"):
        _t_migration_body(ck)

def _t_migration_body(ck):
    # A NEW profile must be stamped CURRENT the moment it is created. It was
    # not, and the next load then judged the unstamped store stale and dropped
    # every chrome + kitty entry it had just learned, and each new monitor set
    # silently losing its browser and terminal placements exactly once.
    import tempfile
    # STATE is what this sandboxes; XDG_STATE_HOME is
    _st = engine.STATE
    _tmp = tempfile.mkdtemp()   # read at import and cannot matter here
    try:
        engine.STATE = _tmp
        load_knowledge()                     # first touch of a fresh profile
        ck("new-profile-stamped", os.path.exists(schema_path())
           and open(schema_path()).read().strip() == KB_SCHEMA)
        _kb = {kkey("google-chrome", "example.com"): {
            "app_id": "google-chrome", "title": "example.com",
            "appid_only": False, "last_seen": 1_800_000_000}}
        save_knowledge(_kb, engine.profile_id())
        ck("new-profile-survives-reload", len(load_knowledge()) == 1)

        # A legacy store must be MERGED even when a profile store already
        # exists. Skipping it there orphaned 1019 placements on manifold and
        # left placement silently doing almost nothing.
        _e = lambda t: {"app_id": "google-chrome", "title": t,
                        "appid_only": False, "last_seen": 1_800_000_000}
        with open(os.path.join(engine.STATE, "knowledge.json"), "w") as f:
            json.dump({kkey("google-chrome", "old.example"): _e("old.example"),
                       kkey("google-chrome", "example.com"): _e("CLOBBER")},
                      f)
        _merged = load_knowledge()
        ck("legacy-merged-into-existing", len(_merged) == 2)

        # THE SCHEMA 7 RULE, which DELETES stored placements, so it is worth
        # pinning from both directions. A chrome entry whose key is not a slot
        # is what the retired title fallback wrote and nothing can ever match
        # it; a chrome SLOT is current and must survive; another app's
        # title-keyed entry is that app's only possible key and must survive.
        _e7 = lambda t: {"app_id": "google-chrome", "title": t,
                         "appid_only": False, "last_seen": 1_800_000_000}
        _s7 = {kkey("google-chrome", "chrome:win:42"): _e7("chrome:win:42"),
               kkey("Google-chrome", "chrome:win:43"): _e7("chrome:win:43"),
               kkey("google-chrome", "Inbox (7) - Google Chrome"):
                   _e7("Inbox (7) - Google Chrome"),
               kkey("google-chrome", "chrome:win:notanumber"):
                   _e7("chrome:win:notanumber"),
               kkey("slack", "Slack"): {"app_id": "slack", "title": "Slack",
                                        "appid_only": False,
                                        "last_seen": 1_800_000_000},
               kkey("kitty", "term:resume"): {"app_id": "kitty",
                                              "title": "term:resume",
                                              "appid_only": False,
                                              "last_seen": 1_800_000_000}}
        _from6 = dict(_s7)
        ck("migrate7-drops-title-keyed-chrome",
           _migrate_store(_from6, "6") == 2)
        ck("migrate7-keeps-the-slots",
           sorted(k.split("\x00")[1] for k in _from6)
           == ["Slack", "chrome:win:42", "chrome:win:43", "term:resume"])
        ck("migrate7-is-idempotent", _migrate_store(_from6, "7") == 0)
        # from a PRE-6 store the key shapes themselves are stale, so chrome and
        # kitty go wholesale, the older rule, still applied from older stamps
        _from4 = dict(_s7)
        _migrate_store(_from4, "4")
        ck("migrate-pre6-drops-chrome-and-kitty",
           sorted(k.split("\x00")[1] for k in _from4) == ["Slack"])
        _unstamped = dict(_s7)
        _migrate_store(_unstamped, "")
        ck("migrate-unstamped-treated-as-oldest",
           sorted(k.split("\x00")[1] for k in _unstamped) == ["Slack"])
        ck("legacy-does-not-clobber",
           _merged[kkey("google-chrome", "example.com")]["title"]
           == "example.com")
        ck("legacy-retired",
           not os.path.exists(os.path.join(engine.STATE, "knowledge.json"))
           and os.path.exists(os.path.join(engine.STATE,
                                           "knowledge.json.pre-profile")))
        ck("legacy-merge-is-once", len(load_knowledge()) == 2)

        # A STORE A HUMAN EDITED. These notes prescribe editing this file by
        # hand in five separate repair recipes, so "valid JSON that is not a
        # store" is a state that really happens. Measured per shape with a
        # dict control before this guard: prune_kb raised in the CAPTURE
        # loop, matched_key in the PLACER, and save_knowledge then WROTE THE
        # CORRUPTION BACK, so the daemon went blind and persisted its cause.
        _corrupt = os.path.join(engine.STATE, "corrupt")
        os.makedirs(_corrupt, exist_ok=True)
        _cst = engine.STATE
        _good = {"app_id": "zzz", "title": "t", "output": "DP-1",
                 "workspace": [0, 0], "pos": [1, 2], "size": [3, 4],
                 "appid_only": False, "last_seen": 1.0}
        try:
            engine.STATE = _corrupt
            with _tprofile("corrupt"):
                for _lbl, _blob in (("null", "null"), ("list", "[1,2,3]"),
                                    ("string", '"hello"'), ("number", "42"),
                                    ("not-json", "{nope")):
                    engine.write_json(kb_path(), _blob)
                    engine.write_json(schema_path(), KB_SCHEMA)
                    # GUARDED, because the entry guard's `.items()` is
                    # deliberately FUSED to the top-level one: that is what
                    # makes the top-level guard impossible to remove
                    # quietly, and it means the pre-fix code RAISES out of
                    # load_knowledge rather than returning a bad value.
                    # Reported by name here all the same.
                    try:
                        _l = load_knowledge()
                    except Exception:                      # noqa: BLE001
                        _l = None
                    # THE TYPE IS THE CLAIM, not emptiness: handing the
                    # daemon a list or a string is what broke it.
                    ck(f"a-store-that-is-{_lbl}-loads-as-a-dict",
                       isinstance(_l, dict))
                # ONE BAD ENTRY MUST NOT COST THE STORE, which is the more
                # reachable half since a hand edit touches one ROW, and an
                # EMPTY object must still be KEPT: that is the boundary
                # between "not an object" and "an object with nothing in
                # it", and the matchers already skip the second.
                engine.write_json(kb_path(), json.dumps({
                    "zzz\x00good": dict(_good), "zzz\x00s": "x",
                    "zzz\x00l": [1], "zzz\x00n": None, "zzz\x00num": 7,
                    "zzz\x00empty": {}}))
                _l = load_knowledge()
                ck("a-bad-entry-is-dropped",
                   sorted(_l) == ["zzz\x00empty", "zzz\x00good"])
                ck("the-good-entry-survives-a-bad-one",
                   _l["zzz\x00good"]["pos"] == [1, 2])
                # AND THE CONTROL: with nothing wrong, nothing is dropped.
                engine.write_json(kb_path(), json.dumps({
                    "zzz\x00good": dict(_good), "zzz\x00b": dict(_good)}))
                ck("a-clean-store-loses-nothing",
                   len(load_knowledge()) == 2)

                # A CORRUPT DORMANT STORE MUST NOT BREAK THE LIVE LOAD,
                # which is the worst of the six readers in this class:
                # migrate_stores walks EVERY profile on every load, so a
                # store for a monitor set nobody has plugged in for months
                # took down the daemon's startup. Measured on manifestor:
                # five dormant stores, 47 to 71 days old, hand-editable,
                # and nothing ever reads them.
                engine.write_json(kb_path(), json.dumps(
                    {"zzz\x00good": dict(_good)}))
                for _lbl, _blob in (("null", "null"), ("a-list", "[1,2]"),
                                    ("a-string", '"x"'), ("junk", "{oops")):
                    engine.write_json(
                        os.path.join(engine.STATE, "knowledge-dorm.json"),
                        _blob)
                    engine.write_json(
                        os.path.join(engine.STATE, "knowledge-dorm.schema"),
                        "4")      # stale, so migrate_stores touches it
                    try:
                        _n = len(load_knowledge())
                    except Exception:                      # noqa: BLE001
                        _n = -1
                    ck(f"a-dormant-store-that-is-{_lbl}-spares-the-live-one",
                       _n == 1)
                os.remove(os.path.join(engine.STATE, "knowledge-dorm.json"))

                # THE LEGACY STORE, merged on every load: it raised `has no
                # attribute items` for every non-object shape. LEFT ALONE
                # rather than retired when unreadable, since the file is the
                # only copy of those placements.
                _leg = os.path.join(engine.STATE, "knowledge.json")
                for _lbl, _blob in (("null", "null"), ("a-list", "[1,2]")):
                    engine.write_json(_leg, _blob)
                    try:
                        _n = len(load_knowledge())
                    except Exception:                      # noqa: BLE001
                        _n = -1
                    ck(f"a-legacy-store-that-is-{_lbl}-is-left-alone",
                       _n == 1 and os.path.exists(_leg))
                os.remove(_leg)

                # ANOTHER DESK'S STORE, which the surface seed reads. Its
                # existing "a corrupt store is skipped rather than fatal"
                # check passed for the WRONG REASON: it only ever saw an
                # unparseable file, and valid JSON that is not an object
                # went straight through to `kb.get`.
                for _lbl, _blob in (("null", "null"), ("a-list", "[1,2]")):
                    engine.write_json(
                        os.path.join(engine.STATE, "knowledge-far.json"),
                        _blob)
                    try:
                        _r = engine.other_profile_entries("zzz", "i")
                    except Exception:                      # noqa: BLE001
                        _r = None
                    ck(f"another-desks-store-that-is-{_lbl}-is-skipped",
                       _r == [])
                os.remove(os.path.join(engine.STATE, "knowledge-far.json"))

                # AND THE INVERT STORE, whose docstring already promised
                # that "a missing or corrupt file means none are inverted"
                # and whose code did not keep it: `null` parsed, so it
                # answered None and is_inverted then raised out of
                # snapshot() for every window on every capture.
                _inv = engine.INVERT_STORE
                try:
                    engine.INVERT_STORE = os.path.join(engine.STATE, "inv")
                    for _lbl, _blob in (("null", "null"),
                                        ("a-list", "[1,2]"),
                                        ("a-number", "42")):
                        engine.write_json(engine.INVERT_STORE, _blob)
                        ck(f"inverts-that-are-{_lbl}-mean-none",
                           engine.load_inverts() == {})
                        # GUARDED: the pre-fix reader answers None and
                        # is_inverted then RAISES, which is the fault, so
                        # it wants naming rather than aborting the area.
                        try:
                            _iv_r = engine.is_inverted(
                                None, 7, engine.load_inverts())
                        except Exception:                  # noqa: BLE001
                            _iv_r = "RAISED"
                        ck(f"is-inverted-survives-{_lbl}", _iv_r is False)
                    # THE CONTROL, or the rows above pass over a reader
                    # that answers {} for everything.
                    engine.write_json(engine.INVERT_STORE, '{"7": "invert"}')
                    ck("inverts-reads-a-real-store",
                       engine.load_inverts() == {"7": "invert"})
                finally:
                    engine.INVERT_STORE = _inv
        finally:
            engine.STATE = _cst
    finally:
        engine.STATE = _st
        shutil.rmtree(_tmp, ignore_errors=True)

def _t_displays(ck):
    """DOCKING: the store must not follow the daemon across a display change,
    and a collapse must not be learned as the new truth.

    The whole area exists because of one measured fault: the daemon loads the
    store ONCE at worker init while save_knowledge resolved the profile FRESH
    on every write, so a single capture after an undock wrote the docked
    layout into the laptop store. A docked laptop does that twice a day and
    the two stores then converge until per-profile stores have stopped
    existing."""
    from .watch import Watcher
    import time as _time

    # ---- save_knowledge writes where the data CAME FROM -------------------
    _st = engine.STATE
    _tmp = tempfile.mkdtemp(prefix="usher-dock-", dir="/var/tmp")
    _rprof = os.environ.get("USHER_PROFILE")
    try:
        engine.STATE = _tmp
        os.environ["USHER_PROFILE"] = "DOCKED"
        _docked = {engine.kkey("signal", ""): {
            "app_id": "signal", "title": "", "appid_only": True,
            "output": "DP-3", "workspace": [2, 0], "pos": [10, 10],
            "size": [800, 600], "last_seen": _time.time()}}
        _kb, _prof = engine.kb_for_profile()
        ck("kb-for-profile-pairs-the-two", _prof == "DOCKED" and _kb == {})
        engine.save_knowledge(_docked, "DOCKED")

        # The monitors change under a daemon that is still holding the docked
        # store. This is the exact sequence that was destructive.
        os.environ["USHER_PROFILE"] = "LAPTOP"
        engine._PROFILE.update({"id": None, "at": 0.0})
        ck("profile-follows-the-monitors", engine.profile_id() == "LAPTOP")
        engine.save_knowledge(_docked, "DOCKED")   # as the capture loop does
        ck("a-save-cannot-land-in-another-profile",
           engine.load_knowledge("LAPTOP") == {})
        ck("the-other-desk-keeps-its-layout",
           list(engine.load_knowledge("DOCKED")) == [engine.kkey("signal",
                                                                "")])
        # And the pair is honoured in the other direction: asking for a
        # profile by name must not be overridden by the current one.
        ck("load-knowledge-takes-a-profile",
           len(engine.load_knowledge("DOCKED")) == 1)
    finally:
        engine.STATE = _st
        if _rprof is None:
            os.environ.pop("USHER_PROFILE", None)
        else:
            os.environ["USHER_PROFILE"] = _rprof
        engine._PROFILE.update({"id": None, "at": 0.0})
        shutil.rmtree(_tmp, ignore_errors=True)

    # ---- a placement on an output nobody has is not readable --------------
    _outs = [{"name": "eDP-1"}, {"name": "DP-3"}]
    ck("attached-output-is-readable",
       not engine.unreadable_placement({"output": "DP-3"}, _outs))
    ck("vanished-output-is-not-readable",
       engine.unreadable_placement({"output": "DP-9"}, _outs))
    # preserve-output parks the views of an unplugged monitor here, so this is
    # the normal state of every external window while the dock is out.
    ck("a-parked-view-is-not-readable",
       engine.unreadable_placement({"output": "null"}, _outs))
    # NO OUTPUT LIST CONCLUDES NOTHING: the fail-safe direction, and the same
    # guard recorded_window_ids and seen_terms take.
    ck("no-output-list-concludes-nothing",
       not engine.unreadable_placement({"output": "DP-9"}, [])
       and not engine.unreadable_placement({"output": "DP-9"}, None))

    # ---- learn() holds such a window back, WITHOUT purging it ------------
    _w = lambda vid, app, title, out: {
        "id": vid, "app_id": app, "title": title, "key": title,
        "output": out, "workspace": [0, 0], "pos": [5, 5], "size": [9, 9],
        "pid": -1, "cmd": None}
    _kb = {}
    engine.learn(_kb, {}, [_w(1, "signal", "Signal", "null")], 1_800_000_000,
                 outputs=_outs)
    ck("learn-skips-an-unreadable-placement", _kb == {})
    _kb = {}
    engine.learn(_kb, {}, [_w(1, "signal", "Signal", "eDP-1")],
                 1_800_000_000, outputs=_outs)
    ck("learn-still-takes-a-readable-one", len(_kb) == 1)
    # THE SUBTLE HALF. A terminal parked on a dead output is still HERE, so
    # the purge must not read it as gone and drop the slot. `hold` is the
    # right mechanism precisely because it does not reach the purge.
    _tk = engine.kkey("kitty", "term:resume")
    _kb = {_tk: {"app_id": "kitty", "title": "term:resume",
                 "output": "DP-3", "workspace": [1, 1], "pos": [1, 1],
                 "size": [9, 9], "last_seen": 1_800_000_000}}
    engine.learn(_kb, {}, [_w(2, "kitty", "term:resume", "null")],
                 1_800_000_000, seen={"term:resume"}, outputs=_outs)
    ck("a-parked-terminal-keeps-its-slot", _tk in _kb)
    ck("a-parked-terminal-slot-is-not-overwritten",
       _kb[_tk]["output"] == "DP-3" and _kb[_tk]["workspace"] == [1, 1])

    # ---- a slot names a MONITOR, not a cable -----------------------------
    _o = {"eDP-1": {"name": "eDP-1", "id": 1},
          "DP-3": {"name": "DP-3", "id": 2}}
    # DP-9 IS IN THE PANEL MAP AND NOT IN THE OUTPUTS, which is a real state
    # rather than a contrived one: hwdp reports what is ATTACHED (it reads DRM)
    # while the compositor reports what is ENABLED, so a panel switched off in
    # the kanshi profile ("ignore the built-in when docked") appears in one and
    # not the other. Without it the `name in outputs` guard is never exercised,
    # and a planted regression removing that guard passed the whole suite.
    _pm = {"eDP-1": "aaaaaaaaaaaa", "DP-3": "bbbbbbbbbbbb",
           "DP-9": "dddddddddddd"}

    # THE CASE THAT PLACES A WINDOW ON THE WRONG MONITOR. The entry was
    # learned when this panel was DP-2; the panel is now DP-3, and something
    # else may be on DP-2. Resolving by name is not merely a miss, it puts the
    # window on a different physical screen.
    _e = {"output": "DP-2", "panel": "bbbbbbbbbbbb"}
    ck("a-slot-follows-its-panel-to-a-new-connector",
       engine.entry_output(_e, _o, _pm) is _o["DP-3"])
    _e2 = {"output": "eDP-1", "panel": "bbbbbbbbbbbb"}
    ck("the-panel-beats-a-stale-name-that-is-still-attached",
       engine.entry_output(_e2, _o, _pm) is _o["DP-3"])

    # EVERY UNCERTAIN CASE FALLS BACK TO THE NAME, which is what usher did
    # before panels were known and is the fail-safe direction.
    ck("no-panel-recorded-falls-back-to-the-name",
       engine.entry_output({"output": "eDP-1"}, _o, _pm) is _o["eDP-1"])
    ck("no-panel-map-falls-back-to-the-name",
       engine.entry_output(_e2, _o, {}) is _o["eDP-1"])
    # A panel the map KNOWS but the compositor is not showing: attached and
    # disabled. The guard this exercises is `name in outputs`.
    ck("an-attached-but-disabled-panel-falls-back-to-the-name",
       engine.entry_output({"output": "eDP-1", "panel": "dddddddddddd"},
                           _o, _pm) is _o["eDP-1"])
    ck("a-panel-the-map-never-heard-of-falls-back-to-the-name",
       engine.entry_output({"output": "eDP-1", "panel": "cccccccccccc"},
                           _o, _pm) is _o["eDP-1"])
    ck("neither-panel-nor-name-attached-is-None",
       engine.entry_output({"output": "HDMI-9", "panel": "cccccccccccc"},
                           _o, _pm) is None)
    ck("a-disabled-panel-with-no-attached-name-is-None",
       engine.entry_output({"output": "DP-9", "panel": "dddddddddddd"},
                           _o, _pm) is None)
    ck("no-entry-at-all-is-None", engine.entry_output(None, _o, _pm) is None)

    # A PLACEMENT ONTO A RENAMED CONNECTOR MUST READ AS LANDED. Comparing the
    # view against the entry's stored NAME would call a correct placement
    # failed and burn the whole retry budget re-issuing it.
    _ro = {"name": "DP-3", "id": 2, "geometry": {"width": 100, "height": 100,
                                                 "x": 0, "y": 0},
           "workspace": {"x": 0, "y": 0}}
    _slot = {"output": "DP-2", "panel": "bbbbbbbbbbbb", "workspace": [0, 0],
             "pos": [10, 10], "size": [50, 50]}
    _view = {"output-name": "DP-3",
             "geometry": {"x": 10, "y": 10, "width": 50, "height": 50}}
    ck("a-placement-on-the-renamed-connector-reads-as-landed",
       engine.placement_landed(_view, _slot, _ro))
    ck("a-placement-on-the-wrong-output-still-reads-as-missed",
       not engine.placement_landed({**_view, "output-name": "eDP-1"},
                                   _slot, _ro))

    # AND THE PANEL IS RECORDED when a window is learned, or none of the above
    # ever engages on a real store.
    _rpm = engine.panel_map
    try:
        engine.panel_map = lambda fresh=False: {"DP-3": "bbbbbbbbbbbb"}
        _ke = engine.kb_entry({"app_id": "signal", "title": "Signal",
                               "output": "DP-3", "workspace": [0, 0],
                               "pos": [1, 2], "size": [3, 4]},
                              "Signal", True, 1_800_000_000)
        ck("kb-entry-records-the-panel", _ke["panel"] == "bbbbbbbbbbbb")
        ck("kb-entry-keeps-the-connector-too", _ke["output"] == "DP-3")
        _ke2 = engine.kb_entry({"app_id": "signal", "title": "Signal",
                                "output": "HDMI-1", "workspace": [0, 0],
                                "pos": [1, 2], "size": [3, 4]},
                               "Signal", True, 1_800_000_000)
        ck("an-unknown-output-records-an-empty-panel", _ke2["panel"] == "")
    finally:
        engine.panel_map = _rpm

    # ---- and EVERY placement path goes through the resolver ---------------
    # The checks above prove the resolver; they say nothing about whether the
    # placers call it, and a bug living in the code AROUND the tested part is
    # this project's most repeated shape. The old form is a precise code
    # pattern rather than a name in prose, so matching it is sharp rather than
    # noisy: `outs.get(e["output"])` is what every site used to be.
    _srcs = {}
    for _m in ("engine", "watch", "doctor"):
        with open(os.path.join(os.path.dirname(__file__), _m + ".py")) as _f:
            _srcs[_m] = _f.read()
    _old = [m for m, s in _srcs.items() if '.get(e["output"])' in s]
    ck("no-placement-path-resolves-by-name-alone", _old == [])
    _uses = sum(s.count("entry_output(") for s in _srcs.values())
    # VACUITY GUARD: the check above passes trivially over a package that has
    # stopped calling the resolver at all, which is the same bug.
    ck("the-resolver-is-actually-wired", _uses >= 5)

    # ---- the SURFACE MAP: hwdp's contract, parsed and spent --------------
    _row = ("code DP-2 0 0 0 0 3840 2160\n"
            "comms DP-2 1 0 0 0 3840 1080\n"
            "ref DP-2 1 0 0 1080 3840 1080\n")
    _m, _w = engine._parse_surfaces(_row)
    ck("surfaces-parse-the-eight-fields",
       _w == "" and sorted(_m) == ["code", "comms", "ref"])
    ck("surfaces-parse-the-rect",
       _m["ref"] == {"output": "DP-2", "workspace": [1, 0],
                     "pos": [0, 1080], "size": [3840, 1080]})
    # A BAD LINE REFUSES THE WHOLE MAP, matching what hwdp does with a bad
    # FILE. Half a map seeds windows into wrong places silently.
    _m2, _w2 = engine._parse_surfaces(_row + "oops DP-2 1 0\n")
    ck("surfaces-a-short-line-refuses-the-whole-map", _m2 == {} and _w2)
    _m3, _w3 = engine._parse_surfaces("a DP-2 0 0 0 0 x 9\n")
    ck("surfaces-a-non-numeric-field-refuses-the-whole-map",
       _m3 == {} and _w3)
    ck("surfaces-an-empty-answer-is-trustworthy",
       engine._parse_surfaces("") == ({}, ""))

    # ---- surface_map's STATUS table, which had no checks at all ---------
    # Where a planted regression hid: reading a non-zero status as an empty
    # map is exactly the three-states bug, and only _parse_surfaces was
    # covered. subprocess.run is stubbed, so no hwdp is needed.
    class _R:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    _rrun, _rwhich = engine.subprocess.run, engine.shutil.which
    try:
        engine.shutil.which = lambda n: "/usr/bin/hwdp"
        engine._SURFACES.update({"map": None, "why": "", "at": 0.0})
        engine.subprocess.run = lambda *a, **k: _R(0, _row)
        _sm, _sw = engine.surface_map(fresh=True)
        ck("surface-map-reads-a-good-answer", _sw == "" and len(_sm) == 3)
        engine.subprocess.run = lambda *a, **k: _R(0, "")
        ck("surface-map-no-file-is-trustworthy-and-empty",
           engine.surface_map(fresh=True) == ({}, ""))
        engine.subprocess.run = lambda *a, **k: _R(2, "", "it is broken")
        _sm, _sw = engine.surface_map(fresh=True)
        ck("surfaces-NOT-AVAILABLE-is-not-an-empty-map",
           _sm == {} and "exited 2" in _sw and "broken" in _sw)
        engine.subprocess.run = lambda *a, **k: _R(3, "", "no session")
        _sm3, _sw3 = engine.surface_map(fresh=True)
        ck("surface-map-no-session-says-so", _sm3 == {} and "exited 3" in _sw3)
        # THE INVARIANT consumers rely on, asserted rather than duplicated in
        # every caller: a `why` always comes with an empty map.
        ck("a-why-always-comes-with-an-empty-map",
           all(not m for m, wy in
               [engine.surface_map(fresh=True)] if wy))
        engine.subprocess.run = lambda *a, **k: _R(0, "bad line here\n")
        _sm4, _sw4 = engine.surface_map(fresh=True)
        ck("a-broken-line-reaches-the-caller-as-a-why",
           _sm4 == {} and _sw4)
        engine.shutil.which = lambda n: None
        _sm5, _sw5 = engine.surface_map(fresh=True)
        ck("no-hwdp-is-a-why-not-a-silent-empty",
           _sm5 == {} and "hwdp" in _sw5)
    finally:
        engine.subprocess.run, engine.shutil.which = _rrun, _rwhich
        engine._SURFACES.update({"map": None, "why": "", "at": 0.0})

    # ---- the cell is hwdp's passthrough, so usher checks it --------------
    _g = {"DP-2": {"name": "DP-2",
                   "workspace": {"x": 0, "y": 0, "grid_width": 3,
                                 "grid_height": 3}}}
    ck("a-cell-inside-the-grid-fits",
       engine.surface_cell_fits(_m["comms"], _g))
    ck("a-cell-outside-the-grid-does-not",
       not engine.surface_cell_fits(
           {"output": "DP-2", "workspace": [5, 9]}, _g))
    ck("a-surface-on-an-unattached-output-does-not-fit",
       not engine.surface_cell_fits(
           {"output": "HDMI-9", "workspace": [0, 0]}, _g))
    # NO GRID REPORTED CONCLUDES NOTHING, the fail-safe direction this file
    # takes everywhere else (recorded_window_ids, seen_terms, panel_map).
    ck("no-grid-reported-concludes-nothing",
       engine.surface_cell_fits(
           {"output": "DP-2", "workspace": [9, 9]},
           {"DP-2": {"name": "DP-2", "workspace": {"x": 0, "y": 0}}}))

    # ---- which surface a placement sits in ------------------------------
    _win = lambda ws, pos, size, out="DP-2": {
        "output": out, "workspace": ws, "pos": pos, "size": size}
    ck("surface-of-picks-the-half-the-centre-is-in",
       engine.surface_of(_win([1, 0], [100, 1200], [800, 600]), _m) == "ref")
    ck("surface-of-picks-the-other-half",
       engine.surface_of(_win([1, 0], [100, 100], [800, 600]), _m) == "comms")
    ck("surface-of-finds-a-full-surface",
       engine.surface_of(_win([0, 0], [10, 10], [50, 50]), _m) == "code")
    ck("surface-of-ignores-another-cell",
       engine.surface_of(_win([2, 2], [100, 100], [800, 600]), _m) == "")
    ck("surface-of-ignores-another-output",
       engine.surface_of(_win([1, 0], [100, 100], [800, 600], "eDP-1"), _m)
       == "")
    ck("surface-of-with-no-map-is-empty",
       engine.surface_of(_win([1, 0], [1, 1], [2, 2]), {}) == "")

    # ---- reading the OTHER desks' stores, which is real file I/O ---------
    _st2 = engine.STATE
    _sd = tempfile.mkdtemp(prefix="usher-others-", dir="/var/tmp")
    try:
        engine.STATE = _sd
        _k = engine.kkey("slack", "")
        for prof, surf, seen in (("HOME", "comms", 10.0),
                                 ("OFFICE", "ref", 99.0),
                                 ("HERE", "nope", 50.0)):
            with open(os.path.join(_sd, f"knowledge-{prof}.json"), "w") as f:
                json.dump({_k: {"app_id": "slack", "surface": surf,
                                "size": [10, 10], "last_seen": seen}}, f)
        _got = engine.other_profile_entries("slack", "", "HERE")
        ck("other-desks-exclude-the-one-we-are-on",
           [e["surface"] for e in _got] == ["ref", "comms"])
        ck("other-desks-come-back-newest-first",
           _got[0]["last_seen"] == 99.0)
        ck("an-identity-no-other-desk-knows-is-empty",
           engine.other_profile_entries("nosuch", "", "HERE") == [])
        # AN UNREADABLE STORE IS SKIPPED, not fatal: one corrupt file must not
        # cost the seed from every other desk.
        with open(os.path.join(_sd, "knowledge-BROKEN.json"), "w") as f:
            f.write("{not json")
        ck("a-corrupt-store-is-skipped-not-fatal",
           len(engine.other_profile_entries("slack", "", "HERE")) == 2)
        # AND THE APP-ID-ONLY KEY IS TRIED TOO, or a uniquely-identified app
        # like Signal could never be seeded.
        ck("the-app-id-only-key-is-tried",
           len(engine.other_profile_entries("slack", "whatever", "HERE")) == 2)
    finally:
        engine.STATE = _st2
        shutil.rmtree(_sd, ignore_errors=True)

    # ---- the SEED: the name is the bridge between desks ------------------
    _away = {"app_id": "slack", "title": "", "appid_only": True,
             "output": "eDP-1", "workspace": [2, 0], "pos": [40, 50],
             "size": [900, 700], "surface": "ref", "last_seen": 100.0}
    _seed = engine.surface_seed([_away], _m)
    ck("a-seed-lands-on-this-desk's-surface-of-that-name",
       _seed["output"] == "DP-2" and _seed["workspace"] == [1, 0]
       and _seed["pos"] == [0, 1080])
    ck("a-seed-keeps-the-window's-own-size",
       _seed["size"] == [900, 700])
    ck("a-seed-says-where-it-came-from", _seed["seeded_from"] == "ref")
    # CLAMPED, or a window taller than the half overflows it.
    _tall = dict(_away, size=[9000, 1800])
    ck("a-seed-is-clamped-to-the-surface",
       engine.surface_seed([_tall], _m)["size"] == [3840, 1080])
    # AND IT CANNOT INVENT ONE. No surface recorded, or a name this desk does
    # not have, both decline: a seed is allowed to be approximate, never
    # fabricated.
    ck("no-surface-recorded-is-no-seed",
       engine.surface_seed([dict(_away, surface="")], _m) is None)
    ck("a-name-this-desk-lacks-is-no-seed",
       engine.surface_seed([dict(_away, surface="nowhere")], _m) is None)
    ck("nothing-from-another-desk-is-no-seed",
       engine.surface_seed([], _m) is None)
    # NEWEST DESK WINS when several remember it, since `others` arrives
    # sorted and the first usable one is taken.
    ck("the-newest-other-desk-wins",
       engine.surface_seed([dict(_away, surface="comms"),
                            dict(_away, surface="ref")], _m)["pos"]
       == [0, 0])

    # ---- and a learned entry RECORDS its surface -------------------------
    _rsm, _rpm = engine.surface_map, engine.panel_map
    try:
        engine.surface_map = lambda fresh=False: (_m, "")
        engine.panel_map = lambda fresh=False: {}
        _ke = engine.kb_entry(
            {"app_id": "x", "title": "X", "output": "DP-2",
             "workspace": [1, 0], "pos": [100, 1200], "size": [800, 600]},
            "X", True, 1_800_000_000)
        ck("kb-entry-records-the-surface", _ke["surface"] == "ref")
    finally:
        engine.surface_map, engine.panel_map = _rsm, _rpm

    # ---- what a display event calls for ----------------------------------
    ck("redisplay-same-monitors-does-nothing",
       engine.redisplay_plan("abc", "abc", 123) == "none")
    ck("redisplay-asks-the-daemon-when-there-is-one",
       engine.redisplay_plan("abc", "xyz", 123) == "ask")
    ck("redisplay-acts-here-with-no-daemon",
       engine.redisplay_plan("abc", "xyz", None) == "here")
    # The first event after login has nothing to compare against and IS a
    # change, which is what you want at login.
    ck("redisplay-first-event-is-a-change",
       engine.redisplay_plan("", "xyz", 123) == "ask")
    # A degenerate input: no resolvable profile concludes nothing.
    ck("redisplay-no-profile-does-nothing",
       engine.redisplay_plan("abc", "", 123) == "none")

    # ---- the daemon's side of it, on a real Watcher -----------------------
    w = Watcher(launch=False)
    _wmod = sys.modules[Watcher.__module__]
    _rrf, _rwrf = engine.REDISPLAY_FILE, _wmod.REDISPLAY_FILE
    _rlog, _rload = engine.logline, engine.load_knowledge
    _rwload = _wmod.load_knowledge
    _rd = tempfile.mkdtemp(prefix="usher-redisp-", dir="/var/tmp")
    try:
        engine.REDISPLAY_FILE = os.path.join(_rd, "usher.redisplay")
        _wmod.REDISPLAY_FILE = engine.REDISPLAY_FILE
        engine.logline = lambda *a, **k: None
        _asked = []
        _wmod.load_knowledge = lambda p=None: (_asked.append(p)
                                               or {"newdesk\x00": {}})
        w.kb, w.kb_profile = {"olddesk\x00": {}}, "DOCKED"
        w.placed.add(7)
        w.slot_held["olddesk\x00"] = 7
        w.verify[7] = {"due": 0}
        w.place_tries[7] = 3
        w.late_ok.add(7)
        w.st["recheck"] = False
        with open(engine.REDISPLAY_FILE, "w") as f:
            f.write("LAPTOP\n")
        _got = w._take_redisplay()
        ck("redisplay-request-is-read", _got == "LAPTOP")
        ck("redisplay-adopts-the-new-profile", w.kb_profile == "LAPTOP")
        ck("redisplay-reloads-that-profiles-store",
           _asked == ["LAPTOP"] and list(w.kb) == ["newdesk\x00"])
        # EVERY LEDGER IS VOID: `placed` would dedup a window out of being
        # re-placed, and slot_held names outputs that may be gone.
        ck("redisplay-voids-the-placement-ledgers",
           not w.placed and not w.slot_held and not w.verify
           and not w.place_tries and not w.late_ok)
        ck("redisplay-requests-a-placement-sweep", w.st["recheck"] is True)
        ck("redisplay-is-consumed",
           not os.path.exists(engine.REDISPLAY_FILE))
        # It ends the hold, but not before the re-place can be read back.
        ck("redisplay-holds-for-the-verify-budget",
           w._in_transition()
           and w.transition_until <= _time.time() + sum(_wmod.PLACE_VERIFY)
           + 1.5)
        _n = len(_asked)
        ck("redisplay-absent-request-is-a-no-op",
           w._take_redisplay() == "" and len(_asked) == _n)

        # ---- A SETTLED WINDOW MUST BE PLACEABLE AFTER A DOCK --------------
        # The bug this pins shipped in the first version of _take_redisplay:
        # it voided `placed` and asked for a sweep, and the sweep placed
        # NOTHING, because a window that mapped hours ago is long past its
        # PLACE_GRACE deadline and late_ok's one-late-chance needs first_look,
        # false for a window already identified. Both gates refused every
        # window the dock existed to move, while the log said "re-placing".
        class _Sock:
            """Just enough place_sock for _adopt_profile and _place_view."""

            def __init__(self, views, outs):
                self._v, self._o = views, outs

            def list_views(self, **kw):
                return self._v

            def list_outputs(self):
                return self._o

        _app = "settledapp"          # owned by no plugin, so app_id-only keyed
        _lv = [{"id": 42, "app-id": _app, "title": "Settled", "parent": -1,
                "geometry": {"x": 9, "y": 9, "width": 10, "height": 10},
                "output-name": "eDP-1", "pid": -1}]
        _lo = [{"name": "eDP-1", "id": 1,
                "geometry": {"x": 0, "y": 0, "width": 800, "height": 600},
                "workspace": {"x": 0, "y": 0}}]
        _slot = {"app_id": _app, "title": "", "appid_only": True,
                 "label": "Settled", "output": "eDP-1", "panel": "",
                 "workspace": [0, 0], "pos": [100, 120], "size": [10, 10],
                 "sticky": False, "inverted": False, "fullscreen": False,
                 "last_seen": _time.time()}
        _seated = []
        _rseat = Watcher._seat_view
        try:
            Watcher._seat_view = lambda self, v, e, o: (_seated.append(v["id"])
                                                        or True)
            w.place_sock = _Sock(_lv, _lo)
            w.kb, w.kb_profile = {engine.kkey(_app, ""): _slot}, "DESK"
            w.identified.add(42)         # identified long ago
            w.deadline[42] = _time.time() - 10_000   # and settled long ago
            w.st["armed_at"] = _time.time() - 10 * _wmod.PLACE_CAP  # settled
            w.placed.clear()
            w.redisplay_ok.clear()
            w._place_view(_lv[0])
            ck("a-long-open-window-is-left-alone-when-settled",
               _seated == [])
            # Now the displays change. _adopt_profile must make it placeable.
            _rload = _wmod.load_knowledge
            try:
                _wmod.load_knowledge = lambda p=None: {engine.kkey(_app, ""):
                                                       _slot}
                w._adopt_profile("DESK2", "test")
            finally:
                _wmod.load_knowledge = _rload
            ck("a-dock-entitles-every-live-window", w.redisplay_ok == {42})
            ck("a-dock-re-graces-them",
               w.deadline[42] > _time.time())
            w._place_view(_lv[0])
            ck("a-settled-window-is-placed-after-a-dock", _seated == [42])
            # ONE chance, not a standing licence: the entitlement is consumed,
            # so a later stray title change does not yank the window again.
            ck("the-dock-entitlement-is-consumed", 42 not in w.redisplay_ok)
        finally:
            Watcher._seat_view = _rseat
            w.place_sock = None
            w.identified.discard(42)
            w.deadline.pop(42, None)
            w.placed.clear()
            w.kb, w.kb_profile = {}, "DESK"

        # ---- AND THE PLACER CALLS THE SEEDER ------------------------------
        # The checks above prove surface_seed; they say nothing about whether
        # _place_view reaches it, and a bug in the code AROUND the tested part
        # is this project's most repeated shape. Driven on the real Watcher
        # with the store EMPTY, which is the only state a seed may act in.
        _seeded = []
        _rseat2 = Watcher._seat_view
        _rsm2, _rope = engine.surface_map, engine.other_profile_entries
        try:
            Watcher._seat_view = lambda self, v, e, o: (
                _seeded.append((v["id"], e.get("seeded_from"),
                                tuple(e["pos"]))) or True)
            w.place_sock = _Sock(_lv, [dict(_lo[0], workspace={
                "x": 0, "y": 0, "grid_width": 3, "grid_height": 3})])
            engine.surface_map = lambda fresh=False: (
                {"ref": {"output": "eDP-1", "workspace": [0, 0],
                         "pos": [0, 300], "size": [800, 300]}}, "")
            engine.other_profile_entries = lambda a, i, p=None: [
                {"surface": "ref", "size": [400, 200], "last_seen": 1.0}]
            w.kb, w.kb_profile = {}, "DESK"     # NOTHING learned here
            w.placed.clear()
            w.redisplay_ok = {42}               # a dock, so the gate passes
            w.deadline[42] = _time.time() + 100
            w._place_view(_lv[0])
            ck("the-placer-seeds-from-a-surface-when-nothing-is-learned",
               _seeded == [(42, "ref", (0, 300))])
            # AND NOT WHEN THE CELL IS NOT IN THE GRID, which is the guard
            # usher owns because hwdp passes the cell through unchecked.
            _seeded.clear()
            engine.surface_map = lambda fresh=False: (
                {"ref": {"output": "eDP-1", "workspace": [5, 9],
                         "pos": [0, 300], "size": [800, 300]}}, "")
            w.placed.clear()
            w.redisplay_ok = {42}
            w._place_view(_lv[0])
            ck("a-surface-outside-the-grid-is-not-seeded", _seeded == [])
            # AND NOT AT ALL WHEN THE MAP COULD NOT BE READ: `why` set must
            # never be treated as an empty map.
            engine.surface_map = lambda fresh=False: ({}, "could not ask")
            w.placed.clear()
            w.redisplay_ok = {42}
            w._place_view(_lv[0])
            ck("an-unreadable-map-seeds-nothing", _seeded == [])
        finally:
            Watcher._seat_view = _rseat2
            engine.surface_map, engine.other_profile_entries = _rsm2, _rope
            w.place_sock = None
            w.redisplay_ok = set()
            w.deadline.pop(42, None)
            w.placed.clear()
            w.kb, w.kb_profile = {}, "DESK"

        # ---- TRANSPOSE is a sweep, and a sweep is a BLIP ------------------
        # The sweep used to be welded into _adopt_profile, which made "how
        # long does a transpose last" unanswerable: it inherited the hold.
        _rseat3 = Watcher._seat_view
        try:
            Watcher._seat_view = lambda self, v, e, o: True
            w.place_sock = _Sock(_lv, _lo)
            w.kb, w.kb_profile = {engine.kkey(_app, ""): _slot}, "DESK"
            w.transition_until = 0.0
            w.st["transposed_at"] = 0
            w.placed.add(42)                 # already placed: a sweep voids it
            w.slot_held["x"] = 42
            _n = w._sweep()
            ck("a-sweep-entitles-every-live-window", _n == 1
               and w.redisplay_ok == {42})
            ck("a-sweep-voids-the-placement-ledgers",
               not w.placed and not w.slot_held)
            ck("a-sweep-asks-the-placer-thread-for-the-work",
               w.st["recheck"] is True)
            ck("a-sweep-stamps-the-event", w.st["transposed_at"] > 0)
            # THE POINT: no hold. A hand-asked transpose happens when nothing
            # is in flux, so suppressing learning would be wrong, and it is
            # what made the old welded version impossible to describe.
            ck("a-sweep-carries-no-hold", not w._in_transition())
        finally:
            Watcher._seat_view = _rseat3
            w.place_sock = None
            w.placed.clear()
            w.slot_held.clear()
            w.redisplay_ok = set()
            w.kb, w.kb_profile = {}, "DESK"

        # ---- THE DAEMON PUBLISHES THE MAP, which is the WIRING ----------
        # The pure publish/adopt pair says nothing about whether the refresh
        # calls it, and a planted `_poll_sources` that never published passed
        # the whole suite: EIGHTH instance of that hole here. Without it
        # every one-shot verb stays blind, which is the gap this closes.
        _rsrp, _rstr = engine.source_refresh_plan, engine.source_trigger
        _rpub, _rlog3 = engine.publish_sources, engine.logline
        _pub = []
        try:
            engine.source_refresh_plan = (
                lambda rows, asked, now, seen: (["titan"], {}))
            engine.source_trigger = lambda *a, **k: 1
            engine.publish_sources = lambda *a, **k: _pub.append(1) or True
            w.src_asked, w.src_seen = {}, {}
            w.kb, w.kb_profile = {}, "DESK"
            w._poll_sources({"windows": []})
        finally:
            engine.source_refresh_plan, engine.source_trigger = _rsrp, _rstr
            engine.publish_sources = _rpub
            w.src_asked, w.src_seen = {}, {}
            w.kb, w.kb_profile = {}, "DESK"
        ck("the-refresh-publishes-the-map-for-every-one-shot-verb",
           _pub == [1])
        # AND A PUBLISH THAT RAISES DOES NOT COST THE REFRESH, since every
        # outcome of that poll is optional: it is a sudo subprocess on the
        # capture thread and the windows keep the source-alone key without it.
        _raised = []
        try:
            engine.source_refresh_plan = (
                lambda rows, asked, now, seen: (["titan"], {}))
            engine.source_trigger = lambda *a, **k: 1
            engine.publish_sources = _raise_it
            engine.logline = lambda *a, **k: None
            w.src_asked, w.src_seen = {}, {}
            _ok_poll = w._poll_sources({"windows": []}) is not None
        except Exception as _e:                            # noqa: BLE001
            _raised.append(type(_e).__name__)
            _ok_poll = False
        finally:
            engine.source_refresh_plan, engine.source_trigger = _rsrp, _rstr
            engine.publish_sources = _rpub
            engine.logline = _rlog3
            w.src_asked, w.src_seen = {}, {}
        ck("a-failed-publish-does-not-break-the-refresh",
           _ok_poll and not _raised)

        # ---- A HAND-ASKED CAPTURE IS THE DAEMON'S, and here is why -------
        # A one-shot verb resolves another account's windows to the SOURCE
        # ALONE, because `_SOURCE_WINDOWS` is per process and filled only by
        # a trigger. Measured 2026-11-06: ten of one account's chrome windows
        # collapsed onto one key from a `usher save`.
        ck("capture-plan-hands-over-to-a-running-daemon",
           engine.capture_plan(True, True) == "ask"
           and engine.capture_plan(True, False) == "ask")
        ck("capture-plan-does-it-here-with-nothing-to-be-blind-about",
           engine.capture_plan(False, False) == "here")
        ck("capture-plan-REFUSES-rather-than-writing-what-it-cannot-see",
           engine.capture_plan(False, True) == "refuse")
        # THE THREE ANSWERS ARE PAIRWISE DISTINCT, which is the assertion this
        # file needs for every answer set: collapsing two is how the wrong
        # branch runs while each cell still reads correct on its own.
        ck("capture-plan-three-answers-are-pairwise-distinct",
           len({engine.capture_plan(True, True),
                engine.capture_plan(False, False),
                engine.capture_plan(False, True)}) == 3)
        # AND `live_sources` ITSELF, which every check below INJECTS over:
        # a planted version answering [] always passed the whole suite, and
        # it is the input the refusal turns on. Given a view list it needs no
        # compositor.
        ck("live-sources-names-a-source-with-windows-here",
           engine.live_sources(
               [{"app-id": "slack", "source": "titan", "pid": -1},
                {"app-id": "signal", "pid": -1}]) == ["titan"])
        ck("live-sources-is-empty-with-only-our-own-windows",
           engine.live_sources([{"app-id": "signal", "pid": -1}]) == [])
        # AND AN IPC IT CANNOT REACH IS NOT READ AS "NOBODY ELSE IS HERE",
        # which would turn the refusal off on exactly the box where no daemon
        # is running. It is the fail-safe direction that costs a capture.
        _rip = engine.ipc
        try:
            engine.ipc = _raise_it
            ck("live-sources-with-no-compositor-answers-nothing",
               engine.live_sources() == [])
        finally:
            engine.ipc = _rip

        # AND THE VERB HONOURS THE PLAN, which is the OTHER wiring half: a
        # `do_save` that captured regardless would pass every cell above.
        # Driven with both seams injected, so no compositor and no second
        # account are needed and nothing real is captured.
        _rwp, _rls = engine.watcher_pid, engine.live_sources
        _rdc, _rt_cf = engine.do_capture, engine.CAPTURE_FILE
        _sdir = tempfile.mkdtemp(prefix="usher-save-", dir="/var/tmp")
        _did = []
        try:
            engine.do_capture = lambda: _did.append("here")
            engine.CAPTURE_FILE = os.path.join(_sdir, "usher.capture")
            _buf_s = io.StringIO()

            engine.watcher_pid = lambda: 4242
            engine.live_sources = lambda *a, **k: ["titan"]
            # CAPTURED, NOT PRINTED: `pid 4242` is this check's own sentinel
            # and reads from the terminal exactly like the suite asking the
            # real daemon to capture.
            with contextlib.redirect_stdout(io.StringIO()):
                _rc_s = engine.do_save()
            ck("save-hands-over-when-a-daemon-is-running",
               _rc_s == engine.EXIT_OK and not _did
               and os.path.exists(engine.CAPTURE_FILE))
            os.remove(engine.CAPTURE_FILE)

            engine.watcher_pid = lambda: None
            engine.live_sources = lambda *a, **k: []
            _rc_s = engine.do_save()
            ck("save-captures-here-with-no-daemon-and-no-other-account",
               _rc_s == engine.EXIT_OK and _did == ["here"]
               and not os.path.exists(engine.CAPTURE_FILE))
            _did.clear()

            engine.live_sources = lambda *a, **k: ["titan"]
            with contextlib.redirect_stderr(_buf_s):
                _rc_s = engine.do_save()
            ck("save-REFUSES-rather-than-collapsing-another-accounts-keys",
               _rc_s == engine.EXIT_CANNOT and not _did
               and not os.path.exists(engine.CAPTURE_FILE))
            # AND IT SAYS WHOSE AND WHAT TO DO, or a refusal is a dead end.
            ck("save-names-the-source-and-the-remedy",
               "titan" in _buf_s.getvalue()
               and "usher-mgr watch" in _buf_s.getvalue())
        finally:
            engine.watcher_pid, engine.live_sources = _rwp, _rls
            engine.do_capture, engine.CAPTURE_FILE = _rdc, _rt_cf
            shutil.rmtree(_sdir, ignore_errors=True)

        # AND THE WORKER CONSUMES IT, DUE AT ONCE. The WIRING, which the pure
        # plan says nothing about: a request nothing acts on is a verb that
        # reports success and captures nothing, which is this file's most
        # repeated failure shape.
        _rt_cap = engine.CAPTURE_FILE
        _wm2 = _word2 = sys.modules[Watcher.__module__]
        _rw_cap = _wm2.CAPTURE_FILE
        _rlog2 = engine.logline
        _cdir = tempfile.mkdtemp(prefix="usher-cap-", dir="/var/tmp")
        try:
            engine.CAPTURE_FILE = os.path.join(_cdir, "usher.capture")
            # PATCHED ON `watch`'s OWN NAME TOO, since it imports the constant
            # BY VALUE: patching engine's alone leaves the daemon's copy live,
            # which is the stale-copy hazard the package split records and
            # which has written real state from this suite once.
            _wm2.CAPTURE_FILE = engine.CAPTURE_FILE
            engine.logline = lambda *a, **k: None
            with open(engine.CAPTURE_FILE, "w") as _f:
                _f.write("1\n")
            w.st["dirty"], w.st["last"] = False, _time.time()
            w._take_capture()
            ck("a-capture-request-dirties-the-store", w.st["dirty"] is True)
            ck("a-capture-request-is-due-at-once-with-no-debounce",
               w.st["last"] == 0)
            ck("a-capture-request-is-consumed",
               not os.path.exists(engine.CAPTURE_FILE))
            # AND THE POLL LOOKS AT IT, which the direct call cannot say:
            # removing the arm from `_poll_files` left every check above
            # passing while in production nothing would ever consume a
            # request. Driven through the real poll, with the OTHER request
            # files pointed at the same scratch dir so this cannot act on a
            # live one.
            # EVERY OTHER KEY IS SEEDED AT ITS CURRENT VALUE, so no other
            # arm of the poll fires: the chrome arm SAVES THE STORE, and the
            # exclude/include/plugin arms reload real config. Only the
            # capture mtime is made to differ.
            _seen_c = {"inv": _word2.store_mtime(engine.INVERT_STORE),
                       "exc": _word2.store_mtime(engine.EXCLUDE_FILE),
                       "inc": _word2.store_mtime(engine.INCLUDE_FILE),
                       "arm": _word2.store_mtime(engine.ARM_FILE),
                       "forget": _word2.store_mtime(engine.FORGET_FILE),
                       "capture": None,
                       "redisplay": _word2.store_mtime(
                           engine.REDISPLAY_FILE),
                       "sweep": _word2.store_mtime(engine.SWEEP_FILE),
                       "plugins": engine.plugins_sig(),
                       "chrome": chrome.session_sig()}
            _took = []
            _rtc2 = w._take_capture
            try:
                w._take_capture = lambda: _took.append(1)
                with open(engine.CAPTURE_FILE, "w") as _f:
                    _f.write("2\n")
                w._poll_files(_seen_c)
            except Exception as _e:                        # noqa: BLE001
                _took.append("RAISED-%s" % type(_e).__name__)
            finally:
                w._take_capture = _rtc2
                try:
                    os.remove(engine.CAPTURE_FILE)
                except OSError:
                    pass
            ck("the-poll-consults-the-capture-request", _took == [1])

            # A FAILED CHROME RE-KEY IS RETRIED, NOT LOST. The baseline was
            # adopted BEFORE the work, so a re-key that raised was never
            # tried again: the next poll saw no change and the pass was
            # gone, which at a browser restart costs every chrome window its
            # slot. Measured live on manifold, three times in the logs.
            def _poll_rekey(ok, tries=0):
                """One poll with the chrome sig CHANGED. Returns whether the
                baseline was adopted, and the try counter after."""
                _s = {"inv": _word2.store_mtime(engine.INVERT_STORE),
                      "exc": _word2.store_mtime(engine.EXCLUDE_FILE),
                      "inc": _word2.store_mtime(engine.INCLUDE_FILE),
                      "arm": _word2.store_mtime(engine.ARM_FILE),
                      "forget": _word2.store_mtime(engine.FORGET_FILE),
                      "capture": _word2.store_mtime(engine.CAPTURE_FILE),
                      "redisplay": _word2.store_mtime(
                          engine.REDISPLAY_FILE),
                      "sweep": _word2.store_mtime(engine.SWEEP_FILE),
                      "plugins": engine.plugins_sig(),
                      "chrome": "a-sig-that-cannot-be-current"}
                _rrk = w._rekey_chrome
                w.rekey_tries = tries
                try:
                    w._rekey_chrome = lambda: ok
                    w._poll_files(_s)
                finally:
                    w._rekey_chrome = _rrk
                return (_s["chrome"] != "a-sig-that-cannot-be-current",
                        w.rekey_tries)

            ck("a-successful-rekey-adopts-the-session-signature",
               _poll_rekey(True) == (True, 0))
            ck("a-failed-rekey-holds-the-signature-so-it-retries",
               _poll_rekey(False) == (False, 1))
            # BOUNDED, or a deterministic failure re-reads Chrome's session
            # files every second for ever. Giving up adopts the sig, so the
            # loop goes quiet until Chrome next writes.
            ck("a-failed-rekey-gives-up-at-the-budget",
               _poll_rekey(False, tries=_word2.REKEY_TRIES) == (True, 0))
            # AND THE RETURN IS WHAT THE CALLER READS, so the function has to
            # answer it: asserting the poll alone would pass over a
            # `_rekey_chrome` that always claimed success.
            _rsk, _rlg = engine.rekey_chrome, _word2.logline
            try:
                def _boom_rk(*a, **k):
                    raise OSError(2, "No such file or directory")
                _word2.rekey_chrome = _boom_rk
                _word2.logline = lambda *a, **k: None
                ck("rekey-reports-a-raise-as-failure",
                   w._rekey_chrome() is False)
                _word2.rekey_chrome = lambda *a, **k: 0
                ck("rekey-reports-a-clean-pass-as-success",
                   w._rekey_chrome() is True)
            finally:
                _word2.rekey_chrome, _word2.logline = _rsk, _rlg
        finally:
            engine.CAPTURE_FILE = _rt_cap
            _wm2.CAPTURE_FILE = _rw_cap
            engine.logline = _rlog2
            shutil.rmtree(_cdir, ignore_errors=True)
            w.st["dirty"], w.st["last"] = False, 0

        # ---- the drift detector, for a hook that never comes --------------
        _rpid2 = engine.profile_id
        try:
            w.kb_profile = "HERE"
            w.profile_drift_at = 0.0
            engine.profile_id = lambda fresh=False: "HERE"
            ck("no-drift-when-the-profile-agrees", not w._profile_drift())
            engine.profile_id = lambda fresh=False: "ELSEWHERE"
            ck("drift-suppresses-capture", w._profile_drift())
            ck("drift-is-dated", w.profile_drift_at > 0)
            # Still within the hold: keep refusing rather than adopting.
            ck("drift-keeps-holding-inside-the-window", w._profile_drift())
            ck("drift-has-not-adopted-yet", w.kb_profile == "HERE")
            # Past DOCK_HOLD it ADOPTS, so a box with no hwdp hook recovers by
            # itself rather than never learning again.
            w.profile_drift_at = _time.time() - _wmod.DOCK_HOLD - 1
            _rload2 = _wmod.load_knowledge
            try:
                _wmod.load_knowledge = lambda p=None: {}
                ck("drift-adopts-after-the-hold", not w._profile_drift())
            finally:
                _wmod.load_knowledge = _rload2
            ck("drift-adopted-the-live-profile", w.kb_profile == "ELSEWHERE")
        finally:
            engine.profile_id = _rpid2
            w.kb_profile, w.profile_drift_at = "HERE", 0.0

        # ---- the transition suppresses the whole capture ------------------
        w.transition_until = 0.0
        ck("not-in-transition-by-default", not w._in_transition())
        w._begin_transition("output-removed")
        ck("an-output-event-begins-a-transition", w._in_transition())
        # A SECOND EVENT EXTENDS IT rather than being ignored: a dock emits a
        # burst, and the last one is the one worth timing from.
        _was = w.transition_until
        w._begin_transition("output-added")
        ck("a-later-output-event-extends-the-hold",
           w.transition_until >= _was)
        # _capture_once must not even SNAPSHOT: current.json is the relaunch's
        # input and the seed for a new profile's first store, so one written
        # mid-collapse teaches a fresh desk the collapse as its baseline.
        _touched = []
        _rsnap = _wmod.snapshot

        class _Stop(Exception):
            pass

        def _spy(*a):
            """Record the call and STOP, so a missing guard cannot carry on
            into learn/save/persist and write the real store. The suite does
            not sandbox XDG_STATE_HOME (STATE is read at import, so a hand-run
            `usher selftest` would be writing for real), which is why this
            refuses to proceed rather than returning a usable snapshot."""
            _touched.append(1)
            raise _Stop()

        _rpid = engine.profile_id
        try:
            _wmod.snapshot = _spy
            # THE LOADED STORE AND THE LIVE PROFILE MUST AGREE, or the drift
            # detector suppresses the capture and this measures that instead.
            # Stubbed rather than assigned, so the check does not depend on
            # what hwdp says about the host.
            engine.profile_id = lambda fresh=False: w.kb_profile
            try:
                w._capture_once(None)
            except _Stop:
                pass
            ck("a-transition-suppresses-the-capture", _touched == [])
            # AND THE OTHER DIRECTION, which is what stops the check above
            # passing vacuously: the spy must be reachable at all.
            w.transition_until = 0.0
            try:
                w._capture_once(None)
            except _Stop:
                pass
            ck("capture-resumes-when-the-transition-ends", _touched == [1])
            # AND THE DRIFT DETECTOR IS WIRED INTO THE SAME GATE. Without
            # this, removing it from _capture_once passes every check above,
            # since those call _profile_drift directly.
            engine.profile_id = lambda fresh=False: "SOMEWHERE-ELSE"
            w.profile_drift_at = 0.0
            try:
                w._capture_once(None)
            except _Stop:
                pass
            ck("a-drifted-profile-suppresses-the-capture", _touched == [1])
        finally:
            _wmod.snapshot = _rsnap
            engine.profile_id = _rpid
    finally:
        engine.REDISPLAY_FILE, _wmod.REDISPLAY_FILE = _rrf, _rwrf
        engine.logline, engine.load_knowledge = _rlog, _rload
        _wmod.load_knowledge = _rwload
        shutil.rmtree(_rd, ignore_errors=True)


def _t_contracts(ck):
    """the cross-tool contracts and the SNSS reader."""
    # THE EXIT CONTRACT, with the allowed set DERIVED from the declaration
    # rather than written out again here. A second hand-written list is how a
    # code silently leaves the contract: it would have to be edited in two
    # places and only ever is in one.
    _declared = {engine.EXIT_OK: "EXIT_OK", engine.EXIT_FAIL: "EXIT_FAIL",
                 engine.EXIT_CANNOT: "EXIT_CANNOT"}
    # AN ARMED MODE MUST NOT OUTLIVE THE DAEMON IT WAS ARMED FOR. `reload`
    # arms quiet; a stop before the worker consumed it used to leave the
    # marker in the runtime dir for the next LOGIN to eat, which then started
    # quiet and restored NOTHING, with no visible cause. Found live, as a
    # `quiet` marker sitting armed with no daemon running.
    _rsw = engine._signal_watcher
    try:
        engine._signal_watcher = lambda *a, **k: None   # do not signal anyone
        engine.arm_mode("quiet")
        ck("mode-arms", engine.take_mode() == "quiet")
        engine.arm_mode("quiet")
        engine.do_stop()
        # "restore" is what take_mode answers with nothing armed, i.e. the
        # DEFAULT start, which is the property that matters: after a stop the
        # next start restores the layout rather than inheriting a quiet that
        # was meant for a daemon no longer running.
        ck("stop-disarms-the-mode", engine.take_mode() == "restore")
    finally:
        engine._signal_watcher = _rsw
        engine.arm_mode("restore")

    # INSTALLED IS NOT RUNNING: all four verdicts, with no install needed.
    # THE WORKER AND NOT THE SUPERVISOR is the fact under test, so our own pid
    # stands in and `pkg_dir` supplies the other side.
    _rwp2 = engine.watcher_pid
    _tmpd = tempfile.mkdtemp(prefix="usher-age-")
    try:
        engine.watcher_pid = lambda: None
        ck("code-age-no-daemon", engine.daemon_code_age()[0] == "none")
        engine.watcher_pid = lambda: os.getpid()
        # a package OLDER than this process: it is running current code
        open(os.path.join(_tmpd, "x.py"), "w").close()
        os.utime(os.path.join(_tmpd, "x.py"), (1, 1))
        ck("code-age-current", engine.daemon_code_age(_tmpd)[0] == "current")
        # ...and one written just now: a reload is owed
        os.utime(os.path.join(_tmpd, "x.py"), None)
        _v, _d = engine.daemon_code_age(_tmpd)
        ck("code-age-stale", _v == "stale")
        ck("code-age-stale-says-reload", "reload" in _d)
        ck("code-age-unknown-on-an-unreadable-dir",
           engine.daemon_code_age(os.path.join(_tmpd, "nope"))[0] == "unknown")
        ck("code-age-verdicts-are-distinct",
           len({"none", "current", "stale", "unknown"}) == 4)
    finally:
        engine.watcher_pid = _rwp2
        shutil.rmtree(_tmpd, ignore_errors=True)

    # ELIMINATION OVER THE RECORDED IDS, which never compares title content.
    # The titles below are DELIBERATELY unrelated to each other: if the claim
    # depended on the strings at all, no fixture here would resolve.
    _rst = chrome.chrome_session_titles
    try:
        def _titles(m):
            chrome.chrome_session_titles = lambda: m
        T = {"Alpha": (11, "u1"), "Beta": (22, "u2"), "Gamma": (33, "u3")}
        _titles(T)
        # two views match exactly, the third's title matches NOTHING -> forced
        chrome._slot_cache.clear()
        got = chrome.claim_by_elimination(
            [(1, "Alpha - Google Chrome"), (2, "Beta - Google Chrome"),
             (3, "something the file has never heard of - Google Chrome")])
        ck("elim-claims-the-forced-view", got == 3)
        ck("elim-writes-the-slot-cache",
           chrome._slot_cache.get(3) == "chrome:win:33")
        # TWO unmatched views could pair either way: refuse.
        chrome._slot_cache.clear()
        ck("elim-refuses-two-unmatched",
           chrome.claim_by_elimination(
               [(1, "Alpha - Google Chrome"), (2, "nope - Google Chrome"),
                (3, "also nope - Google Chrome")]) is None)
        ck("elim-refuses-leave-cache-alone", not chrome._slot_cache)
        # ONE unmatched view but TWO free ids: equally unforced.
        chrome._slot_cache.clear()
        ck("elim-refuses-two-free-ids",
           chrome.claim_by_elimination(
               [(1, "Alpha - Google Chrome"),
                (2, "nope - Google Chrome")]) is None)
        # AN INCOGNITO WINDOW is a view Chrome never recorded, so it shows up
        # as one more view than id and must decline rather than steal the id.
        chrome._slot_cache.clear()
        ck("elim-refuses-with-an-unrecorded-window",
           chrome.claim_by_elimination(
               [(1, "Alpha - Google Chrome"), (2, "Beta - Google Chrome"),
                (3, "Gamma - Google Chrome"),
                (4, "incognito - Google Chrome")]) is None)
        # NOTHING LEFT OVER is not a claim either.
        chrome._slot_cache.clear()
        ck("elim-nothing-to-do-when-all-match",
           chrome.claim_by_elimination(
               [(1, "Alpha - Google Chrome"), (2, "Beta - Google Chrome"),
                (3, "Gamma - Google Chrome")]) is None)

        # AN ID A LIVE VIEW ALREADY HOLDS IS NOT FREE. The manifold incident
        # of 2026-10-13: view 1 was resolved and cached, then its title went
        # stale, so it was neither matched nor unmatched and its OWN id read
        # as free. View 2, a window Chrome never recorded, was handed it.
        # ONE recorded id here, so the cache is the only thing standing
        # between the stranger and the owner's slot.
        _titles({"Alpha": (11, "u1")})
        chrome._slot_cache.clear()
        chrome._slot_cache[1] = "chrome:win:11"
        ck("elim-an-id-a-live-view-holds-is-not-free",
           chrome.claim_by_elimination(
               [(1, "a title the file no longer carries - Google Chrome"),
                (2, "never recorded at all - Google Chrome")]) is None)
        ck("elim-leaves-the-cached-owner-alone",
           chrome._slot_cache == {1: "chrome:win:11"})
        # ...and it still claims a genuinely free id with a cached sibling
        # present, or the guard above would have made the whole thing inert.
        _titles({"Alpha": (11, "u1"), "Beta": (22, "u2")})
        chrome._slot_cache.clear()
        chrome._slot_cache[1] = "chrome:win:11"
        ck("elim-still-claims-beside-a-cached-view",
           chrome.claim_by_elimination(
               [(1, "stale - Google Chrome"),
                (2, "also stale - Google Chrome")]) == 2)
        ck("elim-claimed-the-unheld-id",
           chrome._slot_cache.get(2) == "chrome:win:22")
    finally:
        chrome.chrome_session_titles = _rst
        chrome._slot_cache.clear()

    # THE AGENT QUESTION IS ABOUT THE DAEMON'S ENVIRONMENT, not the caller's.
    # Our own pid stands in for the daemon, which gives a REAL
    # /proc/<pid>/environ to read. That file is the EXEC-TIME environment, so
    # a value poked into os.environ now does NOT appear in it: asserting the
    # poked sentinel is NOT returned is what proves /proc was read and the
    # caller's live environment was not.
    _rwp = engine.watcher_pid
    _renv = os.environ.get("SSH_AUTH_SOCK")
    try:
        os.environ["SSH_AUTH_SOCK"] = "/nonexistent/from-the-caller"
        engine.watcher_pid = lambda: os.getpid()
        _dsock, _dwhose = engine.session_agent_sock()
        ck("agent-sock-names-the-daemon", str(os.getpid()) in _dwhose)
        ck("agent-sock-ignores-the-callers-env",
           _dsock != "/nonexistent/from-the-caller")
        # ...and with no daemon it falls back to our own and SAYS so, because
        # the two answers mean different things.
        engine.watcher_pid = lambda: None
        _ssock, _swhose = engine.session_agent_sock()
        ck("agent-sock-falls-back-to-the-shell",
           _ssock == "/nonexistent/from-the-caller" and "shell" in _swhose)
        # DISTINCT RATHER THAN each individually right: conflating the two is
        # the whole bug, and a substring probe is what got this check wrong
        # the first time ("no daemon is running" contains "daemon").
        ck("agent-sock-sources-are-distinguishable", _dwhose != _swhose)
    finally:
        engine.watcher_pid = _rwp
        if _renv is None:
            os.environ.pop("SSH_AUTH_SOCK", None)
        else:
            os.environ["SSH_AUTH_SOCK"] = _renv

    # THE STATUS FILE IS A CROSS-PACKAGE CONTRACT with no check: the daemon
    # writes it, `usher status` and the TRAY read it, and the notes record
    # the two sides being moved in one commit by DISCIPLINE. A renamed field
    # blanks the tray silently, because `read_status` treats anything it
    # cannot understand as `down`.
    #
    # DERIVED FROM BOTH SOURCES, like the tunables check, so neither side is
    # a hand-written list that goes stale. The writer is the one json.dump
    # in `_write_status`; the readers are every `.get("<name>")` against the
    # parsed status in cli and in the tray's own module, which lives in this
    # repo and is therefore readable from here.
    _wsrc = inspect.getsource(sys.modules["usher.watch"])
    _wbody = _wsrc.split("def _write_status", 1)[1].split("\n    def ", 1)[0]
    _written = set(re.findall(r'["\'](\w+)["\']\s*:', _wbody))
    _ind = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(engine.__file__))),
        "indicator", "usher_indicator", "__main__.py")
    _csrc = inspect.getsource(sys.modules["usher.cli"])
    _cstat = _csrc.split('elif verb == "status"', 1)[1].split("\n    elif ",
                                                              1)[0]
    # BOTH QUOTE STYLES, because an f-string body commonly uses the other
    # one and a double-quote-blind scrape then reads a real reader as
    # nobody: this check flagged `recording` as unread one minute after it
    # was given a reader, for exactly that reason.
    _GET = r"""s\.get\(["'](\w+)["']"""
    _read = set(re.findall(_GET, _cstat))
    # ONLY IN A CHECKOUT: an INSTALL has the engine in site-packages with no
    # `indicator/` beside it, so the tray's half is unreadable there and the
    # skip is announced rather than silently narrowing the contract.
    _tray = os.path.exists(_ind)
    if _tray:
        with open(_ind) as _ifh:
            _isrc = _ifh.read()
        _rs = _isrc.split("def read_status", 1)[1].split("\n\ndef ", 1)[0]
        _read |= set(re.findall(_GET, _rs))
    # VACUITY GUARD ON BOTH SCRAPES, because an empty set satisfies every
    # assertion below and the line still reads ok.
    ck("status-writer-scrape-is-not-vacuous", len(_written) >= 5)
    # WHICH HALVES WERE READ IS IN THE CHECK'S NAME, which is how this suite
    # announces a skip: `test/selftest.t` also runs from the INSTALLED venv,
    # where the engine sits in site-packages with no `indicator/` beside it,
    # and a check that quietly covered one side there would be reporting the
    # same thing whether or not half of it ran.
    ck("status-reader-scrape-is-not-vacuous-%s"
       % ("cli-and-tray" if _tray else "cli-only-no-indicator-source"),
       len(_read) >= 4)
    # A FIELD A READER ASKS FOR MUST BE WRITTEN, which is the direction that
    # breaks the tray.
    ck("every-status-field-read-is-written", _read <= _written)
    # AND A FIELD WRITTEN FOR NOBODY IS NOT PUBLISHED, it is litter:
    # `recording` was written every tick and read by nothing at all for as
    # long as it has existed, which is this file's published-and-never-read
    # shape for the sixth time.
    ck("every-status-field-written-is-read", _written <= _read)

    ck("exit-codes-are-distinct", len(_declared) == 3)
    ck("exit-codes-are-0-1-2", set(_declared) == {0, 1, 2})
    # Every INTEGER literal handed to sys.exit anywhere in the package must be
    # one of them. Read off the AST, so a `sys.exit(3)` fails here naming the
    # set instead of reaching a caller that branches on 0/1/2.
    _sites, _lits, _strs = 0, [], []
    for _nm in ("engine", "cli", "doctor", "watch", "chrome"):
        _m = sys.modules[f"usher.{_nm}"]
        for _node in ast.walk(ast.parse(inspect.getsource(_m))):
            if (isinstance(_node, ast.Call)
                    and isinstance(_node.func, ast.Attribute)
                    and _node.func.attr == "exit" and _node.args):
                _sites += 1
                _a = _node.args[0]
                if isinstance(_a, ast.Constant) and isinstance(_a.value, int):
                    _lits.append(_a.value)
                # A STRING ARGUMENT IS AN EXIT CODE OF ONE, whatever it says.
                # This check classified only the INTEGER literals, so fifteen
                # sites across cli and engine died with a message and exited
                # 1 while meaning "could not do it at all": `usher cleanly
                # not-a-verb` gave 1 where `usher not-a-verb` gave 2, for the
                # one class the man page names for 2 in as many words. An f
                # string is a JoinedStr rather than a Constant, so both
                # shapes have to be caught.
                elif isinstance(_a, ast.JoinedStr) or (
                        isinstance(_a, ast.Constant)
                        and isinstance(_a.value, str)):
                    _strs.append(f"{_nm}.py:{_node.lineno}")
    # VACUITY GUARD ON THE SCRAPE ITSELF, not on what it found. Counting only
    # the integer literals would make this pass by finding NONE, which is the
    # "a check passes for the wrong reason" shape; and naming the codes is
    # what removes those literals, so the guard has to count every exit SITE.
    ck("exit-scrape-is-not-vacuous", _sites >= 15)
    ck("every-literal-exit-is-declared",
       all(v in _declared for v in _lits))
    # NO EXIT MAY BE A BARE STRING, because that is a code of 1 chosen by
    # Python rather than by anybody here. `engine.die_cannot` says it on
    # stderr and exits 2, which is what all fifteen of them meant.
    # The offenders are NAMED in the check name's own failure path by
    # being left in `_strs`, which the driver prints with the area.
    ck("no-exit-dies-with-a-bare-string", _strs == [])
    # AND THE HELPER IS WHAT THEY USE, so a future site has somewhere
    # obvious to go: the wiring half, which the scrape above cannot assert.
    ck("die-cannot-is-used-widely",
       sum(inspect.getsource(sys.modules[f"usher.{n}"]).count("die_cannot(")
           for n in ("engine", "cli")) >= 15)
    ck("die-cannot-exits-cannot",
       "sys.exit(EXIT_CANNOT)" in inspect.getsource(engine.die_cannot))
    # CONTRACT with mux: `mux resume --list` must stay BARE NAMES, one per line.
    # This is the guard the old `mux ls` scrape lacked, because a cosmetic
    # change over
    # in mux (the agent-state glyph) silently killed relaunch with no symptom.
    # Skipped when mux is absent (the soft dep); an empty set is legitimate.
    ck("mux-list-contract",
       all(re.fullmatch(r"[^\s:]+", s) for s in mux_session_set()))

    # identity() is a STRICT no-op for a non-plugin app
    ck("noop-slack", identity(_tv("slack", "Slack")) == "Slack")

    # DOCTOR MUST SCREAM WHEN IT CANNOT SEE THE SESSION. With no live windows
    # the relaunch section calls every saved window missing and the browser
    # not running: every line false, none of it marked so, and it used to
    # exit 0. Met twice in one afternoon over a non-interactive ssh, which
    # carries none of the session environment. Imported here rather than at
    # the top because doctor imports THIS module; at call time both are
    # loaded, and keeping the module-level edge one-way is the point.
    from .doctor import do_doctor
    import contextlib
    import io
    _buf = io.StringIO()
    with _tblind(), contextlib.redirect_stdout(_buf):
        _rc = do_doctor()
    _rep = _buf.getvalue()
    ck("doctor-blind-exits-nonzero", _rc == 2)
    ck("doctor-blind-shouts", "CANNOT SEE THE LIVE SESSION" in _rep)
    ck("doctor-blind-skips-live-sections",
       "saved windows -> relaunch" not in _rep
       and "live windows -> placement" not in _rep)
    ck("doctor-blind-keeps-the-store-report",
       "== store ==" in _rep and "== contracts ==" in _rep)

    # parse_snss recovers the active-tab url from a synthetic session file
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, snss_build([(11, 22, "https://example.com/x",
                                  "Example")]))
        os.close(fd)
        m = parse_snss(path)
        # the WINDOW ID is what identity now rests on, so assert it, not just
        # the url: dropping it is the bug this whole change undoes.
        ck("snss-parse", m.get("Example") == (11, "https://example.com/x"))
        ck("snss-window-id", m["Example"][0] == 11)
    finally:
        os.remove(path)

    # any real session file present must parse without raising
    try:
        for p in session_files():
            parse_snss(p)
        ck("snss-live", True)
    except Exception:
        ck("snss-live", False)

def _t_watcher(ck):
    """the DAEMON's state machine, which needs no compositor.

    The notes said the only way to verify watch.py was to run the daemon. That
    is half true: placement and capture need a live socket, but the STATE
    MACHINE does not, and Watcher.__init__ opens nothing. Two of one day's bugs
    lived exactly here: the capture loop racing the placer over one window's
    position, and a hold that never released, and both were found by hand in
    a session that should have been a test.

    Imported here rather than at the top because watch imports THIS module; at
    call time both are loaded, and keeping the module-level edge one-way is the
    point."""
    from .watch import Watcher
    import time as _time
    w = Watcher(launch=False)      # reads the store, opens no socket
    now = _time.time()

    # THE FORGET REQUEST, driven on the real Watcher. The DAEMON makes the
    # edit because it owns the store while it runs, so the one thing that must
    # hold is that a request is applied and then CONSUMED: left behind, it
    # would be re-applied on every poll.
    _rfk, _rsave = engine.FORGET_FILE, engine.save_knowledge
    _rlog, _rbk = engine.logline, engine.backup_knowledge
    _fd = tempfile.mkdtemp(prefix="usher-forget-", dir="/var/tmp")
    try:
        engine.FORGET_FILE = os.path.join(_fd, "usher.forget")
        _wmod = sys.modules[Watcher.__module__]
        _rwfk = _wmod.FORGET_FILE
        _wmod.FORGET_FILE = engine.FORGET_FILE
        _saved = []
        engine.save_knowledge = lambda kb, prof: _saved.append(dict(kb))
        engine.backup_knowledge = lambda: "/dev/null"
        engine.logline = lambda *a, **k: None
        w.kb = {engine.kkey("google-chrome", "chrome:win:9"): {},
                engine.kkey("kitty", "term:resume"): {}}
        with open(engine.FORGET_FILE, "w") as f:
            f.write("chrome:win:*\n")
        _sel = w._take_forget()
        ck("forget-request-is-read", _sel == ["chrome:win:*"])
        ck("forget-request-drops-from-the-live-kb",
           list(w.kb) == [engine.kkey("kitty", "term:resume")])
        ck("forget-request-saves-the-store", len(_saved) == 1)
        ck("forget-request-is-consumed",
           not os.path.exists(engine.FORGET_FILE))
        # A SECOND POLL MUST DO NOTHING, which is what consuming it buys.
        _sel2 = w._take_forget()
        ck("forget-absent-request-is-a-no-op",
           _sel2 == [] and len(_saved) == 1)
        # ...and an unparsable request is removed too, or it is retried for
        # the life of the daemon.
        with open(engine.FORGET_FILE, "w") as f:
            f.write("\n   \n")
        w._take_forget()
        ck("forget-an-empty-request-is-still-consumed",
           not os.path.exists(engine.FORGET_FILE) and len(_saved) == 1)
    finally:
        engine.FORGET_FILE, engine.save_knowledge = _rfk, _rsave
        engine.logline, engine.backup_knowledge = _rlog, _rbk
        _wmod.FORGET_FILE = _rwfk
        shutil.rmtree(_fd, ignore_errors=True)

    # THE PLACE/SETTLED CLOCK. settled when the FLOOR has passed and it has
    # been quiet for IDLE_SETTLE, but never past the CAP.
    w.st["armed_at"] = now
    w.st["last_map"] = now
    ck("clock-place-after-arming", w._placing_now())
    w.st["armed_at"] = now - START_FLOOR - IDLE_SETTLE - 10
    w.st["last_map"] = now - IDLE_SETTLE - 10
    ck("clock-settles-when-quiet", not w._placing_now())
    # a NEW window pushes last_map, which extends place past the floor
    w.st["last_map"] = now
    ck("clock-extends-on-a-new-map", w._placing_now())
    # ...but never past the CAP, which is what bounds a login storm
    w.st["armed_at"] = now - PLACE_CAP - 1
    ck("clock-capped", not w._placing_now())

    # A QUIET START (a code reload) MUST LAND SETTLED. A fresh worker stamps
    # armed_at with NOW, so without this every reload re-armed place for
    # START_FLOOR and any window mapping in those five minutes was snapped to
    # its remembered slot: a deploy changing placement behaviour. This is the
    # property `setup.sh install` relies on to reload unconditionally, so it
    # is checked rather than assumed.
    _q = Watcher(launch=False)
    _q.mode = "quiet"
    _q.st["armed_at"] = _q.st["last_map"] = _time.time()
    ck("quiet-start-is-place-before-init", _q._placing_now())
    _q._init_layout()
    ck("quiet-start-lands-settled", not _q._placing_now())
    # ...and a later kick still works, or quiet would have broken the knob.
    _q.st["armed_at"] = _time.time()
    ck("quiet-start-does-not-break-the-kick", _q._placing_now())
    # RESTORE mode must NOT be quietened: it is the login path and has to
    # place, so asserting quiet alone would pass with the clock always dead.
    _r = Watcher(launch=False)
    _r.mode = None
    _r.st["armed_at"] = _r.st["last_map"] = _time.time()
    ck("restore-start-stays-place", _r._placing_now())

    # THE HOLD: while place, a window the placer has not reached is
    # sitting where its app dropped it, and learning that overwrites the slot
    # the placer is about to aim at.
    w.st["armed_at"], w.st["last_map"] = now, now
    w.placed.clear()
    w.deadline.clear()
    w.deadline[7] = now + 60                       # still inside its grace
    _wins = [{"id": 7, "app_id": "kitty", "title": "x"}]
    ck("hold-holds-an-unplaced-window", w._held(_wins) == {7})
    w.placed.add(7)
    ck("hold-releases-once-placed", w._held(_wins) == frozenset())
    w.placed.discard(7)
    w.deadline[7] = now - 1                        # grace expired
    ck("hold-releases-when-the-grace-runs-out",
       w._held(_wins) == frozenset())
    w.deadline[7] = now + 60
    w.st["armed_at"] = now - PLACE_CAP - 1          # settled
    ck("hold-holds-nothing-in-settled-state", w._held(_wins) == frozenset())

    # EVENT ROUTING. A map grants the grace and feeds the settle clock; a
    # place-event queues the view for the placer with the right settle; an
    # unmap forgets everything about the window; a knowledge trigger dirties
    # the store and only a LAYOUT one rolls history.
    w.st["armed_at"], w.st["last_map"] = now, now - 999
    w.placed.clear()
    w.deadline.clear()
    w.pending.clear()
    w.identified.clear()
    w.st["dirty"], w.st["layout"] = False, False
    w._on_event({"event": "view-mapped",
                 "view": {"id": 11, "app-id": "kitty", "title": "t"}})
    ck("event-map-grants-a-grace", w.deadline.get(11, 0) > now)
    ck("event-map-feeds-the-settle-clock", w.st["last_map"] > now - 5)
    ck("event-map-queues-for-the-placer", 11 in w.pending)
    ck("event-map-dirties-and-rolls", w.st["dirty"] and w.st["layout"])
    # a BROWSER waits longer before being moved, because it churns its title
    # through a session restore and moving it mid-restore can drop the window
    w.pending.clear()
    w._on_event({"event": "view-title-changed",
                 "view": {"id": 12, "app-id": "google-chrome", "title": "t"}})
    w._on_event({"event": "view-title-changed",
                 "view": {"id": 13, "app-id": "kitty", "title": "t"}})
    ck("event-browser-waits-longer",
       w.pending[12]["due"] > w.pending[13]["due"])
    # a title change is NOT a layout change: it must not roll the history ring,
    # or a day of tab-flips floods it
    w.st["layout"] = False
    w.st["dirty"] = False
    w._on_event({"event": "view-title-changed",
                 "view": {"id": 13, "app-id": "kitty", "title": "u"}})
    ck("event-title-dirties-without-rolling",
       w.st["dirty"] and not w.st["layout"])
    # an already-placed window is not re-queued
    w.pending.clear()
    w.placed.add(13)
    w._on_event({"event": "view-title-changed",
                 "view": {"id": 13, "app-id": "kitty", "title": "v"}})
    ck("event-placed-window-not-requeued", 13 not in w.pending)
    # an unmap forgets the window entirely, or the state leaks for the life of
    # the daemon and a reused view id inherits it
    w.identified.add(13)
    w.deadline[13] = now + 60
    w.pending[13] = {"v": {}, "due": now}
    w._on_event({"event": "view-unmapped", "view": {"id": 13}})
    ck("event-unmap-forgets-everything",
       13 not in w.placed and 13 not in w.identified
       and 13 not in w.deadline and 13 not in w.pending)

    # RECOGNITION RESTARTS THE GRACE, which is what lets a window that could
    # not be identified for minutes still be placed once it can.
    w.deadline.clear()
    w.identified.clear()
    w.st["last_map"] = now - 999
    w._recognise(21, "kitty", "late window")
    ck("recognise-restarts-the-grace", w.deadline.get(21, 0) > now)
    ck("recognise-feeds-the-settle-clock", w.st["last_map"] > now - 5)
    ck("recognise-is-once-only", 21 in w.identified)

@contextlib.contextmanager
def _quiet_log():
    """Keep everything the suite drives out of the REAL watch.log.

    A FIXTURE LINE IS INDISTINGUISHABLE FROM A REAL ONE, and watch.log is the
    forensic record this repo leans on to settle "usher or the human". Found
    for the second time on 2026-10-05, while reading that log to diagnose a
    genuine placement failure: every `./test/run` had been appending rows like

        slot taken, left in place: signal | Signal
        recognised late, re-graced: kitty | late window

    from _t_slots and _t_lifecycle, which drive the real Watcher. The first
    instance (the relaunch announcements) was fixed per-area by stubbing at
    the seam the test already stubbed; a second instance says the AREA is the
    wrong place to fix it, because every future area that touches daemon code
    has to remember, and the suite passes just as cheerfully when one forgets.

    BOTH SPELLINGS ARE PATCHED. watch.py imports `logline` BY NAME, so it
    holds its own reference and patching engine's global alone leaves the
    daemon's copy live: the exact stale-copy hazard the package split is
    careful about. An area that wants to ASSERT what was logged still stubs
    for itself, and restoring to whatever it found keeps that working."""
    from . import watch as _wmod
    me = engine
    sink = []
    saved = (me.logline, _wmod.logline)
    me.logline = _wmod.logline = sink.append
    try:
        yield sink
    finally:
        me.logline, _wmod.logline = saved

def selftest():
    """Offline unit checks for the plugin framework and the store: no
    compositor, deterministic. Run with `usher selftest`.

    Split by AREA rather than written as one list, so a failure names the area
    it came from and a new check has an obvious home."""
    fails = []
    ran = []

    def ck(name, cond):
        # COUNTED, because the failure mode of any refactor in here is DROPPING
        # a check, and the suite passes just as cheerfully over a smaller set.
        # These notes have used "88 before and after" as the verification for
        # three separate splits; the number was counted by hand every time
        # because nothing printed it.
        ran.append(name)
        if not cond:
            fails.append(name)

    # EACH AREA IS GUARDED, so one that raises is reported as a failure and
    # the OTHER areas still run and still print a summary. Unguarded, the
    # first exception aborts the suite before the summary line, and a
    # regression harness grepping for `selftest FAIL:` then reads a crash as
    # "nothing failed" and concludes the CHECK is weak. That false negative
    # has now bitten this fleet twice (the greeter regression run, and
    # planting the Resolution guard removal), so it is fixed here rather than
    # in each caller.
    # THE REAL STATE IS A CANARY, because the suite CAN write it and did.
    # watch.py imports `save_knowledge` and `persist` BY NAME, so an area
    # that drives the daemon and patches only engine's globals leaves the
    # real ones live: one such check wrote `{}` over a live profile store and
    # eight fixture rows into the history ring.
    #
    # IT WATCHES THIS PROCESS'S WRITES, not the files. The first version
    # DIGESTED the state files before and after, and that reported a change
    # the LIVE DAEMON had made: its capture loop rewrites the store and the
    # ring on its own, so the check fired at random on a busy desk and said
    # the suite had written state it had not touched. A CANARY THAT CRIES
    # WOLF GETS SWITCHED OFF, and the fix is to ask the question that was
    # always meant: did WE write there? Every state file goes through
    # `write_json`, so one seam answers it exactly, with no timing and
    # nothing a concurrent daemon can confuse.
    #
    # THE REAL ROOT IS CAPTURED HERE, before any area can rebind `STATE`: a
    # sandboxing area writes under its own temp dir and is correctly
    # invisible, and the point is only ever the unsandboxed path.
    _real_state = engine.STATE
    _leaked = []
    _real_wj = engine.write_json
    # AND THE WHOLE LOOP RUNS OVER A SCRATCH STATE DIR, which is the fix
    # rather than the detector: several areas build a real Watcher, and
    # `kb_for_profile` legitimately STAMPS a store that does not exist yet
    # ("a store that does not exist is CURRENT by construction"). On a box
    # that already has one that writes nothing; on a FRESH one it stamps the
    # real state dir, so the canary would fail there and nowhere else, which
    # is a check on the host. Sandboxing the root makes the write harmless
    # AND leaves the canary sharper, since it still anchors on the REAL root
    # and so catches anything that reaches it another way (watch.py and
    # doctor.py import `STATE` BY NAME and hold their own copies).
    #
    # NAMED `usher`, because one check asserts exactly that about the state
    # dir and it should keep asking about the value production uses rather
    # than being special-cased for the harness.
    _scratch_root = tempfile.mkdtemp(prefix="usher-selftest-state-")
    _scratch_state = os.path.join(_scratch_root, "usher")
    os.makedirs(_scratch_state)
    # AND THE PUBLISHED PER-WINDOW MAP, which is the one thing in the RUNTIME
    # dir a check now READS without being asked to: `resolution` adopts it
    # lazily, so on a box whose daemon has published one every foreign-window
    # check would be answering from the live desk. A check that depends on
    # the host is a check on the host, and that class has cost this package
    # four green-on-one-box suites.
    _real_sources = engine.SOURCES_FILE
    _scratch_sources = os.path.join(_scratch_root, "usher.sources")

    def _wj_canary(path, blob):
        try:
            if _under_root(path, _real_state):
                _leaked.append(os.path.relpath(path, _real_state))
        except Exception:                                  # noqa: BLE001
            pass
        return _real_wj(path, blob)

    # THE CANARY'S OWN DETECTOR IS PROVEN, which it otherwise could not be:
    # nothing leaks today, so disabling the test passes the whole suite and a
    # planted regression against it is UNCATCHABLE. Pulling the predicate out
    # as a pure function gives it a positive to assert without writing a byte
    # of real state, which is the one thing it exists to prevent.
    ck("the-state-canary-fires-on-a-path-under-the-real-root",
       _under_root(os.path.join(_real_state, "current.json"), _real_state))
    ck("the-state-canary-fires-on-a-nested-path",
       _under_root(os.path.join(_real_state, "history", "1.json"),
                   _real_state))
    ck("the-state-canary-ignores-a-sandboxed-path",
       not _under_root("/var/tmp/elsewhere/current.json", _real_state))
    ck("the-state-canary-ignores-the-root-itself",
       not _under_root(_real_state, _real_state))
    # AND A SIBLING WHOSE NAME MERELY STARTS THE SAME WAY IS NOT UNDER IT,
    # which a bare string prefix would get wrong.
    ck("the-state-canary-is-not-a-string-prefix",
       not _under_root(_real_state + "-other/current.json", _real_state))

    engine.write_json = _wj_canary
    engine.STATE = _scratch_state
    engine.SOURCES_FILE = _scratch_sources
    engine._SOURCES_ADOPTED = False
    try:
        for area in (_t_registry, _t_resolution, _t_lock,
                     _t_toplevels, _t_roster,
                     _t_lifecycle, _t_desktop, _t_slots, _t_verify,
                     _t_terminals, _t_cli_split,
                     _t_launch_source,
                     _t_relaunch, _t_chrome, _t_learn,
                     _t_geometry, _t_placement, _t_snapshots, _t_profiles,
                     _t_migration, _t_watcher, _t_displays, _t_contracts):
            try:
                with _quiet_log():
                    area(ck)
            except Exception as e:
                ck(f"{area.__name__}-RAISED-{type(e).__name__}", False)
                print(f"selftest: {area.__name__} raised "
                      f"{type(e).__name__}: {e}", file=sys.stderr)
    finally:
        engine.write_json = _real_wj
        engine.STATE = _real_state
        engine.SOURCES_FILE = _real_sources
        engine._SOURCES_ADOPTED = False
        shutil.rmtree(_scratch_root, ignore_errors=True)
    # NAMED, so a leak is a check rather than something a reader has to
    # notice. It runs after every area, because any of them could be the one.
    if _leaked:
        ck("the-suite-wrote-no-real-usher-state", False)
        print("selftest: the suite WROTE real state: %s"
              % ", ".join(sorted(set(_leaked))[:6]), file=sys.stderr)
    else:
        ck("the-suite-wrote-no-real-usher-state", True)
    if fails:
        print("selftest FAIL: " + ", ".join(fails), file=sys.stderr)
        return 1
    dupes = len(ran) - len(set(ran))
    print(f"selftest OK ({len(ran)} checks"
          + (f", {dupes} duplicate name(s)" if dupes else "") + ")")
    return 0
