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
    SOCKET_HUNTED   _loginctl       _spawn_kitty    logline
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
import sys
import tempfile
import time
from collections import Counter
from datetime import date

from . import chrome, engine
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
    _safe_profile, _single_id, _size_opts, _spec_to_date, _verify_find,
    chrome_profiles_for, config_path, desktop_launch_for,
    desktop_relaunch_missing, entries_from_snapshot, identity, is_mux_term,
    is_owned, kb_path, kitty_candidates, kitty_relaunch_missing, kkey,
    launch_missing, learn, live_keys, load_knowledge, lock_plan,
    lock_summoned_session, match, mux_candidates, mux_cmd_of_saved,
    mux_host_of, mux_relaunch_missing, mux_session_of, mux_session_set,
    pick_socket, place_of, placement_landed, profile_id, pview,
    rekey_chrome, resolution, save_knowledge, saved_sizes, schema_path,
    is_unique, seated_session, target_geometry, unidentified,
    wayfire_socket)


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

def _trv(app, title="", pid=-1, vid=None):
    """A RAW view, shaped as the compositor reports one. Not interchangeable
    with _tv: anything reached through pview takes either, but app_of and the
    matcher read `app-id` and see nothing in a normalized view."""
    return {"app-id": app, "title": title, "pid": pid, "id": vid}

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
    _lk = {"term:resume": {"key": "term:resume", "title": "a:b"}}
    _ll = {"a:b": {"key": "term:resume", "title": "a:b"},
           "Inbox": {"key": "chrome:win:9", "title": "Inbox"}}
    ck("verify-matches-on-key",
       _verify_find({"key": "term:resume", "label": "zz"},
                    _lk, _ll)[1] == "key")
    ck("verify-falls-back-to-label",
       _verify_find({"key": "chrome:win:1", "label": "Inbox"},
                    _lk, _ll)[1] == "label")
    ck("verify-reports-no-match",
       _verify_find({"key": "nope", "label": "nope"}, _lk, _ll) == (None, None))
    # A row with no slot must NOT be matched by an empty label, which would
    # pair it with whatever window happens to have a blank title.
    ck("verify-ignores-an-empty-label",
       _verify_find({"key": None, "label": ""}, _lk, _ll) == (None, None))

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
    ck("collision-chrome-blames-usher",
       "mis-resolved" in _cfix("chrome:win:123"))
    ck("collision-chrome-does-not-say-plugin",
       "plugin" not in _cfix("chrome:win:123"))
    ck("collision-kitty-names-settitle", "settitle" in _cfix("kitty:/w"))
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
    _real_lc, _real_hint = engine._loginctl, engine.session_locked_hint
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

        engine._loginctl = _lc

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
        engine._loginctl = _lc_empty
        engine.session_locked_hint = lambda _s: "no"
        ok, plan, _d = engine.lock_now()
        ck("lock-now-no-session-declines", (not ok) and plan == "no-session")
        ck("lock-now-no-session-asks-nothing",
           not any(c[0] == "lock-session" for c in calls))
    finally:
        engine._loginctl = _real_lc
        engine.session_locked_hint = _real_hint

    # THE SUMMONED-LOCK MARKER, which must be per SESSION and not per boot.
    # On this fleet the login user LINGERS, so XDG_RUNTIME_DIR survives a
    # logout and a boot-scoped marker suppressed the lock on every summoned
    # login after the first. That leaves a console open for somebody who is
    # not in front of it, and it is the exact shape of a test campaign.
    _rl, _rs, _rln = engine._loginctl, engine._seated_now, engine.logline
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
    finally:
        engine._loginctl = _rl
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
               [], spawn=_got.append) == 0 and _got == [])
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
           n == 1 and got == [["calibre"]])
        # ALREADY RUNNING: its windows are its own business
        got = []
        n = desktop_relaunch_missing([W("calibre-gui")],
                                     [_trv("calibre-gui", "t")],
                                     spawn=got.append)
        ck("desktop-pass-skips-a-live-app", n == 0 and got == [])
        # AN OWNED APP IS NEVER TOUCHED HERE, which is what makes a specific
        # plugin an override rather than a competitor.
        got = []
        n = desktop_relaunch_missing([W("kitty")], [], spawn=got.append)
        ck("desktop-pass-skips-an-owned-app", n == 0 and got == [])
        # ONE INVOCATION PER APP, not per window: all six chrome windows
        # report one pid and a desktop entry describes an APP.
        got = []
        n = desktop_relaunch_missing([W("calibre-gui", "a"),
                                      W("calibre-gui", "b")], [],
                                     spawn=got.append)
        ck("desktop-pass-is-per-app-not-per-window",
           n == 1 and got == [["calibre"]])
        # a refusal is silent-but-logged, never a crash, and never a spawn
        got = []
        n = desktop_relaunch_missing([W("nm-applet")], [], spawn=got.append)
        ck("desktop-pass-honours-a-refusal", n == 0 and got == [])
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
    w = Watcher(launch=False)
    now = _t.time()

    # place, and inside the grace, so placement is actually attempted
    w.st["armed_at"] = now
    w.st["last_map"] = now

    seated = []

    class _Sock:
        def list_outputs(self):
            return [{"name": "DP-1", "geometry": {"x": 0, "y": 0,
                                                  "width": 100, "height": 100}}]

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

        # ONE LATE CHANCE, and the distinction it encodes. In SETTLED, past the
        # PLACE_CAP (so nothing can re-enter place), a window that MAPPED
        # while place was in force is still placed the first time it
        # becomes identifiable; one opened mid-session is not. Conflating
        # those cost a Chrome window its slot for 2.5 hours on manifold: it
        # logged `recognised late, re-graced` and was then refused.
        from .engine import PLACE_CAP as _CAP
        def _steady_watcher():
            x = Watcher(launch=False)
            x.st["armed_at"] = _t.time() - _CAP - 1    # settled, past the cap
            x.st["last_map"] = _t.time()               # cannot rescue it
            x.place_sock = _Sock()
            x.kb = w.kb
            return x
        ck("cap-really-defeats-the-regrace",
           not _steady_watcher()._aggressive_now())
        s1 = []
        x = _steady_watcher()
        x._seat_view = lambda v, e, o: (s1.append(v["id"]) or True)
        x.deadline[7] = _t.time() + PLACE_GRACE
        x.late_ok.add(7)                               # mapped at login
        x._try_place(V(7))
        ck("late-chance-places-a-login-window", s1 == [7])
        s2 = []
        y = _steady_watcher()
        y._seat_view = lambda v, e, o: (s2.append(v["id"]) or True)
        y.deadline[8] = _t.time() + PLACE_GRACE        # NOT in late_ok
        y._try_place(V(8))
        ck("settled-still-leaves-a-new-window-alone", s2 == [])
        # ...and the chance is spent: identified, so not a first look again.
        s3 = []
        z = _steady_watcher()
        z._seat_view = lambda v, e, o: (s3.append(v["id"]) or True)
        z.deadline[9] = _t.time() + PLACE_GRACE
        z.late_ok.add(9)
        z.identified.add(9)                            # already had its look
        z._try_place(V(9))
        ck("late-chance-is-only-the-first-look", s3 == [])
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

    ck("kitty-candidates",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp"),
                         S("kitty:/nonexistent-" + "z" * 12),
                         S("mux@manifestor:wf")], set()) == ["/tmp"])
    ck("kitty-candidates-live",
       kitty_candidates([S("kitty:/tmp")], {"kitty:/tmp"}) == [])

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
            engine.desktop_relaunch_missing)
    seen, desk = [], []

    class _P:
        def relaunch_missing(self, saved, live):
            seen.append([w.get("cmd") for w in saved])
            return 0

    try:
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
           seen[-1] == ["FROM THE FILE"])
        # AN EMPTY SNAPSHOT MUST NOT BE MISTAKEN FOR "nothing was saved": it is
        # what the caller hands us at a cold start, and relaunching from it is
        # the bug. Passing it through unchanged is what lets the caller decide.
        with contextlib.redirect_stdout(io.StringIO()):
            launch_missing({"windows": []})
        ck("launch-passes-an-empty-snapshot-through", seen[-1] == [])
        # ASSERT THE STUB WAS REACHED, or a future launch_missing that stops
        # calling the registry default would make this silently vacuous and
        # the spawn could come back unnoticed.
        ck("launch-reaches-the-registry-default", len(desk) == 3)
    finally:
        (engine.load_snapshot, engine.plugins,
         engine.desktop_relaunch_missing) = real

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
            try:
                _cli.session_start("login")
                ck("a-non-executable-provider-is-refused", False)
            except SystemExit as _e:
                ck("a-non-executable-provider-is-refused",
                   "not executable" in str(_e))
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
        engine.spawn_term = lambda *a, **k: _spawned.append(("mux", a))
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
        ck("relaunch-mux-runs", n_mux == 2)
        ck("relaunch-kitty-runs", n_kit == 1)
        ck("relaunch-spawned", len(_spawned) == 3)
        ck("relaunch-announced",
           len(_logged) == 3 and all(m.startswith("launch") for m in _logged))
    finally:
        (engine.spawn_term, engine._spawn_kitty,
         engine.logline) = _real

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
    ck("chrome-no-saved", _ch.relaunch_missing([], []) == 0)
    ck("chrome-already-live",
       _ch.relaunch_missing([{"app_id": "google-chrome"}],
                            [_tv("google-chrome", "x")]) == 0)

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
    _e = entries_from_snapshot(_snap)
    ck("milestone-entries", len(_e) == 3)
    ck("milestone-keys",
       sorted(x["title"] for x in _e if x["app_id"] == "kitty")
       == ["mux@manifestor:usher", "mux@manifold:x"])
    # signal is the only window of its app here, so it keys by app_id alone
    ck("milestone-unique",
       [x["appid_only"] for x in _e if x["app_id"] == "signal"] == [True])

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

    ck("exit-codes-are-distinct", len(_declared) == 3)
    ck("exit-codes-are-0-1-2", set(_declared) == {0, 1, 2})
    # Every INTEGER literal handed to sys.exit anywhere in the package must be
    # one of them. Read off the AST, so a `sys.exit(3)` fails here naming the
    # set instead of reaching a caller that branches on 0/1/2.
    _sites, _lits = 0, []
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
    # VACUITY GUARD ON THE SCRAPE ITSELF, not on what it found. Counting only
    # the integer literals would make this pass by finding NONE, which is the
    # "a check passes for the wrong reason" shape; and naming the codes is
    # what removes those literals, so the guard has to count every exit SITE.
    ck("exit-scrape-is-not-vacuous", _sites >= 15)
    ck("every-literal-exit-is-declared",
       all(v in _declared for v in _lits))
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
    ck("clock-place-after-arming", w._aggressive_now())
    w.st["armed_at"] = now - START_FLOOR - IDLE_SETTLE - 10
    w.st["last_map"] = now - IDLE_SETTLE - 10
    ck("clock-settles-when-quiet", not w._aggressive_now())
    # a NEW window pushes last_map, which extends place past the floor
    w.st["last_map"] = now
    ck("clock-extends-on-a-new-map", w._aggressive_now())
    # ...but never past the CAP, which is what bounds a login storm
    w.st["armed_at"] = now - PLACE_CAP - 1
    ck("clock-capped", not w._aggressive_now())

    # A QUIET START (a code reload) MUST LAND SETTLED. A fresh worker stamps
    # armed_at with NOW, so without this every reload re-armed place for
    # START_FLOOR and any window mapping in those five minutes was snapped to
    # its remembered slot: a deploy changing placement behaviour. This is the
    # property `setup.sh install` relies on to reload unconditionally, so it
    # is checked rather than assumed.
    _q = Watcher(launch=False)
    _q.mode = "quiet"
    _q.st["armed_at"] = _q.st["last_map"] = _time.time()
    ck("quiet-start-is-place-before-init", _q._aggressive_now())
    _q._init_layout()
    ck("quiet-start-lands-settled", not _q._aggressive_now())
    # ...and a later kick still works, or quiet would have broken the knob.
    _q.st["armed_at"] = _time.time()
    ck("quiet-start-does-not-break-the-kick", _q._aggressive_now())
    # RESTORE mode must NOT be quietened: it is the login path and has to
    # place, so asserting quiet alone would pass with the clock always dead.
    _r = Watcher(launch=False)
    _r.mode = None
    _r.st["armed_at"] = _r.st["last_map"] = _time.time()
    ck("restore-start-stays-place", _r._aggressive_now())

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
    for area in (_t_registry, _t_resolution, _t_lock,
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
            print(f"selftest: {area.__name__} raised {type(e).__name__}: {e}",
                  file=sys.stderr)
    if fails:
        print("selftest FAIL: " + ", ".join(fails), file=sys.stderr)
        return 1
    dupes = len(ran) - len(set(ran))
    print(f"selftest OK ({len(ran)} checks"
          + (f", {dupes} duplicate name(s)" if dupes else "") + ")")
    return 0
