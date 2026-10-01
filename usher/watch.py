"""The daemon: the supervisor, and the worker it keeps alive.

`usher-mgr watch` runs both halves. Supervisor holds the single-instance
lock, spawns the worker and respawns it with backoff; Watcher IS the worker,
placing each window onto its known spot as it appears and recording the layout
into the knowledge base as it changes.

This is the only part of usher that runs continuously, and it is a LEAF: it
uses the engine and nothing in the engine uses it. cli enters both.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time

# THE ENGINE NAMES THIS MODULE USES, listed rather than star-imported, so the
# daemon's whole dependency on the engine is one readable block.
#
# Three engine globals are REBOUND at runtime: EXCLUDE_RULES/EXCLUDE_ERRORS by
# reload_exclude, ANCHOR_RULES/ANCHOR_ERRORS by reload_anchor, _PLUGINS by
# reload_plugins, and importing one of those BY VALUE here would freeze
# whatever it held at import time and then go silently stale on the next reload.
# So the one this module reads is reached through the MODULE instead
# (engine.EXCLUDE_ERRORS). Everything imported by name below is a constant or a
# function, which a rebind never touches.
from . import chrome, engine
from .engine import (AGGR_CAP, ARM_FILE, EXCLUDE_FILE, IDLE_SETTLE,
                     INCLUDE_FILE, INVERT_STORE, LAUNCHED, SKIP_TITLE,
                     START_FLOOR, STATE, STATUS_FILE, _signal_watcher,
                     acquire_singleton, app_of, apply_fullscreen,
                     apply_invert, connect, do_capture, identity, is_anchored,
                     is_desync_error,
                     is_transient, kkey, launch_missing, learn,
                     load_knowledge, logline, persist, place, plugins_sig,
                     reload_anchor, reload_exclude, reload_plugins,
                     rekey_chrome, save_knowledge, snapshot,
                     store_mtime, take_mode, target_geometry, unidentified)


# Layout-significant events: re-snapshot AND roll the history/milestone ring.
LAYOUT_TRIGGERS = {
    "view-geometry-changed", "view-workspace-changed", "view-tiled",
    "view-set-output", "view-wset-changed", "view-mapped", "view-unmapped",
    "view-fullscreen", "view-sticky", "output-added", "output-removed",
    "wset-workspace-changed",
}
# A title/app-id change (a tab switch) also feeds the knowledge base (it adds
# a title to the window's group) but must NOT roll history, or the ring
# floods with tab-flips. So the knowledge trigger set is broader than layout.
KNOWLEDGE_TRIGGERS = LAYOUT_TRIGGERS | {
    "view-title-changed", "view-app-id-changed"}
# Events that mean "a window appeared or renamed": try to place it.
PLACE_EVENTS = {"view-mapped", "view-title-changed", "view-app-id-changed"}
DEBOUNCE = 2.0        # seconds of quiet before a capture is written
PLACE_GRACE = 120.0   # place a window only within this long of it appearing,
#                       then it is "settled" and left alone (a window you moved
#                       is never yanked back). Generous because on login Chrome
#                       opens every window and only sets each title once its
#                       content loads, and under CPU/network spikes that whole
#                       storm can take a minute or two.
PLACE_SETTLE = 1.5    # BROWSER windows: seconds the title must be QUIET before
#                       we place. A browser churns its title through a session-
#                       restore as tabs load, and reconfiguring it mid-restore
# can make it DROP the window, since a heavy tab-group window
#                       was lost exactly this way. A PLACE_EVENT only re-arms
#                       the timer; the move waits for the churn to stop. Well
#                       under PLACE_GRACE.
PLACE_SETTLE_FAST = 0.15  # everything else: the title is already stable at map
#                           and nothing restores tabs, so place almost at once
#                           (one placer tick). No reason to make normal apps sit
#                           out the browser settle, which is the common case.


def is_browser(app):
    # Chrome/Chromium/Firefox: restore-heavy, title-churning clients that can
    # drop a window if it is moved mid-restore. ONLY these wait PLACE_SETTLE;
    # the (chrome-<ext>-Profile_N) app-mode ids match too, via the substring.
    a = (app or "").lower()
    return ("chrom" in a) or ("firefox" in a)


# Consecutive failing captures before the worker exits for a clean supervisor
# respawn. capture_loop reconnects on every error, so a transient stall self-
# heals far below this; only a genuinely wedged compositor sustains a streak
# this long, where a full respawn (fresh sockets + connect() retry) is the
# correct recovery, not limping on a dead thread.
CAPTURE_FAIL_LIMIT = 15


class Supervisor:
    """Hold the single-instance lock, spawn a worker, and respawn it with
    backoff if it dies. The worker is this same script RE-EXEC'd (the `_worker`
    verb), not a fork, so it reloads its code from disk on every respawn
    (kill the worker to pick up an edit), and only the supervisor holds the
    lock (the worker no longer inherits the fd, so an orphan can never block a
    restart). If a watcher is ALREADY running, run() reloads it in place
    (SIGHUP re-exec, picking up a code edit and the armed mode) instead of
    exiting, so re-running watch/resume IS the reload. Two paths in one
    script, self-contained (contrast kanshi/kanshi-mgr); session teardown reaps
    both via the cgroup kill, so the supervisor need not detect session end
    itself."""

    def __init__(self, launch=True):
        self.launch = launch
        self.script = os.path.abspath(sys.argv[0])
        self.lock = None     # None until run(); an fd, or "unlocked"
        self.proc = None     # the live worker, for the signal handlers

    def run(self):
        self.lock = acquire_singleton()
        if self.lock is None:
            # already running -> reload it (picks up code + the armed mode).
            _signal_watcher(signal.SIGHUP, "reload", "reloaded")
            return
        if self.lock == "unlocked":
            logline("singleton lock unavailable; supervising unlocked")
        elif isinstance(self.lock, int):
            try:                # record our pid so a re-run/stop can signal us
                os.ftruncate(self.lock, 0)
                os.write(self.lock, f"{os.getpid()}\n".encode())
            except OSError:
                pass
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        signal.signal(signal.SIGHUP, self._reload)
        # A fresh supervisor (login or a re-run) starts un-launched: drop a
        # stale marker so this generation relaunches. (A reload is safe, because
        # the
        # open terminals are live, so launch_missing skips them.)
        try:
            os.makedirs(STATE, exist_ok=True)
            os.remove(LAUNCHED)
        except OSError:
            pass
        self._respawn_forever()

    def _stop(self, signum, _frame):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        logline(f"supervisor stopping (signal {signum})")
        os._exit(0)

    def _reload(self, signum, _frame):
        # Signal-handler context: the main loop is blocked in proc.wait(), so
        # do NOT call Popen.wait() here, because it re-enters the same lock and
        # deadlocks. Just SIGTERM the worker (it holds no lock and dies on its
        # own; execv abandons the wait anyway) and release the lock fd so the
        # re-exec'd self can re-acquire it.
        if self.proc:
            try:
                os.kill(self.proc.pid, signal.SIGTERM)
            except OSError:
                pass
        if isinstance(self.lock, int):
            try:
                os.close(self.lock)
            except OSError:
                pass
        logline("reload (SIGHUP): re-exec supervisor")
        # Re-exec via the internal _super verb, NOT the original watch/resume
        # argv: a re-exec must supervise WITHOUT re-arming/clearing the adopt
        # flag, so a `usher-mgr resume` that triggered this reload is
        # honoured by the next worker instead of clobbered by a re-run of
        # arm_mode.
        keep = ["--no-launch"] if "--no-launch" in sys.argv[1:] else []
        os.execv(sys.executable,
                 [sys.executable, self.script, "_super"] + keep)

    def _respawn_forever(self):
        """Respawn the worker forever, with backoff."""
        base = [sys.executable, self.script, "_worker"]
        backoff = 2
        while True:
            # Relaunch missing mux terminals on the first worker that actually
            # REACHES launch_missing (which drops LAUNCHED), NOT merely the
            # first spawned. The first worker often dies to the compositor-
            # startup race before it can launch; welding launch to it lost the
            # relaunch entirely. While the marker is absent, every spawn keeps
            # launch on, so a crashed-early worker just hands the launch to its
            # successor. launch_missing is idempotent (it skips sessions a live
            # window already shows), so at worst a rare double-pass is
            # harmless.
            argv = base if (self.launch and not os.path.exists(LAUNCHED)) \
                else base + ["--no-launch"]
            try:
                self.proc = subprocess.Popen(argv)
            except OSError as e:
                logline(f"spawn failed: {e}; retry in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            started = time.time()
            try:
                rc = self.proc.wait()
            except Exception as e:
                logline(f"wait: {e}")
                rc = -1
            self.proc = None
            ran = int(time.time() - started)
            if ran >= 60:
                backoff = 2            # a healthy run resets the backoff
            logline(f"worker exited (rc {rc}, ran {ran}s); "
                    f"respawn in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


def do_watch(launch=True):
    """Start supervising, or reload the supervisor already running."""
    Supervisor(launch).run()


class Watcher:
    """The daemon proper: place windows to their known spot as they appear
    (react), and continuously record the layout into the knowledge base
    (capture). Runs as a child of do_watch's supervisor; an uncaught crash
    here is caught there and the worker respawned. On startup, unless launch
    is False, it also relaunches personal mux terminals that have no window.
    Placement and capture each get their own IPC socket so neither blocks the
    events.

    WHY A CLASS. Three threads share one pile of mutable placement state:
    what is already placed, what is pending a settle, each window's grace
    deadline, the aggressive-mode clock, the knowledge base. That sharing is
    inherent to the design, and as nested closures it was expressed by nine
    captured locals inside one 400-line function, which is why the function
    could not be split: any extraction would have had to take them all as
    arguments. The state is unchanged; calling it `self` is what lets each
    phase be a method you can read on its own.

    If a `usher-mgr resume` armed the adopt flag, the FIRST worker to reach
    init consumes it and LEARNS the current hand-arranged layout as the
    baseline instead of restoring the remembered one, for use after killing
    session and fixing windows by hand, so it does not undo the good state.
    Then it watches normally; respawns (flag gone) restore as usual."""

    def __init__(self, launch=True):
        os.makedirs(STATE, exist_ok=True)
        self.launch = launch
        self.mode = None
        self.kb = load_knowledge()
        self.lock = threading.Lock()
        # dirty: knowledge needs a capture. layout: roll history too (not on a
        # tab-flip).
        self.st = {"dirty": True, "layout": True, "last": time.time(),
                   "armed_at": time.time(),  # aggressive clock (reset by kick)
                   "last_map": time.time()}  # last new toplevel map, which
        #                                      feeds IDLE_SETTLE
        self.placed = set()
        self.pending = {}      # vid -> {"v": latest view, "due": place-after
        #                        time}: the settle-debounce queue, drained by
        #                        _placer_loop
        self.deadline = {}     # vid -> time after which we no longer place it
        self.identified = set()   # vids we have ever been able to RECOGNISE
        #                           (see _recognise: the grace runs from that
        #                           moment, not from the map, so a slow login
        #                           sequence still lands)
        self.groups = {}       # vid -> {"app", "titles": set}: the in-session
        #                        tab-group, fed to learn()
        self.seen_terms = set()   # terminal identities this generation has
        #                           actually OBSERVED alive. The terminal purge
        #                           may only drop what is in here, because a
        #                           window absent from a snapshot has either
        #                           closed or not mapped yet and nothing else
        #                           tells the two apart. Empty at startup, which
        #                           is exactly when the windows we just launched
        #                           have not arrived.
        self.hold_until = 0    # when the earliest HELD window is released, so
        #                        a quiet session still comes back to learn it
        self.saved = None      # the snapshot the RELAUNCH works from, read in
        #                        run() before the capture loop can overwrite it
        self.place_sock = None

    def run(self):
        """Connect, start the capture thread, act once on the start mode, then
        watch events forever. The ORDER is the same one the function had: the
        capture loop is running before the mode is consumed, and the relaunch
        happens only after we are watching, so the windows it spawns produce
        map events we catch."""
        self.place_sock = connect()
        logline("usher-mgr: starting")
        # THE DAEMON'S STDERR IS DISCARDED by the compositor autostart, so the
        # warning engine prints for a CLI caller reaches nobody here. An
        # unclean SESSION environment is the more serious of the two cases
        # (every child of the session inherits it), so it goes in the log where
        # a reader of watch.log will meet it.
        if engine.SOCKET_HUNTED:
            logline("WAYFIRE_SOCKET was unset: found the socket by searching "
                    f"{engine.SOCKET_HUNTED}. The session should export it; "
                    "something that starts usher does not.")
        for _n, _text, _msg in engine.EXCLUDE_ERRORS:
            logline(f"exclude rule error (line {_n}): {_msg}: {_text!r}")
        # BEFORE anything reads or writes the store. If Chrome restarted while
        # no worker was up, every chrome slot in the store is already keyed to
        # the dead ids and must be moved across before the first placement or
        # the first capture.
        self._rekey_chrome()
        # READ THE SAVED LAYOUT BEFORE ANYTHING CAN OVERWRITE IT. The relaunch
        # is driven by the last snapshot, and it does not run until _init_launch
        # below, eleven lines and a socket connect later. The capture loop
        # starting on the next line writes current.json within a second, and at
        # session start it writes ZERO WINDOWS, because none have mapped yet. So
        # whether anything is relaunched came down to a race between two
        # threads, and losing it means the login brings back nothing at all.
        #
        # Measured 2026-09-30 on a summoned login: the good 8-window capture
        # from the logout was replaced by a 0-window one at 18:09:57, the
        # relaunch read that and launched nothing, and the session came back
        # with one window. The same startup on a faster run at 22:30 won the
        # race and restored everything, which is exactly why this hid.
        self.saved = engine.load_snapshot()
        threading.Thread(target=self._capture_loop, daemon=True).start()
        # Consume the one-shot adopt flag (armed by `usher-mgr resume`): the
        # first worker to reach here adopts; a respawn sees it gone and
        # restores.
        self.mode = take_mode()
        self._init_layout()
        watch = connect()
        watch.watch(list(KNOWLEDGE_TRIGGERS | PLACE_EVENTS))
        print(f"usher-mgr: {len(self.kb)} known windows; watching",
              flush=True)
        logline(f"watching, {len(self.kb)} known windows")
        self._init_launch()
        threading.Thread(target=self._placer_loop, daemon=True).start()
        self._event_loop(watch)

    # --- startup: the one-shot decisions -------------------------------------

    def _init_layout(self):
        """Act on the start MODE, once. quiet touches nothing, adopt takes the
        current layout as the new truth, restore (the default) places what is
        already open."""
        if self.mode == "quiet":
            # A code reload: express NO opinion about the layout. No
            # init-place, no capture, no grace deadlines. The windows keep
            # their positions AND the store keeps its memory of where they
            # belong, so a reload can never be the reason the two silently
            # converge on the wrong answer.
            logline("reload: neither restoring nor re-baselining")
        elif self.mode == "adopt":
            # Capture-and-resume: adopt the CURRENT layout as the baseline and
            # do NOT restore. No init-place and no grace deadlines for open
            # windows, so they stay exactly where they are; the refreshed
            # knowledge means new windows FROM HERE are maintained against the
            # good state, not the stale pre-kill one. _capture_loop keeps it
            # current after this.
            try:
                do_capture()
                self.kb = load_knowledge()   # so _place_view sees the fresh KB
                logline("adopt: captured current layout as baseline; "
                        "not restoring")
            except Exception as e:
                logline(f"adopt capture error: {e}")
        else:
            self._init_place()

    def _init_place(self):
        """Place anything already open when we start (the event loop handles
        the rest). These get a grace window from NOW, so init-place lands but
        later stray title changes on them do not."""
        now = time.time()
        n_placed = 0
        for v in self.place_sock.list_views(filter_mapped_toplevel=True):
            if v.get("id") is not None:
                self.deadline[v["id"]] = now + PLACE_GRACE
            try:
                if self._try_place(v):
                    n_placed += 1
            except Exception as e:
                logline(f"init place error: {e}")
        logline(f"init-placed {n_placed} window(s)")

    def _init_launch(self):
        """Relaunch missing terminals, once we are watching, so their map
        events are caught and placed by the event loop. Chrome restores itself.
        Drop the LAUNCHED marker only after launch_missing RETURNS, so the
        supervisor keeps launch on for a successor if this worker dies first.

        `quiet` (usher reload) suppresses the relaunch too, and MUST do
        so here rather than through the `launch` argument. A reload signals the
        running supervisor, which re-execs with its OWN original argv, so the
        launch flag the reload was invoked with never reaches the worker,
        while a fresh supervisor generation deletes the LAUNCHED marker,
        re-arming the relaunch. A deploy therefore spawned a terminal every
        time. The mode travels in the flag file, which the worker DOES read, so
        that is the only place the suppression can actually take effect."""
        if self.launch and self.mode != "quiet":
            try:
                launch_missing(self.saved)
                open(LAUNCHED, "w").close()
            except Exception as e:
                logline(f"launch_missing error: {e}")
        elif self.mode == "quiet":
            logline("reload: relaunch suppressed")

    # --- the aggressive/steady clock, and what it publishes -------------------

    def _steady_at(self):
        # steady when (FLOOR passed AND quiet for SETTLE) OR past CAP; the kick
        # resets armed_at and a new map pushes last_map, and both extend
        # aggressive.
        with self.lock:
            armed = self.st["armed_at"]
            last_map = self.st["last_map"]
        return min(armed + AGGR_CAP,
                   max(armed + START_FLOOR, last_map + IDLE_SETTLE))

    def _aggressive_now(self):
        return time.time() < self._steady_at()

    def _write_status(self):
        # Publish {mode, seconds_left} for `usher status` + the tray. The
        # steady-at estimate assumes no more windows arrive; a map or a kick
        # moves it out. Atomic replace so a reader never sees a half file.
        now = time.time()
        steady_at = self._steady_at()
        # arc = fraction of the aggressive window still to run, for the tray's
        # depleting ring; ~1.0 right after a kick, 0.0 once steady.
        arc = max(0.0, min(1.0, (steady_at - now) / START_FLOOR))
        try:
            tmp = STATUS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(
                    {"mode": "aggressive" if now < steady_at else "steady",
                     "seconds_left": max(0, round(steady_at - now)),
                     "arc": round(arc, 3)}, f)
            os.replace(tmp, STATUS_FILE)
        except OSError:
            pass

    # --- placement -----------------------------------------------------------

    def _try_place(self, v):
        """_place_view with the IPC error policy wrapped round it. A desync-
        class error (timeout / off-by-one) poisons place_sock the same way it
        poisons the capture socket, and would then silently fail EVERY
        placement for the rest of the session, so rebuild it on one. A benign
        server error-response (e.g. "view is not toplevel" for a popup) leaves
        the socket in sync: log it and move on, never reconnect."""
        try:
            return self._place_view(v)
        except Exception as e:
            if is_desync_error(e):
                logline(f"place desync: {e}; reconnecting place socket")
                try:
                    self.place_sock.close()
                except Exception:
                    pass
                try:
                    self.place_sock = connect()
                except Exception as e2:
                    logline(f"place reconnect failed: {e2}")
            else:
                logline(f"place error: {e}")
            return None

    def _place_view(self, v):
        """Decide whether this view may be placed right now, and where. Returns
        True only if it was actually moved."""
        vid = v.get("id")
        if vid is None or vid in self.placed:
            return
        if v.get("parent", -1) != -1:
            return   # a dialog / child view (a file picker, a "Save As" sheet):
            # it MUST stay on its parent's output. Issuing an output
            # move for it aborts the whole compositor, because wayfire's
            # move_view_to_output dassert("Cannot move a dialog to a
            # different output than its parent"). The event path is not
            # toplevel-filtered like the init path, so dialogs reach
            # here; the parent field (-1 == none) is the reliable tell,
            # where is_transient's title match is not (a portal file
            # chooser has a null/foreign title).
        app = app_of(v)
        title = v.get("title", "")
        if SKIP_TITLE.search(title) or is_transient(v):
            return   # work / scratch / transient-chrome: leave where it opened
        if unidentified(v):
            # Its plugin cannot say which window this is, so the only key we
            # could look it up under is one the store is deliberately never
            # written under. Matching on the title anyway is how "revisit an
            # old page, watch the window jump to another desktop" worked, and
            # the same predicate governs learning and placing so they cannot
            # drift apart.
            #
            # NOT YET is the common case, so RE-QUEUE rather than drop, and
            # RE-READ THE VIEW when the retry comes due. A plugin reads live
            # state that lags the map: measured, a kitty window's identity
            # resolves 0.25s after mapping while the placer first looks at
            # 0.15s, and the event payload we were handed is a snapshot of
            # that moment, so retrying it asks the same question forever. The
            # grace bounds the retrying, which is the same "stay willing until
            # the window has had one real chance" rule the grace exists for.
            if time.time() <= self.deadline.get(vid, 0):
                with self.lock:
                    self.pending[vid] = {"v": v, "refetch": True,
                                         "due": time.time() + PLACE_SETTLE}
            return
        with self.lock:
            e = (self.kb.get(kkey(app, ""))
                 or self.kb.get(kkey(app, identity(v))))
        if e is not None and vid not in self.identified:
            self._recognise(vid, app, title)
        if time.time() > self.deadline.get(vid, 0):
            return   # past the grace window: the window is settled, hands off
        if not self._aggressive_now() and not is_anchored(app, title):
            return   # steady state: only usher/include anchors are (re)placed
        if not e:
            return   # never seen this identity -> we don't know where it goes
        outs = {o["name"]: o for o in self.place_sock.list_outputs()}
        o = outs.get(e["output"])
        if not o:
            return
        return self._seat_view(v, e, o)

    def _recognise(self, vid, app, title):
        """THE GRACE RUNS FROM RECOGNITION, NOT FROM THE MAP. A window can be
        unidentifiable for a long time after it appears: a terminal that has to
        wait for a keyring to be unlocked before its ssh connects and the
        remote tmux paints a banner is a bare shell until then, and its real
        title can arrive minutes later. Measuring the grace from the map meant
        that window was already past it, so it was never placed and the human
        had to do it by hand.

        So the FIRST time a window can be recognised, restart its grace and
        feed the settle clock, exactly as if it had just mapped, because from
        usher's point of view it just has. This needs no model of the sequence,
        no knowledge of keyrings or agents, and no new persistent state: it
        simply stays willing to place a window until it has had one real
        chance. Still bounded, since the aggressive check still governs."""
        self.identified.add(vid)
        late = time.time() > self.deadline.get(vid, 0)
        self.deadline[vid] = time.time() + PLACE_GRACE
        with self.lock:
            self.st["last_map"] = time.time()
        if late:
            logline(f"recognised late, re-graced: {app[:16]} | {title[:34]}")

    def _seat_view(self, v, e, o):
        """Move the view onto its remembered slot (unless it is already exactly
        there), carry the invert with it, and say so in the log."""
        vid = v["id"]
        app, title = app_of(v), v.get("title", "")
        # Skip if already exactly there (init-place over an in-place session
        # would otherwise re-issue every window). The event view carries
        # geometry for init (list_views); a freshly-mapped view may not, and
        # then we place unconditionally, which is what a new window wants.
        g = v.get("geometry")
        if g:
            t = target_geometry(e, o)
            if (g.get("x") == t["x"] and g.get("y") == t["y"] and
                    g.get("width") == t["width"] and
                    g.get("height") == t["height"] and
                    v.get("output-name") == e["output"]):
                self.placed.add(vid)
                # Invert and fullscreen follow the WINDOW, not the move, so
                # they are re-applied even when nothing needed moving. placed
                # dedups, so each fires once per map and never fights a later
                # Super+N or F11.
                self._restate(vid, e)
                return
        place(self.place_sock, vid, e, o)
        self.placed.add(vid)
        self._restate(vid, e)
        msg = (f"placed  {app[:18]:18} {e['output']} "
               f"ws{tuple(e['workspace'])} | {title[:32]}"
               f"{' [inv]' if e.get('inverted') else ''}"
               f"{' [full]' if e.get('fullscreen') else ''}")
        print(msg, flush=True)
        # ALSO to the log. The autostart discards the worker's stdout, so a
        # per-window placement left no trace anywhere, and the only record of
        # placement was the init-placed COUNT. Reconstructing why one window
        # was not placed then depends entirely on the history ring, which
        # samples on capture and cannot say whether usher acted or the human
        # did. This is the line that answers that next time.
        logline(msg)
        return True

    def _restate(self, vid, e):
        """Re-apply the window STATE a geometry move does not carry: the
        colour-invert shader, and fullscreen. Both are only ever set, never
        cleared (see apply_fullscreen), and both belong here rather than inside
        the move branch: a window an app already restored at its target
        position is matched-but-not-moved and must still get its state back,
        which is exactly the bug that made invert "forget some"."""
        if e.get("inverted"):
            apply_invert(self.place_sock, vid)
        if e.get("fullscreen"):
            apply_fullscreen(self.place_sock, vid)

    def _placer_loop(self):
        """Settle-debounce placer. Moves a window only once its title has been
        QUIET for PLACE_SETTLE: a restoring client churns its title as tabs
        load, and reconfiguring it mid-restore can make it drop the window. The
        event loop only records the latest view + a due time in `pending`; this
        thread does the actual place when the churn stops, reusing place_sock
        (nothing else touches it once init is done, so it has one writer)."""
        while True:
            time.sleep(0.1)
            now = time.time()
            ready = []
            with self.lock:
                for vid in list(self.pending):
                    if vid in self.placed:
                        self.pending.pop(vid, None)
                    elif now >= self.pending[vid]["due"]:
                        ready.append(self.pending.pop(vid))
            for item in ready:
                v = item["v"]
                if item.get("refetch"):
                    v = self._fresh_view(v.get("id")) or v
                self._try_place(v)
            with self.lock:
                again = self.st.pop("recheck", False)
            if again:
                self._recheck_all()

    def _fresh_view(self, vid):
        """The compositor's CURRENT view dict for vid, or None if it is gone.
        A retry has to re-read: the payload an event handed us describes the
        instant it fired, and the whole reason for retrying is that something
        about the window was not readable yet. Runs on the placer thread, which
        is the one writer place_sock has."""
        if vid is None:
            return None
        try:
            for v in self.place_sock.list_views(filter_mapped_toplevel=True):
                if v.get("id") == vid:
                    return v
        except Exception as e:
            logline(f"refetch view {vid}: {e}")
        return None

    def _recheck_all(self):
        """Give every live window another chance at placement, because what
        usher KNOWS just changed rather than what the windows are doing.

        Placement is event-driven: a window is considered when it maps or
        renames. That is right while the store is fixed, and WRONG the moment
        the store changes underneath it. A Chrome window that was
        unidentifiable when its last event arrived becomes identifiable the
        instant its session file catches up or its slot is re-keyed, and
        nothing tells us so, because the window is not doing anything. One
        whose title has settled emits no further events at all, so it is never
        reconsidered and simply stays where Chrome put it.

        MEASURED, twice, on the same window: an article page that finished
        loading early sat at Chrome's default position through an entire
        session start, while its five noisier siblings landed correctly. That
        is the difference between "nearly always" and pixel perfect, and it is
        a gap in the TRIGGER, not in any of the deciding.

        Cheap and bounded: `placed` already dedups, so anything that landed is
        a set lookup, and the grace still governs the rest. Runs on the placer
        thread because place_sock has exactly one writer."""
        try:
            views = self.place_sock.list_views(filter_mapped_toplevel=True)
        except Exception as e:
            logline(f"recheck: {e}")
            return
        n = 0
        for v in views:
            try:
                if self._try_place(v):
                    n += 1
            except Exception as e:
                logline(f"recheck place error: {e}")
        if n:
            logline(f"re-checked after a store change: placed {n} window(s)")

    # --- capture -------------------------------------------------------------

    def _capture_loop(self):
        """Every second: pick up config edits, publish status, and write a
        snapshot once the layout has been quiet for DEBOUNCE."""
        cap = connect()
        seen = {"inv": store_mtime(INVERT_STORE),
                "exc": store_mtime(EXCLUDE_FILE),
                "inc": store_mtime(INCLUDE_FILE),
                "arm": store_mtime(ARM_FILE),
                "plugins": plugins_sig(),
                "chrome": chrome.session_sig()}
        errstreak = 0
        while True:
            time.sleep(1)
            self._poll_files(seen)
            self._write_status()
            with self.lock:
                due = (self.st["dirty"]
                       and time.time() - self.st["last"] >= DEBOUNCE)
            if not due:
                continue
            # A transient IPC timeout (the compositor stalls under a slow
            # login) must not kill this thread: leave st["dirty"] set and the
            # next tick retries. Without the guard the capture thread died
            # silently and snapshots simply stopped.
            try:
                self._capture_once(cap)
                errstreak = 0
            except Exception as e:
                errstreak += 1
                cap = self._capture_failed(e, cap, errstreak)

    def _poll_files(self, seen):
        """Adopt edits to the files that steer us, by mtime. Auto-incorporating
        usher/exclude + usher/include means a new never-place or anchor
        rule applies on save; ARM_FILE is the one seam aggressive/settle/toggle
        drive; and a change to the invert store is the only signal a Super+N
        toggle gives us, since inversion has no view event of its own."""
        e = store_mtime(EXCLUDE_FILE)
        if e != seen["exc"]:
            seen["exc"] = e
            reload_exclude()
        i = store_mtime(INCLUDE_FILE)
        if i != seen["inc"]:
            seen["inc"] = i
            reload_anchor()
        # A USER PLUGIN is the same class of config as those two files and now
        # reloads the same way. Identity may change for the app it claims, so
        # its windows relearn; that is what editing a plugin asks for.
        pl = plugins_sig()
        if pl != seen["plugins"]:
            seen["plugins"] = pl
            reload_plugins()
        # aggressive/settle/toggle all write a timestamp to ARM_FILE; adopt it
        # as the new armed_at (now = kick, a past ts = settle to steady).
        a = store_mtime(ARM_FILE)
        if a != seen["arm"]:
            seen["arm"] = a
            try:
                with self.lock:
                    self.st["armed_at"] = float(
                        open(ARM_FILE).read().strip())
                logline("aggressive re-armed (kick)"
                        if self._aggressive_now() else "settled to steady")
            except (OSError, ValueError):
                pass
        # Treat a change to the invert store as a capture trigger, so
        # invert/un-invert persists on its own without waiting for a move.
        # (apply_invert also writes it during restore, which is harmless, just a
        # redundant capture of state we set ourselves.)
        m = store_mtime(INVERT_STORE)
        if m != seen["inv"]:
            seen["inv"] = m
            with self.lock:
                self.st["dirty"] = True
                self.st["last"] = time.time()
        # A BROWSER RESTART IS VISIBLE RIGHT HERE and nowhere else. Chrome
        # mints fresh SessionIDs for every restored window, so the store's
        # chrome slots go dead the instant it rotates its session file, and
        # that rotation is exactly this signature changing. It is also the one
        # moment the PREVIOUS file is still on disk to bind against, so this
        # cannot be deferred to something slower.
        if self.hold_until and time.time() > self.hold_until:
            self.hold_until = 0
            with self.lock:
                self.st["dirty"] = True
                self.st["last"] = 0      # due at once, no debounce wait
        c = chrome.session_sig()
        if c != seen["chrome"]:
            seen["chrome"] = c
            self._rekey_chrome()
            with self.lock:
                self.st["recheck"] = True

    def _rekey_chrome(self):
        """Move the chrome slots onto the current session's window ids, and
        say so in the log. Silent and cheap when nothing is stale, which is
        every call but the ones just after a browser restart."""
        try:
            with self.lock:
                moved = rekey_chrome(self.kb)
                if moved:
                    save_knowledge(self.kb)
        except Exception as e:
            logline(f"chrome re-key error: {e}")
            return
        if moved:
            logline(f"chrome: re-keyed {moved} window slot(s) onto the"
                    f" restarted browser's session ids")

    def _held(self, windows):
        """The view ids whose CURRENT position must not be believed yet.

        While placement is AGGRESSIVE, a window the placer has not reached is
        sitting wherever its app dropped it, and learning that OVERWRITES the
        remembered slot the placer is about to aim at. The capture loop and the
        placer were racing over the same fact, and capture won because it runs
        every second.

        MEASURED, and it is what stood between this and pixel perfect: a Chrome
        window that resolved its identity a few seconds late had its slot
        replaced by Chrome's cascade position on every single restart, so by
        the time it became placeable the store had already been taught that the
        cascade WAS its home. Two failures compounding: one late identity,
        one eager capture, and only the second is fixable here.

        A window is released the moment it is placed, or when its grace runs
        out and usher is no longer going to act on it. In steady state nothing
        is placed, so nothing is held."""
        if not self._aggressive_now():
            return frozenset()
        now = time.time()
        return frozenset(w["id"] for w in windows
                         if w.get("id") is not None
                         and w["id"] not in self.placed
                         and now <= self.deadline.get(w["id"], 0))

    def _capture_once(self, cap):
        """One snapshot: learn from it, save the knowledge, roll the history if
        this was a layout change rather than a tab flip. The SNAPSHOT is always
        whole: only what we LEARN from it is held back."""
        snap = snapshot(cap)
        hold = self._held(snap["windows"])
        # WHEN THE HOLD LIFTS, COME BACK. Capture is event-driven, so a window
        # held through the pass that recorded it gets no second look until
        # something else happens to dirty the store. In a busy session that is
        # immediate and invisible; in a quiet one the window sits in the
        # snapshot with no learned slot indefinitely, so it comes back at the
        # next login and has nowhere to be put. Measured by spawning one
        # terminal and then doing nothing for two minutes.
        #
        # Only the "grace expired, never placed" release needs this. A window
        # that gets PLACED leaves the hold too, but placing it moves it, and a
        # geometry change is already a capture trigger.
        self.hold_until = min((self.deadline.get(i, 0) for i in hold),
                              default=0)
        with self.lock:
            roll = self.st["layout"]
            learn(self.kb, self.groups, snap["windows"], snap["time"], hold,
                  seen=self.seen_terms)
            self.st["dirty"] = False
            self.st["layout"] = False
            save_knowledge(self.kb)
        persist(snap, roll=roll)

    def _capture_failed(self, e, cap, errstreak):
        """Handle a failed capture and return the socket to keep using. A
        request timeout leaves its response unread in cap's buffer, desyncing
        it off-by-one: every later call then reads the PREVIOUS call's response
        (the name/mapped KeyError storm). Reusing it never resyncs, so on a
        desync-class error drop the socket and reconnect; st["dirty"] stays
        set, so the next tick retries on the fresh socket. A benign error would
        not desync, so it is left alone: the streak backstop still covers a
        persistent one."""
        logline(f"capture error: {e} (streak {errstreak})")
        if is_desync_error(e):
            try:
                cap.close()
            except Exception:
                pass
            try:
                cap = connect()
            except Exception as e2:
                logline(f"cap reconnect failed: {e2}")
        # Fail loud: a sustained streak means the error is not clearing
        # (compositor wedged, or a class reconnect cannot fix). Exit so the
        # supervisor does a clean full respawn instead of limping on a broken
        # capture thread.
        if errstreak >= CAPTURE_FAIL_LIMIT:
            logline(f"capture failing {errstreak}x; exit for respawn")
            os._exit(1)
        return cap

    # --- events --------------------------------------------------------------

    def _event_loop(self, watch):
        """Read compositor events until the compositor goes away. Guard the
        WHOLE event body: a stalled-compositor IPC timeout, or any unforeseen
        error, on one event must skip that event, never fall out of the loop
        and end the daemon. The login-storm crash that piled Chrome up came in
        through exactly this path (a placement call)."""
        while True:
            try:
                msg = watch.read_next_event()
            except Exception as e:
                logline(f"watch loop exit: {e}")   # compositor gone: teardown
                break
            try:
                self._on_event(msg)
            except Exception as e:
                logline(f"event error ({msg.get('event', '?')}): {e}")

    def _on_event(self, msg):
        ev = msg.get("event", "")
        v = msg.get("view", {}) or {}
        if ev == "view-mapped" and v.get("id") is not None:
            self.deadline[v["id"]] = time.time() + PLACE_GRACE  # start grace
            with self.lock:
                self.st["last_map"] = time.time()  # feed the IDLE_SETTLE clock
        if ev in PLACE_EVENTS:
            vid = v.get("id")
            if vid is not None and vid not in self.placed:
                # Defer to _placer_loop. Browsers wait PLACE_SETTLE (re-armed
                # on every title change) so we never move one mid-restore;
                # other apps are stable at map -> a tiny settle, placed on the
                # next tick.
                wait = (PLACE_SETTLE if is_browser(app_of(v))
                        else PLACE_SETTLE_FAST)
                with self.lock:
                    self.pending[vid] = {"v": v, "due": time.time() + wait}
        elif ev == "view-unmapped" and v.get("id") is not None:
            self.placed.discard(v["id"])
            self.identified.discard(v["id"])
            self.deadline.pop(v["id"], None)
            # and the identity chrome resolved for it once and remembered. A
            # cache that only ever grows is a leak in a process that runs for
            # weeks, and this is the one moment we know the view is gone.
            chrome.forget_window(v["id"])
            with self.lock:
                self.pending.pop(v["id"], None)
        if ev in KNOWLEDGE_TRIGGERS:
            with self.lock:
                self.st["dirty"] = True
                self.st["last"] = time.time()
                if ev in LAYOUT_TRIGGERS:
                    self.st["layout"] = True


def watch_worker(launch=True):
    """The supervised worker (the internal `_worker` verb): one Watcher, run
    until the compositor goes away or it crashes for the supervisor to
    catch."""
    Watcher(launch).run()
