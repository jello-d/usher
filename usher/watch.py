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
from .engine import (PLACE_CAP, ARM_FILE, CAPTURE_FILE, EXCLUDE_FILE,
                     FORGET_FILE,
                     IDLE_SETTLE,
                     INCLUDE_FILE, INVERT_STORE, LAUNCHED, REDISPLAY_FILE,
                     SWEEP_FILE,
                     SKIP_TITLE,
                     START_FLOOR, STATE, STATUS_FILE, _signal_watcher,
                     acquire_singleton, app_of, apply_fullscreen,
                     apply_invert, connect, do_capture, identity, is_anchored,
                     is_desync_error,
                     entry_output, is_transient, kb_for_profile, kkey,
                     launch_missing, learn, live_holder,
                     load_knowledge, logline, persist, place, placement_landed,
                     plugins_sig,
                     reload_anchor, reload_exclude, reload_plugins,
                     runtime_dir,
                     rekey_chrome, save_knowledge, snapshot,
                     store_mtime, take_mode, target_geometry, unidentified)


# Layout-significant events: re-snapshot AND roll the history/milestone ring.
LAYOUT_TRIGGERS = {
    "view-geometry-changed", "view-workspace-changed", "view-tiled",
    "view-set-output", "view-wset-changed", "view-mapped", "view-unmapped",
    "view-fullscreen", "view-sticky", "output-added", "output-removed",
    "wset-workspace-changed",
}

# A MONITOR ARRIVING OR LEAVING, which is a different kind of event from
# anything a view does: every slot on the affected output is about to become
# unanswerable and every window on it is about to be moved by somebody else.
OUTPUT_EVENTS = {"output-added", "output-removed"}
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
TITLE_QUIET = 1.5    # BROWSER windows: seconds the title must be QUIET before
#                       we place. A browser churns its title through a session-
#                       restore as tabs load, and reconfiguring it mid-restore
# can make it DROP the window, since a heavy tab-group window
#                       was lost exactly this way. A PLACE_EVENT only re-arms
#                       the timer; the move waits for the churn to stop. Well
#                       under PLACE_GRACE.
TITLE_QUIET_FAST = 0.15  # everything else: the title is already stable at map
#                           and nothing restores tabs, so place almost at once
#                           (one placer tick). No reason to make normal apps sit
#                           out the browser's title churn, the
#                           common case.

# WHEN TO READ A PLACEMENT BACK, one delay per attempt, so the length of this
# tuple is how many times a window may be re-placed per map.
#
# A BACKOFF RATHER THAN A FIXED INTERVAL, because the thing being raced is an
# app finishing its own startup, and that takes as long as it takes: wayfire's
# cascade placer assigns the losing position when the client's first real
# commit arrives, which on a relaunched calibre was about four seconds after
# the map. Three tries spanning 5.1s cover that without a window being dragged
# around for the whole 120s grace. The first delay must also be long enough
# for the compositor to have APPLIED the request we are checking, or every
# placement reads as failed; 0.6s against a measured sub-second apply.
PLACE_VERIFY = (0.6, 1.5, 3.0)
# The visibility guarantee (Watcher._ensure_visible): how often it looks,
# and how many times one window is rescued before usher says so and stops.
VISIBLE_EVERY = 5.0
RESCUE_TRIES = 3

# HOW MANY TIMES A FAILED CHROME RE-KEY IS RETRIED before its session
# signature is adopted anyway. The measured failure is a session file
# vanishing between being listed and being read, which is a race and so
# needs one more look rather than persistence; the bound is what stops a
# deterministic failure from re-reading those files every second for ever.
REKEY_TRIES = 2


# HOW LONG AN OUTPUT CHANGE SUPPRESSES LEARNING.
#
# A dock coming out makes the compositor move every window that was on the
# vanished monitor, and the capture loop runs every SECOND, so with no hold
# the collapse is simply what gets learned. Measured in a nested rehearsal:
# wayfire remaps each position proportionally into the surviving output
# (140/1080 becomes 248.9/1920) and keeps the absolute workspace, so the
# result is plausible, wrong, and indistinguishable from the human having
# rearranged everything.
#
# TWO SIGNALS, EACH FOR WHAT IT KNOWS. The compositor's own output-added /
# output-removed events are instant and say THAT the displays changed; hwdp's
# hook says WHAT the new profile is, and arrives later because it runs after
# kanshi has applied the new arrangement. So the compositor event starts this
# hold and the hook does the placement, which is the same reason usher's hook
# is numbered 40 and runs last.
#
# BOUNDED, because what ENDS a transition properly is that hook arriving, and
# a hook that never comes (a box with no hwdp) must not suppress learning for
# the rest of the session. It cannot be tiny either: a re-place issued at the
# end of a transition still needs its PLACE_VERIFY read-backs to land before
# anything it did is believed. A tunable because the honest value depends on
# one real dock's kanshi-plus-hook latency, which no amount of rehearsal here
# can tell us.
DOCK_HOLD = float(os.environ.get("USHER_DOCK_HOLD", 20))


# THE WORKER RESPAWN BOUNDS. Named because they govern how the daemon
# recovers from a crash, which is a thing a reader needs to reason about and
# nobody gets to choose: a worker dying in a loop is the case these decide,
# and the cap is what keeps a persistently broken one from spinning.
RESPAWN_BACKOFF_MIN = 2    # first retry, and what a healthy run resets to
RESPAWN_BACKOFF_MAX = 30   # so a worker that cannot start is retried twice a
#                            minute rather than as fast as it can fail
WORKER_HEALTHY_S = 60      # ran at least this long -> it was working, so the
#                            next crash starts the backoff over


def is_browser(app):
    # Chrome/Chromium/Firefox: restore-heavy, title-churning clients that can
    # drop a window if it is moved mid-restore. ONLY these wait TITLE_QUIET;
    # the (chrome-<ext>-Profile_N) app-mode ids match too, via the substring.
    a = (app or "").lower()
    return ("chrom" in a) or ("firefox" in a)


# Consecutive failing captures before the worker exits for a clean supervisor
# respawn. capture_loop reconnects on every error, so a transient stall self-
# heals far below this; only a genuinely wedged compositor sustains a streak
# this long, where a full respawn (fresh sockets + connect() retry) is the
# correct recovery, not limping on a dead thread.
CAPTURE_FAIL_LIMIT = 15


def subscribe(sock, events, connect_one=None):
    """Subscribe to as many of `events` as this compositor HAS. Returns the
    ones it accepted.

    A MISSING EVENT IS A CAPABILITY GAP, NOT A FATAL ERROR, and before this it
    was fatal: wayfire refuses the whole call on the first name it does not
    know, the worker died rc 1, and `_respawn_forever` then did exactly what
    it is written to do, settling at one dead worker every 30s FOREVER with
    `rc 1` and no cause in the log. Reported by tackup (T8) from the distro's
    wayfire 0.10.0, which has no `output-added`; reachable on a CURRENT box
    with any name the compositor has retired or renamed.

    THE FALLBACK NEEDS NO ERROR PARSING, which is what makes it safe to keep.
    Measured on wayfire 0.11.0: a REJECTED `watch` leaves the connection
    USABLE (the same socket accepted a good list straight afterwards), so the
    retry happens on the socket we already have, and wayfire's wording is
    never read. tackup rightly warned off parsing it: the release that renames
    an event is exactly the one that rewords the error.

    AND ONE CONNECTION WATCHES ONCE. A second `watch` on a subscribed socket
    is refused outright (`Client is already watching events!`), so the probe
    cannot share this socket and per-event subscribing is not available at
    all. Each name is tried on a THROWAWAY connection, which costs 14 connects
    ONLY on the failure path: a healthy box makes exactly one call, as before.

    WHAT IS LOST IS NAMED, both in the log and to `doctor`, because a silently
    reduced daemon is the thing this repo keeps finding. Losing
    `output-added` costs dock DETECTION, which `_poll_outputs` and
    `_profile_drift` already cover, so the degradation is real rather than
    theoretical.
    """
    try:
        sock.watch(list(events))
        return list(events)
    except Exception as e:                                     # noqa: BLE001
        logline(f"event subscription refused ({e}); asking name by name")
    one = connect_one or connect
    ok, bad = [], []
    for ev in events:
        try:
            probe = one()
            probe.watch([ev])
            ok.append(ev)
        except Exception:                                      # noqa: BLE001
            bad.append(ev)
    if not ok:
        # Nothing at all: let the caller die rather than pretend to watch.
        raise RuntimeError(
            f"this compositor accepted none of {len(events)} events")
    logline(f"compositor has no {', '.join(bad)}: that capability is "
            f"DEGRADED, the daemon is not")
    sock.watch(ok)
    return ok


WORKER_ERR = "usher.worker-err"   # the worker's stderr, re-made per spawn
WORKER_ERR_LINES = 6              # how much of it reaches watch.log
WORKER_ERR_WIDTH = 200            # per line, so one long row cannot flood
LOOP_SHOUT_AT = 4                 # consecutive early deaths before saying so


def respawn_report(streak, shout_at=LOOP_SHOUT_AT):
    """What to put in the log after `streak` consecutive early worker deaths:
    one of "quiet", "detail", "shout".

    IT NEVER GIVES UP, which is where this parts company with the shape
    tackup suggested ("stop respawning and say so loudly"). The premise that
    N early deaths mean the next one will too is FALSE here, and this repo has
    the counter-example written down: the compositor IPC dropped five seconds
    into a session on manifold and the supervisor respawned correctly, which
    was that machinery working under load. A slow or storm-bound login
    produces exactly this streak and then recovers, so a supervisor that quit
    would turn a transient into a dead session, on the one path where the user
    is least able to see why.

    SO IT STOPS SHOUTING INSTEAD OF STOPPING WORKING. Up to `shout_at` the
    stderr tail is logged, because the first deaths are where the cause is;
    AT the threshold it says once that this looks deterministic; after that it
    goes quiet, which is the actual complaint (the same line twice a minute
    for the life of the session, indistinguishable from a transient).

    THE TAIL IS RATE-LIMITED BY THE SAME COUNTER, and it has to be: logging
    six lines of traceback on every respawn made the spam SEVEN TIMES worse
    than the bare `rc 1` tackup was complaining about. A fix that multiplies
    the thing it was asked to fix is worth catching before it ships.
    """
    if streak < shout_at:
        return "detail"
    return "shout" if streak == shout_at else "quiet"


def worker_error_tail(path, keep=WORKER_ERR_LINES, width=WORKER_ERR_WIDTH):
    """The last few lines a dead worker wrote to stderr, for watch.log.

    PURE OVER A PATH so the bounds are checkable without spawning anything,
    and BOUNDED BOTH WAYS because this runs on every respawn: a worker that
    crash-loops on a bad event subscription would otherwise write its
    traceback into watch.log every two seconds, which is the log turning into
    the problem. Six lines keeps the exception and its last frame, which is
    the part that names the cause.

    MISSING OR EMPTY IS SILENT, not an error: a worker told to stop exits
    cleanly and writes nothing, and that is the overwhelmingly common case.
    """
    try:
        with open(path, errors="replace") as f:
            lines = [ln.rstrip() for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return []
    return [ln[:width] for ln in lines[-keep:]]


class Supervisor:
    """Hold the single-instance lock, spawn a worker, and respawn it with
    backoff if it dies. The worker is this same script RE-EXEC'd (the `_worker`
    verb), not a fork, so it reloads its code from disk on every respawn
    (kill the worker to pick up an edit), and only the supervisor holds the
    lock (the worker no longer inherits the fd, so an orphan can never block a
    restart). If a watcher is ALREADY running, run() reloads it in place
    (SIGHUP re-exec, picking up a code edit and the armed mode) instead of
    exiting, so re-running watch/resume IS the reload. Two paths in one
    script, self-contained (contrast kanshi/kanshi-mgr).

    NEITHER PROCESS DETECTS SESSION END, deliberately: whatever owns the
    cgroup the autostart lands in reaps both when the session goes. That is
    the session scope today and will be the compositor's own unit once tackup
    makes it one, so the PROPERTY is what this relies on and not the owner.
    IT WANTS A CGROUP KILL AND NOT A MAIN-PROCESS ONE: under systemd's default
    `KillMode=control-group` the whole group goes, but a unit configured
    `KillMode=process` would leave this supervisor orphaned into a dead
    session, respawning a worker that can never connect, for ever."""

    def __init__(self, launch=True):
        self.launch = launch
        self.script = os.path.abspath(sys.argv[0])
        self.lock = None     # None until run(); an fd, or "unlocked"
        self.proc = None     # the live worker, for the signal handlers

    def run(self):
        self.lock = acquire_singleton()
        if self.lock is None:
            # ALREADY RUNNING -> signal it instead of starting a second one.
            # This is the SERVICE being idempotent, which the autostart relies
            # on: a second login must not produce two supervisors.
            #
            # IT IS NOT THE CLIENT'S RELOAD PATH, and `usher reload` borrowing
            # it was a real confusion: this function DAEMONISES when the lock
            # is free, so a command-line reload on a box with no daemon became
            # one, in the foreground, with the command shell's environment.
            # `engine.do_reload` signals and never runs anything.
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
        backoff = RESPAWN_BACKOFF_MIN
        # CONSECUTIVE deaths inside WORKER_HEALTHY_S. See respawn_report: this
        # decides how LOUD to be, never whether to carry on.
        streak = 0
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
            errlog = os.path.join(runtime_dir(), WORKER_ERR)
            try:
                # STDERR TO A FILE WE READ ON EXIT, because the autostart's
                # stderr goes NOWHERE and watch.log is the one place a reader
                # looks. A worker that dies before it can log (a bad event
                # subscription, an import error, any traceback) otherwise
                # leaves `rc 1` with no cause: tackup lost a VM run to exactly
                # that, over a compositor with no `output-added` event, and
                # had to re-run `_worker` by hand in the session's environment
                # to see the traceback at all.
                #
                # A FILE AND NOT `subprocess.PIPE`: this loop calls `wait()`,
                # and a PIPE nobody drains deadlocks the moment a worker that
                # runs for weeks fills the buffer. A file never blocks, and a
                # fixed name in the runtime dir cannot accumulate.
                with open(errlog, "wb") as ef:
                    self.proc = subprocess.Popen(argv, stderr=ef)
            except OSError as e:
                logline(f"spawn failed: {e}; retry in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, RESPAWN_BACKOFF_MAX)
                continue
            started = time.time()
            try:
                rc = self.proc.wait()
            except Exception as e:
                logline(f"wait: {e}")
                rc = -1
            self.proc = None
            ran = int(time.time() - started)
            if ran >= WORKER_HEALTHY_S:
                backoff = RESPAWN_BACKOFF_MIN
                if streak >= LOOP_SHOUT_AT:
                    logline(f"worker is healthy again after {streak} early "
                            f"death(s)")
                streak = 0
            else:
                streak += 1
            say = respawn_report(streak)
            if say != "quiet":
                logline(f"worker exited (rc {rc}, ran {ran}s); "
                        f"respawn in {backoff}s")
                for line in worker_error_tail(errlog):
                    logline(f"  worker stderr: {line}")
            if say == "shout":
                logline(f"WORKER HAS DIED {streak} TIMES IN A ROW inside "
                        f"{WORKER_HEALTHY_S:.0f}s: this looks deterministic "
                        f"rather than transient. Still respawning every "
                        f"{RESPAWN_BACKOFF_MAX}s, and going QUIET about it "
                        f"from here. The cause is in the stderr above.")
            time.sleep(backoff)
            backoff = min(backoff * 2, RESPAWN_BACKOFF_MAX)


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
    deadline, the place-mode clock, the knowledge base. That sharing is
    inherent to the design, so the state is `self` rather than a pile of
    captured locals no method could be extracted from.

    If a `usher-mgr resume` armed the adopt flag, the FIRST worker to reach
    init consumes it and LEARNS the current hand-arranged layout as the
    baseline instead of restoring the remembered one, for use after killing
    session and fixing windows by hand, so it does not undo the good state.
    Then it watches normally; respawns (flag gone) restore as usual."""

    def __init__(self, launch=True):
        os.makedirs(STATE, exist_ok=True)
        self.launch = launch
        self.mode = None
        # THE STORE AND THE PROFILE IT CAME FROM, as one pair. save_knowledge
        # takes the profile because resolving it per write bound the in-memory
        # store to one desk and the file it landed in to another, so a single
        # capture after a display change overwrote the other desk's store.
        self.kb, self.kb_profile = kb_for_profile()
        # WHEN THE DISPLAY TRANSITION ENDS. Nothing is learned before then:
        # see DOCK_HOLD.
        self.transition_until = 0.0
        # WINDOWS OWED ONE PLACEMENT BECAUSE THE DISPLAYS CHANGED under them.
        # Distinct from late_ok: see _adopt_profile.
        self.redisplay_ok = set()
        # When the live profile started disagreeing with the loaded store, or
        # 0.0 when they agree. See _profile_drift.
        self.profile_drift_at = 0.0
        self.lock = threading.Lock()
        # dirty: knowledge needs a capture. layout: roll history too (not on a
        # tab-flip).
        self.st = {"dirty": True, "layout": True, "last": time.time(),
                   "armed_at": time.time(),  # place clock (reset by kick)
                   "last_map": time.time()}  # last new toplevel map, which
        #                                      feeds IDLE_SETTLE
        self.placed = set()
        # WHICH LIVE WINDOW HOLDS EACH SLOT: store key -> vid. A slot holds
        # ONE window at a time, the same rule match() has always had (it POPS
        # the entry it used). Without it, N windows sharing a key are all
        # seated at the identical geometry and stack perfectly, which with no
        # taskbar is invisible. Worst for an app_id-keyed app, where
        # kkey(app, "") matches EVERY window of that app whatever its title.
        self.slot_held = {}
        # (vid, slot key) pairs we have already SAID were refused, so the
        # standing condition is reported once per window instead of on every
        # rename. Discarded with the rest of a view's state on unmap.
        self.slot_said = set()
        # VIEWS WE HAVE ALREADY SAID ARE OFF THIS DESK'S GRID. Its own set
        # rather than slot_said's, because that one keys on the slot a rival
        # window holds and this is a property of the desk; one set would make
        # either message suppress the other.
        self.cell_said = set()
        # The visibility guarantee: when it next runs, and how often each
        # window has been rescued (bounded, so a window something keeps
        # pushing off-screen cannot become a placement loop).
        self.visible_due = 0.0
        self.rescued = {}
        # VIEWS WE HAVE ALREADY SAID ARE STICKY and so never moved. A third
        # set for the same reason as the one above: it is a property of the
        # window, and a browser renames constantly.
        # (vid, kind) PAIRS WHOSE REFUSAL TO REMEMBER WE HAVE ALREADY SAID.
        # The capture loop runs every second and a refused window stays
        # refused, so this is per window rather than per pass. Discarded with
        # the rest of a view's state on unmap. See _note_refusals.
        self.refused_said = set()
        # HOW MANY WINDOWS WERE PARKED AT THE LAST REPORT. Not per window:
        # during an undock EVERY external-monitor window is parked at once, so
        # a line each would bury the one fact a reader wants, which is the
        # count and that it is deliberate.
        #
        # ZERO RATHER THAN A "NOT YET ASKED" SENTINEL, which is the baseline
        # trap this daemon's polls have hit four times: a sentinel makes the
        # FIRST pass a change, so an ordinary start would log that nothing is
        # parked. Starting with nothing parked is not news; starting DURING an
        # undock is, and 0 reports that correctly.
        self.parked_said = 0
        # THE OUTPUT SET AS OF THE LAST POLL, or None before the first one.
        # None is not the empty set: the first poll must not read "everything
        # arrived" as a display change. See _poll_outputs.
        self.outputs_seen = None
        # ISSUED PLACEMENTS AWAITING A READ-BACK: vid -> {"e", "o", "due"}.
        # `placed` on its own cannot tell a request that worked from one the
        # compositor overwrote, and it DEDUPS, so a lost race was locked in
        # for the life of the window. See placement_landed().
        # WINDOWS ENTITLED TO ONE LATE PLACEMENT: vids that MAPPED while
        # place was in force. Such a window was part of the session being
        # restored, and if usher could not identify it in time that is usher's
        # problem, not a reason to leave it adrift. Distinct from a window
        # OPENED mid-session, which the settled mode deliberately leaves alone.
        self.late_ok = set()
        self.verify = {}
        self.place_tries = {}  # vid -> placements ISSUED for it this map, so
        #                        the retry budget survives the re-place that
        #                        clears it from `placed`
        self.pending = {}      # vid -> {"v": latest view, "due": place-after
        #                        time}: the settle-debounce queue, drained by
        #                        _placer_loop
        self.deadline = {}     # vid -> time after which we no longer place it
        self.identified = set()   # vids we have ever been able to RECOGNISE
        #                           (see _recognise: the grace runs from that
        #                           moment, not from the map, so a slow login
        #                           sequence still lands)
        self.groups = {}       # fed to learn() and read by nothing: the
        #                        in-session title groups went with the title
        #                        keyspace, and the parameter is retired on
        #                        its own rather than inside that change
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
        # when each source was last asked to identify its windows, so the ask
        # is rate limited and a never-identifiable window cannot make a loop
        self.src_asked = {}
        # {source: (its app set, when that set last changed)}: the ask waits
        # for a login to stop bringing windows up, since a capture REPLACES
        # that account's roster with what is live
        self.src_seen = {}
        # consecutive failed chrome re-keys, so the session signature is
        # held back and retried rather than adopted over a lost pass
        self.rekey_tries = 0
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
        # whether anything is relaunched would otherwise come down to a race
        # between two threads, and losing it means the login brings back
        # nothing at all. A fast run wins that race and a slow one does not,
        # which is exactly why it hid.
        self.saved = engine.load_snapshot()
        threading.Thread(target=self._capture_loop, daemon=True).start()
        # Consume the one-shot adopt flag (armed by `usher-mgr resume`): the
        # first worker to reach here adopts; a respawn sees it gone and
        # restores.
        self.mode = take_mode()
        # LOCK FIRST, BEFORE ANY PLACEMENT, if this session was summoned. The
        # exposure is the gap between the console being logged in and being
        # locked, so nothing should widen it, and nothing is lost by closing
        # it early: placement works under a lock, both a window move and a
        # full relaunch chain having been measured landing while swaylock held
        # the output. A no-op unless USHER_SUMMONED=1, and once per session.
        engine.lock_summoned_session()
        self._init_layout()
        watch = connect()
        subscribe(watch, sorted(KNOWLEDGE_TRIGGERS | PLACE_EVENTS))
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
            #
            # AND IT STARTS SETTLED, which is the other half of "touch
            # nothing" and was missing: a fresh worker stamps armed_at with
            # NOW, so every reload re-armed PLACE for START_FLOOR and any
            # window mapping in those five minutes was snapped to its
            # remembered slot. A deploy must not change placement behaviour,
            # and this is what lets `setup.sh install` reload unconditionally.
            # Expiring the CAP is what settles it whatever last_map holds,
            # since _settled_at takes min(armed + PLACE_CAP, ...). A later
            # `usher place` kick re-stamps armed_at and works normally.
            with self.lock:
                self.st["armed_at"] = time.time() - PLACE_CAP
            logline("reload: neither restoring nor re-baselining")
            logline("reload: starting SETTLED, so a deploy places nothing")
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

    # --- the place/settled clock, and what it publishes -------------------

    def _settled_at(self):
        # settled when (FLOOR passed AND quiet for SETTLE) OR past CAP; the kick
        # resets armed_at and a new map pushes last_map, and both extend
        # place.
        with self.lock:
            armed = self.st["armed_at"]
            last_map = self.st["last_map"]
        return min(armed + PLACE_CAP,
                   max(armed + START_FLOOR, last_map + IDLE_SETTLE))

    def _placing_now(self):
        return time.time() < self._settled_at()

    def _write_status(self):
        # Publish {mode, seconds_left} for `usher status` + the tray. The
        # settled-at estimate assumes no more windows arrive; a map or a kick
        # moves it out. Atomic replace so a reader never sees a half file.
        now = time.time()
        settled_at = self._settled_at()
        # arc = fraction of the place window still to run, for the tray's
        # depleting ring; ~1.0 right after a kick, 0.0 once settled.
        arc = max(0.0, min(1.0, (settled_at - now) / START_FLOOR))
        try:
            tmp = STATUS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(
                    {"mode": "place" if now < settled_at else "settled",
                     "seconds_left": max(0, round(settled_at - now)),
                     "arc": round(arc, 3),
                     # TWO MORE FACTS, each on its own axis, so a reader never
                     # has to infer one from the other.
                     #
                     # `transposed_at` IS AN INSTANT, NOT A STATE. A sweep is
                     # a blip, so a state field could be missed entirely by a
                     # one-second poller; a timestamp cannot. How long to
                     # DWELL on it is presentation and belongs to the tray,
                     # which also keeps this file honest for every other
                     # reader: at no point does it claim a transpose is
                     # happening when one is not.
                     "transposed_at": round(self.st.get("transposed_at", 0), 3),
                     # RECORDING IS THE CONSTANT, with exactly one exception:
                     # a display change in flux, where believing the geometry
                     # would teach the store a collapse. Published because the
                     # exception is worth seeing, not because it is a mode.
                     "recording": not (self._in_transition()
                                       or bool(self.profile_drift_at))}, f)
            os.replace(tmp, STATUS_FILE)
        except OSError:
            pass

    # --- placement -----------------------------------------------------------

    def _try_place(self, v):
        """_place_view under the placer thread's IPC error policy."""
        return self._guarded("place", self._place_view, v)

    def _guarded(self, what, fn, *a):
        """Run one placer-thread step under the IPC error policy. A desync-
        class error (timeout / off-by-one) poisons place_sock the same way it
        poisons the capture socket, and would then silently fail EVERY
        placement for the rest of the session, so rebuild it on one. A benign
        server error-response (e.g. "view is not toplevel" for a popup) leaves
        the socket in sync: log it and move on, never reconnect.

        SHARED RATHER THAN COPIED, because _placer_loop now drives two kinds
        of step. The verify read-back was added calling _verify_one DIRECTLY
        from the loop, which has no guard of its own, so one raise would have
        killed the placer thread and placement would stop for the session with
        nothing in the log. Two copies of this policy is also how they drift."""
        try:
            return fn(*a)
        except Exception as e:
            if is_desync_error(e):
                # `what` is "place" for the placement path, so those three
                # lines come out exactly as they always have.
                logline(f"{what} desync: {e}; reconnecting place socket")
                try:
                    self.place_sock.close()
                except Exception:
                    pass
                try:
                    self.place_sock = connect()
                except Exception as e2:
                    logline(f"{what} reconnect failed: {e2}")
            else:
                logline(f"{what} error: {e}")
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
        # REDACTED FOR ANOTHER ACCOUNT. Every log line below renders
        # this value, and watch.log is the session user's readable
        # state, so the derivation is the one place to ask.
        title = engine.log_title(v)
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
                                         "due": time.time() + TITLE_QUIET}
            return
        # THE SOURCE GATES WHICH KEYS THIS WINDOW MAY MATCH. Without it a
        # window from another account would be offered `kkey(app, "")`, the
        # app_id-only key, which is the OWNER's and matches every window of
        # that app: a work Slack would be placed onto the owner's Slack slot
        # and the owner's onto the work one. match_keys is the one definition.
        _src = engine.window_origin(v.get("pid"))[0]
        # ONE SLOT PER WINDOW, so this asks for a FREE one rather than for
        # the identity's only one. N windows sharing an identity now have N
        # entries (see next_slot_key), and `free_slot` is the one definition
        # that picks among them: the base keys in `match_keys` order, then
        # the indexed siblings, skipping any a LIVE window already holds.
        # Resolved once here and reused for the ledger below, or the entry
        # placed and the slot recorded could be two different slots.
        _views = self._live_views()
        _live = {w.get("id") for w in _views}
        with self.lock:
            # A WINDOW ALREADY AT A SLOT'S RECT HOLDS IT (see slot_squatters),
            # recorded before the pick so this window is offered the NEXT one
            # and not a stack on top of the occupant.
            try:
                _outs0 = {o["name"]: o for o in
                          self.place_sock.list_outputs()}
                for _k, _id in engine.slot_squatters(
                        self.kb, self.slot_held, app, identity(v),
                        _src or "", vid, _views, _outs0,
                        engine.panel_map()).items():
                    self.slot_held[_k] = _id
            except Exception as _e:                      # noqa: BLE001
                logline(f"slot occupancy: {_e}")
            skey, e = engine.free_slot(self.kb, self.slot_held, app,
                                       identity(v), _src or "", vid, _live)
        # A STICKY WINDOW IS PLACED BY MONITOR AND POSITION, never onto a
        # workspace (see engine.sticky_entry): the slot is marked sticky when
        # the live window is, so the arithmetic and the read-back both skip
        # the workspace and `place()` keeps it sticky.
        e = engine.sticky_entry(v, e)
        # CAPTURED BEFORE _recognise, which is what records the identification:
        # read it afterwards and this is always False.
        first_look = e is not None and vid not in self.identified
        if first_look:
            self._recognise(vid, app, title)
        # ONE CHANCE BECAUSE THE DISPLAYS MOVED, consumed on sight whether or
        # not we go on to place: the entitlement is for this dock, not a
        # standing licence.
        #
        # NOT TESTED AGAINST THE GRACE BELOW, deliberately. _adopt_profile
        # re-graces every window it entitles, in the same locked block, so a
        # `not dock_chance` guard there could never change the outcome: a
        # planted regression removing it was uncatchable, which is how a dead
        # condition announces itself. The re-grace owns the grace gate and the
        # entitlement owns the settled gate, one mechanism each.
        dock_chance = vid in self.redisplay_ok
        if dock_chance:
            with self.lock:
                self.redisplay_ok.discard(vid)
        if time.time() > self.deadline.get(vid, 0):
            return   # past the grace window: the window is settled, hands off
        # ONE LATE CHANCE FOR A WINDOW THAT WAS ALWAYS HERE. _recognise
        # re-graces a window the instant it becomes identifiable and says it
        # is "still bounded, since the place check still governs", and
        # that check is what defeated it: _settled_at takes
        # min(armed + PLACE_CAP, ...), so once the cap has passed NOTHING can
        # re-enter place, and feeding last_map cannot help. Measured on
        # manifold: a Chrome window became identifiable 2.5 hours after login,
        # logged `recognised late, re-graced`, and was then refused here, so
        # the re-grace was spent on nothing.
        #
        # SETTLED WAS CONFLATING TWO WINDOWS. One you OPENED mid-session should
        # stay where it opens; one that was PRESENT at login and merely
        # unidentifiable until now should go to its remembered slot. `late_ok`
        # is the ones that mapped while place was in force, i.e. the
        # session being restored, and this is their single chance: `placed`
        # dedups, and first_look is true exactly once per view.
        late_chance = first_look and vid in self.late_ok
        if (not self._placing_now() and not is_anchored(app, title)
                and not late_chance and not dock_chance):
            return   # settled state: only usher/include anchors are (re)placed
        if dock_chance and not self._placing_now():
            logline(f"display changed, re-placing: {app[:18]} | "
                    f"{title[:30]}")
        if late_chance and not self._placing_now():
            logline(f"late chance (present at login, identifiable only now): "
                    f"{app[:18]} | {title[:30]}")
        if not e:
            # NOTHING LEARNED HERE, so ask the surface map whether this window
            # has a named home at another desk. Deliberately AFTER the settled
            # gate above: a seed is a guess, so it may only happen where usher
            # was going to place anyway, which is place, an anchor, a
            # late chance, or a dock. A dock is exactly when it is wanted.
            e = self._seed(app, v)
        if not e:
            return   # never seen this identity -> we don't know where it goes
        # ONE WINDOW PER SLOT. Whoever got here first owns it until it
        # unmaps; a second window with the same key is LEFT WHERE IT OPENED,
        # which is the same answer place-vs-settled already gives a window
        # opened mid-session, and it refuses to invent geometry rather than
        # guessing an offset. Stacking is never what anyone wanted.
        # THE LEDGER KEY IS THE ONE `free_slot` CHOSE, which is also the one
        # the entry above came from: picking it again here is what let the
        # two drift, and with several slots per identity they would be
        # different keys rather than the same one twice.
        if skey is None:
            # A SEED has no slot key of its own: the entry came from another
            # desk's store, so there is nothing in THIS store to hold. The
            # identity's own key is the right ledger entry, since that is
            # what the next capture will write it under.
            skey = engine.matched_key(self.kb, app, identity(v), _src or "")
        with self.lock:
            holder = self.slot_held.get(skey)
        own = live_holder(holder, vid, _live)
        if own == "held":
            # ONCE PER WINDOW, NOT PER EVENT. This runs from every map and
            # every rename, and a browser renames constantly, so logging it
            # here unconditionally turns one standing condition into a line a
            # second: measured on manifold 2026-11-03, 126 rows in one hour
            # from seven windows sharing one key, which is most of what the
            # log said all day. watch.log's whole value is being readable
            # afterwards, so a repeating line costs more than it reports.
            with self.lock:
                _first = (vid, skey) not in self.slot_said
                if _first:
                    self.slot_said.add((vid, skey))
            if _first:
                logline(f"slot taken, left in place: {app} | {title[:34]}")
            return
        if own == "stale":
            # The holder is GONE and its unmap never reached us. Drop it only
            # if it is still the holder we just read, so a concurrent seating
            # cannot be evicted by this.
            with self.lock:
                if self.slot_held.get(skey) == holder:
                    del self.slot_held[skey]
            logline(f"slot holder {holder} is gone, releasing: {app} | "
                    f"{title[:30]}")
        outs = {o["name"]: o for o in self.place_sock.list_outputs()}
        o = entry_output(e, outs)
        if not o:
            return
        moved = self._seat_view(v, e, o)
        if moved:
            with self.lock:
                self.slot_held[skey] = vid
        return moved

    def _seed(self, app, v):
        """A starting slot from the SURFACE this window occupies at another
        desk, or None. Logged, because silently placing from a guess is as bad
        as silently not placing: watch.log is what settles "usher or the
        human", so a seeded placement has to be distinguishable from a learned
        one in it."""
        # ONE TEST, because surface_map guarantees an empty map whenever it
        # sets `why` and a check in engine pins that. Testing both here was
        # unprovable: the planted regression dropping `why` was uncatchable.
        surfaces, _why = engine.surface_map()
        if not surfaces:
            return None
        # Its own output list rather than the caller's, which is built
        # further down: this runs only when a map EXISTS, so on a desk with
        # none (every desk today) it costs one cached call and no IPC.
        try:
            outs = {o["name"]: o for o in self.place_sock.list_outputs()}
        except Exception:
            return None
        others = engine.other_profile_entries(app, identity(v),
                                              self.kb_profile)
        seed = engine.surface_seed(others, surfaces,
                                   engine.surface_default())
        if not seed:
            return None
        # THE DEFAULT HAS NO CELL, so the window kept its own, which this
        # desk's grid may not have: brought inside it rather than refused,
        # since the default exists so that every window has a destination.
        if seed.get("seeded_default"):
            seed = engine.clamp_cell(seed, outs)
        # THE CELL IS hwdp's PASSTHROUGH, so it is ours to check: seeding into
        # a cell the live grid does not have puts the window where no
        # workspace navigation reaches it.
        if not engine.cell_fits(seed, outs):
            logline(f"surface `{seed['seeded_from']}` names cell "
                    f"{tuple(seed['workspace'])}, which this grid does not "
                    f"have: not seeding {app[:18]}")
            return None
        logline(f"seeded from surface `{seed['seeded_from']}`"
                + (" (the default)" if seed.get("seeded_default") else "")
                + f": {app[:18]} -> {seed['output']} "
                f"ws{tuple(seed['workspace'])}")
        return seed

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
        chance. Still bounded, since the place check still governs."""
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
        app, title = app_of(v), engine.log_title(v)
        # A CELL THIS DESK DOES NOT HAVE IS NOT A PLACEMENT, it is a window
        # put where no workspace navigation reaches it. Measured live: wayfire
        # accepts a geometry past the edge of the virtual desktop exactly as
        # asked, and the read-back then CONFIRMS it, so nothing downstream can
        # catch this. Left where it opened instead, which is what every other
        # slot usher cannot honour already gets.
        # ONCE PER WINDOW, NOT PER EVENT, and for the slot ledger's reason: a
        # browser renames constantly, so logging a standing condition here
        # unconditionally turns it into a line a second.
        if not engine.cell_fits(e, {o["name"]: o}):
            with self.lock:
                _first = vid not in self.cell_said
                if _first:
                    self.cell_said.add(vid)
            if _first:
                _ws = o.get("workspace") or {}
                logline(f"slot is off this desk's grid, left in place: "
                        f"{app} ws{tuple(e['workspace'])} outside "
                        f"{_ws.get('grid_width')}x{_ws.get('grid_height')}")
            return
        # FITTED TO THE WORK AREA, so a slot learned off its panel or under
        # thinner bars still lands where it can be seen (engine.fit_entry).
        # Before everything below, so the "already there" test, the request
        # and the read-back all mean the same rect.
        e = engine.fit_entry(e, o)
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
                    v.get("output-name") == o["name"]):
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
        # ...and `placed` still only means ASKED, which is why the read-back
        # below exists. The word is deliberately NOT reworded: this repo's
        # notes quote it verbatim in a dozen places, and the failure gets its
        # own lines rather than making every existing quotation false.
        with self.lock:
            n = self.place_tries.get(vid, 0)
            self.place_tries[vid] = n + 1
        self._verify_later(vid, e, o, n)
        return True

    def _verify_later(self, vid, e, o, n):
        """Arm a read-back of the placement just issued for vid, n having been
        issued before it. Past the retry budget, nothing is armed and the last
        attempt simply stands."""
        if vid is None or n >= len(PLACE_VERIFY):
            return
        with self.lock:
            self.verify[vid] = {"e": e, "o": o,
                                "due": time.time() + PLACE_VERIFY[n]}

    def _verify_one(self, vid, item):
        """Read one issued placement back, and re-place it if it did not land.

        Runs on the placer thread, so the re-read uses place_sock's one
        writer, and it RE-READS rather than trusting the view dict it was
        handed, for the same reason the identity retry does: the payload
        describes the instant it fired and the whole question here is what
        happened AFTERWARDS."""
        v = self._fresh_view(vid)
        if v is None:
            return             # the window is gone: nothing left to verify
        e, o = item["e"], item["o"]
        if placement_landed(v, e, o):
            return             # it stuck, which is the overwhelmingly common
            #                    case and says nothing worth logging
        app, title = app_of(v), engine.log_title(v)
        with self.lock:
            n = self.place_tries.get(vid, 0)
        if n >= len(PLACE_VERIFY):
            # GIVING UP IS SAID OUT LOUD. The window is left where it is
            # rather than fought over, and the one thing that must not happen
            # is this passing for success, which is the whole bug.
            logline(f"place did not take after {n} tries, left where it is: "
                    f"{app[:18]} | {title[:28]}")
            return
        logline(f"place did not take (try {n}), re-placing: "
                f"{app[:18]} | {title[:34]}")
        with self.lock:
            # Clearing `placed` is what lets _place_view consider it again;
            # it re-runs every gate (grace, place, the slot ledger), so
            # a retry can never place something a first attempt may not.
            self.placed.discard(vid)
            self.pending[vid] = {"v": v, "refetch": True, "due": time.time()}

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
        QUIET for TITLE_QUIET: a restoring client churns its title as tabs
        load, and reconfiguring it mid-restore can make it drop the window. The
        event loop only records the latest view + a due time in `pending`; this
        thread does the actual place when the churn stops, reusing place_sock
        (nothing else touches it once init is done, so it has one writer)."""
        streak = 0
        while True:
            time.sleep(0.1)
            try:
                self._placer_step()
            except Exception as e:                         # noqa: BLE001
                streak += 1
                self._loop_failed("placer", e, streak)
            else:
                streak = 0

    def _placer_step(self):
        """One placer tick. Separate from the loop so the loop can guard the
        WHOLE of it: see _loop_failed."""
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
        # Read back placements already issued. AFTER the places above, so
        # one issued on this very tick is never verified before the
        # compositor has had its delay to apply it.
        checks = []
        with self.lock:
            for vid in list(self.verify):
                if now >= self.verify[vid]["due"]:
                    checks.append((vid, self.verify.pop(vid)))
        for vid, item in checks:
            self._guarded("verify", self._verify_one, vid, item)
        with self.lock:
            again = self.st.pop("recheck", False)
        if again:
            self._recheck_all()
        if now >= self.visible_due:
            self.visible_due = now + VISIBLE_EVERY
            self._guarded("visible", self._ensure_visible)

    def _ensure_visible(self):
        """NO WINDOW IS LEFT WHERE IT CANNOT BE SEEN, whatever put it there.

        Every path that leaves a window alone (a refused slot, an off-grid
        slot, a desk with no map) used to leave it wherever it was, and three
        of those were invisible on one desk in one day: a parked window that
        lost a shared slot sat on the null output, a slot learned mostly off
        its panel restored Signal off-screen, and a grid shrank under windows.
        So the RESULT is checked (engine.visibility) and a window failing it
        is put on this desk (engine.rescue_slot): its surface, its cell's
        surface, the default, else its own cell or the built-in panel.

        NOT DURING A DISPLAY CHANGE, when windows are legitimately parked
        and the layout is not yet true. BOUNDED PER WINDOW, so something that
        keeps pushing a window away is reported rather than fought."""
        if self._in_transition():
            return
        sock = self.place_sock
        outs = {o["name"]: o for o in sock.list_outputs()}
        surfaces, _why = engine.surface_map()
        dflt = engine.surface_default()
        for v in sock.list_views(filter_mapped_toplevel=True):
            # A MINIMIZED window is hidden on purpose, and one the user's
            # exclude rules name is one usher never places.
            if ((v.get("parent", -1) or -1) != -1 or v.get("minimized")
                    or is_transient(v)):
                continue
            why = engine.visibility(v, outs)
            vid = v.get("id")
            if not why:
                continue
            n = self.rescued.get(vid, 0)
            if n >= RESCUE_TRIES:
                if n == RESCUE_TRIES:
                    logline(f"still not visible after {n} rescue(s), giving "
                            f"up: {app_of(v)[:18]} | "
                            f"{engine.log_title(v)[:30]} ({why})")
                    self.rescued[vid] = n + 1
                continue
            app = app_of(v)
            try:
                others = engine.other_profile_entries(
                    app, identity(v) or "", self.kb_profile)
            except Exception:                              # noqa: BLE001
                others = []
            tgt = engine.rescue_slot(v, outs, others, surfaces, dflt)
            if not tgt:
                continue
            o = outs[tgt["output"]]
            place(sock, vid, tgt, o)
            self.rescued[vid] = n + 1
            logline(f"rescued, it could not be seen ({why}): {app[:18]} -> "
                    f"{o['name']} ws{tuple(int(x) for x in tgt['workspace'])}"
                    + (f" surface `{tgt['seeded_from']}`"
                       if tgt.get("seeded_from") else "")
                    + f" | {engine.log_title(v)[:30]}")

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

    def _live_views(self):
        """Every mapped toplevel right now, or [] if the list could not be
        read (the no-evidence answer, see _live_ids)."""
        try:
            return list(self.place_sock.list_views(
                filter_mapped_toplevel=True))
        except Exception as e:
            logline(f"live view list: {e}")
            return []

    def _live_ids(self):
        """The ids of every mapped toplevel right now, or an EMPTY set if the
        list could not be read. Empty is the no-evidence answer `live_holder`
        refuses on, so a failure here costs a placement rather than handing a
        held slot away. Runs on the placer thread, place_sock's one writer."""
        try:
            return {v.get("id") for v in
                    self.place_sock.list_views(filter_mapped_toplevel=True)}
        except Exception as e:
            logline(f"live view list: {e}")
            return set()

    def _recheck_all(self):
        """Give every live window another chance at placement, because what
        usher KNOWS just changed rather than what the windows are doing.

        AN EVENT-DRIVEN DECISION HAS TO BE RE-RUN WHEN ITS INPUTS CHANGE, not
        only when its subject moves. A window is considered when it maps or
        renames, which is right while the store is fixed and WRONG the moment
        the store changes underneath it: a Chrome window becomes identifiable
        when its session file catches up or its slot is re-keyed, and nothing
        tells us, because the window is not doing anything. One whose title has
        settled emits no further events at all.

        Cheap and bounded: `placed` already dedups, so anything that landed is
        a set lookup, and the grace still governs the rest. Runs on the placer
        thread because place_sock has exactly one writer."""
        try:
            views = self.place_sock.list_views(filter_mapped_toplevel=True)
        except Exception as e:
            logline(f"recheck: {e}")
            return
        # ELIMINATION NEEDS THE WHOLE SET, which is why it runs here and not
        # in the plugin: a plugin is handed ONE view and cannot see what the
        # other titles already account for. Done before the placement loop so
        # a view it claims is placeable on this very pass.
        # OURS ONLY: the ids come from the OWNER's session files, so a
        # foreign chrome view is not a candidate for any of them. One got
        # handed an owner id here, live, with its title as the label.
        _claimed = chrome.claim_by_elimination(
            engine.chrome_elimination_pool(views))
        if _claimed is not None:
            logline("chrome: the one unmatched window is settled by "
                    "elimination over the recorded ids")
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
                "forget": store_mtime(FORGET_FILE),
                "capture": store_mtime(CAPTURE_FILE),
                "redisplay": store_mtime(REDISPLAY_FILE),
                "sweep": store_mtime(SWEEP_FILE),
                "plugins": plugins_sig(),
                "chrome": chrome.session_sig()}
        errstreak = pollstreak = 0
        while True:
            time.sleep(1)
            # THESE THREE SAT OUTSIDE THE GUARD BELOW, so anything they
            # failed to catch internally killed the capture thread and
            # snapshots simply stopped. The tick still proceeds to the
            # capture step afterwards: that work is independent of the polls,
            # and it is the half whose loss costs the layout.
            try:
                self._poll_files(seen)
                cap = self._poll_outputs(cap)
                # AND THE PROFILE, not just the output NAMES that poll
                # compares. A desk change that keeps the names is invisible to
                # it: same connector, same resolution, a DIFFERENT monitor,
                # which is two docks reached through one port. `hwdp id` is
                # EDID-derived so it differs, nothing moves, so nothing
                # dirties the store, so `_capture_once` (the drift detector's
                # only other caller) is never due: the wrong desk's store
                # stays loaded AND goes on being written, which is the
                # cross-contamination the profile binding cannot see because
                # it only guarantees we write where we LOADED from.
                #
                # PRECEDENCE IS THE CAPTURE STEP'S, ordered exactly as it
                # orders them, so an arriving monitor is laid out before
                # anything adopts. Costs at most one subprocess per
                # PROFILE_TTL, which the id cache bounds.
                if not self._in_transition():
                    self._profile_drift()
                self._write_status()
                pollstreak = 0
            except Exception as e:                         # noqa: BLE001
                pollstreak += 1
                self._loop_failed("poll", e, pollstreak)
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

    def _poll_outputs(self, cap):
        """Notice an output arriving or leaving, because the COMPOSITOR DOES
        NOT TELL US ABOUT ARRIVALS.

        MEASURED on wayfire 0.11.0-d3990237, subscribing to usher's own
        fourteen events in a nested compositor: creating an output emits
        ZERO events and destroying the same output emits `output-removed`.
        So half of `OUTPUT_EVENTS` has never fired, and the half that never
        fires is the DOCK, which is the direction a laptop user meets every
        morning.

        WHAT THAT COST, and it is not merely the missing log line: with no
        event nothing calls `_begin_transition`, so there is no HOLD while an
        arriving monitor is being laid out, and a capture triggered by any
        view event in that window teaches the new desk's store a layout taken
        mid-transition. `_profile_drift` is the backstop and could not reach
        it either, because CAPTURE IS EVENT-DRIVEN: on an idle session nothing
        dirtied the store, so no snapshot was taken, so the derived profile
        never changed and the drift was never noticed. tackup measured
        exactly that in a guest, 40 seconds of total silence on an addition
        against the full cascade on the matching removal.

        SO THE SET IS POLLED, in the one loop that runs whether or not
        anything happens. This is the file's own rule about an event-driven
        decision needing to be re-run when its INPUTS change, in the case
        where the input changes with no event at all.

        BOTH DIRECTIONS GO THROUGH HERE rather than only arrivals, so the
        behaviour no longer depends on which half a compositor implements.
        `output-removed` still fires `_begin_transition` from `_on_event`
        first, and that is harmless: it extends the hold rather than
        restarting it.

        NO EVIDENCE CHANGES NOTHING. An IPC failure leaves the remembered set
        alone and reconnects, because reading a failure as "every output went
        away" would start a transition on every blip.
        """
        try:
            now = frozenset(o.get("name") for o in cap.list_outputs())
        except Exception as e:                                 # noqa: BLE001
            return self._capture_failed(e, cap, 1)
        was, self.outputs_seen = self.outputs_seen, now
        if was is None or was == now:
            return cap
        gone, came = sorted(was - now), sorted(now - was)
        what = ", ".join(filter(None, [
            "+" + "/".join(came) if came else "",
            "-" + "/".join(gone) if gone else ""]))
        self._begin_transition(f"outputs polled: {what}")
        return cap

    def _poll_files(self, seen):
        """Adopt edits to the files that steer us, by mtime. Auto-incorporating
        usher/exclude + usher/include means a new never-place or anchor
        rule applies on save; ARM_FILE is the one seam place/settle/toggle
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
        # place/settle/toggle all write a timestamp to ARM_FILE; adopt it
        # as the new armed_at (now = kick, a past ts = settle to settled).
        a = store_mtime(ARM_FILE)
        if a != seen["arm"]:
            seen["arm"] = a
            try:
                with self.lock:
                    self.st["armed_at"] = float(
                        open(ARM_FILE).read().strip())
                logline("place re-armed (kick)"
                        if self._placing_now() else "settled to settled")
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
        if store_mtime(FORGET_FILE) != seen["forget"]:
            self._take_forget()
            seen["forget"] = store_mtime(FORGET_FILE)
        if store_mtime(CAPTURE_FILE) != seen["capture"]:
            self._take_capture()
            seen["capture"] = store_mtime(CAPTURE_FILE)
        if store_mtime(REDISPLAY_FILE) != seen["redisplay"]:
            self._take_redisplay()
            seen["redisplay"] = store_mtime(REDISPLAY_FILE)
        if store_mtime(SWEEP_FILE) != seen["sweep"]:
            self._take_sweep()
            seen["sweep"] = store_mtime(SWEEP_FILE)
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
            # THE BASELINE IS ADOPTED ON SUCCESS, which is the baseline trap
            # this package records three times over, met in the one loop
            # where losing a pass costs a login. Adopting first meant a
            # re-key that RAISED was never retried: the next poll saw no
            # change and the pass was simply gone, so every chrome window
            # keyed fresh and landed at the browser's own cascade.
            #
            # BOUNDED, because a deterministic failure must not re-read the
            # session files every second for ever. The failure is a race, so
            # one more look is almost always enough; the budget is the same
            # shape as PLACE_VERIFY's and giving up adopts the sig so the
            # loop goes quiet until Chrome next writes.
            if self._rekey_chrome() or self.rekey_tries >= REKEY_TRIES:
                seen["chrome"] = c
                self.rekey_tries = 0
            else:
                self.rekey_tries += 1
            with self.lock:
                self.st["recheck"] = True

    def _take_forget(self):
        """Apply a `usher forget --apply` request and remove it.

        WE MAKE THE EDIT BECAUSE WE OWN THE STORE while we run: the capture
        loop rewrites the whole thing from memory, so a client editing the
        file would simply lose it at the next capture. Handing us the
        selectors is what makes the whole operation race-free without
        stopping anything.

        CONSUMED LIKE ADOPT_FLAG, and removed even when it holds nothing
        usable, or an unparsable request would be retried on every poll."""
        try:
            with open(FORGET_FILE) as f:
                sel = [ln.strip() for ln in f if ln.strip()]
        except OSError:
            sel = []
        if sel:
            with self.lock:
                gone = engine.forget_apply(self.kb, sel, self.kb_profile)
            logline(f"forget: dropped {len(gone)} on request")
        try:
            os.remove(FORGET_FILE)
        except OSError:
            pass
        return sel

    def _take_capture(self):
        """Apply a `usher save` request and remove it.

        WE DO IT BECAUSE WE CAN SEE, which is the whole reason the verb hands
        it over: a one-shot client resolves another account's windows to the
        source alone, where this process holds the per-window map the refresh
        filled. See engine.capture_plan.

        `last = 0` SO IT IS DUE AT ONCE, with no debounce wait, because the
        caller asked for a capture rather than for one eventually: the same
        pair the dock hold's expiry uses.

        Consumed and removed like the forget request, so a request we cannot
        act on is not retried on every poll."""
        try:
            os.remove(CAPTURE_FILE)
        except OSError:
            pass
        with self.lock:
            self.st["dirty"] = True
            self.st["last"] = 0
        logline("capture on request")

    def _rekey_chrome(self):
        """Move the chrome slots onto the current session's window ids, and
        say so in the log. Silent and cheap when nothing is stale, which is
        every call but the ones just after a browser restart.

        TRUE WHEN THE PASS COMPLETED, so the caller can hold its baseline and
        try again. The measured failure is a session file VANISHING mid-read,
        which is transient by nature and likeliest at a browser restart,
        i.e. exactly when the re-key is the thing that saves every chrome
        window's slot."""
        try:
            with self.lock:
                moved = rekey_chrome(self.kb)
                if moved:
                    save_knowledge(self.kb, self.kb_profile)
            return True
        except Exception as e:
            logline(f"chrome re-key error: {e}")
            return False
            return
        if moved:
            logline(f"chrome: re-keyed {moved} window slot(s) onto the"
                    f" restarted browser's session ids")

    def _held(self, windows):
        """The view ids whose CURRENT position must not be believed yet.

        While placement is PLACE, a window the placer has not reached is
        sitting wherever its app dropped it, and learning that OVERWRITES the
        remembered slot the placer is about to aim at. The capture loop runs
        every second and would otherwise win that race, teaching the store
        that the app's cascade position IS the window's home.

        A window is released the moment it is placed, or when its grace runs
        out and usher is no longer going to act on it. In settled state nothing
        is placed, so nothing is held."""
        now = time.time()
        held = set()
        if self._placing_now():
            held |= {w["id"] for w in windows
                     if w.get("id") is not None
                     and w["id"] not in self.placed
                     and now <= self.deadline.get(w["id"], 0)}
        # AND A WINDOW THE LEDGER REFUSED, IN ANY MODE, which is the half this
        # was missing. Several windows can share one store key (another
        # account's app, or two terminals in one directory): the ledger gives
        # the slot to ONE and leaves the rest where they opened. Those others
        # are never placed, so the clause above released them the moment place
        # mode ended, and the capture loop then learned a CASCADE position
        # into a key the window does not own, overwriting the holder's
        # geometry. Self-worsening, because the next login restores the
        # cascade and the pass repeats.
        #
        # MEASURED on manifold 2026-11-06 from the pre-logoff pair: ten of one
        # account's Chrome windows shared `google-chrome NUL titan`, one was
        # placed to ws[0,1] and nine were refused, and the slot went
        # ws[0,1] pos[128,155] -> ws[2,0] pos[172,150], which is exactly where
        # one of the refused windows was sitting.
        #
        # SO SUCH A WINDOW HAS NO MEMORY, which is what `doctor` already tells
        # the user ("1 gets the remembered place, the rest stay where they
        # opened"). It owns no slot, so there is nowhere its position could
        # honestly be written.
        #
        # THE LIVE SET COMES FROM THE SNAPSHOT, not from `_live_ids()`: that
        # reads `place_sock`, whose one writer is the PLACER thread, and this
        # runs on the capture thread. The snapshot in hand IS the live set at
        # this instant, which is the same evidence `live_holder` wants and
        # costs no extra round trip.
        live = {w.get("id") for w in windows if w.get("id") is not None}
        with self.lock:
            ledger = dict(self.slot_held)
        for w in windows:
            vid = w.get("id")
            if vid is None or vid in held:
                continue
            # THROUGH `free_slot`, THE SAME DEFINITION THE PLACER USES, and
            # it has to be: with a slot per window this asked `matched_key`,
            # which answers the IDENTITY's key for all N of them, so the
            # ledger showed one holder and the other N-1 were held out of the
            # capture. That would suppress the learning of exactly the
            # windows the extra slots exist to serve.
            #
            # SO THE QUESTION IS "IS EVERY SLOT TAKEN", not "is the identity's
            # slot taken". A window with a free one is going to be placed into
            # it and its position is then worth learning; one with none owns
            # nothing, so there is nowhere its position could honestly go.
            k, _e = engine.free_slot(self.kb, ledger, w.get("app_id") or "",
                                     w.get("key") or "",
                                     w.get("source") or "", vid, live)
            if k is None:
                continue          # no slot at all: nothing to be refused by
            h = ledger.get(k)
            if h is not None and h != vid and h in live:
                held.add(vid)
        return frozenset(held)

    def _in_transition(self):
        return time.time() < self.transition_until

    def _begin_transition(self, why):
        """The displays are changing: believe nothing about where windows are.

        Started by the compositor's own output-added / output-removed, which is
        the instant signal, and ended by hwdp's hook arriving with the new
        profile (or by DOCK_HOLD expiring, so a box with no hwdp recovers).

        IT SUPPRESSES THE WHOLE CAPTURE, not just the learn. The snapshot is
        the relaunch's input and the seed for a profile's first store, so a
        `current.json` written mid-collapse would teach a brand-new desk the
        collapse as its starting layout, which is the one state that cannot be
        relearned by waiting."""
        if self._in_transition():
            self.transition_until = time.time() + DOCK_HOLD
            return
        self.transition_until = time.time() + DOCK_HOLD
        logline(f"displays changing ({why}): holding capture for "
                f"{DOCK_HOLD:.0f}s")

    def _take_redisplay(self):
        """Adopt a new display profile on hwdp's request, and re-place.

        THE STORE IS RELOADED, NOT MIGRATED. A slot is pixels on a named
        output, so the entries learned at the other desk describe geometry
        that is not attached; the new profile's own store is the only thing
        that can answer here, even when it is empty.

        EVERY PLACEMENT LEDGER IS VOID, which is the part that is easy to
        miss: `placed` would dedup a window out of being re-placed, and
        `slot_held` records which window owns a slot on outputs that may no
        longer exist. Clearing them is what makes the sweep a real one.

        Consumed and removed like the forget request, so an unparsable one is
        not retried on every poll."""
        try:
            with open(REDISPLAY_FILE) as f:
                prof = f.read().strip()
        except OSError:
            prof = ""
        try:
            os.remove(REDISPLAY_FILE)
        except OSError:
            pass
        if not prof:
            return ""
        self._adopt_profile(prof, "on request")
        return prof

    def _adopt_profile(self, prof, why):
        """Switch to a display profile's store and re-place everything once.

        Shared by the hook's request and by the drift detector below, because
        two copies of this is how they drift.

        EVERY LIVE WINDOW IS RE-GRACED AND ENTITLED TO ONE PLACEMENT, which
        the first version of this got wrong: it voided `placed` and asked for
        a sweep, and the sweep placed NOTHING. A window that mapped hours ago
        is long past its PLACE_GRACE deadline, and `late_ok`'s one-late-chance
        needs `first_look`, which is false for a window already identified. So
        both gates refused every window the dock was meant to move, and the log
        said "re-placing" over a sweep that could not act.

        A DISPLAY CHANGE IS THE THIRD KIND OF ENTITLEMENT, named rather than
        folded into `late_ok`: that set means "mapped while place, owed a
        placement at first identification", where this means "the display
        changed under a window that was already settled, so its slot is new
        information". Overloading the first would have made its own meaning
        unreadable."""
        # THE PANEL MAP IS CERTAINLY STALE NOW, and it is cached, so re-ask
        # before anything resolves a slot against it. This is the one moment a
        # connector can have changed what monitor it names.
        engine.panel_map(fresh=True)
        try:
            vids = [v.get("id") for v in
                    self.place_sock.list_views(filter_mapped_toplevel=True)]
        except Exception as e:
            logline(f"redisplay: cannot list views: {e}")
            vids = []
        now = time.time()
        with self.lock:
            was, self.kb_profile = self.kb_profile, prof
            self.kb = load_knowledge(prof)
            self.profile_drift_at = 0.0
            self.st["dirty"] = True
            self.st["layout"] = True
            # END THE HOLD, but not before the re-place has had its verify
            # budget: learning the instant we issue placements would record
            # the positions we are still correcting. THE HOLD IS NOT THE
            # SWEEP: see _sweep, which is a blip and carries no hold at all.
            self.transition_until = now + sum(PLACE_VERIFY) + 1.0
        n = self._sweep(vids)
        logline(f"display profile {was} -> {prof} ({why}): {len(self.kb)} "
                f"known window(s) here; re-placing {n}")

    def _sweep(self, vids=None):
        """TRANSPOSE: put the windows that ALREADY EXIST where they belong
        NOW. Returns how many were entitled.

        A BLIP, AND THAT IS THE WHOLE POINT. It issues placements and returns;
        it holds nothing, waits for nothing and has no duration of its own.
        The read-backs that follow are PLACE_VERIFY, which is the placer's
        standing behaviour for ANY placement and is not charged to this.

        SEPARATE FROM THE HOLD it used to be welded to. The hold suppresses
        LEARNING while the displays are in flux and has to outlive the sweep,
        because it spans the interval in which we do not yet know which store
        to write. A sweep asked for by hand needs no hold at all: nothing is
        in flux.

        EVERY PLACEMENT LEDGER IS VOID, which is the part that is easy to
        miss: `placed` would dedup a window out of being re-placed, and
        `slot_held` records which window owns a slot on outputs that may no
        longer exist. Clearing them is what makes the sweep a real one.

        AND EVERY LIVE WINDOW IS RE-GRACED AND ENTITLED TO ONE PLACEMENT. A
        window that mapped hours ago is long past its PLACE_GRACE deadline,
        and `late_ok`'s one-late-chance needs `first_look`, false for a window
        already identified, so without this both gates refuse every window the
        sweep exists to move. Measured when it shipped that way: the log said
        "re-placing" over a sweep that could not act."""
        if vids is None:
            try:
                vids = [v.get("id") for v in
                        self.place_sock.list_views(filter_mapped_toplevel=True)]
            except Exception as e:
                logline(f"sweep: cannot list views: {e}")
                return 0
        now = time.time()
        with self.lock:
            self.placed.clear()
            self.slot_held.clear()
            self.verify.clear()
            self.place_tries.clear()
            self.late_ok.clear()
            self.redisplay_ok = {i for i in vids if i is not None}
            for i in self.redisplay_ok:
                self.deadline[i] = now + PLACE_GRACE
            # Runs on the PLACER thread, which is place_sock's one writer, so
            # it is REQUESTED here rather than done here: the same seam a
            # store change already uses.
            self.st["recheck"] = True
            # THE EVENT, published as a FACT rather than as a state. A tray
            # dwelling on it for a few seconds is presentation and belongs in
            # the tray; a timestamp cannot be missed by a one-second poller,
            # where a sub-second state can.
            self.st["transposed_at"] = now
        return len(self.redisplay_ok)

    def _take_sweep(self):
        """Apply a `usher transpose` request and remove it. A sweep ONLY: no
        store reload and no hold, because a hand-asked transpose happens when
        nothing is in flux."""
        try:
            os.remove(SWEEP_FILE)
        except OSError:
            pass
        n = self._sweep()
        logline(f"transpose on request: re-placing {n} window(s)")
        return n

    def _profile_drift(self):
        """Notice a display profile that changed with nobody telling us.

        The hook is the PROMPT and correctly-ordered path, not the only one. A
        box with no hwdp has no hook at all, and a hook slower than DOCK_HOLD
        would let the hold expire and a capture write the collapsed layout into
        the store of the desk we are leaving: the binding fix stops that
        reaching the OTHER desk's store, and nothing stopped it corrupting
        this one.

        So while the current profile disagrees with the loaded one, capture is
        suppressed; and once it has disagreed for longer than DOCK_HOLD we
        ADOPT it ourselves rather than refusing forever, which is what makes
        the hook an optimisation rather than a dependency."""
        try:
            cur = engine.profile_id()
        except Exception:
            return False
        if cur == self.kb_profile:
            self.profile_drift_at = 0.0
            return False
        now = time.time()
        if not self.profile_drift_at:
            self.profile_drift_at = now
            logline(f"display profile is now {cur}, store is {self.kb_profile}"
                    f": holding capture for up to {DOCK_HOLD:.0f}s")
            return True
        if now - self.profile_drift_at < DOCK_HOLD:
            return True
        self._adopt_profile(cur, "noticed, no hook")
        return False

    def _poll_sources(self, snap):
        """Ask a source to identify its own windows when we cannot, and apply
        what it says about its restarted browser. Returns whether anything
        it reported CHANGED what a snapshot would now stamp, so the caller
        knows to take one again.

        THE PLAN DECIDES, and it is pure and checked: demand-driven, rate
        limited, and only where a capture cannot shrink that account's
        roster. See `engine.source_refresh_plan`.

        IT WAITS FOR THE WINDOW SET TO SETTLE rather than for the owner's
        expectation to be met. The first version compared against
        `self.saved` and required every app saved for that source to be
        live, and it NEVER FIRED at a login: that account's saved set names
        installers and dialogs that do not come back. See
        `engine.source_refresh_plan`.

        NEVER FATAL. This is a sudo subprocess on the capture thread, and
        every outcome of it is optional: without it the windows keep the
        source-alone key, which is where they were before any of this.
        """
        try:
            plan, self.src_seen = engine.source_refresh_plan(
                snap["windows"], self.src_asked, time.time(),
                self.src_seen, answered=engine._SOURCE_WINDOWS)
        except Exception as e:                             # noqa: BLE001
            logline(f"could not plan a source refresh: {e}")
            return False
        changed = False
        for src in plan:
            self.src_asked[src] = time.time()
            before = dict(engine._SOURCE_WINDOWS.get(src) or {})
            try:
                # THE PIDS GO WITH THE QUESTION. The snapshot rows carry
                # both halves (`pid` and `identifier`), which is the only
                # reason the refresh can send them from the capture thread
                # without a second round trip to the compositor.
                engine.source_trigger([src], "capture",
                                      views=snap["windows"])
            except Exception as e:                         # noqa: BLE001
                logline(f"could not ask {src} to identify its windows: {e}")
                continue
            if (engine._SOURCE_WINDOWS.get(src) or {}) != before:
                changed = True
            with self.lock:
                n = engine.rekey_source(self.kb, src,
                                        engine.take_source_rekey(src))
            if n:
                changed = True
                logline(f"{src}: re-keyed {n} window slot(s) onto that "
                        f"account's restarted browser")
        # PUBLISHED FOR EVERY ONE-SHOT VERB, because the map is per process:
        # without this `restore`, `restore --dry-run`, `predict` and `verify`
        # all read another account's windows as the source ALONE, and
        # measured on manifold a blind verb matched ZERO of eleven
        # per-window slots. The daemon is the only thing that has the map, so
        # it is the only thing that can publish it.
        #
        # NEVER FATAL AND CONTENT-COMPARED, so a poll that changed nothing
        # neither writes nor can fail the refresh.
        try:
            if engine.publish_sources():
                logline("published the per-window map for %d source(s)"
                        % len(engine._SOURCE_WINDOWS))
        except Exception as e:                             # noqa: BLE001
            logline(f"could not publish the per-window map: {e}")
        return changed

    def _capture_once(self, cap):
        """One snapshot: learn from it, save the knowledge, roll the history if
        this was a layout change rather than a tab flip. The SNAPSHOT is always
        whole: only what we LEARN from it is held back."""
        if self._in_transition() or self._profile_drift():
            return        # st["dirty"] stays set, so the next tick retries
        snap = snapshot(cap)
        # AND RE-TAKE IT IF THE REFRESH LEARNED ANYTHING, which is not an
        # optimisation: `snapshot` STAMPS each window's key, so the rows above
        # were stamped before the refresh could fill the cache they read.
        # Learning from them records the source-alone key and the per-window
        # identities arrive one capture LATE, which in a quiet session is the
        # event-driven-capture trap this file already records twice: nothing
        # dirties the store, so "next capture" can be never.
        #
        # ONE EXTRA SNAPSHOT, and only on the pass where a refresh actually
        # changed something, which the rate limit bounds to once a minute.
        if self._poll_sources(snap):
            snap = snapshot(cap)
        hold = self._held(snap["windows"])
        # WHEN THE HOLD LIFTS, COME BACK. Capture is event-driven, so a window
        # held through the pass that recorded it gets no second look until
        # something else happens to dirty the store. In a busy session that is
        # immediate and invisible; in a quiet one the window sits in the
        # snapshot with no learned slot indefinitely, so it comes back at the
        # next login and has nowhere to be put.
        #
        # Only the "grace expired, never placed" release needs this. A window
        # that gets PLACED leaves the hold too, but placing it moves it, and a
        # geometry change is already a capture trigger.
        self.hold_until = min((self.deadline.get(i, 0) for i in hold),
                              default=0)
        refused = []
        with self.lock:
            roll = self.st["layout"]
            learn(self.kb, self.groups, snap["windows"], snap["time"], hold,
                  seen=self.seen_terms, outputs=snap["outputs"],
                  refused=refused)
            self.st["dirty"] = False
            self.st["layout"] = False
            save_knowledge(self.kb, self.kb_profile)
        self._note_refusals(refused)
        persist(snap, roll=roll)
        # A WINDOW STILL WAITING FOR ITS ACCOUNT KEEPS THE LOOP COMING BACK.
        # The ask in `_poll_sources` runs only inside a capture, and a capture
        # is due only when something dirties the store, so a window that is
        # pending and then goes quiet would never be asked about and would sit
        # unplaced until the fallback bound: found in the enclave VM rig, where
        # a pending window was still unplaced 45 seconds after login. BOUNDED,
        # because a pending window falls back to the source-alone key after
        # SOURCE_PENDING_S and so stops being pending, and the pause is the
        # debounce, so this is one snapshot every couple of seconds for at
        # most that long.
        if any(w.get("source") and w.get("app_id") and not w.get("key")
               for w in snap["windows"]):
            with self.lock:
                self.st["dirty"] = True
                self.st["last"] = time.time()

    def _note_refusals(self, refused):
        """Say why a live window is not being remembered. ONCE.

        THE DESIGN RULE IS TWO HALVES: never write an entry that cannot
        round-trip, and LOG the ones refused. The write path had enforced the
        first half for a month and said nothing at all, which is the silent
        refusal this package keeps rediscovering in other clothes.

        WHICH KINDS REACH THE LOG IS THE WHOLE JUDGEMENT, and the rest of this
        is bookkeeping. watch.log is the forensic record these notes quote
        verbatim, so a line that fires on a normal desk every second, or per
        window per session, costs more than it buys:

            never   ONE line per window. Decided and final, so it will not
                    resolve by waiting, and a reader who sees it knows that
                    window is not coming back. This is the class the rule is
                    about.
            parked  ONE line per CHANGE in the count, because an undock parks
                    every external window at once and the useful fact is the
                    number plus that it is deliberate. It self-clears on
                    redock, and says so.
            pending NOTHING. Sub-second and retried every capture (a terminal
                    at 0.25s, chrome until its session file catches up), so a
                    line here would be two per window per session describing a
                    state that was already over. `doctor` reports it per
                    window, which is where a question about one window goes."""
        now = [r for r in refused if r[3] == "never"]
        with self.lock:
            fresh = [r for r in now if (r[0], r[3]) not in self.refused_said]
            self.refused_said |= {(r[0], r[3]) for r in now}
            parked = len([r for r in refused if r[3] == "parked"])
            say_parked = parked != self.parked_said
            self.parked_said = parked
        for _vid, app, label, kind, why in fresh:
            logline(engine.refusal_note(app, label, kind, why))
        if say_parked and parked:
            logline(f"{parked} window(s) parked on an output that is not"
                    f" attached: not learning where they are until it is back")
        elif say_parked:
            logline("no windows are parked now: learning positions again")

    def _loop_failed(self, what, e, streak):
        """Report an error that escaped a daemon thread's loop BODY, and
        escalate rather than limp.

        **A THREAD WHOSE TARGET RAISES EXITS THAT THREAD ALONE.** The process
        lives, the status file may keep ticking, and whatever the thread was
        for stops dead: for the placer that is NOTHING IS EVER PLACED AGAIN
        this session, with no line anywhere. That is this package's "restore
        works, mostly" shape with the diagnostic removed.

        AND THE THREAD'S SURVIVAL MUST NOT DEPEND ON EVERY CALLEE HOLDING,
        which is the reason this is a BODY guard rather than more per-call
        ones. Measured by classifying each loop statement: the capture
        thread's `_poll_files`, `_poll_outputs` and `_write_status` all sat
        OUTSIDE its try, and the placer's `_recheck_all` guards its own
        `list_views` and its own place loop and not the elimination step
        between them. Auditing every raise path of every callee is an
        invariant nobody can hold, and the sweep says it was not held.

        THE POLICY IS THE CAPTURE STEP'S, deliberately, rather than a second
        one: log with the streak, and at the limit EXIT so the supervisor
        does a clean full respawn with fresh sockets. A guard that merely
        continued for ever would turn a dead thread into a silent one, which
        trades a loud failure for a quiet one. See respawn_report, which
        bounds the log when the respawn itself keeps failing."""
        logline(f"{what} loop error: {e} (streak {streak})")
        if streak >= CAPTURE_FAIL_LIMIT:
            logline(f"{what} loop failing {streak}x; exit for respawn")
            os._exit(1)

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
        if ev in OUTPUT_EVENTS:
            # THE COMPOSITOR IS THE FIRST TO KNOW, and it is the only signal
            # that arrives before the windows move. hwdp's hook follows with
            # the new profile; this just stops us believing anything meanwhile.
            self._begin_transition(ev)
        if ev == "view-mapped" and v.get("id") is not None:
            self.deadline[v["id"]] = time.time() + PLACE_GRACE  # start grace
            if self._placing_now():
                self.late_ok.add(v["id"])   # see Watcher.late_ok
            with self.lock:
                self.st["last_map"] = time.time()  # feed the IDLE_SETTLE clock
        if ev in PLACE_EVENTS:
            vid = v.get("id")
            if vid is not None and vid not in self.placed:
                # Defer to _placer_loop. Browsers wait TITLE_QUIET (re-armed
                # on every title change) so we never move one mid-restore;
                # other apps are stable at map -> a tiny settle, placed on the
                # next tick.
                wait = (TITLE_QUIET if is_browser(app_of(v))
                        else TITLE_QUIET_FAST)
                with self.lock:
                    self.pending[vid] = {"v": v, "due": time.time() + wait}
        elif ev == "view-unmapped" and v.get("id") is not None:
            self.placed.discard(v["id"])
            self.identified.discard(v["id"])
            self.deadline.pop(v["id"], None)
            # RELEASE THE SLOT, or closing a window would leave its place
            # permanently unusable and the NEXT window of that app would be
            # left adrift for the rest of the session.
            with self.lock:
                for _k in [k for k, _vid in self.slot_held.items()
                           if _vid == v["id"]]:
                    self.slot_held.pop(_k, None)
                # and forget having SAID it was refused, or a new window
                # reusing this vid would be refused silently. Same reason the
                # rest of this block exists: a per-view set that only grows
                # is a leak in a process that runs for weeks.
                self.slot_said = {p for p in self.slot_said
                                  if p[0] != v["id"]}
                self.cell_said.discard(v["id"])
                self.rescued.pop(v["id"], None)
                # and having said it would never be remembered, for the same
                # two reasons: a vid is reused, and a set that only grows is a
                # leak in a process that runs for weeks.
                self.refused_said = {p for p in self.refused_said
                                     if p[0] != v["id"]}
            # and the identity chrome resolved for it once and remembered. A
            # cache that only ever grows is a leak in a process that runs for
            # weeks, and this is the one moment we know the view is gone.
            chrome.forget_window(v["id"])
            # and the identity another ACCOUNT reported for it, cached for
            # the life of the view for the same reason chrome's is.
            engine.forget_source_window(v["id"])
            with self.lock:
                self.pending.pop(v["id"], None)
                # The retry budget is PER MAP, so it goes with the window.
                self.verify.pop(v["id"], None)
                self.place_tries.pop(v["id"], None)
                self.late_ok.discard(v["id"])
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
