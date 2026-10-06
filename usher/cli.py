"""The verb dispatch, and the console scripts' entries.

TWO FRONT ENDS OVER ONE TABLE, split by who does the typing:

    usher-mgr   the SERVICE. Started by the compositor autostart, by systemd,
                or by a hook. A human should never need to type it.
    usher       the CLI. Everything you ask of a running usher, plus the
                session's own coming and going (`usher cleanly ...`).

They are one dispatch because two lists of verbs drift: this was a single
command once, and the split is in the AUDIENCE column of VERBS rather than in
duplicated code.

The top of the three layers, and the only one that knows about both of the
others, which is what keeps the engine free of any reference to the daemon.
Every name is reached through its module (engine.do_capture, watch.do_watch)
rather than imported: it is a dispatch, so the qualification says which layer
a verb lands in, and it cannot accidentally freeze one of the engine globals
that reload_exclude / reload_anchor / reload_plugins REBIND at runtime: the
exclude and include verbs read two of them.
"""
import json
import os
import signal
import subprocess
import sys
import time

from . import doctor, engine, watch

# WHO MAY TYPE WHAT, and the usage text, in one place. "mgr" is the service,
# "cli" is the human, "both" is anything useful from either side. A verb missing
# here cannot be dispatched, which is deliberate: adding one means saying who it
# is for.
VERBS = {
    "watch":           ("mgr", "start the daemon in RESTORE mode"),
    "resume":          ("mgr", "start the daemon in ADOPT mode (no restore)"),
    "display-changed": ("mgr", "hwdp changed hook; no-op if the set matches"),
    "_super":          ("mgr", None),   # internal: the re-exec'd supervisor
    "_worker":         ("mgr", None),   # internal: the supervised worker
    "save":            ("cli", "record the current layout"),
    "capture":         ("both", "record the current layout (alias of save)"),
    "restore":         ("cli", "put windows back [--dry-run] [--only S] "
                               "[--from SPEC]"),
    # predict/verify are a PAIR and only mean anything together: the reference
    # has to predate the event, which is what makes them the one end-to-end
    # check that is not circular the way `restore --dry-run` is.
    "lock":            ("both", "lock the seated session, and verify it took"),
    "predict":         ("cli", "record what the next restore SHOULD produce"),
    "verify":          ("cli", "diff the live layout against a prediction"),
    "cleanly":         ("cli", "login | logoff | reboot | shutdown"
                               " [--force]"),
    "reload":          ("both", "pick up new code, touch nothing else"),
    "stop":            ("both", "stop the daemon (SIGTERM, not pkill)"),
    "launch":          ("both", "respawn saved-but-absent windows"),
    "wind-down":       ("both", "last capture, then let the apps go"),
    "doctor":          ("both", "what it is doing, and what it is NOT"),
    "status":          ("both", "placement mode and seconds to steady"),
    "aggressive":      ("both", "re-arm aggressive placement"),
    "settle":          ("both", "go steady now"),
    "toggle":          ("both", "flip aggressive/steady (the tray click)"),
    "exclude":         ("both", "show the never-place rules as loaded"),
    "include":         ("both", "show the anchor rules as loaded"),
    "plugins":         ("both", "list loaded plugins"),
    "selftest":        ("both", "offline checks; no compositor needed"),
}

PROG = "usher"     # set per entry point, so messages name what was typed


def gate_blocks(who, audience):
    """Does an ENTRY with this audience refuse a VERB with that one?

    THE RULE, named once. A verb's audience says who it is for ("mgr", "cli",
    "both"); an entry's says what it accepts ("mgr", "cli", "any"). Conflating
    them once refused the SERVICE ITS OWN VERB, so the rule lives here and the
    tests call THIS rather than restating it, because a second copy of a
    predicate is a second thing to get wrong.
    """
    return audience != "any" and who != "both" and who != audience


def _usage(audience):
    shown = [(v, h) for v, (a, h) in VERBS.items()
             if h and (audience == "any" or a in (audience, "both"))]
    print(f"usage: {PROG} <verb> [options]\n", file=sys.stderr)
    for v, h in shown:
        print(f"  {v:16} {h}", file=sys.stderr)
    if audience == "cli":
        print("\nThe daemon itself is usher-mgr, started by the session.",
              file=sys.stderr)
    sys.exit(2)


def session_start(action):
    """Hand `action` to whatever this machine uses to start a console session.

    THE SEAM, and the reason usher has no idea what greetd is. The provider is
    exec'd, so it inherits the terminal (a password prompt must reach the human)
    and REPLACES us, which means its exit status is ours with nothing to
    forward or mistranslate.
    """
    path = engine.SESSION_START
    if not os.path.exists(path):
        sys.exit(f"{PROG}: no session-start provider at {path}.\n"
                 "  usher does not know how this machine starts a session.\n"
                 "  Install one (tackup's compositor module provides one) or\n"
                 f"  link it yourself: ln -s <your-starter> {path}")
    if not os.access(path, os.X_OK):
        sys.exit(f"{PROG}: {path} is not executable, so it would be silently\n"
                 "  skipped. That is the same no-op a 0644 hook is.")
    try:
        os.execv(path, [path, action])
    except OSError as e:
        sys.exit(f"{PROG}: cannot run {path}: {e}")


def do_cleanly(args):
    """Enter and leave the session in good order.

    ONE SEQUENCE, WHICH USED TO BE COPIED FOUR TIMES: capture while the session
    is still true, stop watching so nothing overwrites that capture, let the
    apps go, and only then hand over power. It lives here because every step of
    it is already usher's, and because the callers that each had their own copy
    (a power menu, a script) could then disagree about it, and did.
    """
    dry = "--dry-run" in args or "-n" in args
    force = "--force" in args or "-f" in args
    # The VERB is the first non-flag word, so `-n reboot` and `reboot -n` both
    # work. Taking args[0] made `-n` the verb and printed usage, which reads
    # like the dry run is unsupported rather than mis-parsed.
    positional = [a for a in args if not a.startswith("-")]
    verb = positional[0] if positional else ""
    aliases = {"login": "login", "in": "login",
               "logoff": "logoff", "logout": "logoff", "out": "logoff",
               "reboot": "reboot", "bounce": "reboot",
               "shutdown": "shutdown", "poweroff": "shutdown",
               "down": "shutdown"}
    if verb not in aliases:
        sys.exit(f"usage: {PROG} cleanly [-n] "
                 "login | logoff | reboot | shutdown")
    verb = aliases[verb]
    # ENTERING IS THE ONE THAT RUNS WITH NO SESSION, so it must not meet any of
    # the checks below, every one of which would refuse for the very reason it
    # is being run.
    if verb == "login":
        # A SUMMONED LOGIN LEAVES A CONSOLE YOU ARE NOT SITTING AT, logged in.
        # usher creates that exposure, so it says so plainly and refuses if
        # this box cannot be locked, which is the user's rule: it does not
        # matter whether a lock is CONFIGURED, it matters whether one can
        # actually happen.
        #
        # THE CHECK IS HONEST ABOUT ITS LIMIT. logind's Lock is a signal and
        # its subscribers are not enumerable, so "a lock can be REQUESTED and
        # CONFIRMED" is the strongest thing provable before the session
        # exists. The daemon verifies the real thing in-session and shouts in
        # watch.log if it did not take.
        can, plan, detail = engine.lock_capability()
        if plan == "no-session":
            # Expected: nothing is logged in yet, which is WHY we are here.
            # The lock is the daemon's job once the session exists.
            can = True
            detail = ("no session yet, as expected; the daemon locks it on "
                      "arrival")
        if not can and not force:
            print(f"{PROG}: this box cannot lock its console ({plan})",
                  file=sys.stderr)
            print(f"{PROG}:   {detail}", file=sys.stderr)
            print(f"{PROG}: a summoned login would leave the console LOGGED "
                  f"IN and UNLOCKED,", file=sys.stderr)
            print(f"{PROG}:   with nobody sitting at it. Refusing.",
                  file=sys.stderr)
            print(f"{PROG}: fix the lock, or accept it with:", file=sys.stderr)
            print(f"{PROG}:   {PROG} cleanly login --force", file=sys.stderr)
            return 1
        if dry:
            print(f"{PROG}: would run {engine.SESSION_START} login")
            print(f"{PROG}: lock on arrival: {plan} ({detail})")
            if not can:
                print(f"{PROG}: FORCED past an unlockable console")
            return 0
        if not can:
            print(f"{PROG}: WARNING: forced past an unlockable console "
                  f"({plan}); it will be left UNLOCKED", file=sys.stderr)
        session_start("login")     # execs; never returns
    return _cleanly_leave(verb, dry, force)


def session_tops(procs, leader, uid):
    """The topmost processes of a session that WE own, given {pid: (ppid, uid)}.

    PURE, so the walk is testable without a session to destroy.

    WHY NOT THE LEADER ITSELF, which is the obvious answer and is wrong here.
    logind records the process that called PAM as a session's leader, and greetd
    keeps that worker as ROOT so it can run pam_close_session at teardown. So on
    this stack the leader is root-owned and unsignalable by us:

        3423     root   greetd
         661839  root   greetd --session-worker 13      <- logind's Leader
          662787 jello  /bin/sh /usr/local/bin/startwayfire
           662894 jello wayfire

    ONE LEVEL DOWN IS OURS, and it is the session COMMAND the display manager
    exec'd as us, whose exit is the session's own graceful teardown. So: walk
    down from the leader and take every process we own whose PARENT we do not,
    which is the boundary where the display manager handed the session over.
    Usually exactly one. If the leader is already ours (a manager that keeps no
    root worker) that boundary is the leader itself, and this returns it.

    NAMES NO COMPOSITOR, which is the point. `killall wayfire` reached for the
    right mechanism and hardcoded the wrong thing about it.
    """
    def ours(pid):
        ent = procs.get(pid)
        return ent is not None and ent[1] == uid

    tops, seen, queue = [], set(), [leader]
    while queue:
        pid = queue.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if ours(pid) and not ours(procs[pid][0]):
            tops.append(pid)
            continue                  # its children are below a top; stop here
        queue.extend(k for k, (pp, _u) in procs.items() if pp == pid)
    return sorted(tops)


def read_procs():
    """{pid: (ppid, uid)} for every process we can see, for session_tops."""
    out = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
            with open(f"/proc/{pid}/stat") as f:
                # comm can contain spaces and parens, so read ppid AFTER the
                # last ')': field 4 of what follows.
                rest = f.read().rsplit(")", 1)[1].split()
            out[int(pid)] = (int(rest[1]), uid)
        except (OSError, ValueError, IndexError):
            continue
    return out


def _end_session(dry=False):
    """End the graphical session by signalling the part of it WE own.

    (target, message). `target` is None when nothing could be ended.

    NOT `killall wayfire`, which hardcoded the compositor's name, matched by
    name rather than by session, and ignored the session manager entirely.

    NOT `loginctl terminate-session` either, which is the obvious generic answer
    and is closed to us. MEASURED with pkcheck, which asks polkit without
    acting:

        org.freedesktop.login1.manage   allow_active=auth_admin_keep
        "Authorization requires authentication"

    so it wants ADMIN auth even for your own ACTIVE session, which over ssh is a
    prompt nobody can answer.

    SO WE SIGNAL WHAT THE DISPLAY MANAGER HANDED US: see session_tops. That is
    discovered rather than named, needs no privilege because it is ours, and its
    exit is the session's own teardown path.
    """
    import getpass
    done = subprocess.run(["loginctl", "list-sessions", "--no-legend"],
                          capture_output=True, text=True)
    if done.returncode != 0:
        return None, "cannot ask logind which session to end"
    found = engine.seated_session(getpass.getuser(), done.stdout)
    if not found:
        return None, "no seated graphical session to end"
    sid, leader = found
    procs = read_procs()
    tops = session_tops(procs, int(leader), os.getuid())
    if not tops:
        return None, (f"session {sid} leads from pid {leader}, which is not "
                      "ours, and nothing below it is either: nothing to signal")
    what = ", ".join(f"{p} ({_argv_of(p)})" for p in tops)
    if dry:
        return tops, f"end session {sid} by signalling {what}"
    for pid in tops:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            return None, f"cannot signal {pid} in session {sid}: {e}"
    return tops, f"asked session {sid} to end: signalled {what}"


def _argv_of(pid):
    """A short command line for a pid, for saying WHAT was signalled."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().replace(b"\0", b" ").decode(errors="replace")
        return raw.strip()[:60] or "?"
    except OSError:
        return "?"


def _no_session_here():
    """True when this user has NO login on the physical display.

    ASKED OF logind, NOT OF THE COMPOSITOR, which is the whole point: the
    compositor is the thing we have just failed to reach, so it cannot be the
    witness to its own absence. `seated_session` already knows the three
    columns that have to agree (user AND a real seat AND class `user`), which
    is what excludes the ssh connection asking the question, the user manager,
    and the greeter's own seated session.
    """
    import getpass
    try:
        out = subprocess.run(["loginctl", "list-sessions", "--no-legend"],
                             capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False        # cannot tell, so assume a session and refuse
    return engine.seated_session(getpass.getuser(), out) is None


def _leave_plan(verb, reachable, session_present, force=False):
    """What `cleanly <verb>` should DO, as a pure function of four facts.

    PURE ON PURPOSE, so the whole matrix is checkable without a compositor, a
    logind or a reboot. The cell that was wrong could not have been caught
    while this was two `if`s around a `connect()`.

        reachable  session  verb    force  ->
        yes        -        any     -        wind-down  capture, then go
        no         YES      any     no       refuse     a layout IS at risk
        no         YES      any     YES      forced     and you said so
        no         no       reboot   no      no-session refuse, name --force
        no         no       reboot   YES     forced
        no         no       logoff   -       nothing    nothing to end

    IT REFUSES WHEN IT CANNOT SEE A SESSION, rather than proceeding, and that
    is a deliberate reversal of this function's first version. The first cut
    read "logind reports no seated session" as permission to skip the capture
    and reboot. But THE COSTS ARE NOT SYMMETRIC: refusing wrongly costs one
    extra word typed, while proceeding wrongly loses the layout, which is the
    single thing this program exists to preserve. `_no_session_here` is a
    HEURISTIC over a text listing, and a heuristic may authorise an annoyance,
    never an unrecoverable act.

    SO THE OVERRIDE IS EXPLICIT AND IT IS THE SAME COMMAND. `--force` keeps
    one verb for one intention instead of growing a second spelling, and makes
    the risk the caller's stated choice rather than usher's guess. Same shape
    as `pick_socket`, which refuses on two candidates rather than picking one.

    `logoff` NEEDS NO FORCE, because with no session there is nothing to end:
    the desired state already holds, and nothing is lost by saying so.
    """
    if reachable:
        return "wind-down"
    if verb == "logoff" and not session_present:
        return "nothing"
    if force:
        return "forced"
    return "refuse" if session_present else "no-session"


def _cleanly_leave(verb, dry, force=False):
    """Wind down, then hand over power. REFUSES if a session is AT RISK.

    Refusing early is the whole value: wind-down deliberately continues when its
    capture fails, because a broken usher must never be why a machine will not
    reboot, so checking afterwards would be too late with the browser already
    down.

    BUT "I CANNOT REACH THE COMPOSITOR" IS TWO DIFFERENT FACTS, and treating
    them alike made usher the reason a machine would not reboot, which is the
    exact outcome the paragraph above exists to prevent:

        a session IS running and we cannot see it  -> REFUSE. A layout would
                                                      be lost, and that is
                                                      what this protects.
        there is NO session at all                 -> nothing to lose, so
                                                      refusing protects
                                                      nothing and only blocks
                                                      the power action.

    Met live 2026-10-02 on a box whose greeter had failed: no compositor, no
    layout, and `usher cleanly reboot` refused to reboot it. From the power
    menu the `;` fallback in wlogout's action covers that, which is why it had
    never been seen; typed by hand there is no fallback.

    THE SAME SHAPE AS doctor's BLINDNESS BUG, fixed earlier the same day: a
    test that is a PROXY for the real question keeps answering after the thing
    it stands for has changed. "Can I reach the compositor" stood in for "is
    there a layout to lose", and those differ exactly when no session exists.
    """
    reachable, why = True, ""
    try:
        engine.connect()
    except Exception as e:                                 # noqa: BLE001
        reachable, why = False, str(e)
    # ONE loginctl CALL, and only when it can change the answer.
    present = True if reachable else not _no_session_here()
    plan = _leave_plan(verb, reachable, present, force)
    if plan == "refuse":
        sys.exit(f"{PROG}: cannot reach the compositor ({why}).\n"
                 "  A session IS running, so winding down without a capture\n"
                 "  would lose the layout this exists to keep: refusing.\n"
                 f"  To {verb} anyway and LOSE that layout: "
                 f"{PROG} cleanly {verb} --force\n"
                 f"  To START a session from here: {PROG} cleanly login")
    if plan == "no-session":
        # REFUSING HERE IS THE POINT. Seeing no session is not the same fact
        # as there being none, and the capture is the whole job, so the
        # benefit of the doubt goes to the layout.
        sys.exit(f"{PROG}: cannot reach the compositor ({why}), and logind "
                 "reports\n"
                 "  no session on the display either, so there is probably "
                 "nothing to\n"
                 "  capture. 'Probably' is not good enough to skip the "
                 "capture, so:\n"
                 f"  To {verb} anyway: {PROG} cleanly {verb} --force\n"
                 f"  To START a session from here: {PROG} cleanly login")
    if plan == "nothing":
        print(f"{PROG}: no session on the display; nothing to log out of")
        return 0
    if plan == "forced":
        # SAID OUT LOUD, AND WHICH RISK IT IS, because a silent skip of the
        # capture is indistinguishable from a capture that worked.
        warn = ("a session IS running and could not be captured, so its "
                "layout is being LOST" if present
                else "no session was found, so there should be nothing to "
                     "lose")
        print(f"{PROG}: --force: {warn}; going straight to {verb}",
              file=sys.stderr)
        if dry:
            print(f"{PROG}: would {verb} (forced, no wind-down)")
            return 0
        if verb == "logoff":
            sid, msg = _end_session()
            print(f"{PROG}: {msg}",
                  file=sys.stderr if sid is None else sys.stdout)
            return 0 if sid else 1
        return _hand_over_power(verb)
    if dry:
        if verb == "logoff":
            _t, msg = _end_session(dry=True)
            print(f"{PROG}: would wind down, then {msg}")
            return 0
        print(f"{PROG}: would wind down, then {verb}")
        return 0
    rc = engine.do_wind_down()
    if rc:
        print(f"{PROG}: wind-down reported {rc}; continuing to {verb}",
              file=sys.stderr)
    if verb == "logoff":
        # Ending the session makes the display manager bring its greeter back,
        # which is what makes `usher cleanly login` usable again afterwards.
        sid, msg = _end_session()
        print(f"{PROG}: {msg}", file=sys.stderr if sid is None else sys.stdout)
        return 0 if sid else 1
    return _hand_over_power(verb)


def _hand_over_power(verb):
    """exec the power action. Never returns on success.

    NAMED ONCE because there are now two routes into it (the normal path and
    the no-session shortcut) and two copies of an `execvp` is how they come to
    disagree about which systemctl verb a word means.
    """
    print(f"{PROG}: {verb}")
    cmd = {"reboot": ["systemctl", "reboot"],
           "shutdown": ["systemctl", "poweroff"]}[verb]
    os.execvp(cmd[0], cmd)


def _dispatch(verb, args):
    """The verb bodies. Gating already happened; this is what each one does."""
    if verb in ("capture", "save"):
        engine.do_capture()
    elif verb == "lock":
        sys.exit(engine.do_lock(forced="--force" in args or "-f" in args))

    elif verb == "predict":
        k = args.index("--out") if "--out" in args else -1
        out = args[k + 1] if (k >= 0 and k + 1 < len(args)) else None
        sys.exit(engine.do_predict(out=out))

    elif verb == "verify":
        k = args.index("--against") if "--against" in args else -1
        ref = args[k + 1] if (k >= 0 and k + 1 < len(args)) else None
        sys.exit(engine.do_verify(against=ref))

    elif verb == "restore":
        only = None
        if "--only" in args:
            k = args.index("--only")
            only = args[k + 1] if k + 1 < len(args) else None
        source = None
        if "--from" in args:      # a stored milestone instead of the live kb
            k = args.index("--from")
            source = engine.resolve_snapshot(args[k + 1] if k + 1 < len(args)
                                             else "list")
        engine.do_restore(dry="--dry-run" in args, only=only, source=source)
    elif verb == "cleanly":
        sys.exit(do_cleanly(args[1:]) or 0)
    elif verb == "watch":         # start, or reload if running: RESTORE mode
        engine.arm_mode("restore")
        watch.do_watch(launch="--no-launch" not in args)
    elif verb == "resume":        # start/reload in ADOPT (no restore)
        engine.arm_mode("adopt")
        watch.do_watch(launch="--no-launch" not in args)
    elif verb == "reload":        # pick up new code, touch NOTHING else
        # What a deploy wants. `resume` looks right for this and is not: it
        # captures, so it rewrites every remembered slot to wherever the window
        # currently sits. Never relaunches either.
        engine.arm_mode("quiet")
        watch.do_watch(launch=False)
    elif verb == "_super":        # internal: must NOT re-arm the mode
        watch.do_watch(launch="--no-launch" not in args)
    elif verb == "_worker":       # internal: the supervised worker
        watch.watch_worker(launch="--no-launch" not in args)
    elif verb == "stop":          # SIGTERM the supervisor cleanly (no pkill)
        engine.do_stop()
    elif verb == "launch":
        n = engine.launch_missing()
        print(f"{PROG}: launched {n} terminal(s)")
    elif verb == "exclude":       # show the never-place rules as loaded
        for ar, tr in engine.EXCLUDE_RULES:
            print(f"{ar.pattern} :: {tr.pattern}")
        for n, text, msg in engine.EXCLUDE_ERRORS:
            print(f"error: line {n}: {msg}: {text!r}", file=sys.stderr)
        print(f"# {len(engine.EXCLUDE_RULES)} rule(s), "
              f"{len(engine.EXCLUDE_ERRORS)} error(s)"
              f" from {engine.EXCLUDE_FILE}", file=sys.stderr)
        sys.exit(1 if engine.EXCLUDE_ERRORS else 0)
    elif verb == "include":       # show the anchor (steady-state) rules loaded
        for ar, tr in engine.ANCHOR_RULES:
            print(f"{ar.pattern} :: {tr.pattern}")
        for n, text, msg in engine.ANCHOR_ERRORS:
            print(f"error: line {n}: {msg}: {text!r}", file=sys.stderr)
        print(f"# {len(engine.ANCHOR_RULES)} rule(s), "
              f"{len(engine.ANCHOR_ERRORS)} error(s)"
              f" from {engine.INCLUDE_FILE}", file=sys.stderr)
        sys.exit(1 if engine.ANCHOR_ERRORS else 0)
    elif verb == "plugins":       # list loaded plugins (built-in + user)
        for p in engine.plugins():
            hooks = [h for h in engine.PLUGIN_HOOKS
                     if h in getattr(type(p), "__dict__", {})]
            print(f"{getattr(p, 'name', '?'):10} {', '.join(hooks)}")
        print(f"# {len(engine.plugins())} plugin(s); "
              f"user dir {engine.PLUGIN_DIR}", file=sys.stderr)
    elif verb == "wind-down":     # last capture, then let the apps go cleanly
        sys.exit(engine.do_wind_down())
    elif verb == "display-changed":   # hwdp's changed hook; no-op if same set
        sys.exit(engine.do_display_changed())
    elif verb == "doctor":        # what is it doing, and what is it NOT doing
        sys.exit(doctor.do_doctor())
    elif verb == "selftest":      # offline unit checks (no compositor needed)
        # Imported HERE rather than at module scope: the suite pulls in every
        # other module to check them, so importing it up top would make every
        # `usher` invocation pay for 2,300 lines nobody called. Same reason
        # the daemon verbs defer their own imports.
        from . import selftest as _selftest
        sys.exit(_selftest.selftest())
    elif verb in ("aggressive", "settle", "toggle"):
        _do_arm(verb)
    elif verb == "status":        # current placement mode + seconds to steady
        try:
            s = json.load(open(engine.STATUS_FILE))
            print(f"mode: {s.get('mode', '?')}  "
                  f"seconds_left: {s.get('seconds_left', '?')}")
        except (OSError, ValueError):
            sys.exit(f"{PROG}: no status (watcher not running?)")


def _do_arm(act):
    """Placement-mode controls (tray + CLI). All three drive the ONE armed_at
    seam the watcher adopts from ARM_FILE: aggressive arms NOW (aggressive for
    START_FLOOR); settle arms in the PAST (steady at once, past the CAP); toggle
    flips from the live STATUS_FILE mode (the tray left-click)."""
    if act == "toggle":
        try:
            act = ("settle"
                   if json.load(open(engine.STATUS_FILE)).get("mode")
                   == "aggressive" else "aggressive")
        except (OSError, ValueError):
            act = "aggressive"
    ts = (time.time() if act == "aggressive"
          else time.time() - engine.AGGR_CAP - 1)
    msg = ("re-armed aggressive placement" if act == "aggressive"
           else "settled to steady")
    try:
        os.makedirs(os.path.dirname(engine.ARM_FILE), exist_ok=True)
        with open(engine.ARM_FILE, "w") as f:
            f.write(f"{ts}\n")
        print(f"{PROG}: {msg}")
    except OSError as e:
        sys.exit(f"{PROG}: cannot {act}: {e}")


def _run(prog, audience):
    """Dispatch for one entry point.

    TWO DIFFERENT THINGS, and conflating them broke the autostart. A VERB's
    audience says who it is for ("mgr", "cli", or "both"); an ENTRY's audience
    says what it will accept ("mgr", "cli", or "any"). The first version used
    "both" for the permissive entry as well, so the gate read `who != "both" and
    who != audience` with audience="both" and who="mgr" as TRUE on both halves
    and refused: the permissive entry rejected `watch` and `_super`, the two
    verbs the service itself needs. That killed the daemon on its next reload,
    since the supervisor re-execs itself through `_super`, and would have
    killed the autostart at the next login. Caught only because a live reload
    left no daemon behind.
    """
    global PROG
    PROG = prog
    args = sys.argv[1:]
    verb = args[0] if args else ""
    who = VERBS.get(verb, (None, None))[0]
    if who is None:
        _usage(audience)
    if gate_blocks(who, audience):
        other = "usher-mgr" if who == "mgr" else "usher"
        sys.exit(f"{prog}: `{verb}` belongs to {other}. Try: {other} {verb}")
    _dispatch(verb, args)


def main():
    """`usher`: the CLI."""
    _run("usher", "cli")


def main_mgr():
    """`usher-mgr`: the service, for the autostart and the hooks."""
    _run("usher-mgr", "mgr")


def main_any():
    """`python -m usher <verb>`: the dev entry, accepting every verb.

    NOT A CONSOLE SCRIPT. The two installed commands are deliberately split and
    each refuses the other's verbs; this is neither, because it is how a dev
    tree is driven against a live session without installing anything, so it has
    to reach `watch` and `selftest` alike.

    The permissive audience outlived the compatibility command it was added
    for: the gate bug that refused the service's own verbs would equally have
    refused `python -m usher watch`, and the checks covering it still guard
    this entry.
    """
    _run("python -m usher", "any")
