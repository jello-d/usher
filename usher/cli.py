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
    "cleanly":         ("cli", "login | logoff | reboot | shutdown"),
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
        if dry:
            print(f"{PROG}: would run {engine.SESSION_START} login")
            return 0
        session_start("login")     # execs; never returns
    return _cleanly_leave(verb, dry)


def seated_session(user, listing):
    """(session id, leader pid) for `user`'s seated login session, or None.

    PURE, over `loginctl list-sessions` output, so the parsing is testable
    without a session. Columns are SESSION UID USER SEAT LEADER CLASS TTY.

    THREE THINGS MUST AGREE and any two give a wrong answer: this user has a
    SEATLESS session for the ssh connection asking the question and another for
    the user manager, and the greeter holds a SEATED one of its own. So it takes
    user AND seat AND class to mean the login on the physical display.
    """
    for line in listing.splitlines():
        col = line.split()
        if (len(col) >= 6 and col[2] == user and col[3] != "-"
                and col[5] == "user"):
            return col[0], col[4]
    return None


def _end_session():
    """End the graphical session by signalling its LEADER. Returns a message.

    NOT `killall wayfire`, which is what this replaced and was wrong three ways:
    it hardcoded the compositor's NAME (so sway, hyprland and any X11 WM were
    out), it matched by name rather than by session (so every seat's compositor
    died, and so would any unrelated process wearing that name), and it ignored
    the session manager that actually knows what a session is.

    NOT `loginctl terminate-session` either, which is the obvious generic answer
    and does not work here. MEASURED in the policy on this box:

        org.freedesktop.login1.manage
            allow_active: auth_admin_keep

    so it asks polkit for ADMIN authentication even for your own active session,
    which over ssh means a prompt nobody can answer.

    THE LEADER IS OUR OWN PROCESS, so signalling it needs no privilege at all,
    and logind defines the session as over when its leader exits. That makes
    this display-server agnostic for free: whatever the session runs, its leader
    is what greetd (or any display manager) started.
    """
    import getpass
    done = subprocess.run(["loginctl", "list-sessions", "--no-legend"],
                          capture_output=True, text=True)
    if done.returncode != 0:
        return None, "cannot ask logind which session to end"
    found = seated_session(getpass.getuser(), done.stdout)
    if not found:
        return None, "no seated graphical session to end"
    sid, leader = found
    try:
        os.kill(int(leader), signal.SIGTERM)
    except (OSError, ValueError) as e:
        return None, f"cannot signal session {sid} leader {leader}: {e}"
    return sid, f"asked session {sid} to end (leader {leader})"


def _cleanly_leave(verb, dry):
    """Wind down, then hand over power. REFUSES if it cannot see the session.

    Refusing early is the whole value: wind-down deliberately continues when its
    capture fails, because a broken usher must never be why a machine will not
    reboot, so checking afterwards would be too late with the browser already
    down.
    """
    try:
        engine.connect()
    except Exception as e:
        sys.exit(f"{PROG}: cannot reach the compositor ({e}).\n"
                 "  Winding down without a capture would lose the layout this\n"
                 "  exists to keep, so it is refusing.\n"
                 f"  To START a session from here: {PROG} cleanly login")
    if dry:
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
    print(f"{PROG}: {verb}")
    cmd = {"reboot": ["systemctl", "reboot"],
           "shutdown": ["systemctl", "poweroff"]}[verb]
    os.execvp(cmd[0], cmd)


def _dispatch(verb, args):
    """The verb bodies. Gating already happened; this is what each one does."""
    if verb in ("capture", "save"):
        engine.do_capture()
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
        sys.exit(engine.selftest())
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
