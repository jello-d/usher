"""The verb dispatch: `session-mgr <verb>`, and the console script's entry.

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
import sys
import time

from . import doctor, engine, watch


def main():
    args = sys.argv[1:]
    verb = args[0] if args else ""
    if verb == "capture":
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
    # internal: the re-exec-ed supervisor, which must NOT re-arm the mode
    elif verb == "_super":
        watch.do_watch(launch="--no-launch" not in args)
    elif verb == "_worker":       # internal: the supervised worker
        watch.watch_worker(launch="--no-launch" not in args)
    elif verb == "stop":          # SIGTERM the supervisor cleanly (no pkill)
        engine.do_stop()
    elif verb == "launch":
        n = engine.launch_missing()
        print(f"session-mgr: launched {n} terminal(s)")
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
        # Placement-mode controls (tray + CLI). All three drive the ONE armed_at
        # seam the watcher adopts from ARM_FILE: aggressive arms NOW (aggressive
        # for START_FLOOR); settle arms in the PAST (steady at once, past the
        # CAP); toggle flips from live STATUS_FILE mode (the tray left-click).
        act = verb
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
            print(f"session-mgr: {msg}")
        except OSError as e:
            sys.exit(f"session-mgr: cannot {act}: {e}")
    elif verb == "status":        # current placement mode + seconds to steady
        try:
            s = json.load(open(engine.STATUS_FILE))
            print(f"mode: {s.get('mode', '?')}  "
                  f"seconds_left: {s.get('seconds_left', '?')}")
        except (OSError, ValueError):
            sys.exit("session-mgr: no status (watcher not running?)")
    else:
        print("usage: session-mgr capture | "
              "restore [--dry-run] [--only S] [--from SPEC] | "
              "watch [--no-launch] | resume | stop | launch | aggressive | "
              "settle | toggle | status | exclude | include | "
              "plugins | reload | wind-down | display-changed | doctor | "
              "selftest",
              file=sys.stderr)
        sys.exit(2)
