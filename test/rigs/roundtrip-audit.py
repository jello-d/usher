#!/usr/bin/env python3
"""EVERY live window: identifiable? in the db? and would it come back?

RUN BY HAND against a live box, not by test/run. The question this package
exists to answer, asked exhaustively rather than per incident: `doctor` says
whether a window has a slot and `verify` says whether it came back, and
neither says whether it COULD.

THREE SEPARATE QUESTIONS, and this package's own seam is why they cannot be
collapsed: THE RELAUNCH READS THE SNAPSHOT, PLACEMENT READS THE STORE. A slot
can PLACE a window that exists and can never cause one to EXIST, so a window
can be perfectly remembered and still never come back. That state is a stable
deadlock no reboot escapes, and it cost this fleet two terminals for three
days.

    1  IDENTIFIABLE   resolution() answers Ready, with a key
    2  IN THE DB      some key match_keys offers has an entry
    3  PLACEABLE      that entry's output is attached AND its cell is on
                      this desk's grid, AND no other live window is holding
                      the same key (the slot ledger places ONE)
    4  WOULD START    some mechanism would make the window EXIST at a login

THE LOGIN CONDITION IS SIMULATED FOR (4), with NOTHING live, which is the
only honest framing: asking "would it start" while it is already running
answers "no, it is up", which is true and useless. So the candidate functions
are driven with live=[] exactly as a fresh session drives them.

READ-ONLY, and that is load-bearing rather than polite: every relaunch
answer is computed from the PURE candidate functions rather than by calling
`launch_missing`, which SPAWNS. This suite has opened sixteen real terminals
on a live desktop once already.

AND IT ADOPTS THE DAEMON'S PUBLISHED PER-WINDOW MAP, or it is blind to
another account's windows individually and reports every one of them under
one shared key: that blindness has produced a wrong reading five times in
these notes, and it is invisible because a per-process cache has nothing to
stat.

Run it with the INSTALLED venv python (the system one has no pywayfire), or
pass a dev tree as argv[1] to A/B a change; it asserts which tree it
imported either way.
"""
import os
import sys

TREE = sys.argv[1] if len(sys.argv) > 1 else "/opt/usher"
if TREE.startswith("/opt"):
    import pathlib
    sys.path.insert(0, str(sorted(pathlib.Path(TREE, "venv/lib").glob(
        "python3*/site-packages"))[0]))
else:
    import pathlib
    sys.path.insert(0, str(sorted(pathlib.Path(
        "/opt/usher/venv/lib").glob("python3*/site-packages"))[0]))
    sys.path.insert(0, TREE)
from usher import engine as E                                   # noqa: E402

if not E.__file__.startswith(TREE):
    sys.exit("WRONG TREE: asked for %s, got %s" % (TREE, E.__file__))
print("imported %s" % E.__file__)

# THE DAEMON'S OWN PER-WINDOW MAP, adopted the way every verb now does, or
# this is blind to another account's windows individually and reports every
# one of them under one shared key. That blindness has produced a wrong
# reading five times in these notes.
pub = E.load_published_sources() or {}
print("published source map: %s"
      % ({k: len(v) for k, v in pub.items()} or "(none)"))

sock = E.ipc()
snap = E.snapshot(sock)
rows, outs = snap["windows"], snap["outputs"]
omap = {o["name"]: o for o in outs}
kb, prof = E.kb_for_profile()
ents = E.desktop_entries()
print("profile %s, %d store entries, %d live window(s), outputs %s"
      % (prof, len(kb), len(rows), sorted(omap)))

# ---- (4) THE LOGIN CONDITION: what would be started, with nothing live ----
# Driven with live=[] so the answer is about a LOGIN and not about now.
# THE TWO CANDIDATE FUNCTIONS RETURN DIFFERENT SHAPES: mux gives (cmd, size)
# pairs and kitty gives FLAT cwd strings, one per missing window. Unpacking
# both the same way raised here and not on the box with no terminals, which
# is the four-helpers-four-shapes trap this repo records most often.
mux_cmds = [c for c, _s in E.mux_candidates(rows, [])]
kitty_cwds = list(E.kitty_candidates(rows, []))
chrome_profs = E.chrome_profiles_for(rows)
sources = E.source_trigger_plan(rows)
print("\nat a login, with nothing live, the relaunch would run:")
print("  chrome profiles : %s" % (chrome_profs or "(none)"))
print("  mux commands    : %d  %s" % (len(mux_cmds), mux_cmds))
print("  plain kitty     : %d  %s" % (len(kitty_cwds), kitty_cwds))
print("  sources asked   : %s" % (sources or "(none)"))


def starts(w):
    """Which mechanism would make THIS window exist at a login, or why none.

    PER WINDOW, which is the question a human asks, even though three of the
    four mechanisms are per APP or per COMMAND. Where a mechanism is counted
    (terminals per cwd or per command, chrome per profile) the count is what
    is reported, because "one of four" is the honest answer for a window
    whose cwd is shared.
    """
    app, src = w.get("app_id") or "", E.source_of(w)
    if src:
        # ANOTHER ACCOUNT STARTS ITS OWN, from a roster written by that
        # account in a home the owner may not read. So the owner's half is
        # "asked", and whether that account has this app in its roster is
        # behind the uid wall by design.
        return ("source", "the %s account is asked to resume itself" % src
                if src in sources else "NOT asked: %s is not in the plan" % src)
    if E.is_chrome(app):
        if not chrome_profs:
            return (None, "no chrome profile would be started")
        return ("chrome", "the browser restores its own session (%d profile(s)"
                " started: %s)" % (len(chrome_profs), chrome_profs))
    # A TERMINAL IS RELAUNCHED FROM ITS SAVED KEY, not from
    # `relaunch_command_for`, and conflating the two was this probe's own
    # error: that helper answers the LIVE window's command, which is a latch
    # target when one is in the process tree and NOTHING for a plain
    # `mux resume` (which execs into tmux and leaves no process to read). The
    # relaunch does not need it: `mux_candidates` derives the command from
    # the STORED key through `mux_cmd_of_saved`, which is why the login plan
    # above lists `mux resume`. Asking the wrong helper reported a window
    # that round-trips perfectly as one that would never start.
    if app == "kitty" and E.TERM_KEY_RE.match(key or ""):
        want = E.mux_cmd_of_saved(w)
        n = sum(1 for c, _s in E.mux_candidates(rows, []) if c == want)
        if not n:
            return (None, "no mux command derives from %r" % (key,))
        return ("mux", "%d window(s) running %s" % (n, want))
    cmd = E.relaunch_command_for(w)
    if cmd:
        return ("plugin", "its own recorded command: %s" % cmd)
    if app == "kitty":
        # A PLAIN SHELL: counted per cwd, so say how many shells that cwd
        # would get, since N windows in one directory is N spawns now.
        k = w.get("key") or ""
        cwd = k.partition("kitty:")[2] if k.startswith("kitty:") else ""
        n = kitty_cwds.count(cwd)
        if not n:
            return (None, "no cwd to reopen it in (key %r)" % (k,))
        return ("kitty", "%d plain shell(s) in %s" % (n, cwd))
    argv, why = E.desktop_launch_for(app, ents)
    if argv:
        return ("registry", " ".join(argv))
    return (None, why or "nothing would start it")


# ---- the per-window table -------------------------------------------------
# WHICH LIVE WINDOWS HOLD EACH KEY, because the slot ledger gives a shared
# slot to exactly ONE and leaves the rest where they open. A window counted
# as "placed" when three others share its key is the report lying.
held = {}
for w in rows:
    k = E.matched_key(kb, w.get("app_id") or "", w.get("key") or "",
                      E.source_of(w))
    held.setdefault(k, []).append(w.get("id"))

print("\n%-3s %-22s %-7s %-34s %-5s %-9s %s"
      % ("#", "app_id", "source", "key", "db", "place", "start"))
tally = {"full": 0, "no-start": 0, "no-slot": 0, "shared": 0,
         "unidentified": 0, "unplaceable": 0}
rowsout = []
for i, w in enumerate(sorted(rows, key=lambda x: (x.get("app_id") or "",
                                                  str(x.get("key")))), 1):
    app, src = w.get("app_id") or "", E.source_of(w)
    r = E.resolution(w)
    key = w.get("key") or ""
    # (1) identifiable
    ident = "yes" if r.is_ready else (r.state or "?")
    # (2) in the db: the first offered key that EXISTS, not matched_key's
    #     fallback, which answers a key whether or not anything is stored.
    ks = E.match_keys(app, key, src)
    dbk = next((k for k in ks if kb.get(k)), None)
    # (3) placeable
    place = "-"
    if dbk:
        e = kb[dbk]
        o = E.entry_output(e, omap)
        if o is None:
            place = "OUT GONE"
        elif not E.cell_fits(e, {o["name"]: o}):
            place = "OFF GRID"
        else:
            n = len(held.get(dbk, []))
            place = "yes" if n <= 1 else "1 of %d" % n
    # (4) would start
    how, why = starts(w)
    rowsout.append((i, app, src, key, ident, dbk, place, how, why,
                    E.log_title(w), r.why or "", list(ks)))
    if not r.is_ready:
        tally["unidentified"] += 1
    elif dbk is None:
        tally["no-slot"] += 1
    elif place in ("OUT GONE", "OFF GRID"):
        tally["unplaceable"] += 1
    elif how is None:
        tally["no-start"] += 1
    elif place.startswith("1 of"):
        tally["shared"] += 1
    else:
        tally["full"] += 1
    print("%-3d %-22s %-7s %-34s %-5s %-9s %s"
          % (i, app[:22], (src or "-")[:7], (key or "(none)")[:34],
             ident[:5], place, how or "NOTHING"))

print("\nthe verdict, per window:")
for k in ("full", "shared", "no-slot", "no-start", "unplaceable",
          "unidentified"):
    print("  %-13s %d" % (k, tally[k]))
print("  total         %d" % len(rows))

print("\nand the ones that are NOT a clean round trip, with the reason:")
_any = False
for (i, app, src, key, ident, dbk, place, how, why, label, rwhy,
     ks) in rowsout:
    if ident == "yes" and dbk and place == "yes" and how:
        continue
    _any = True
    print("  #%-3d %-20s %s" % (i, app[:20], label[:28]))
    if ident != "yes":
        print("        NOT IDENTIFIABLE (%s): %s" % (ident, rwhy))
    if not dbk:
        print("        NO SLOT: nothing stored under any of %r" % (ks,))
    elif place != "yes":
        print("        SLOT NOT USABLE: %s" % place)
    if not how:
        print("        WOULD NOT START: %s" % why)
    else:
        print("        would start: %s (%s)" % (how, why))
print("  (none)" if not _any else "")
print("\nread-only: nothing spawned, nothing written. pid %d" % os.getpid())
