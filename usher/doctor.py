"""`usher doctor`: say out loud what usher is and is not doing.

A pure REPORTER. It reads the store, the plugin registry, the cross-tool
contracts and the live compositor, and says per window what would be
relaunched or placed AND WHY NOT. It changes nothing, and nothing in the
engine calls it: cli does, and that is the only inbound edge.

It exists because almost every fault this tree has had was SILENT: a scrape
that matched nothing, a purge that deleted what it had just learned, a legacy
store orphaned by a migration that declined to run. None of those showed a
symptom you could name; every one of them is visible here. Run it before
forming any theory about what usher is doing.

The exit code is non-zero ONLY for a CONTRACT breach: the class of fault
that otherwise shows no symptom at all. A store that looks odd is reported and
exits 0, because "odd" is often correct.
"""
import glob
import json
import os
import re
import shutil
import time
from collections import Counter

# The engine's names, listed rather than star-imported, so this module's whole
# dependency is one readable block, the same rule watch.py follows. None of
# these is one of the three globals the engine REBINDS at runtime
# (EXCLUDE_RULES/ERRORS, ANCHOR_RULES/ERRORS, _PLUGINS), so importing by value
# cannot go stale here; the registry is reached through plugins(), which is a
# function.
from .chrome import is_chrome, is_chrome_slot
# CONFIG_DIR is reached through the MODULE rather than imported by value, the
# same hazard the daemon documents for anything that can be rebound.
from . import engine
from .engine import (KB_SCHEMA, LOCAL_HOST, PLUGIN_HOOKS, STATE, TERM_KEY_RE,
                     WayfireSocket, app_of, hwdp_id, is_mux_term, live_keys,
                     load_knowledge, load_snapshot, match, mux_candidates,
                     mux_host_of, mux_session_of, mux_sessions, plugins,
                     lock_capability, profile_id, pview,
                     desktop_entries, desktop_launch_for, identity,
                     kkey, kitty_key_parts, KITTY_RUN_SEP, load_replay_rules,
                     saved_key,
                     schema_path)

# Every failure this tool has had was SILENT: the store looked healthy, Chrome
# kept restoring itself, and the parts that had stopped working stopped saying
# anything at all. `doctor` is the standing answer to "is it actually doing the
# thing?": it reports the store, the cross-tool contracts, and, per window,
# what would happen and WHY. A zero-kitty knowledge base is obvious here.

def _doctor_surfaces(out):
    """This desk's named surfaces, and the three NO-MAP states kept apart.

    "No map authored", "could not ask hwdp" and "the file is broken" are
    different facts, and a report that printed an empty list for all three
    would be the oldest recurring bug in this project: a diagnostic that
    cannot see the thing it diagnoses must say so louder than it says anything
    else. hwdp separates them by exit status for exactly this, so spending
    that distinction here is the whole point of its having made it."""
    surfaces, why = engine.surface_map(fresh=True)
    if why:
        out(f"  surfaces     NOT AVAILABLE: {why}")
        return
    if not surfaces:
        out("  surfaces     none authored for this desk (learned-only, which"
            " is the default)")
        return
    try:
        outs = {o["name"]: o for o in engine.ipc().list_outputs()}
    except Exception:
        outs = {}
    out(f"  surfaces     {len(surfaces)} on this desk")
    for name, s in sorted(surfaces.items()):
        bad = "" if engine.cell_fits(s, outs) else \
            "  CELL NOT IN THE LIVE GRID, so it is not seeded"
        out(f"                 {name:12} {s['output']:8} "
            f"ws{tuple(s['workspace'])} "
            f"{s['size'][0]}x{s['size'][1]} at "
            f"{s['pos'][0]},{s['pos'][1]}{bad}")


def _doctor_store(out):
    kb = load_knowledge()
    counts = Counter(k.split("\x00", 1)[0] for k in kb)
    out("== store ==")
    out(f"  state dir    {STATE}")
    out(f"  config dir   {engine.CONFIG_DIR}")
    src = ("USHER_PROFILE" if os.environ.get("USHER_PROFILE")
           else "hwdp" if hwdp_id() else "derived from outputs")
    out(f"  profile      {profile_id()}  ({src})")
    others = sorted(os.path.basename(p)[len("knowledge-"):-len(".json")]
                    for p in glob.glob(os.path.join(STATE, "knowledge-*.json"))
                    if os.path.basename(p)[len("knowledge-"):-len(".json")]
                    != profile_id())
    if others:
        out(f"  other sets   {', '.join(others)}  (remembered separately)")
    # THE NOTE THAT USED TO SIT HERE IS RETIRED, not merely silent. It
    # warned that returning to a desk unvisited for longer than the TTL would
    # place from its slots and then have the first capture strip them, which
    # was true and is no longer: `forgive_dormancy` shifts a store forward by
    # the gap it was away, so a desk's memory ages only while the desk is in
    # USE. A warning about a loss that cannot happen is worse than none,
    # because it answers a question the reader then stops asking.
    _doctor_surfaces(out)
    try:
        schema = open(schema_path()).read().strip()
    except OSError:
        schema = "(unstamped)"
    out(f"  knowledge    {len(kb)} entr{'y' if len(kb) == 1 else 'ies'}"
        f"  (schema {schema}, current {KB_SCHEMA})")
    for app, n in counts.most_common():
        out(f"                 {app or '(blank app-id)':32} {n}")
    # UNMATCHABLE BY CONSTRUCTION, so the TTL is the only thing that removes
    # them and nothing said they were there. Counted rather than named: the
    # dry run already lists them as UNMATCHED-LAYOUT rows, and a count plus
    # the remedy is what a reader needs here.
    # EVERY CLASS, not chrome's alone. This was `stale_chrome_titles`, which
    # was the same idea for one app and is retired rather than wrapped: two
    # shipped detectors over one fact is the drift `match_keys` and
    # `PLUGIN_HOOKS` both exist to have removed.
    _un = engine.unmatchable_entries(kb)
    if _un:
        _by = {}
        for _k, _w in _un:
            _by[_w] = _by.get(_w, 0) + 1
        out(f"  NOTE         {len(_un)} entr"
            f"{'y' if len(_un) == 1 else 'ies'} no window can ever match ("
            + ", ".join(f"{w} {n}" for w, n in sorted(_by.items()))
            + "): litter the 30-day TTL removes, or `usher forget` now")
    # AND EVERY OTHER STORE, which is the hole that actually cost something:
    # five wildcard entries sat in manifestor's DORMANT stores for 51 days,
    # invisible to every check because they all read the store you happen to
    # be plugged into. doctor already globs these to NAME them, so looking
    # inside is the same walk.
    #
    # A DORMANT STORE IS ALSO WHERE THE TTL CANNOT REACH: it prunes on the
    # load and save of its own profile, so a store for a monitor set that
    # never comes back keeps whatever it holds forever. So this is not a
    # smaller version of the line above, it is the only thing that will ever
    # say so.
    _oth = 0
    for _p in sorted(glob.glob(os.path.join(STATE, "knowledge-*.json"))):
        if os.path.basename(_p)[len("knowledge-"):-len(".json")] \
                == profile_id():
            continue
        _k2 = engine.json_object(_p)
        if isinstance(_k2, dict):
            _oth += len(engine.unmatchable_entries(_k2))
    if _oth:
        # AND THE REMEDY IS NOT THE SAME ONE. `usher forget` edits the store
        # the daemon has LOADED and cannot reach a dormant file at all, so
        # naming it here would send a reader somewhere that is nowhere to go,
        # which is a fault this report has had four times.
        out(f"  NOTE         {_oth} such entr"
            f"{'y' if _oth == 1 else 'ies'} in OTHER monitor sets' stores,"
            " which no TTL reaches (it prunes a store on its own profile's"
            " load) and which `usher forget` cannot edit: those want the"
            " file itself, and have no writer to race")
    # An un-adopted pre-profile store is invisible otherwise: placement simply
    # goes quiet while the knowledge sits in a file nothing opens.
    legacy = os.path.join(STATE, "knowledge.json")
    if os.path.exists(legacy):
        # THE LAST SPELLING OF THE QUESTION. This one was already SAFE, its
        # `len` sitting inside the try, so it is changed to keep the derived
        # check EXACT rather than to fix a fault: an invariant with one
        # justified exception is one that grows a list of them.
        _lkb = engine.json_object(legacy)
        n = "?" if _lkb is None else len(_lkb)
        out(f"  ORPHANED     knowledge.json holds {n} entries and is NOT in"
            " use: it should have been merged into the profile above")
    snap = load_snapshot()
    if snap is None:
        out("  snapshot     current.json MISSING: nothing to relaunch from")
    else:
        age = int(time.time()) - snap.get("time", 0)
        out(f"  snapshot     {len(snap.get('windows', []))} window(s),"
            f" {age}s old")
    # A STORE WITH NO TERMINAL ENTRIES IS ONLY A FAULT IF THERE ARE
    # TERMINALS. The 2026-09-15 purge compared store KEYS against RAW live
    # titles, so nothing ever matched and it deleted every terminal entry on
    # the very pass that wrote it: measured as 294 entries, ZERO for kitty,
    # WITH TWO MUX TERMINALS ON SCREEN. The on-screen half is the whole
    # signal, and this line did not ask it: gated on the store alone it fired
    # on every box with no terminal open, which is an ordinary state, and
    # named a fault that was not happening.
    #
    # THE SNAPSHOT RATHER THAN THE LIVE VIEWS, because this section
    # deliberately makes no IPC call: it is the half of the report that still
    # prints when usher cannot see the compositor at all. A missing snapshot
    # therefore says NOTHING here, which is the fail-safe reading.
    if snap is not None and not counts.get("kitty"):
        _terms = sum(1 for w in snap.get("windows", [])
                     if isinstance(w, dict) and w.get("app_id") == "kitty")
        if _terms:
            out(f"  NOTE         {_terms} terminal(s) in the last capture and"
                " NO kitty entries: terminals are not being remembered, so"
                " they cannot be placed")
    return kb, snap


def source_seam_report(sources, reachable, apps, roster_why, hook=""):
    """The source-seam lines, as (level, text); level "" continues the one
    above. PURE, because the cell that was wrong could not be checked while
    it was four branches wrapped around an os.access.

    SILENCE IS ONE OF THE ANSWERS, and it is the common one: a box with
    neither a hook nor another account says NOTHING here. A line that is
    always present and never actionable is the kind a reader learns to skim
    past, and this section is read when something did not come back.
    """
    rows = []
    if sources and reachable:
        rows.append(("OK", f"source-trigger present; {len(sources)} other "
                           f"account(s) can be asked: {' '.join(sources)}"))
    elif sources:
        rows.append(("WARN", f"{len(sources)} other account(s) had windows "
                             f"here ({' '.join(sources)}) and there is no "
                             f"source-trigger hook at {hook}"))
        rows.append(("", "their windows are placed, and their apps are "
                         "never started"))
    elif reachable:
        rows.append(("OK", "source-trigger present; no other account had "
                           "windows at the last capture"))
    # IF THIS ACCOUNT IS ITSELF A SOURCE, its roster is what decides whether
    # anything comes back, so the contents are the finding. An UNREADABLE
    # roster says nothing at all: that is simply a box that is not an
    # enclave, and it must not read the same as a captured-but-empty one.
    if apps:
        rows.append(("OK", f"this account's own roster: {' '.join(apps)}"))
    elif not roster_why:
        rows.append(("WARN", "this account's roster is EMPTY, so a resume "
                             "would start nothing"))
        rows.append(("", "it is captured while the session is intact, "
                         "before a teardown"))
    return rows


def _doctor_contracts(out, snap=None):
    """The cross-tool assumptions. These are the ones that break in SILENCE,
    because they live in another repo's output format."""
    rc = 0
    out("== contracts ==")
    # THE CONSOLE LOCK, FIRST, because it is the only line here that is a
    # SECURITY state rather than a degraded feature. A summoned login creates
    # a logged-in console nobody is sitting at, so an unlocked one after that
    # is the fault worth seeing before anything else.
    _summoned = os.environ.get("USHER_SUMMONED") == "1"
    _can, _plan, _detail = lock_capability()
    if _plan == "already":
        out("  [OK]   the console is locked")
    elif _can:
        out(f"  [OK]   the console can be locked ({_plan})")
    else:
        out(f"  [WARN] the console CANNOT be locked: {_detail}")
        out("         a summoned login would leave it logged in and"
            " unlocked")
    if _summoned and _plan != "already":
        # Only loud when this session WAS summoned: an unlocked console you
        # are sitting at is not a finding.
        out("  [WARN] this session was SUMMONED and is not locked")
    # ANOTHER ACCOUNT'S APPS, and reported HERE rather than lower down
    # because the mux block below RETURNS EARLY when mux is absent, so
    # anything after it is silently skipped on a box without mux.
    #
    # DRIVEN BY THE LAST CAPTURE, which is the only source list available at
    # this point (the live views are read further down, after this section).
    # That is the right one anyway: it is what `launch_missing` asks from.
    _hook = engine.SOURCE_TRIGGER_HOOK
    for _lvl, _msg in source_seam_report(
            engine.source_trigger_plan((snap or {}).get("windows", [])),
            bool(_hook) and os.access(_hook, os.X_OK),
            *engine.load_roster(), hook=_hook):
        # ONE PREFIX WIDTH for both levels, matching every other line in this
        # section: `[OK]` and `[WARN]` differ by two characters, so padding
        # the bracketed word rather than the level is what keeps the column.
        out(f"  {'[' + _lvl + ']':<6} {_msg}" if _lvl else f"{'':9}{_msg}")
    # RESOLVED BY PATH, never a prefix, and not a third copy of the name: this
    # hardcoded `~/.local/bin/mux` and reported mux ABSENT on a box where mux
    # had simply moved to a machine-wide install. Reporting the path it FOUND
    # is the useful half, since "present" and "present where I expected" are
    # different facts and only one of them is worth printing.
    mux = shutil.which(engine.MUX_BIN)
    if not mux:
        out(f"  [WARN] {engine.MUX_BIN} not on PATH; terminal relaunch"
            " degrades to a no-op")
        return rc
    out(f"  [OK]   mux present ({mux})")
    # Terminals inherit THIS process's environment, so a missing agent here is
    # a missing agent in every session usher respawns, and a remote one then
    # cannot authenticate. mux latch copes (it polls for a credential rather
    # than failing), but only if it can see an agent socket at all.
    # A STALE DAEMON IS THE FIRST THING TO KNOW, because every line below
    # describes the code on DISK while the session is being run by whatever
    # was loaded at startup. Reported here rather than left to setup.sh check,
    # since doctor is what this repo tells you to run first.
    _age, _why = engine.daemon_code_age()
    if _age == "stale":
        out(f"  [WARN] the DAEMON is running OLDER code than this: {_why}")
    elif _age == "none":
        out("  [OK]   no daemon running (this reports the store only)")
    elif _age == "current":
        out("  [OK]   the daemon is running this code")
    sock, whose = engine.session_agent_sock()
    if not sock:
        out(f"  [WARN] no SSH_AUTH_SOCK in {whose}: a respawned REMOTE"
            " session has no way to authenticate")
    elif not os.path.exists(sock):
        out(f"  [WARN] SSH_AUTH_SOCK points at a missing socket ({sock})")
    else:
        out(f"  [OK]   ssh agent socket present  (read from {whose})")
    names, _mwhy = mux_sessions()
    bad = [s for s in names if not re.fullmatch(r"[^\s:]+", s)]
    # THREE STATES, NOT TWO, and the third was wearing the first's words: a
    # mux that FAILS answers the same empty set as a box with no sessions, so
    # `[OK] -> 0 bare name(s)` was printed over a dead contract. Which it is
    # decides what a reader does about it, so they are worded apart.
    if _mwhy:
        out(f"  [FAIL] `mux resume --list` could not be read: {_mwhy}")
        out("         the durable session SET is what a cold boot rebuilds"
            " from, so this is not a quiet degradation")
        rc = 1
    elif bad:
        out(f"  [FAIL] `mux resume --list` is not bare names: {bad[:3]}")
        out("         relaunch will match NOTHING (this exact break has"
            " happened before)")
        rc = 1
    else:
        out(f"  [OK]   `mux resume --list` -> {len(names)} bare name(s)")
    # THE RULE FILES, which doctor reported NOT AT ALL until a rule could be
    # refused for being dangerous. A broken rule is already surfaced by
    # `usher exclude` and by a line in watch.log, and neither is somewhere
    # anybody looks: this is the verb these notes say to run FIRST, and a
    # refused rule is a FAULT the system is carrying rather than a note.
    #
    # READ THROUGH THE MODULE, never imported by value: reload_exclude and
    # reload_anchor REBIND these, so a snapshot taken at import would report
    # a file the daemon has already re-read.
    for _what, _errs, _path in (
            ("exclude", engine.EXCLUDE_ERRORS, engine.EXCLUDE_FILE),
            ("include", engine.ANCHOR_ERRORS, engine.INCLUDE_FILE)):
        if not _errs:
            continue
        rc = 1
        out(f"  [FAIL] {len(_errs)} bad rule(s) in {_path}")
        for _n, _text, _msg in _errs:
            out(f"         line {_n}: {_msg}")
            out(f"           {_text!r}")
    if not engine.EXCLUDE_ERRORS and not engine.ANCHOR_ERRORS:
        out("  [OK]   the rule files load with no errors"
            f"  ({len(engine.EXCLUDE_RULES)} exclude,"
            f" {len(engine.ANCHOR_RULES)} include)")
    return rc


def collision_fix(ident, source="", per_window=0):
    """What to tell a reader whose windows share one store key. FOUR cases,
    and they must stay distinct: handing the wrong one out sends somebody to
    fix the wrong thing.

    A WINDOW FROM ANOTHER ACCOUNT IS THE FOURTH AND MUST NOT SAY "write a
    plugin": a plugin could not read that account's application state either,
    because it is behind the uid wall, so there is nothing a reader can DO and
    saying so plainly is the honest answer. usher keys such windows by their
    SOURCE alone, so several windows of one of its apps legitimately share one
    key.

    A TERMINAL SHARING A CWD KEY HAS TWO REMEDIES, and the second is the one
    for windows that BELONG in one directory. Give the window its own
    app-id (`kitty --app-id work-logs`): no plugin claims that app-id, so it
    is keyed by the app-id ALONE and gets its own slot, and an authored
    `work-logs.desktop` starts it again. MEASURED end to end rather than
    reasoned: `is_appid_keyed` answers True for it, `match_keys` offers
    `work-logs NUL`, and `desktop_launch_for` returns the entry's argv with
    the field codes stripped. That is the README's SECOND TIER doing exactly
    what it is for, with no new identity shape.

    THE OLD ADVICE WAS `settitle` AND IT IS FALSE, in the direction that
    makes things worse (measured on manifold 2026-11-03): `MuxPlugin.owns` is
    `":" in title`, so ANY colon in the name hands the window to it, and with
    no latch target `_mux_slot` answers `term:resume`, which the real mux
    terminal already holds. A colon-free name changes nothing at all, since
    KittyPlugin keys on the cwd either way. Two wrong outcomes and no right
    one, so it was removed; THIS SECTION THEN SAID THERE WAS NO REMEDY,
    which is the opposite overclaim and just as expensive, because a reader
    who believes it stops looking.

    WHAT IS STILL MISSING IS NAMING A WINDOW THAT IS ALREADY OPEN, and that
    is a different feature rather than this one being unfinished: an app-id
    is fixed at exec, so both remedies above are decided when the terminal is
    opened. Nothing usher can read post hoc is both per-window and stable
    (the title churns, /proc's environ is fixed at exec, and a kitty user-var
    needs `listen_on` in somebody else's config plus a socket read), so it is
    recorded as not done rather than hinted at here.

    For an ordinary app a plugin is the answer, which is what the README's
    tiers describe.

    A CHROME SLOT IS NEITHER, and must NOT say "write a plugin": a SessionID
    names exactly ONE window, so two live views holding one is usher having
    mis-resolved rather than a gap in the user's config, and Chrome already
    HAS a plugin. The resolution cache is per view, so it clears on a reload
    or when either window closes. Measured on manifold 2026-10-13, where this
    state sat live for two days and the advice would have been useless."""
    if source:
        if ident != source:
            # A GENUINE COLLISION ON A PER-WINDOW KEY, which is a different
            # thing from the blindness below and became reachable the moment
            # the daemon started PUBLISHING its map: the report resolved
            # these windows per window and they still landed on one key,
            # because that account's own identity for them is the same (four
            # shells in one directory, or two windows of one command).
            #
            # NOTHING A READER CAN DO HERE, and the remedy is not ours: only
            # that account can make them distinct, and it would do it the
            # same way the owner does, by moving one.
            # SAYS WHAT THE OUTER LINE DOES NOT. That line already states
            # the consequence ("1 gets the remembered place, N-1 stay where
            # they opened"), so repeating it here was the whole message
            # twice; what a reader cannot get anywhere else is the CAUSE and
            # who could fix it.
            return (f"they resolve to ONE identity inside the {source} "
                    f"account (the same directory, or the same command), so "
                    f"only that account can make them distinct")
        if per_window:
            # NOT A COLLISION AT ALL, AND THIS REPORT CANNOT SEE WHY. The
            # per-window map lives in the DAEMON's memory and is PUBLISHED
            # for a verb to adopt, so this is now the state of a box whose
            # daemon has not published yet (a fresh boot, or a reload before
            # the first refresh): the windows resolve to the source-alone key
            # and count as sharing a slot. The store's own per-window slots
            # are the evidence a verb can read either way.
            return (f"{per_window} per-window slot(s) are stored for this "
                    f"source, so they are told apart where the map lives; "
                    f"this one-shot report cannot see it")
        return (f"usher cannot tell the {source} source's windows apart: "
                f"that account's app state is in a home it may not read")
    if is_chrome_slot(ident):
        return "usher mis-resolved these; usher reload clears it"
    if ident.startswith("kitty:"):
        return ("usher keys a terminal on its shell's directory and an "
                "allowlisted foreground command (usher/replay), so idle shells "
                "in one directory share a slot; list what they run there, "
                "move one, or give it its own app-id (kitty --app-id NAME) "
                "plus a NAME.desktop entry")
    return "a plugin can tell them apart; see README"


def _doctor_relaunch(out, snap, live):
    """Per saved window: would it come back, and if not, why not."""
    out("== saved windows -> relaunch ==")
    if snap is None:
        return
    saved = snap.get("windows", [])
    # The store, for the collision report below: whether a key is app_id-only
    # is a property of the STORE, not of the window, so it has to be asked.
    kb = load_knowledge()
    lk = live_keys(live)
    # OURS ONLY, which is what the engine asks: another account's browser is
    # not evidence that the owner's is up, so counting it reported `self,
    # Chrome restores its own` for a window usher would in fact START. The
    # quiet direction, and the one a reader has no way to doubt.
    chrome_up = any(is_chrome(pview(v)["app"])
                    for v in engine.our_views(live))
    chrome_note = ("Chrome restores its own" if chrome_up
                   else "browser NOT running: usher starts it, Chrome"
                        " restores its own")
    # Terminals are reported per COMMAND, because that is how they are
    # relaunched: counted, not matched per session. Reporting them per session
    # would describe a mechanism usher no longer uses.
    # Read the registry ONCE: 189 entries here, and re-parsing it per saved
    # window turns a report into a measurable pause.
    _dentries = desktop_entries()
    todo = Counter(c for c, _ in mux_candidates(saved, live))
    for c, n in todo.items():
        out(f"  RELAUNCH   {n} terminal(s)  {c}")
    n_term = sum(1 for w in saved if w.get("app_id") == "kitty"
                 and TERM_KEY_RE.match(saved_key(w)))
    if n_term and not todo:
        out(f"  live       all {n_term} terminal(s) already up")
    # ANOTHER ACCOUNT'S SAVED WINDOWS, REPORTED AS THE ASK THEY ARE. Reaching
    # the per-window verdicts below, a foreign row resolved its app-id in the
    # OWNER's registry and printed `RELAUNCH slack (/usr/bin/slack)`: an
    # action usher does not take, naming the owner starting another account's
    # application, which is the single most alarming thing this report could
    # say falsely. The engine skips every row `snapshot` stamped with an
    # `owner` and asks that ACCOUNT to resume its own, so that is the verdict.
    #
    # PER SOURCE AND COUNTED, like the terminal lines above, because the
    # account restores from its OWN roster and the owner cannot read it: one
    # line per window would be seventeen identical rows on a real desk and
    # would imply usher knows which of them come back.
    _theirs = Counter(engine.source_of(w) or f"uid {w['owner']}"
                      for w in saved if w.get("owner") is not None)
    _hook_ok = os.access(engine.SOURCE_TRIGGER_HOOK, os.X_OK)
    for _src, _n in sorted(_theirs.items()):
        if _hook_ok:
            out(f"  ASK        {_src:14} {_n} saved window(s); that account"
                f" resumes its own")
        else:
            # SAID, because source_trigger's own rule is never silent: with
            # no hook nothing starts them and the reader is owed the reason
            # and the path, not a cheerful omission.
            out(f"  none       {_src:14} {_n} saved window(s), and no"
                f" source-trigger hook: nothing will start them"
                f" ({engine.SOURCE_TRIGGER_HOOK})")
    for w in saved:
        app, key = w.get("app_id", ""), saved_key(w)
        if w.get("owner") is not None:
            continue        # covered by the per-source lines above
        if is_chrome(app):
            out(f"  {'self' if chrome_up else 'START':10} {app:14}"
                f" {key[:36]:36}  ({chrome_note})")
            continue
        if TERM_KEY_RE.match(key):
            continue        # covered by the per-command lines above
        if kitty_key_parts(key) is not None:
            cwd, line = kitty_key_parts(key)
            shown = key.replace(KITTY_RUN_SEP, " :: ")
            if key in lk:
                out(f"  live       {shown[:56]}")
            elif not os.path.isdir(cwd):
                out(f"  skip       {shown[:44]}  (directory is gone)")
            elif line and line not in load_replay_rules():
                out(f"  RELAUNCH   {shown[:44]}  (a plain shell: `{line}` is"
                    f" no longer in usher/replay)")
            else:
                out(f"  RELAUNCH   {shown[:44]}  (kitty --directory {cwd}"
                    + (f", running `{line}`" if line else "") + ")")
            continue
        # THE DEFAULT RELAUNCH's VERDICT. "No plugin respawns this" stopped
        # being true when the freedesktop registry became the fallback, and a
        # report calling a window lost when it is not is the stale sentence
        # doctor exists to avoid. The resolved COMMAND matters more:
        # it is the only way to see, before trusting a reboot, that usher
        # would run `calibre` and not something surprising.
        if app in {app_of(v) for v in live}:
            out(f"  live       {app:14} {key[:44]}")
        else:
            _argv, _why = desktop_launch_for(app, _dentries)
            if _argv:
                out(f"  RELAUNCH   {app:14} {key[:36]:36}"
                    f"  ({' '.join(_argv)[:28]})")
            else:
                # THE WHOLE REASON, untruncated. At 30 characters
                # "nm-applet.desktop is NoDisplay=true: the registry treats
                # ..." was cut to "nm-applet.desktop is NoDisplay", which
                # reads as a COMPLETE sentence, so a reader never learns the
                # explanation was taken away; and "no desktop entry names
                # this app" lost its last letter and read as a typo. It is
                # the last field on the line and nothing is aligned after it.
                out(f"  none       {app:14} {key[:36]:36}  ({_why})")
    # WINDOWS SHARING ONE KEY, which now has a VISIBLE consequence rather
    # than a silent one: a slot holds one window at a time, so the first gets
    # the remembered place and the rest are left where they opened. Before
    # that they were all seated at the identical geometry, stacked perfectly,
    # and with no taskbar nobody found out.
    #
    # REPORTED OVER LIVE WINDOWS, NOT THE SNAPSHOT, because that is where the
    # consequence lands, and for EVERY app rather than kitty alone: an
    # app_id-only key (Signal, slack, a single-window app) matches every
    # window of that app whatever its title, which is the worse case of the
    # two and was not reported at all.
    live_dupes = Counter()
    _byfam = {}
    for lv in live:
        _a = app_of(lv)
        if not _a:
            continue
        # GATED ON THE SOURCE, like every other lookup: without it a window
        # from another account is counted against the OWNER's app_id-only
        # key, inflating a collision the owner does not have. SIXTH place
        # asking which keys a window may match, and the reason match_keys
        # exists.
        _src = engine.source_of(lv)
        # THE FAMILY, which `matched_key` already answers: it only ever
        # returns a key `match_keys` OFFERS, and those are never indexed, so
        # it is the family key by construction. A `slot_base` around it was
        # dead code and a plant said so, which is this package's signal for
        # exactly that.
        _k = engine.matched_key(kb, _a, identity(lv), _src)
        live_dupes[_k] += 1
        _byfam[_k] = (_a, identity(lv), _src)
    for key, n in live_dupes.items():
        _fa, _fi, _fs = _byfam[key]
        # IT IS A COLLISION ONLY IF THERE ARE FEWER SLOTS THAN WINDOWS, which
        # is the fix rather than the refinement: once an identity can hold a
        # slot PER WINDOW, "N windows share this key" stopped meaning any
        # window loses its place. Measured LIVE on manifold the hour the
        # keyspace change deployed, with four slots stored and all four
        # windows placed:
        #
        #   COLLISION kitty (titan)  4 live windows share this key; 1 gets
        #   the remembered place, 3 stay where they opened
        #
        # Every clause of that was false, and the remedy it named was no
        # longer the thing to do. FIFTH time this report has named a fault
        # that was not happening.
        #
        # AND ZERO SLOTS IS NOT A COLLISION EITHER, which the old `n < 2`
        # also got wrong: with nothing stored NO window gets a remembered
        # place, so there is nothing to contend for, and after one capture
        # there will be a slot each.
        _slots = len(engine.slot_keys(kb, _fa, _fi, _fs))
        if not _slots or n <= _slots:
            continue
        _app, _ident = key.split("\0", 1)
        _csrc = (kb.get(key) or {}).get("source", "")
        _shown = (f"{_app} ({_csrc})" if _csrc
                  else _ident or f"{_app} (by app-id)")
        # "1 keep" read as a typo; phrase it so the count never needs a
        # plural, which is the cheapest fix and reads better at every n.
        _pw = engine.source_per_window_slots(kb, _app, _csrc)
        # THE BLIND TAG IS ONLY FOR A SOURCE-ALONE KEY. With the map
        # published a verb resolves per window, so a collision on a
        # `<source>:<digest>` key is REAL: reporting it as something this
        # report cannot see would send a reader to look for a daemon that is
        # working. Measured on manifold the moment publishing went live.
        if _pw and _ident == _csrc:
            # A DIFFERENT TAG, because COLLISION names a FAULT and invites a
            # reader to act. Reporting one that is not happening is worse
            # than reporting nothing, which is this file's standing rule
            # about a diagnostic that cannot see what it is diagnosing.
            out(f"  NOT RESOLVED HERE {_shown[:40]:40}  {n} live windows"
                f" share this key IN THIS REPORT"
                f" ({collision_fix(_ident, _csrc, _pw)})")
            continue
        # THE SLOT COUNT IS IN THE LINE, because with a slot per window the
        # interesting fact is the SHORTFALL rather than the sharing: "4
        # windows, 1 slot" says what to expect where "4 share this key" no
        # longer does. Phrased so no count ever needs a plural.
        out(f"  COLLISION  {_shown[:40]:40}  {n} live windows and {_slots}"
            f" remembered slot(s), so {_slots} get a remembered place and"
            f" {n - _slots} stay where they opened"
            f" ({collision_fix(_ident, _csrc)})")


def _doctor_placement(out, kb, live, outs):
    """Per live window: does it match a remembered slot, and is that slot's
    output actually attached."""
    out("== live windows -> placement ==")
    pairs, unlive, _ = match(live, list(kb.values()))
    for lv, e in pairs:
        where = f"{e['output']} ws{tuple(e['workspace'])}"
        # A slot deliberately does not encode what the window is SHOWING, so
        # say it here. Without this, `term:resume` on a screen full of mux
        # terminals is unmatchable to the thing a human is looking at.
        shows = ""
        # THROUGH `log_title` TOO, which is not merely tidiness: this parses a
        # LIVE title and prints what it finds, so a foreign mux terminal would
        # have its session and host described here. Redacted, the parse finds
        # no colon and `shows` stays empty, which is the right answer for a
        # window whose content is not ours to narrate. LATENT rather than
        # live: that account's terminals are titled `terminal` today.
        t = engine.log_title(lv)
        if is_mux_term(app_of(lv), t):
            sess, host = mux_session_of(t), mux_host_of(t)
            shows = f"  [showing {sess}@{host or LOCAL_HOST}]" if sess else ""
        # THREE STATES, NOT TWO, and the third was printing as `placeable`: a
        # slot whose OUTPUT is here but whose CELL this desk's grid does not
        # have cannot be placed either, and saying it is placeable sends a
        # reader looking for a fault in the placer. Which of the two refusals
        # it is decides what to do about it, so they are worded apart.
        # A STICKY WINDOW IS PLACED BY MONITOR AND POSITION (sticky_entry),
        # so its cell never decides anything.
        e = engine.sticky_entry(lv, e)
        _o = engine.entry_output(e, outs)
        if _o is None:
            out(f"  UNPLACEABLE {app_of(lv)[:13]:13} {e['title'][:34]:34}"
                f" -> {where} NOT ATTACHED")
        elif not engine.cell_fits(e, {_o["name"]: _o}):
            _ws = _o.get("workspace") or {}
            out(f"  UNPLACEABLE {app_of(lv)[:13]:13} {e['title'][:34]:34}"
                f" -> {where} OFF THIS GRID "
                f"({_ws.get('grid_width')}x{_ws.get('grid_height')})")
        elif engine.refusal_of(lv) is not None:
            # AND A SLOT IS NOT A PLACEMENT IF THE PLACER WILL REFUSE THE
            # WINDOW. `match` does not ask about readiness, so a window usher
            # cannot identify can still pair with a slot here, and this said
            # `placeable` over one `_place_view` declines on the next line it
            # reaches. NO OUTPUTS PASSED, deliberately: that asks the identity
            # half, which is the half that stops a placement. A PARKED window
            # is held out of LEARNING and is still perfectly placeable, so
            # passing them would condemn a row that is fine.
            _t, _w = _unmatched_why(lv)
            out(f"  {_t:10} {app_of(lv)[:14]:14} {e['title'][:34]:34}"
                f" -> {where}{_w}")
        else:
            out(f"  placeable  {app_of(lv)[:14]:14} {e['title'][:34]:34}"
                f" -> {where}{shows}")
    for lv in unlive:
        tag, why = _unmatched_why(lv, outs)
        # THE ONE REPORT LINE THAT RENDERS A LIVE VIEW'S OWN TITLE, so it is
        # the one that needs redacting: every other line here prints a kb
        # entry's key-title, which for another account is already its source
        # name. `engine.log_title` is the same predicate watch.log uses.
        out(f"  {tag:10} {app_of(lv)[:14]:14}"
            f" {engine.log_title(lv)[:34]:34}{why}")


def _unmatched_why(lv, outs=None):
    """(label, reason) for a live window with no slot, in the words of the
    plugin that knows.

    PRINT THE PLUGIN'S OWN REASON, never a per-app explanation held here. A
    report that hardcodes another component's facts cannot keep them current:
    this once answered "incognito and guest windows never are" for every
    unidentified chrome window, including ones Chrome had merely not written
    yet. Same drift PLUGIN_HOOKS exists to kill.

    Saying something at all is the point: a window silently missing from the
    report reads as a fault in usher and is not one."""
    # THROUGH THE WRITERS' OWN LABELLING, so the report cannot name a refusal
    # the store's writers do not make, nor miss one they do. The kinds are
    # FACTS and these words are PRESENTATION, which is why the mapping sits
    # here rather than in the engine: `unjoinable` is the word this package's
    # notes quote verbatim, and renaming it to match an internal kind would
    # falsify every one of them.
    # AND `ambiguous` IS RETIRED, which is this rule enforced against itself.
    # It reported a window whose title another live window wore, because both
    # store writers refused one: the TITLE was the key, so two views wearing
    # it meant one slot and no way to say which window owned it. With the
    # title out of the keyspace the writers INDEX them instead, a slot each,
    # so the label named a refusal nobody makes any more. A report that
    # describes a mechanism the code has retired is worse than one that says
    # nothing, because it answers a question the reader then stops asking.
    r = engine.refusal_of(lv, outs)
    if r is None:
        return "unmatched", ""      # identified fine; no slot yet
    kind, why = r
    # FOUR STATES, FOUR LABELS, and the fourth was printing as `unmatched`: a
    # window parked on a monitor that is away is identified perfectly and is
    # DELIBERATELY not being learned, where `unmatched` means "nothing is
    # remembered yet", which the next capture fixes. Two opposite facts under
    # one word, and the second is the state a docking laptop is in several
    # times a day. Collapsing any two is the overclaim the hardcoded text
    # above was, so the check asserts all four are PAIRWISE DISTINCT rather
    # than each one individually correct.
    label = {"never": "unjoinable",     # no join is possible, ever
             "pending": "pending",      # it will know shortly; ask again
             "parked": "parked"}[kind]  # its monitor is away; correct
    return label, f"  ({why})" if why else ""


def _doctor_blind(out, what, *fix):
    """The banner for "this report cannot see the live session".

    IT HAS TO SHOUT, because the sections it disables are exactly the ones
    that read as findings. With no live windows the relaunch section says
    every saved window needs starting and the browser is not running: every
    line of it false, none of it marked as such, and the report exited 0. That
    happened twice in one afternoon over a NON-INTERACTIVE ssh, which carries
    none of the session environment, and both times it looked like a real
    answer. A diagnostic that cannot see the thing it is diagnosing must say
    so louder than it says anything else."""
    out("")
    out(f"  !!! CANNOT SEE THE LIVE SESSION: {what}")
    for line in fix:
        out(f"  !!! {line}")
    out("  !!! The store and contract checks above STAND. Everything needing")
    out("  !!! live windows is SKIPPED, not answered, with none to look at,")
    out("  !!! those sections would call every saved window missing.")
    out("")


def _doctor_compositor(out):
    """Connect to the live session, or say LOUDLY why not. Returns
    (live, outs, ok), and `ok` is NOT `bool(live)`, because a reachable
    session with no windows open is a real answer and an unreachable one is
    not."""
    out("== compositor ==")
    if WayfireSocket is None:
        _doctor_blind(out, "pywayfire is NOT IMPORTABLE",
                      "Run this from the venv (~/.venvs/usher/bin/python),"
                      " not the system python3.")
        return [], {}, False
    # NOT "is WAYFIRE_SOCKET set?". usher DISCOVERS the socket under
    # XDG_RUNTIME_DIR, so an unset variable is the normal case from a shell
    # and says nothing about reachability; asking it would make doctor report
    # itself blind from exactly the places the discovery serves. WHEN A
    # DIAGNOSTIC'S "I CANNOT SEE" TEST IS A PROXY, FIXING THE REAL CONDITION
    # LEAVES THE PROXY LYING.
    try:
        _sock_path = engine.wayfire_socket()
    except RuntimeError as e:           # several candidates: ambiguous
        _doctor_blind(out, str(e),
                      "Name the one you mean and run again.")
        return [], {}, False
    if not _sock_path:
        _doctor_blind(
            out, "NO COMPOSITOR SOCKET FOUND",
            "Nothing matching wayfire-*.socket under the runtime dir, and",
            "WAYFIRE_SOCKET is unset, so there is nothing to connect to. A",
            "NON-INTERACTIVE ssh carries no XDG_RUNTIME_DIR either, which is",
            "how this is usually met. Pass it:  WAYFIRE_SOCKET=/run/user/"
            "$(id -u)/wayfire-<display>-.socket")
        return [], {}, False
    try:
        sock = engine.ipc()
        live = sock.list_views(filter_mapped_toplevel=True)
        outs = {o["name"]: o for o in sock.list_outputs()}
    except Exception as e:
        _doctor_blind(out, f"the compositor did not answer ({e})",
                      f"{_sock_path} exists but is stale, or no session is",
                      "running on this seat.")
        return [], {}, False
    out(f"  outputs      {', '.join(sorted(outs))}")
    # AN UNCLEAN ENVIRONMENT IS A FINDING, not a detail. usher copes by
    # searching, so nothing breaks, and that is exactly why it needs saying:
    # the next tool to want the variable fails for a reason nobody connects
    # back to this.
    if engine.SOCKET_HUNTED:
        out("  !! WAYFIRE_SOCKET was unset; found the socket by searching "
            f"{engine.SOCKET_HUNTED}")
        out("     a tool that does not search will fail in this shell")
    else:
        out(f"  socket       {engine.wayfire_socket()}  (from the environment)")
    if not live:
        out("  (no windows open: the sections below are answered, not"
            " skipped)")
    return live, outs, True


def do_doctor():
    """The whole report. Returns an exit code, non-zero for either of the two
    things that must not pass silently: a CONTRACT breach (1), which is the
    class of fault that otherwise shows no symptom, or a report that COULD NOT
    LOOK (2): see _doctor_blind."""
    lines = []

    def out(s):
        lines.append(s)

    kb, snap = _doctor_store(out)
    out("== plugins ==")
    for p in plugins():
        hooks = [h for h in PLUGIN_HOOKS
                 if h in getattr(type(p), "__dict__", {})]
        out(f"  {getattr(p, 'name', '?'):10} {', '.join(hooks)}")
    rc = _doctor_contracts(out, snap)
    live, outs, ok = _doctor_compositor(out)
    if ok:
        _doctor_relaunch(out, snap, live)
        _doctor_placement(out, kb, live, outs)
    print("\n".join(lines))
    return rc or (engine.EXIT_OK if ok else engine.EXIT_CANNOT)
