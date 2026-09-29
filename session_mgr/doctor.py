"""`session-mgr doctor`: say out loud what usher is and is not doing.

A pure REPORTER. It reads the store, the plugin registry, the cross-tool
contracts and the live compositor, and says per window what would be
relaunched or placed AND WHY NOT. It changes nothing, and nothing in the
engine calls it -- cli does, and that is the only inbound edge.

It exists because almost every fault this tree has had was SILENT: a scrape
that matched nothing, a purge that deleted what it had just learned, a legacy
store orphaned by a migration that declined to run. None of those showed a
symptom you could name; every one of them is visible here. Run it before
forming any theory about what usher is doing.

The exit code is non-zero ONLY for a CONTRACT breach -- the class of fault
that otherwise shows no symptom at all. A store that looks odd is reported and
exits 0, because "odd" is often correct.
"""
import glob
import json
import os
import re
import time
from collections import Counter

# The engine's names, listed rather than star-imported, so this module's whole
# dependency is one readable block -- the same rule watch.py follows. None of
# these is one of the three globals the engine REBINDS at runtime
# (EXCLUDE_RULES/ERRORS, ANCHOR_RULES/ERRORS, _PLUGINS), so importing by value
# cannot go stale here; the registry is reached through plugins(), which is a
# function.
from .chrome import is_chrome
from .engine import (KB_SCHEMA, LOCAL_HOST, PLUGIN_HOOKS, STATE, TERM_KEY_RE,
                     WayfireSocket, app_of, hwdp_id, is_mux_term, live_keys,
                     load_knowledge, load_snapshot, match, mux_candidates,
                     mux_host_of, mux_session_of, mux_session_set, plugins,
                     profile_id, pview, saved_key, schema_path)

# Every failure this tool has had was SILENT: the store looked healthy, Chrome
# kept restoring itself, and the parts that had stopped working stopped saying
# anything at all. `doctor` is the standing answer to "is it actually doing the
# thing?" -- it reports the store, the cross-tool contracts, and, per window,
# what would happen and WHY. A zero-kitty knowledge base is obvious here.

def _doctor_store(out):
    kb = load_knowledge()
    counts = Counter(k.split("\x00", 1)[0] for k in kb)
    out("== store ==")
    out(f"  state dir    {STATE}")
    src = ("SESSION_PROFILE" if os.environ.get("SESSION_PROFILE")
           else "hwdp" if hwdp_id() else "derived from outputs")
    out(f"  profile      {profile_id()}  ({src})")
    others = sorted(os.path.basename(p)[len("knowledge-"):-len(".json")]
                    for p in glob.glob(os.path.join(STATE, "knowledge-*.json"))
                    if os.path.basename(p)[len("knowledge-"):-len(".json")]
                    != profile_id())
    if others:
        out(f"  other sets   {', '.join(others)}  (remembered separately)")
    try:
        schema = open(schema_path()).read().strip()
    except OSError:
        schema = "(unstamped)"
    out(f"  knowledge    {len(kb)} entr{'y' if len(kb) == 1 else 'ies'}"
        f"  (schema {schema}, current {KB_SCHEMA})")
    for app, n in counts.most_common():
        out(f"                 {app or '(blank app-id)':32} {n}")
    if not counts.get("kitty"):
        out("  NOTE         no kitty entries: terminals are not being"
            " remembered, so they cannot be placed")
    # An un-adopted pre-profile store is invisible otherwise: placement simply
    # goes quiet while the knowledge sits in a file nothing opens.
    legacy = os.path.join(STATE, "knowledge.json")
    if os.path.exists(legacy):
        try:
            with open(legacy) as f:
                n = len(json.load(f))
        except (OSError, ValueError):
            n = "?"
        out(f"  ORPHANED     knowledge.json holds {n} entries and is NOT in"
            " use -- it should have been merged into the profile above")
    snap = load_snapshot()
    if snap is None:
        out("  snapshot     current.json MISSING -- nothing to relaunch from")
    else:
        age = int(time.time()) - snap.get("time", 0)
        out(f"  snapshot     {len(snap.get('windows', []))} window(s),"
            f" {age}s old")
    return kb, snap


def _doctor_contracts(out):
    """The cross-tool assumptions. These are the ones that break in SILENCE,
    because they live in another repo's output format."""
    rc = 0
    out("== contracts ==")
    mux = os.path.expanduser("~/.local/bin/mux")
    if not os.path.exists(mux):
        out(f"  [WARN] mux absent ({mux}); terminal relaunch degrades to a"
            " no-op")
        return rc
    out(f"  [OK]   mux present ({mux})")
    # Terminals inherit THIS process's environment, so a missing agent here is
    # a missing agent in every session usher respawns -- and a remote one then
    # cannot authenticate. mux latch copes (it polls for a credential rather
    # than failing), but only if it can see an agent socket at all.
    sock = os.environ.get("SSH_AUTH_SOCK")
    if not sock:
        out("  [WARN] no SSH_AUTH_SOCK: a respawned REMOTE session has no way"
            " to authenticate")
    elif not os.path.exists(sock):
        out(f"  [WARN] SSH_AUTH_SOCK points at a missing socket ({sock})")
    else:
        out("  [OK]   ssh agent socket present")
    names = mux_session_set()
    bad = [s for s in names if not re.fullmatch(r"[^\s:]+", s)]
    if bad:
        out(f"  [FAIL] `mux resume --list` is not bare names: {bad[:3]}")
        out("         relaunch will match NOTHING (this exact break has"
            " happened before)")
        rc = 1
    else:
        out(f"  [OK]   `mux resume --list` -> {len(names)} bare name(s)")
    return rc


def _doctor_relaunch(out, snap, live):
    """Per saved window: would it come back, and if not, why not."""
    out("== saved windows -> relaunch ==")
    if snap is None:
        return
    saved = snap.get("windows", [])
    lk = live_keys(live)
    chrome_up = any(is_chrome(pview(v)["app"]) for v in live)
    chrome_note = ("Chrome restores its own" if chrome_up
                   else "browser NOT running: usher starts it, Chrome"
                        " restores its own")
    # Terminals are reported per COMMAND, because that is how they are
    # relaunched: counted, not matched per session. Reporting them per session
    # would describe a mechanism usher no longer uses.
    todo = Counter(c for c, _ in mux_candidates(saved, live))
    for c, n in todo.items():
        out(f"  RELAUNCH   {n} terminal(s)  {c}")
    n_term = sum(1 for w in saved if w.get("app_id") == "kitty"
                 and TERM_KEY_RE.match(saved_key(w)))
    if n_term and not todo:
        out(f"  live       all {n_term} terminal(s) already up")
    for w in saved:
        app, key = w.get("app_id", ""), saved_key(w)
        if is_chrome(app):
            out(f"  {'self' if chrome_up else 'START':10} {app:14}"
                f" {key[:36]:36}  ({chrome_note})")
            continue
        if TERM_KEY_RE.match(key):
            continue        # covered by the per-command lines above
        if key.startswith("kitty:"):
            cwd = key[len("kitty:"):]
            if key in lk:
                out(f"  live       {key[:56]}")
            elif not os.path.isdir(cwd):
                out(f"  skip       {key[:44]}  (directory is gone)")
            else:
                out(f"  RELAUNCH   {key[:44]}  (kitty --directory {cwd})")
            continue
        out(f"  none       {app:14} {key[:44]}  (no plugin respawns this)")
    # Two kitty windows in one directory share a key, so only ONE slot is
    # remembered and the other silently loses its place. Keying on the running
    # program instead would be worse -- the key would change every time a
    # command started or exited -- so the limitation stands, but it should at
    # least be VISIBLE, with the escape hatch named.
    dupes = Counter(saved_key(w) for w in saved
                    if w.get("app_id") == "kitty")
    for key, n in dupes.items():
        if n > 1 and key.startswith("kitty:"):
            out(f"  COLLISION  {key[:44]}  {n} windows share this key; one"
                " slot is remembered (name one: settitle)")


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
        t = lv.get("title") or ""
        if is_mux_term(app_of(lv), t):
            sess, host = mux_session_of(t), mux_host_of(t)
            shows = f"  [showing {sess}@{host or LOCAL_HOST}]" if sess else ""
        if e["output"] in outs:
            out(f"  placeable  {app_of(lv)[:14]:14} {e['title'][:34]:34}"
                f" -> {where}{shows}")
        else:
            out(f"  UNPLACEABLE {app_of(lv)[:13]:13} {e['title'][:34]:34}"
                f" -> {where} NOT ATTACHED")
    for lv in unlive:
        out(f"  unmatched  {app_of(lv)[:14]:14} {lv.get('title','')[:34]}")


def do_doctor():
    """The whole report. Returns an exit code: non-zero only for a CONTRACT
    breach, which is the class of fault that otherwise shows no symptom."""
    lines = []

    def out(s):
        lines.append(s)

    kb, snap = _doctor_store(out)
    out("== plugins ==")
    for p in plugins():
        hooks = [h for h in PLUGIN_HOOKS
                 if h in getattr(type(p), "__dict__", {})]
        out(f"  {getattr(p, 'name', '?'):10} {', '.join(hooks)}")
    rc = _doctor_contracts(out)
    live, outs = [], {}
    out("== compositor ==")
    if WayfireSocket is None:
        # The import is guarded so this module runs anywhere; say which of the
        # two "no compositor" cases this is, since the fixes differ entirely.
        out("  pywayfire NOT IMPORTABLE -- run this from the venv"
            " (~/.venvs/usher/bin/python), not the system python3")
    else:
        try:
            sock = WayfireSocket()
            live = sock.list_views(filter_mapped_toplevel=True)
            outs = {o["name"]: o for o in sock.list_outputs()}
            out(f"  outputs      {', '.join(sorted(outs))}")
        except Exception as e:
            out(f"  NOT REACHABLE ({e}) -- set WAYFIRE_SOCKET, or there is"
                " no session")
    if not live:
        out("  (live checks below are skipped; store checks above stand)")
    _doctor_relaunch(out, snap, live)
    if live:
        _doctor_placement(out, kb, live, outs)
    print("\n".join(lines))
    return rc
