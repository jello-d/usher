"""The engine: the store, window identity, the plugins, and the verbs.

Everything usher knows how to DO, minus the daemon that does it
continuously (see usher.watch) and the verb dispatch that invokes it
(see usher.cli). Nothing here imports either of those.

Store ($XDG_STATE_HOME/usher, default ~/.local/state/usher):
  current.json             the latest snapshot
  history/<epoch>.json     rolling recent snapshots (match hints)
  milestones/<date>.json   first snapshot of each day (a stable "yesterday")

Identity for matching is (app_id, key), where key = identity(view). Unique-
app_id windows (slack, --app Gmail) key by app_id alone, title-independent.
App-SPECIFIC identity + respawn live in PLUGINS (see WindowPlugin): chrome, mux
and kitty ship built in, users add more in ~/.config/usher/plugins/. THE
VOLATILE TITLE IS NEVER THE KEY, and neither is whatever the window currently
shows: chrome keys by the SessionID of the window (from its own session file,
stable across a restart), mux by the COMMAND the terminal runs (`term:resume`,
or `term:latch <host>:<session>`, which is also how it is brought back), kitty
by the shell's CWD from /proc (`kitty:<cwd>`, respawned as a shell there). See
WindowPlugin, plugins(), identity() and learn().
"""
import contextlib
import fnmatch
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import date

# Chrome's own knowledge lives in usher.chrome, which imports NOTHING
# from here (it is a leaf), so this can be a plain module-level import with
# no cycle. Imported by name rather than qualified because chrome rebinds no
# global of its own (its one cache is mutated in place, never reassigned), so
# there is nothing here that can go stale. The engine's users of it are
# ChromePlugin, chrome_profiles_for, and the selftest fixtures.
from .chrome import (CHROME_FLAGS, CHROME_STAGGER, browser_pids,
                     chrome_bind_windows, chrome_profile_map, chrome_slot,
                     chrome_window_for, chrome_window_tabs, is_chrome,
                     is_chrome_slot, recorded_window_ids, session_history,
                     window_slot)

# usher.toplevels is the other leaf, and is imported QUALIFIED rather than by
# name so a test can stub `toplevels.list_toplevels` and have the engine see
# it: a name imported here would be a snapshot, which is the stale-copy hazard
# the package split already records for EXCLUDE_ERRORS and _PLUGINS.
from . import toplevels

# pywayfire is needed only to talk to the live compositor, and is guarded so the
# module still imports (and `usher selftest` runs) without it.
try:
    from wayfire import WayfireSocket
    from wayfire.extra.wpe import WPE
except ImportError:
    WayfireSocket = WPE = None

# The work/personal boundary: this daemon runs as the personal account, so it
# must not record or move work-enclave windows. mux stamps work terminals with
# a "[WORK: <label>]" title banner; anything matching this is ignored end to
# end (never captured, never placed). Override with USHER_SKIP_TITLE.
SKIP_TITLE = re.compile(os.environ.get("USHER_SKIP_TITLE", r"^\[WORK"))


# THE EXIT CONTRACT, declared in one place because it is a contract: scripts
# and the power menu branch on it. The whole set, so a reader does not have to
# infer it from literals scattered over three modules, and so the check that
# polices it can DERIVE the allowed codes from here rather than carry a
# second hand-written copy that goes stale.
#
# THE SPLIT THAT MATTERS is between 1 and 2, and it is not "error" versus
# "worse error": 1 means usher DID what you asked and the answer is bad, 2
# means it could not do it at all. `doctor` exiting 2 (it cannot see the
# session) must not read like `doctor` exiting 1 (it saw a contract breach),
# because the first says nothing about the system and the second says
# something specific. `verify` with no prediction file and an unknown verb are
# the same shape: nothing was assessed.
EXIT_OK = 0        # did what you asked, and it was fine
EXIT_FAIL = 1      # did what you asked; the answer is bad
EXIT_CANNOT = 2    # could not do it at all: no such verb, no prediction,
#                    no visible session. Nothing was assessed.


# This box's short hostname, matching tmux's #{host_short} (and `hostname -s`).
# It is what tells a LOCAL mux session from one reached over ssh: mux stamps the
# tmux SERVER's host into the terminal title, so the tag naming another box is
# the durable "this session lives on a different machine" signal. See
# mux_host_of.
LOCAL_HOST = os.uname().nodename.split(".")[0]


# --- never-place rules: transient windows session must ignore ---------------
# usher/exclude is the user-grown repository of windows that must open
# wherever you are, never be captured or placed: a blank New Tab, the Chrome
# profile picker, and so on. The old hardcoded Chrome list now ships as the
# file's default content. See the file's header for the format.
# ONE definition of where usher's user config lives. It was built inline three
# times and a fourth was about to be added; the same fact in four places is the
# thing this tree's single-source rule exists to stop.
_XDG_CONFIG = os.environ.get("XDG_CONFIG_HOME",
                             os.path.expanduser("~/.config"))
CONFIG_DIR = os.path.join(_XDG_CONFIG, "usher")


def config_path(name):
    """Where `name` lives. One directory, no fallback.

    This carried a per-file fallback to the pre-rename ~/.config/session for one
    release, so the two repos could cut over independently. Both machines are
    migrated and the old directory is gone from each, so the fallback is dead
    weight that would only ever resurrect a stale file someone restored by
    accident.
    """
    return os.path.join(CONFIG_DIR, name)


EXCLUDE_FILE = os.environ.get(
    "USHER_EXCLUDE_FILE", config_path("exclude"))


def load_exclude_rules(path=EXCLUDE_FILE):
    """Parse usher/exclude into compiled (app_re, title_re) pairs. Every rule
    is one line, '<app-regex> :: <title-regex>': both fields required, use
    '.*' for "any". A line starting with # is a comment, blanks ignored.
    Patterns are Python regexes matched with re.search, so they are UNANCHORED
    (a substring test): add ^...$ to pin, exactly as the work boundary's own
    ^\\[WORK does. Returns (rules, errors): a line missing '::' or with a bad
    regex is collected into errors: surfaced by `usher exclude`,
    logged by the watcher, and skipped, never crashing the headless
    daemon. A missing
    or unreadable file yields ([], []); the built-in work-boundary and
    scratch-terminal skips still apply. Read once per process, so an edit is
    picked up by the next worker respawn or a re-run of usher-mgr watch."""
    rules, errors = [], []
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return rules, errors
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "::" not in line:
            errors.append((n, line, "missing '::' (use '<app> :: <title>')"))
            continue
        app, title = (s.strip() for s in line.split("::", 1))
        try:
            rules.append((re.compile(app or ".*"), re.compile(title or ".*")))
        except re.error as e:
            errors.append((n, line, f"bad regex: {e}"))
    return rules, errors


EXCLUDE_RULES, EXCLUDE_ERRORS = load_exclude_rules()


def is_transient(v):
    """True if the window must open wherever the user is: never captured (a
    stored "New Tab" would drag every future new tab to one spot), never placed.
    Takes a view/window/entry dict. Two sources: a usher/exclude config rule
    (blank New Tab, profile picker, a pre-load "Google Chrome" title: config-
    driven, grows without a code change).

    POLICY ONLY. READINESS BELONGS TO Resolution, and conflating the two is a
    bug this has had before: "the user does not want this window remembered"
    is a different fact from "usher cannot identify this window", and they
    produce the same boolean."""
    v = pview(v)
    app, t = v["app"], v["title"].strip()
    return any(ar.search(app) and tr.search(t) for ar, tr in EXCLUDE_RULES)


def reload_exclude():
    """Re-read usher/exclude into the module globals, live: the watch loop
    calls this when the file's mtime changes, so an edit applies on save with no
    reload. is_transient reads EXCLUDE_RULES on each call, so the swap is picked
    up immediately (the GIL makes the rebinding atomic across the threads)."""
    global EXCLUDE_RULES, EXCLUDE_ERRORS
    EXCLUDE_RULES, EXCLUDE_ERRORS = load_exclude_rules()
    logline(f"exclude reloaded: {len(EXCLUDE_RULES)} rule(s),"
            f" {len(EXCLUDE_ERRORS)} error(s)")
    for _n, _text, _msg in EXCLUDE_ERRORS:
        logline(f"exclude rule error (line {_n}): {_msg}: {_text!r}")


# --- anchor (include) rules: the OPT-IN set placed in SETTLED state -----------
# usher/include mirrors usher/exclude's '<app-regex> :: <title-regex>'
# format. It is the settled-state whitelist: once the place start window
# ages out, ONLY windows matching an anchor rule are (re)placed; everything else
# opens where you are and stays (default follow-me: an empty/absent file
# anchors nothing). Exclude still wins: a window matching both is never placed.
INCLUDE_FILE = os.environ.get(
    "USHER_INCLUDE_FILE", config_path("include"))

ANCHOR_RULES, ANCHOR_ERRORS = load_exclude_rules(INCLUDE_FILE)


def is_anchored(app, title):
    """True if the window matches a usher/include rule: the opt-in set that
    is STILL placed in the conservative settled state."""
    t = title.strip()
    return any(ar.search(app) and tr.search(t) for ar, tr in ANCHOR_RULES)


def reload_anchor():
    """Re-read usher/include live, exactly as reload_exclude does its file."""
    global ANCHOR_RULES, ANCHOR_ERRORS
    ANCHOR_RULES, ANCHOR_ERRORS = load_exclude_rules(INCLUDE_FILE)
    logline(f"anchor reloaded: {len(ANCHOR_RULES)} rule(s),"
            f" {len(ANCHOR_ERRORS)} error(s)")
    for _n, _text, _msg in ANCHOR_ERRORS:
        logline(f"anchor rule error (line {_n}): {_msg}: {_text!r}")


def is_mux_term(app, title):
    """A named mux terminal: kitty whose title is 'session:window' (a mux
    session attached). NOT a plain 'terminal', a scratch 'ksh:', or a work
    window. These are the only terminals session tracks, places and
    relaunches, and the ones a single window cycles through as it switches
    sessions."""
    return (app == "kitty" and ":" in title
            and not SKIP_TITLE.search(title))


STATE = os.path.join(
    os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
    "usher")
# Marker a worker drops once it has actually RUN launch_missing, so the launch
# survives the first worker dying to the compositor-startup race: the supervisor
# keeps launch on until this exists, not just for the first-spawned worker.
LAUNCHED = os.path.join(STATE, ".launched")
HISTORY_KEEP = 20      # recent snapshots retained under history/
MILESTONE_DAYS = 14    # daily milestones retained under milestones/


# --- display PROFILE: one remembered layout per monitor set -----------------
# A placement only means anything on the monitors it was learned on. With ONE
# flat store, docking and undocking overwrite each other's layout, and a window
# whose output is absent is simply unplaceable, which reads as "usher does
# nothing" rather than "that layout belongs to your other desk". So the
# knowledge base is keyed by the CONNECTED SET.
#
# hwdp owns display identity on these boxes (`hwdp id` is EDID-derived), so it
# is the preferred source and the two agree by construction. It is a SOFT
# dependency, like mux: without it the id is derived from the outputs the last
# snapshot saw, and failing that everything lands in one "default" profile,
# which is exactly the old behaviour.
PROFILE_TTL = 5.0             # seconds; a display change settles well inside it
_PROFILE = {"id": None, "at": 0.0}


def hwdp_id():
    exe = shutil.which("hwdp")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "id"], capture_output=True, text=True,
                             timeout=3)
    except Exception:
        return None
    return out.stdout.strip() or None


# The connector -> panel map, cached like the profile for the same reason: it
# is consulted on every placement and costs a subprocess. Invalidated outright
# on a display change, which is the one moment it is certainly wrong.
PANEL_TTL = 5.0
_PANELS = {"map": None, "at": 0.0}


def panel_map(fresh=False):
    """{connector: panel-id} from `hwdp id --panels`, empty when it cannot be
    asked.

    A SLOT NAMES A MONITOR, NOT A CABLE. usher stores the output a window was
    learned on, and in a docking setup the connector name is the least stable
    thing there is: which port, which MST hub, what order the hub enumerated.
    Measured in a nested compositor, a re-created output came back as WL-3
    having been WL-2, so every slot stored for the old name was unreachable
    while the monitor was sitting right there.

    SOFT, exactly like hwdp_id: with no hwdp the map is empty and every slot
    falls back to matching on the connector name, which is the behaviour this
    had before. An empty map must therefore never be read as "no panel
    matches", only as "we cannot tell", which is what entry_output does."""
    now = time.time()
    if not fresh and _PANELS["map"] is not None \
            and now - _PANELS["at"] < PANEL_TTL:
        return _PANELS["map"]
    out = {}
    exe = shutil.which("hwdp")
    if exe:
        try:
            r = subprocess.run([exe, "id", "--panels"], capture_output=True,
                               text=True, timeout=3)
            for ln in r.stdout.splitlines():
                parts = ln.split()
                if len(parts) == 2:
                    out[parts[0]] = parts[1]
        except Exception:
            out = {}
    _PANELS["map"], _PANELS["at"] = out, now
    return out


# The desk's surface map, cached like the panel map and for the same reason.
SURFACE_TTL = 5.0
_SURFACES = {"map": None, "why": "", "at": 0.0}


def surface_map(fresh=False):
    """({surface: slot}, why) from `hwdp surfaces`, where a slot is the same
    shape a store entry uses: output, workspace, pos, size.

    A SURFACE IS A NAME FOR A PART OF A PANEL AT THIS DESK, authored per
    display profile in hwdp. hwdp resolves the rect, so usher never sees a
    fraction and the scale model stays where only hwdp can compute it: a
    4K portrait at scale 1 is logically 2160x3840 and at 1.25 it is 1728x3072,
    so the same "bottom half" is a different rect on the same hardware.

    THE RECT NEEDS NO CONVERSION. hwdp reports it output-local and usher's
    `pos` is cell-local, and those coincide because in wayfire every workspace
    is exactly the output's size. Verified by round-tripping a real row
    through target_geometry and place_of: identical.

    `why` IS EMPTY WHEN THE ANSWER IS TRUSTWORTHY, including when it is
    legitimately empty because this desk has no map authored. It is a sentence
    only when we could not ask, because those are different facts and a report
    that showed an empty map for both would be this project's oldest recurring
    bug. hwdp separates them by STATUS on purpose:

        rc 0   answered; no file is also 0, with nothing printed
        rc 2   the file is BROKEN, and stdout is empty by design
        rc 3   no session, so it cannot know what is switched on

    SO ANY NON-ZERO IS "NO MAP", never a partial one. hwdp refuses a broken
    file whole rather than emitting the good lines, for the reason usher's own
    pick_socket refuses two sockets: a half-right map seeds windows into the
    wrong places silently, which is worse than no map at all."""
    now = time.time()
    if not fresh and _SURFACES["map"] is not None \
            and now - _SURFACES["at"] < SURFACE_TTL:
        return _SURFACES["map"], _SURFACES["why"]
    out, why = {}, ""
    exe = shutil.which("hwdp")
    if not exe:
        why = "no hwdp on PATH, so this desk has no surface map"
    else:
        try:
            r = subprocess.run([exe, "surfaces"], capture_output=True,
                               text=True, timeout=5)
            if r.returncode:
                why = (f"`hwdp surfaces` exited {r.returncode}: "
                       + (r.stderr.strip().splitlines() or ["no detail"])[0])
            else:
                out, why = _parse_surfaces(r.stdout)
        except Exception as e:
            why = f"could not run `hwdp surfaces`: {e}"
    # THE INVARIANT A CONSUMER RELIES ON: a `why` always comes with an EMPTY
    # map, so one test for "usable" is enough downstream and nobody has to
    # check both. Asserted by a check, since duplicating the guard in every
    # caller is how two of them come to disagree.
    if why:
        out = {}
    _SURFACES.update({"map": out, "why": why, "at": now})
    return out, why


def _parse_surfaces(text):
    """({surface: slot}, why) for one `hwdp surfaces` stdout.

    REFUSED WHOLE ON A BAD LINE, matching what hwdp does with a bad FILE. A
    map we have half parsed is the same hazard as one hwdp half validated, and
    the two sides disagreeing about which half to trust is worse than either."""
    out = {}
    for n, ln in enumerate(text.splitlines(), 1):
        if not ln.strip():
            continue
        f = ln.split()
        if len(f) != 8:
            return {}, (f"`hwdp surfaces` line {n} has {len(f)} fields, "
                        "expected 8; ignoring the whole map")
        try:
            nums = [int(float(x)) for x in f[2:]]
        except ValueError:
            return {}, (f"`hwdp surfaces` line {n} has a non-numeric field; "
                        "ignoring the whole map")
        out[f[0]] = {"output": f[1], "workspace": nums[0:2],
                     "pos": nums[2:4], "size": nums[4:6]}
    return out, ""


def surface_cell_fits(slot, outputs):
    """Is a surface's workspace cell inside the live grid of its output?

    hwdp passes the cell through WITHOUT checking it, deliberately: the grid
    size is the integrator's (tackup's shapes/<shape>/), not hwdp's. Measured
    on a 3x3 desk, `cell 5 9` resolves and prints at status 0.

    USHER IS THE ONLY ONE THAT CAN CHECK IT, which is why it does. hwdp knows
    the shape but not the grid, the integrator knows the grid but not the
    surface file, and usher reads the LIVE grid straight off the compositor.
    That is the same division as everything else here: a consumer reads
    geometry, grid included, from the compositor, and asks hwdp only for what
    the compositor cannot know.

    AND IT MATTERS RATHER THAN BEING TIDY: seeding a window into a cell the
    grid does not have puts it where no workspace navigation can reach it,
    which is a shape this project has already met twice from other causes."""
    o = outputs.get(slot.get("output"))
    if not o:
        return False
    ws = o.get("workspace") or {}
    gw = int(ws.get("grid_width") or 0)
    gh = int(ws.get("grid_height") or 0)
    if gw <= 0 or gh <= 0:
        return True     # no grid reported: conclude nothing, as ever
    x, y = slot.get("workspace", [0, 0])
    return 0 <= int(x) < gw and 0 <= int(y) < gh


def surface_of(w, surfaces):
    """The surface name whose rect CONTAINS window w's placement, or "".

    Recorded on a learned entry so the slot carries its logical address as
    well as its pixels. That name is the only thing that can carry meaning
    from one desk to another, because a cell coordinate cannot: (2,2) does not
    exist in a 2x2 grid, and a 1920x1080 rect means nothing on a portrait
    panel. The rect stays per-profile and learned; the name is what travels.

    BY CENTRE, NOT BY CORNER OR BY CONTAINMENT. A window is rarely flush with
    a surface and may overhang it, so "which half is it in" is the question
    rather than "is it inside". With halves that is unambiguous, and it is the
    cheapest rule that cannot report nothing for a window plainly in one.

    THE FIRST CONTAINING MATCH WINS, AND THERE CAN ONLY BE ONE. hwdp refuses a
    file whose surfaces overlap inside one panel and cell, verified against the
    real verb (a `full` and a `top` in one cell exits 2, naming the pair), so
    no centre can fall in two. A size tie-break was written here first and
    removed: the planted regression inverting it was UNCATCHABLE, which is how
    code that can never change an outcome announces itself."""
    if not surfaces:
        return ""
    pos = w.get("pos") or [0, 0]
    size = w.get("size") or [0, 0]
    cx = pos[0] + size[0] / 2.0
    cy = pos[1] + size[1] / 2.0
    cell = [int(n) for n in (w.get("workspace") or [0, 0])]
    for name, s in sorted(surfaces.items()):
        if s["output"] != w.get("output"):
            continue
        if [int(n) for n in s["workspace"]] != cell:
            continue
        sx, sy = s["pos"]
        sw, sh = s["size"]
        if sx <= cx < sx + sw and sy <= cy < sy + sh:
            return name
    return ""


def source_ident(source, ident):
    """The per-window identity `ident` names, if it belongs to `source`. PURE.

    A per-window key is `<source>:<identity>`, so the source name is a
    PREFIX of it and not a coincidence. ONE DEFINITION, read by both
    `match_keys` and `entry_matches`, because an arbitrary identity reaching
    either of them becomes a key that is not this account's: the first cut
    of this gate tested only `ident != source` and so offered `slack\0ident`
    to a titan window, which the pre-existing
    `match-keys-foreign-gets-only-its-source` check caught at once.
    """
    return ident if ident and ident.startswith(source + ":") else ""


def match_keys(app, ident, source="", ident_first=False):
    """The store keys a window may match, most specific first.

    ONE DEFINITION, because FIVE places ask this question and a disagreement
    between any two of them is how every silent failure in this package has
    started.

    A WINDOW FROM ANOTHER ACCOUNT MATCHES EXACTLY ONE KEY, ITS OWN SOURCE'S.
    The app_id-only key means "every window of this app whatever its
    identity", which is true only WITHIN one account: offering it to another
    account's window would place a work Slack onto the owner's Slack slot, and
    the owner's onto the work one. `kkey(app, "")` is the OWNER's by
    construction, so a foreign window must never be offered it.

    `ident_first` PRESERVES A PRE-EXISTING DIFFERENCE rather than quietly
    changing it: the placer has always tried the app_id-only key first and
    `other_profile_entries` has always tried the identity first. That
    disagreement is latent (it shows only where BOTH keys exist for one app)
    and worth unifying on its own, not inside this change."""
    if source:
        # MOST SPECIFIC FIRST, the same rule as the owner's own pair: a
        # per-window key when that account could say which window this is,
        # and the source-alone key as the fallback. The fallback is what
        # every entry carried before per-window identities existed and what
        # a window with no per-window handle still uses, so keeping it is
        # what makes this additive rather than a migration.
        if source_ident(source, ident):
            return (kkey(app, ident), kkey(app, source))
        return (kkey(app, source),)
    return ((kkey(app, ident), kkey(app, "")) if ident_first
            else (kkey(app, ""), kkey(app, ident)))


def entry_matches(e, app, ident, source=""):
    """Does stored entry `e` describe this window? The SCAN form of
    match_keys, for the matcher, which walks entries rather than keys.

    Same rule and the same reason: `appid_only` means "every window of this
    app", so an owner's app_id-only entry must not claim another account's
    window. A foreign window matches only an entry stored under its source."""
    if e.get("app_id") != app:
        return False
    if source:
        if e.get("source") != source:
            return False
        # AND A PER-WINDOW ENTRY CLAIMS ONLY ITS OWN WINDOW, exactly as an
        # owner's per-title entry does. An entry stored under the source
        # ALONE is that account's app_id-only key and claims any of its
        # windows, which is what the shape meant before this.
        et = e.get("title") or ""
        return et == source or (bool(source_ident(source, ident))
                                and et == ident)
    return bool(e.get("appid_only")) or e.get("title") == ident


def other_profile_entries(app, ident, profile=None, source=""):
    """This identity's learned entries from every OTHER display profile,
    newest first. Reads the stores directly, since the point is the desks that
    are not attached."""
    profile = profile or profile_id()
    keys = match_keys(app, ident, source, ident_first=True)
    found = []
    for path in glob.glob(os.path.join(STATE, "knowledge-*.json")):
        name = os.path.basename(path)[len("knowledge-"):-len(".json")]
        if name == profile:
            continue
        try:
            with open(path) as f:
                kb = json.load(f)
        except (OSError, ValueError):
            continue
        for k in keys:
            e = kb.get(k)
            if e:
                found.append(e)
                break
    found.sort(key=lambda e: e.get("last_seen", 0), reverse=True)
    return found


def surface_seed(others, surfaces):
    """A starting slot for a window this desk has never learned, from the
    SURFACE it occupies on another desk. None when nothing can be derived.

    THE NAME IS THE BRIDGE BETWEEN DESKS and the only thing that can be. A
    cell coordinate cannot travel, because (2,2) does not exist in a 2x2 grid;
    a rect cannot travel, because 1920x1080 means nothing on a portrait panel.
    A name resolves to a different panel and a different rect at every desk,
    which is the whole reason surfaces are named.

    A SEED, NEVER A PROJECTION. It answers only where a profile has NO learned
    slot; the moment the window is placed, the capture loop learns its real
    geometry and that learned slot wins from then on, permanently. So this
    cannot overrule "Slack on the laptop panel at home, on the portrait at the
    office", which is the per-desk divergence the whole per-profile store
    exists for.

    AND IT MAY BE APPROXIMATE AT NO COST, which is what makes guessing
    allowed here where this project normally refuses to. A wrong KEY corrupts
    the store silently and invisibly; a wrong PLACEMENT is visible at once and
    self-corrects on the first nudge. Different risk class, different rule.

    POSITION FROM THE SURFACE, SIZE FROM THE WINDOW, clamped. Filling the
    surface would throw away what the window was: a narrow chat window pinned
    in `comms` on the laptop should arrive narrow, not stretched across a 4K
    half. Clamping is what stops a 1800-tall window overflowing a 1080-tall
    half."""
    for e in others:
        name = e.get("surface") or ""
        s = surfaces.get(name)
        if not s:
            continue
        w = min(int(e.get("size", [0, 0])[0]) or s["size"][0], s["size"][0])
        h = min(int(e.get("size", [0, 0])[1]) or s["size"][1], s["size"][1])
        seed = dict(e)
        seed.update({"output": s["output"], "workspace": list(s["workspace"]),
                     "pos": list(s["pos"]), "size": [w, h],
                     "panel": "", "seeded_from": name})
        return seed
    return None


def entry_output(e, outputs, panels=None):
    """The live output entry `e` should be placed on, or None.

    THE PANEL WINS OVER THE NAME, because the panel is what the slot means.
    An entry learned on the monitor now called DP-3 is still that monitor's
    entry, and placing it by name would put it on whatever happens to be
    plugged into DP-2 instead.

    FALLS BACK TO THE NAME in every uncertain case, which is the behaviour
    before panels were known and is the fail-safe direction: an entry with no
    panel recorded (learned before this existed), no hwdp to ask, or a panel
    that is genuinely not attached all end up asking the question usher used
    to ask. None means "not attached", which callers report rather than
    guessing around.

    TWO IDENTICAL PANELS SHARE A PANEL ID, so the first match wins and which
    one that is comes down to probe order. Nothing here can do better: a model
    with no serial number is anonymous in its EDID, so the two monitors are
    indistinguishable to every layer below this one.
    """
    if not e:
        return None
    pan = e.get("panel")
    if pan:
        pmap = panel_map() if panels is None else panels
        for name, pid in pmap.items():
            if pid == pan and name in outputs:
                return outputs[name]
    return outputs.get(e.get("output"))


def _derived_id(snap):
    """A stable id for the monitor set the last snapshot saw. Hashed rather
    than spelled out because it becomes a filename and an output list is
    neither short nor guaranteed filename-safe. Geometry is included, so the
    same cables at a different resolution are a different profile."""
    outs = (snap or {}).get("outputs") or []
    if not outs:
        return None
    parts = sorted(f"{o.get('name')}@{(o.get('geometry') or {}).get('width')}"
                   f"x{(o.get('geometry') or {}).get('height')}" for o in outs)
    return hashlib.sha256("+".join(parts).encode()).hexdigest()[:12]


def _safe_profile(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:64] or "default"


def profile_id(fresh=False):
    """The current display profile. Cached briefly: this is consulted on every
    knowledge load, and the capture loop runs often. The window in which a
    just-changed display can still resolve to the OLD profile is bounded by
    PROFILE_TTL, and the cost of losing it is a handful of entries written to
    the wrong profile, which the next capture in the right one supersedes.

    `fresh` bypasses the cache, for the one caller that must not be told the
    old answer: the display-change handler, which runs within a second of the
    change and decides whether anything happened at all."""
    env = os.environ.get("USHER_PROFILE")
    if env:
        return _safe_profile(env)
    now = time.time()
    if not fresh and _PROFILE["id"] and now - _PROFILE["at"] < PROFILE_TTL:
        return _PROFILE["id"]
    pid = hwdp_id() or _derived_id(load_snapshot()) or "default"
    _PROFILE["id"], _PROFILE["at"] = _safe_profile(pid), now
    return _PROFILE["id"]


def kb_path(profile=None):
    return os.path.join(STATE, f"knowledge-{profile or profile_id()}.json")


def schema_path(profile=None):
    """Per PROFILE, not global: a schema bump has to be applied to each store
    separately, and a single global stamp would mark them all migrated the
    first time any one of them was."""
    return os.path.join(STATE, f"knowledge-{profile or profile_id()}.schema")


def adopt_legacy_store():
    """Fold a pre-profile knowledge.json into the CURRENT profile, once.

    IT MERGES RATHER THAN ADOPTING ONLY INTO AN EMPTY PROFILE, which is the
    whole point: if anything creates a profile store first (a seed from a
    snapshot, a run before the displays came up) an adopt-if-absent rule skips
    FOREVER and orphans the legacy store in silence. The symptom is windows
    simply staying where they open, which reads as usher having stopped.

    Entries already in the profile WIN: they were learned on these monitors,
    the legacy ones were learned across whatever was attached at the time. So
    the legacy store only fills gaps. The file is RETIRED rather than deleted,
    both so this runs once and so a bad merge is recoverable."""
    legacy = os.path.join(STATE, "knowledge.json")
    if not os.path.exists(legacy):
        return
    try:
        with open(legacy) as f:
            old = json.load(f)
    except (OSError, ValueError) as e:
        logline(f"legacy store unreadable, leaving it alone: {e}")
        return
    try:
        with open(kb_path()) as f:
            cur = json.load(f)
    except (OSError, ValueError):
        cur = {}
    added = 0
    for k, v in old.items():
        if k not in cur:
            cur[k] = v
            added += 1
    try:
        os.makedirs(STATE, exist_ok=True)
        write_json(kb_path(), json.dumps(cur, indent=2))
        # Stamp it: the merged result is in TODAY's key scheme as far as we can
        # tell, and an unstamped store is one load away from having its chrome
        # and kitty entries dropped as stale, which would undo the merge.
        # Legacy keys in an older scheme simply never match and age out by TTL.
        write_json(schema_path(), KB_SCHEMA)
        os.replace(legacy, legacy + ".pre-profile")
        sch = os.path.join(STATE, "knowledge.schema")
        if os.path.exists(sch):
            os.replace(sch, sch + ".pre-profile")
        logline(f"adopted the pre-profile store into profile {profile_id()}: "
                f"{added} entr{'y' if added == 1 else 'ies'} merged, "
                f"{len(cur)} total")
    except OSError as e:
        logline(f"could not adopt the legacy store: {e}")

# Colour-invert is a SEPARATE mechanism (toggle_invert_focused, Super+N): a
# per-view filters shader whose live state lives in its own store, keyed by the
# ephemeral wayfire view id. session bridges it across a restart: it reads that
# store at capture and records an `inverted` flag against each window's DURABLE
# identity, then re-applies the shader when it restores the window, and writes
# the view's new id back to the store, so the two mechanisms share one registry
# and a later Super+N un-inverts on the first press. The path is hardcoded to
# match the toggle script (which does not honour XDG_STATE_HOME).
INVERT_STORE = os.path.expanduser(
    "~/.local/state/wayfire-per-window-invert.json")
INVERT_SHADER = "/opt/wayfire-filters/shaders/invert"
INVERT_VALUE = "invert"


def load_inverts():
    """View-ids recorded colour-inverted, per toggle_invert_focused's store
    (keyed by view id as a string; presence == invert was toggled on). The store
    is invert-SPECIFIC but only session-live in spirit: view ids reset every
    wayfire session while this file persists, so it accumulates stale ids: see
    is_inverted for why we gate it on the live shader. Best-effort: a missing or
    corrupt file means none are inverted."""
    try:
        with open(INVERT_STORE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def store_mtime(path):
    """mtime of a state file, 0 if absent. Used to notice the invert store
    changing: a Super+N toggle writes it but fires no view event, so the capture
    loop watches this to persist inversion on its own (see capture_loop)."""
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0


def is_inverted(sock, vid, inverts):
    """True iff the view is colour-inverted RIGHT NOW: recorded in the invert
    store AND actually carrying a live filter shader. The store alone is not
    enough: it is keyed by view id, and ids reset each session while the file
    persists, so a stale id reused by a fresh window would read as inverted (the
    "negates some that never were" bug). Gating on the compositor's live
    view-has-shader kills that: a reused id whose window carries no shader is
    excluded. (view-has-shader is not shader-specific: one "filters"
    transformer name covers invert/monochrome/..., but the store gate keeps
    the result invert-specific, and only Super+N writes the store.)"""
    if vid is None or str(vid) not in inverts:
        return False
    try:
        return bool(WPE(sock).view_has_shader(int(vid)).get("has-shader"))
    except Exception:
        return False


def place_of(view, outputs):
    """Frame-robust placement for one view: output name, ABSOLUTE workspace,
    and position within that workspace.

    Wayfire reports view geometry relative to the output's current workspace
    (the current workspace sits at the origin; a workspace one to the right
    adds the output width). So the view's absolute workspace is the output's
    current workspace plus the whole-screen offset in its geometry.

    NOTE: if a restored window ever lands one workspace off, this offset is
    the thing to re-check first (same caveat the old enforcer carried).
    """
    name = view.get("output-name", "null")
    geo = view.get("geometry", {}) or {}
    gx, gy = geo.get("x", 0), geo.get("y", 0)
    gw, gh = geo.get("width", 0), geo.get("height", 0)

    o = outputs.get(name)
    if not o:
        return {"output": name, "workspace": [0, 0], "pos": [gx, gy],
                "size": [gw, gh], "raw": [gx, gy]}

    ow = o["geometry"].get("width") or 1
    oh = o["geometry"].get("height") or 1
    cx = o["workspace"]["x"]
    cy = o["workspace"]["y"]
    # floor, not round: the workspace holding the window's ORIGIN. A window in
    # the lower half of the current workspace (gy/oh ~ 0.5) is still on it, not
    # the next one down; floor keeps pos within [0, output size) too.
    rx = gx // ow
    ry = gy // oh
    return {
        "output": name,
        "workspace": [cx + rx, cy + ry],
        "pos": [gx - rx * ow, gy - ry * oh],
        "size": [gw, gh],
        "raw": [gx, gy],   # raw geometry, kept for coordinate calibration
    }


# The snapshot FORMAT version, written by snapshot() and checked by
# load_snapshot(). One constant, so the writer and the reader cannot disagree.
SNAPSHOT_VERSION = 1


def snapshot(sock):
    outputs = {o["name"]: o for o in sock.list_outputs()}
    inverts = load_inverts()
    windows = []
    for v in sock.list_views(filter_mapped_toplevel=True):
        title = v.get("title", "")
        if SKIP_TITLE.search(title) or is_transient(v):
            continue   # work / scratch / transient-chrome: never record it
        p = place_of(v, outputs)
        pid = v.get("pid", -1)
        _src, _own = window_origin(pid)
        w = {
            "id": v.get("id"),   # wayfire view id: the in-session window key
            "app_id": v.get("app-id") or v.get("app_id") or "",
            "title": v.get("title", ""),
            # The RESOLVED identity, recorded HERE because this is the only
            # moment it can be: a plugin derives it from live state (kitty reads
            # the shell's cwd out of /proc, chrome the SNSS file), and by the
            # time anything replays this snapshot the pid is gone. Without it
            # the relaunch path had only the raw title to match an identity-
            # shaped prefix against, so it matched nothing and never fired.
            "key": identity(v),
            # How to bring this window BACK, asked of the live
            # window while it can still answer. See
            # WindowPlugin.relaunch_command.
            "cmd": relaunch_command_for(v),
            "pid": pid,
            "output": p["output"],
            "workspace": p["workspace"],
            "pos": p["pos"],
            "size": p["size"],
            "tiled": v.get("tiled-edges", 0),
            "fullscreen": bool(v.get("fullscreen", False)),
            "sticky": bool(v.get("sticky", False)),
            "inverted": is_inverted(sock, v.get("id"), inverts),
            "raw_geometry": p["raw"],
        }
        # WHOSE WINDOW, recorded ONLY when it is not ours, so the field's
        # presence is the fact and our own snapshots are unchanged. The
        # relaunch paths read it: a saved window belonging to another account
        # must not be started by us, since resolving its app-id in OUR
        # registry and running it would launch a second, personal copy of
        # somebody's work application.
        if _own is not None or _src:
            w["owner"] = _own
            # THE NAME AS WELL AS THE NUMBER. The name is what a key carries
            # and what a future relaunch hands to the owning account; the uid
            # is kept because it is the reading usher can always make for
            # itself, so a row stays meaningful with no provider wired.
            if _src:
                w["source"] = _src
            # REDACTED, AND THIS IS A PRIVACY BOUNDARY RATHER THAN TIDINESS.
            # A window belonging to another account is captured so the
            # relaunch paths can SKIP it and so a reader can see one was
            # here, and its TITLE is the one field that carries that
            # account's content: a chat window names who is messaging, a
            # browser window names the page.
            #
            # usher's state lives in the OWNER's `~/.local/state/usher`, which
            # every one of the owner's processes can read, and `history/` is a
            # rolling ring, so a title recorded here is work content sitting
            # in the owner's filesystem for as long as the ring holds it.
            # The whole point of a separate account is that the owner's side
            # cannot stumble into that.
            #
            # MEASURED 2026-11-02 before this existed: `current.json` and two
            # history files held a work Slack DM's correspondent, a meeting
            # invitation naming a person, and a calendar week.
            #
            # WHAT SURVIVES IS WHAT usher NEEDS: the app-id, whose window it
            # was, and the geometry. That is enough to skip it in the
            # relaunch, enough to say "a titan window was here" in a report,
            # and enough for a future restore to ask the OWNING account to
            # start that app. Position and size are not content.
            #
            # `cmd` GOES TOO, read from a process tree usher may not run
            # anything from anyway.
            #
            # `key` IS KEPT ONLY WHEN IT IS OPAQUE BY CONSTRUCTION, which is
            # exactly when the window RESOLVED. `identity()` falls back to the
            # raw title for a window that did not, so keeping it unconditional
            # would reinstate the leak under another field name; the foreign
            # branch of `resolution` never reaches a title fallback, so a
            # ready key is the source name plus at most a validated opaque
            # identity. The distinction matters because learn() reads this
            # field and the live title it would otherwise need is blanked
            # one line below.
            w["cmd"] = None
            if not resolution(pview(v)).is_ready:
                w["key"] = ""
            w["title"] = ""
        windows.append(w)
    return {
        "version": SNAPSHOT_VERSION,
        "time": int(time.time()),
        "host": os.uname().nodename,
        "outputs": [{"name": o["name"], "geometry": o["geometry"],
                     "workspace": o["workspace"]} for o in outputs.values()],
        "windows": windows,
    }


def prune(dirpath, keep):
    try:
        files = sorted(os.listdir(dirpath))
    except FileNotFoundError:
        return
    for f in files[:-keep]:
        try:
            os.remove(os.path.join(dirpath, f))
        except OSError:
            pass


def write_json(path, blob):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(blob)
    os.replace(tmp, path)


# --- plugin framework: app-specific window identity + restore --------------
# The engine is app-AGNOSTIC; how to IDENTIFY and RESPAWN a given app's windows
# lives in a plugin. chrome, mux, and kitty ship built in; a user drops more
# into ~/.config/usher/plugins/*.py (each a module defining a top-level PLUGIN
# with the WindowPlugin surface: duck-typed, no import of this script needed).
# The engine consults the registry (order matters: FIRST owner wins) at each
# app-specific site: identity, transient and relaunch. Every window hook takes
# a normalized VIEW (see pview: app, title, pid so a plugin can read /proc, and
# id so it can cache what it worked out) and every one is optional but owns.


def chrome_profiles_for(saved):
    """The profile directories to start, one per profile that actually had a
    window last session, in first-seen order. Falls back to a single unnamed
    launch (Chrome's own choice, possibly the picker) when nothing can be
    matched: no worse than before, and only when there is nothing to go on."""
    pm = chrome_profile_map()
    out = []
    for w in saved:
        if not is_chrome(w.get("app_id")):
            continue
        prof = pm.get(saved_key(w))
        if prof and prof not in out:
            out.append(prof)
    return out or [None]


def pview(v):
    """Normalize a wayfire view, a snapshot window, or a kb entry to the fields
    plugins read: app, title, pid (-1 when absent, e.g. a stored entry), and
    id.

    `id` is the WAYFIRE VIEW id, or None for anything that is not a live view.
    It is the only handle that is stable for exactly one window's lifetime, so
    it is what a plugin caches a hard-won identity against: chrome resolves a
    window from its title once and then remembers it, because the title is a
    bootstrap and not an identity. Anything replayed from the store has no
    live view and gets None, which means no caching, which is correct."""
    if "app" in v and "app_id" not in v and "app-id" not in v:
        return v                                # already normalized
    return {"app": v.get("app-id") or v.get("app_id") or "",
            "title": v.get("title", ""),
            "pid": v.get("pid", -1),
            "id": v.get("id")}


class Resolution:
    """What a plugin knows about a window's identity RIGHT NOW. Three states,
    and the whole framework is that the third one exists.

        Ready(key)    this is definitively window <key>
        Pending(why)  I will know soon; do not place it, do not remember it
        Never(why)    I will never know; it is not mine to remember

    WHY THIS REPLACED `identity() -> str | None` PLUS `transient() -> bool`:
    four separate bugs, all the same shape, all of them a readiness state
    reported wrongly because the contract could not express it.

        chrome's session file lags      should say PENDING, said Ready(title)
        kitty's cwd unreadable 0.25s    should say PENDING, said NEVER
        mux's banner not painted yet    should say PENDING, said Ready(cwd)
        chrome incognito, never saved   should say NEVER,   said PENDING

    The third row is the sharpest argument: a plugin returning a CONFIDENT
    WRONG KEY is what the old contract allowed, and it cost a mux terminal its
    size. "Ready with a key I am not sure about" is now unrepresentable.

    THE REASON IS CARRIED, not just the state, which is what makes this a
    framework rather than a safer `identity`: the plugin that KNOWS why
    supplies the sentence and the report just prints it, instead of the
    report holding another component's facts.

    ONE PREDICATE, TWO CALL SITES stays the rule it always was. learn() and
    the placer both gate on `.ready`, so a store can no longer be written
    under a key the matcher will never look up."""

    __slots__ = ("state", "key", "why")

    READY = "ready"
    PENDING = "pending"
    NEVER = "never"

    def __init__(self, state, key=None, why=None):
        self.state, self.key, self.why = state, key, why

    @classmethod
    def ready(cls, key):
        return cls(cls.READY, key=key)

    @classmethod
    def pending(cls, why):
        return cls(cls.PENDING, why=why)

    @classmethod
    def never(cls, why):
        return cls(cls.NEVER, why=why)

    @property
    def is_ready(self):
        return self.state == Resolution.READY

    def __repr__(self):
        return (f"Resolution({self.state}"
                + (f", key={self.key!r}" if self.key else "")
                + (f", why={self.why!r}" if self.why else "") + ")")


class WindowPlugin:
    """Base + interface. A plugin CLAIMS an app's windows (owns) and can add
    identity RESOLUTION, a way to respawn a missing window, and a clean stop.
    Every window hook takes a normalized view (v["app"], v["title"], v["pid"]);
    the defaults make each opt-in."""
    name = "base"

    def owns(self, v):
        return False

    def resolve(self, v):
        """What this plugin knows about the window's identity. See Resolution.

        THE DEFAULT IS Ready(title), NOT Pending, because a plugin may
        legitimately claim an app only to provide a relaunch and have no
        identity opinion at all. For such a window the raw title is the best
        handle there is, exactly as it is for an app no plugin claims, and
        defaulting to Pending would defer it forever."""
        return Resolution.ready(v["title"])

    def relaunch_missing(self, saved, live):
        # respawn this app's saved-but-absent windows; return WHICH app-ids
        # were started. A count still works (see launched_apps) and costs
        # the registry default its chance to start what this plugin did not.
        return set()

    def relaunch_command(self, v):
        """The command that brings THIS window back, read from the live window
        while it can still be read, or None if the plugin has no opinion.

        Recorded per window at capture. That is the difference between asking
        "what was this window DOING" and inferring it from what the window is
        currently SHOWING: a title names one thing, and a window that can show
        many loses the rest."""
        return None

    def wind_down(self, live):
        """Ask this app's windows to exit CLEANLY, and return the pids asked.

        The mirror of relaunch_missing: that one knows how to bring an app
        back, this one knows how to let it go. An app that needs nothing (a
        terminal, whose mux session outlives the window by design) leaves it
        alone and returns [], which is most of them.

        Return pids rather than waiting: the engine waits for all of them at
        once, under ONE bounded deadline, so no plugin can hold up a reboot."""
        return []


# The hooks a plugin may implement, named ONCE: `plugins` and `doctor` both
# report which of them a plugin defines, and listing them separately is how
# relaunch_command and wind_down came to be missing from both.
PLUGIN_HOOKS = ("owns", "resolve", "relaunch_command",
                "relaunch_missing", "wind_down")

PLUGIN_DIR = config_path("plugins")

# THE SESSION-START SEAM. usher does not know how this machine starts a console
# session, and must not: greetd, a different display manager or a bare
# `startx` are all somebody else's business. It knows only that ONE executable
# can do it, found here, usually as a symlink so `ls -l` names the provider.
#
# A SINGLE PATH, NOT A `.d` DIRECTORY, and the difference is the shape of the
# job. A directory fits a fan-out event (hwdp's changed.d, which usher itself
# hooks into): every provider runs, none of them answers. Starting a session is
# one ACTION with one result, needing its exit status and its stdio, since a
# password prompt has to reach the terminal. Two providers would be a bug, not
# a feature.
#
# The provider gets the action as its argument and OBTAINS ITS OWN PRIVILEGE if
# it needs any, which is what lets this stay a plain symlink to a root-owned
# helper rather than usher deciding who should be root.
SESSION_START = config_path("session-start")

_PLUGINS = None


def plugins():
    """The loaded plugin list (built-ins first, then user plugins) lazily
    built and cached. reload_plugins() drops the cache. mux is BEFORE kitty so a
    mux-attached kitty window is claimed by mux, the rest by kitty."""
    global _PLUGINS
    if _PLUGINS is None:
        _PLUGINS = [ChromePlugin(), MuxPlugin(), KittyPlugin()] \
            + _load_user_plugins()
    return _PLUGINS


def plugins_sig():
    """A signature of the user plugin dir: which *.py files are there and when
    each was last written. Changes on an add, a remove and an edit alike, which
    the same shape as chrome.session_sig.

    NOT THE DIRECTORY'S OWN MTIME: importing a plugin writes a `__pycache__`
    beside it, which bumps that mtime and fires the watch again on a change
    its own reload caused. A TRIGGER MUST NOT INCLUDE ANYTHING THE ACTION IT
    TRIGGERS MODIFIES."""
    try:
        return tuple(sorted(
            (f, os.path.getmtime(f))
            for f in glob.glob(os.path.join(PLUGIN_DIR, "*.py"))))
    except OSError:
        return ()


def reload_plugins():
    """Drop the registry cache so the next plugins() rebuilds it, and say so.

    WIRED TO THE PLUGIN DIR'S MTIME, which it was not for a long time: it
    existed, nothing called it, and two comments in other modules cited it as
    the reason _PLUGINS must not be imported by value. A reload function with
    no trigger is the same shape as data captured and never read.

    A user editing a plugin now sees it take effect within a second, which is
    what usher/exclude and usher/include already promise. Safe because
    _load_user_plugins is best-effort: a half-saved file is logged and skipped,
    leaving the three built-ins, and the next save fixes it."""
    global _PLUGINS
    _PLUGINS = None
    ps = plugins()
    logline("plugins reloaded: "
            + ", ".join(getattr(p, "name", "?") for p in ps))


def _load_user_plugins():
    """Import every ~/.config/usher/plugins/*.py and collect its top-level
    PLUGIN object. Best-effort: a bad plugin is logged and skipped, never
    crashing the headless daemon."""
    import importlib.util
    out = []
    try:
        files = sorted(glob.glob(os.path.join(PLUGIN_DIR, "*.py")))
    except OSError:
        files = []
    for f in files:
        try:
            spec = importlib.util.spec_from_file_location(
                "session_plugin_" + os.path.basename(f)[:-3], f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            p = getattr(mod, "PLUGIN", None)
            if p is not None:
                out.append(p)
        except Exception as e:
            logline(f"plugin load error ({os.path.basename(f)}): {e}")
    return out


def _owner(v):
    """The first plugin that claims this window (normalized view), or None."""
    v = pview(v)
    for p in plugins():
        try:
            if p.owns(v):
                return p
        except Exception:
            pass
    return None


def identity(v):
    """The kb KEY-title for a window: the single chokepoint every keying site
    routes through (upsert, learn, match, place). An owning plugin's identity()
    wins (Chrome's URL, mux's session, kitty's cwd); otherwise the raw title."""
    r = resolution(pview(v))
    return r.key if r.key else pview(v)["title"]


def proc_uid(pid):
    """The uid owning process `pid`, or None if it cannot be read.

    `/proc/<pid>`'s OWNER rather than `Uid:` in status: one stat instead of a
    read and parse, and the same fact for anything not setuid."""
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except OSError:
        return None


# THE WINDOW-SOURCE SEAM. Some windows on this display belong to a different
# account, and usher must treat those differently (see resolution). The uid
# below answers "is it mine"; this answers "WHOSE", which usher cannot work out
# for itself without learning another tool's vocabulary.
#
# SO IT IS A HOOK AND NOT A DEPENDENCY. usher names no provider, knows nothing
# about what a source IS, and works identically with no hook at all. An
# integrator wires whatever on this box can answer the question. Same shape as
# the session-start seam beside it, and the same reasoning: ONE QUESTION WITH
# ONE ANSWER wants a single path rather than a `.d` directory, because it needs
# that provider's exit status and its one word, where a fan-out directory suits
# an event every provider reacts to and none answers.
#
#   usher/window-source <PID>
#     exit 0 + ONE WORD on stdout   that window's SOURCE name
#     exit 1, no output             no source: the session user's own window
#     anything else                 could NOT tell
#
# THREE STATES AND NOT TWO, which this fleet has had to learn repeatedly: "it
# is mine", "it is somebody's, named" and "I cannot tell" are different facts,
# and a hook that cannot answer must not be read as either answer.
#
# A NAME, NEVER A NUMBER, and that is the whole reason this beats the uid for
# anything DURABLE: a uid is an allocation, so a repave or a second account
# renumbers it and every slot keyed on it is orphaned, where a name survives.
SOURCE_HOOK = config_path("window-source")

# pid -> the provider's settled answer, valid for that process's lifetime.
_SOURCE_CACHE = {}


def _pid_stamp(pid):
    """(pid, starttime) or None: a key a REUSED pid cannot collide with.

    starttime is field 22 of /proc/<pid>/stat, read the unambiguous way
    (`comm` can hold spaces and parens, so the fields start after the LAST
    ')'), which is the same reading browser_started already does."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            st = f.read()
        return (pid, st[st.rindex(")") + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def window_source(pid, run=None, hook=None):
    """(name, state) for the account a window's process belongs to.

    state is one of:
        "source"   a provider named it; `name` is that name
        "mine"     a provider says this is the session user's own window
        "unknown"  a provider exists and could not answer
        "nohook"   no provider is wired, so nothing was asked

    BOUNDED AND NEVER FATAL. This is called per window on a placement path, so
    a hook that hangs would hang placement: it gets 2 seconds, and every
    failure mode (missing, not executable, raising, timing out, answering
    rubbish) lands in a state the caller already handles rather than in an
    exception.

    ONE WORD, VALIDATED. A provider that prints a usage block or a sentence has
    not answered the question, and reading its first word as a source name
    would key windows on prose. Anything that is not a single bare token is
    "unknown".
    """
    path = SOURCE_HOOK if hook is None else hook
    if not path or not os.access(path, os.X_OK):
        return (None, "nohook")
    # CACHED PER PROCESS, because a foreign window is re-resolved on every
    # event and every capture pass too, and the answer cannot change while
    # the process lives. KEYED ON THE START TIME AS WELL AS THE PID, since a
    # pid is reused: without it a new window could inherit a dead process's
    # source, which is the mis-binding this whole seam exists to prevent.
    # THE HOOK PATH IS PART OF THE KEY, not just the process: an answer from
    # one provider must never be handed back for another. Found by the checks
    # below, which vary the hook for one pid and got the first hook's answer
    # every time.
    stamp = _pid_stamp(pid)
    stamp = None if stamp is None else (path,) + stamp
    if stamp is not None and stamp in _SOURCE_CACHE:
        return _SOURCE_CACHE[stamp]
    try:
        r = (subprocess.run if run is None else run)(
            [path, str(pid)], capture_output=True, text=True, timeout=2)
    except Exception:                                      # noqa: BLE001
        return (None, "unknown")
    if r.returncode == 1:
        ans = (None, "mine")
    elif r.returncode != 0:
        ans = (None, "unknown")
    else:
        name = (r.stdout or "").strip()
        ans = ((name, "source") if name and len(name.split()) == 1
               else (None, "unknown"))
    # ONLY A SETTLED ANSWER IS CACHED. "unknown" is the state a provider
    # reaches when it could not tell YET (a race, a timeout), and freezing
    # that for the life of the process would turn a blip into a permanent
    # wrong answer.
    if stamp is not None and ans[1] != "unknown":
        _SOURCE_CACHE[stamp] = ans
    return ans


def window_origin(pid, source=None, uid_of=None, me=None):
    """Where this window came from: (source_name, foreign_uid).

    TWO SIGNALS, EACH FOR WHAT IT KNOWS, AND THE uid GOES FIRST:

        uid == mine     -> (None, None)         ours. The hook is NOT asked.
        uid != mine     -> (name-or-None, uid)  foreign; the hook supplies the
                                                NAME when it can

    THE ORDER IS A COST DECISION, measured in forks rather than guessed:
    `resolution` runs on every event and on every capture pass for every
    window, so asking a hook first would mean a subprocess per window per
    second, forever, in a daemon. The uid is one stat and answers for all but
    a handful of windows.

    WHAT THAT GIVES UP, said rather than hidden: a client of the SESSION
    USER'S OWN uid that arrived through another account's display socket reads
    as ours and is never put to the hook. The compositor's security context is
    the only signal that settles that one (U-W1); this seam upgrades "not
    mine" to "whose", which is a different and smaller claim.

    WITH NO PROVIDER WIRED the answer is exactly what usher computed for
    itself before this seam existed, which is what makes it safe to adopt: a
    box with no hook behaves identically to one that never had the concept."""
    other = foreign_owner(pid, uid_of=uid_of, me=me)
    if other is None:
        return (None, None)
    name, state = window_source(pid) if source is None else source
    return (name if state == "source" else None, other)


def source_of(v):
    """This window's SOURCE name, or "" for the session user's own.

    ONE DEFINITION, because `resolution` and `_single_id` both need it and a
    disagreement between them is how this package's silent failures start.

    A RECORDED SOURCE WINS OVER A RE-DERIVED ONE, for the same reason the
    snapshot's `key` field exists: capture is the only moment the fact can be
    read. A replayed row's pid is long dead, so re-deriving would answer "this
    is ours" about a window that was somebody else's, which is the dangerous
    direction. A live view never carries the field, so nothing changes for one.
    """
    if isinstance(v, dict):
        rec = v.get("source")
        if rec:
            return rec
    return window_origin(pview(v).get("pid"))[0] or ""


def chrome_elimination_pool(views):
    """The chrome views `claim_by_elimination` may consider: OURS ONLY.

    THE ID SET IT MATCHES AGAINST IS THE OWNER'S, read out of the owner's own
    session files, so the VIEW set has to be the owner's too. A foreign
    chrome view is not a candidate for any of those ids, and offering it one
    is how it gets handed somebody else's slot.

    PRODUCT, LIVE on manifold 2026-11-02, found while testing the enclave
    restore. The call site filtered on `is_chrome` alone, so a work account's
    Chrome view sat in the pool, and one second after a capture the log read

        chrome: the one unmatched window is settled by elimination

    leaving `google-chrome\0chrome:win:327657740` in the owner's store with
    the WORK window's title as its label and no `source` field, under an id
    the owner's current session does not record. `window_slot` then caches
    that pairing for the view's life, so it is a sticky wrong slot and a
    disclosure in one.

    THE SAME SHAPE AS `d5798da` ONE LEVEL OUT. That fix stopped elimination
    consulting the unreliable TITLES for its own preconditions; this stops it
    considering windows that were never its to pair. A mechanism that forces
    a pairing must have the right candidates before the forcing is sound.
    """
    return [(v.get("id"), v.get("title") or "") for v in views
            if is_chrome(app_of(v)) and not source_of(v)]


def log_title(v):
    """The title a LOG LINE or a REPORT may carry for this view.

    ANOTHER ACCOUNT'S TITLE IS ITS CONTENT, and `watch.log` sits in the
    session user's own readable state, so a foreign window contributes its
    SOURCE NAME and never its title. The name is not a secret: the compositor
    already paints it on the window's frame.

    THE SAME DISCLOSURE BY A SECOND ROUTE, which is why this exists at all.
    `snapshot()` redacts what is STORED, and that was fixed first; a log line
    printing a LIVE view's title was still live afterwards. Measured on
    manifold within a minute of the fixed daemon starting:

        recognised late, re-graced: google-chrome | Inbox (23) - jello@...

    So the rule is the one this package keeps arriving at: ONE predicate, and
    every site that renders a window for a human asks it. Eight log sites are
    fed by three derivations, and they all come through here.

    THE OWNER'S OWN TITLE IS UNTOUCHED, deliberately. watch.log's entire
    value is being readable afterwards, and this repo's forensics quote those
    lines constantly, so redacting everything would cost the thing the log is
    for.
    """
    src = source_of(v)
    if src:
        return f"[{src}]"
    # A FOREIGN WINDOW NOBODY CAN NAME IS STILL FOREIGN, which this missed
    # until 2026-11-04. `snapshot` redacts on `_own is not None or _src`, the
    # uid OR the name, and this asked only the name, so the two predicates
    # disagreed about the same window: with no provider wired `source_of` is
    # "" for a window the uid plainly says is somebody else's, and the raw
    # title was printed. Sixth instance in this package of a gate scoped to
    # one category meeting something outside it, and the disagreement class
    # this file names as the start of every silent failure here.
    #
    # THE uid IS FINE AS A LABEL where it is banned as a KEY: a key must
    # identify what its data describes and an allocation cannot, but a log
    # line only has to be honest, and it is the reading usher can always make
    # for itself. `snapshot` keeps the same number for the same reason.
    own = v.get("owner") if isinstance(v, dict) else None
    if own is None:
        own = foreign_owner(pview(v).get("pid"))
    if own is not None:
        return f"[uid {own}]"
    return v.get("title") or ""


def foreign_owner(pid, uid_of=None, me=None):
    """The uid owning `pid` when that is NOT this session's user, else None.

    THE WHOLE QUESTION IS "IS THIS WINDOW MINE?", and it is deliberately not
    "which enclave is it": a uid comparison needs no vocabulary from any other
    package, where knowing WHICH would mean usher reading somebody else's
    registry. So this answers the narrow question usher can answer for itself,
    and the compositor's security context is the upgrade when it arrives.

    THREE CASES AND ONLY ONE IS FOREIGN, because the costs are not symmetric.
    A wrong key corrupts the store silently, which is this project's whole bug
    history, while declining costs one placement and is visible. But declining
    a window that IS ours would break every placement, so it answers "foreign"
    only on a POSITIVE read of a different uid:

        pid < 0 or None   a STORED entry, whose pid is long dead   -> ours
        uid unreadable    gone, or a racy read                     -> ours
        uid == mine                                                -> ours
        uid != mine       somebody else's process                  -> FOREIGN

    Injectable so the table is checkable without a second account on the box.
    """
    if pid is None or pid < 0:
        return None
    me = os.getuid() if me is None else me
    u = (proc_uid if uid_of is None else uid_of)(pid)
    if u is None or u == me:
        return None
    return u


def resolution(v):
    """What usher knows about this window's identity. See Resolution.

    THE ONE PLACE A PLUGIN IS ASKED, and the only one. identity(),
    unidentified() and _single_id() are thin readers of it, so no two call
    sites can come to disagree about a window's key.

    An UNOWNED app resolves Ready(title), because the title is the only handle
    there is and for those it is the right one. A plugin raising is treated as
    Pending rather than Ready: a broken plugin must not be able to get a
    window remembered under a guessed key.

    NO APP-ID AND NO TITLE IS NO HANDLE AT ALL, and that is NEVER rather than
    Ready(""): the key it would produce carries no information, so it matches
    every other handle-less window and would drag the next one onto whatever
    geometry the last one had. The same rule as a plugin declining, one level
    down, where there is not even an app to ask about."""
    # A RECORDED SOURCE WINS OVER A RE-DERIVED ONE, for the same reason the
    # snapshot's `key` field exists: capture is the only moment the fact can be
    # read. A replayed row's pid is long dead, so re-deriving would answer
    # "this is ours" for a window that was somebody else's, which is the
    # dangerous direction. A live view never carries the field, so nothing
    # changes for one.
    _rec_src = source_of(v)
    v = pview(v)
    # ANOTHER ACCOUNT'S WINDOW IS NOT OURS TO IDENTIFY, asked BEFORE any
    # plugin because no plugin can answer for it: the app's own state lives in
    # a home this user may not read, so every handle a plugin would reach for
    # is missing and the fallbacks are worse than nothing.
    #
    # MEASURED, NOT PREDICTED. On 2026-11-02 a work account's Chrome window
    # joined the OWNER's recorded session ids and was learned into the slot of
    # a personal window, overwriting its workspace and position with the work
    # window's. A title is not a discriminator between two BROWSERS owned by
    # two users, and `claim_by_elimination` forces a pairing when one view and
    # one id are left free, which an unidentifiable stranger in the pool makes
    # likely rather than rare.
    #
    # NEVER RATHER THAN PENDING, and the reason is honest: waiting cannot
    # help, because the state usher would need is behind a uid wall. It costs
    # the placement of that window, which usher could do, and buys the
    # correctness of every slot of ours it would otherwise take. When the
    # compositor publishes the security context a window arrived through,
    # these become keyable per source and the trade goes away.
    _unused_src, other = window_origin(v.get("pid"))
    src = _rec_src
    if src:
        # A NAMED SOURCE *IS* THE KEY. Keyed on the NAME and never on the uid,
        # which is an allocation: `useradd --system` picks a number, a repave
        # or a second account renumbers it, and every slot keyed on it is
        # orphaned with nothing to say it was ever valid.
        #
        # THE SOURCE ALONE, with no per-window part, because there is no
        # per-window handle to add: the app's own state lives in a home usher
        # may not read, so the SNSS-style join that tells the owner's Chrome
        # windows apart is unavailable across the uid wall and the title is
        # precisely the thing that does not discriminate. So several windows
        # of one foreign app share this key, the slot ledger places the first
        # and leaves the rest where they open, and doctor reports the
        # collision: the same honest degradation an app_id-only app has always
        # had, rather than a guess.
        #
        # BUT A SOURCE NAMES THE ACCOUNT, NOT THE WINDOW, so it is only half
        # a key and needs the app-id as the other half. With no app-id the key
        # degenerates to `\0<source>`, which matches EVERY handle-less window
        # of that whole account and would drag the next one onto whatever
        # geometry the last one had.
        #
        # FIFTH INSTANCE OF ONE SHAPE: a rule scoped to one category, met by
        # something outside it. `is_unique` has refused an empty app-id since
        # `d9dbc9f` killed the `'\0'` wildcard, and the source branch above
        # runs FIRST and never consulted it. Found on manifold as a live
        # `'\x00titan'` entry beside the five legitimate source keys, by
        # sweeping the store by SHAPE after a content filter had twice missed
        # things.
        if not v["app"]:
            return Resolution.never(
                f"this window belongs to the {src} source and reports no "
                "app-id, so the source name is the only handle and keying on "
                "it alone would match every handle-less window of that "
                "account")
        # AND A PER-WINDOW PART WHEN THE SOURCE COULD NAME ONE. The paragraph
        # above said there is no such handle, and that was true of what the
        # OWNER can see: the account's own app state is behind its uid wall.
        # The account itself can read it, so it reports a digest of each live
        # window title beside an opaque identity and the owner joins on the
        # title it already has. Measured 6 of 6 on manifold 2026-11-03.
        #
        # THE SOURCE STAYS THE FIRST COMPONENT, so the key still names the
        # account that owns the window and can never collide with the owner's
        # own `chrome:win:<id>`. The source ALONE remains the fallback, which
        # is every entry stored before this and every window whose account
        # cannot say which one it is, so nothing relearns.
        _per = source_window_identity(src, v)
        return Resolution.ready(f"{src}:{_per}" if _per else src)
    if other is not None:
        # FOREIGN AND UNNAMED: no provider is wired, or it could not answer.
        # NOT keyable, because the only thing usher has is the uid and a uid
        # must not be a key. Declining is what it has always been, and a
        # window with no stable name is better forgotten than mis-filed.
        return Resolution.never(
            f"this window belongs to uid {other}, not to this session's user, "
            f"and nothing here can name its source, so there is no stable "
            f"handle to key it on")
    p = _owner(v)
    if p is None:
        if not v["app"] and not v["title"].strip():
            return Resolution.never(
                "the compositor reports neither an app-id nor a title, so "
                "there is nothing to key this window on")
        return Resolution.ready(v["title"])
    try:
        r = p.resolve(v)
    except Exception as e:
        return Resolution.pending(f"plugin {p.name} raised: {e}")
    return _as_resolution(r, p.name)


def _as_resolution(r, who):
    """Normalise what a plugin returned, accepting the DUCK-TYPED form.

    A user plugin is explicitly documented as needing NO import of usher
    (share/plugins/example.py says so, and that is a feature worth keeping:
    a dropped-in file with no dependency cannot break on an internal move).
    Requiring a Resolution instance would have quietly ended that, so a plain
    2-tuple is equally valid and is the form the example teaches:

        ("ready", "spotify")        same as Resolution.ready("spotify")
        ("pending", "why")          ("never", "why")

    ANYTHING ELSE IS PENDING, NOT READY, including the bare string the OLD
    contract returned. That is deliberate and it is the fail-safe direction:
    forgetting a window costs a placement, keying it on a guess corrupts the
    slot (see the 2026-10-03 shrink bug). The message names the fix."""
    if isinstance(r, Resolution):
        return r
    if (isinstance(r, tuple) and len(r) == 2
            and r[0] in (Resolution.READY, Resolution.PENDING,
                         Resolution.NEVER) and isinstance(r[1], str)):
        return Resolution(r[0], key=r[1] if r[0] == Resolution.READY else None,
                          why=None if r[0] == Resolution.READY else r[1])
    return Resolution.pending(
        f"plugin {who} returned {type(r).__name__}; resolve() must return a "
        f'Resolution or a 2-tuple like ("ready", key)')


def _single_id(v):
    """An owning plugin's stable single-key identity, or None to fall through
    to the title-grouping path. Drives the keying branch in upsert()/learn()."""
    # NO SOURCE BRANCH HERE, DELIBERATELY. One was written and removed: both
    # callers (`upsert` and `_learn_stamp`) now ask `source_of` themselves,
    # because the app_id-only branch above them had to be gated anyway, so a
    # second answer here was unreachable. A planted regression removing it
    # changed nothing, which is this file's own signal for dead code.
    v = pview(v)
    if _owner(v) is None:
        return None       # unowned: the title-grouping path, as before
    r = resolution(v)
    return r.key if r.is_ready else None


def unidentified(v):
    """True if usher cannot say WHICH window this is, so it must neither
    remember it nor match it against anything remembered.

    ASK THIS, NOT identity(), which always answers and falls back to the raw
    title. That fallback is right for an app no plugin claims (the title is
    the only handle there is) and wrong for an owned one, where a title the
    plugin declined to resolve is a key known to be false. Chrome hits it
    whenever its session file has not caught up with a window.

    IT ASKS resolution() AND NOTHING ELSE. It used to require is_owned first,
    which scoped it to "a plugin declined" and left the case where there is no
    plugin AND no handle answering Ready(""). Dropping that gate changes no
    owned answer (the plugin is still the authority) and lets the handle-less
    case be refused by the one predicate both sides already consult.

    BOTH LEARNING AND PLACING MUST ASK THE SAME PREDICATE. A store written
    under a key the matcher never looks up, or matched under a key the writer
    never produces, is the fault this exists to prevent."""
    return not resolution(v).is_ready


def launched_apps(result):
    """The app-ids a plugin says it STARTED, or None if it answered the old
    count-only contract. PURE.

    `relaunch_missing` used to return a count. It returns a set of app-ids
    now, because a count cannot answer the only question the registry
    default needs to ask: did the owning plugin actually start this app, or
    merely claim it? A plugin that still returns a number is read as None
    here, which the callers treat as "may have started anything it owns",
    i.e. exactly the old behaviour. So an unmigrated plugin keeps working
    with an unchanged outcome and this is additive rather than breaking.

    THE DEGRADATION RUNS TOWARDS NOT LAUNCHING, which is the cheap failure.
    Reading an unknown answer as "it started nothing" would have the default
    start the app a second time, and for a browser that is two processes
    against one profile: the singleton fight, a ProcessSingleton error, and
    a window the human has to close."""
    if isinstance(result, (set, frozenset, list, tuple)):
        return {str(a) for a in result if a}
    return None


def launched_count(result):
    """How many a plugin started, under either contract. PURE.

    Keeps every count this package already prints byte-identical, which is
    what makes the change invisible in `watch.log`."""
    apps = launched_apps(result)
    if apps is not None:
        return len(apps)
    try:
        return int(result or 0)
    except (TypeError, ValueError):
        return 0


def roster_claimed(missing, started, registry=None):
    """Which of these app-ids the registry default must NOT start. PURE.

    THE ROSTER PATH ASKS A DIFFERENT QUESTION FROM A RESTORE. On a restore
    the default skips any app a plugin CLAIMS, which is right: the plugin
    has a recorded command per window and would double-launch. A roster row
    is an app-id and NOTHING else, so a plugin keyed on a recorded command
    finds nothing and no-ops, and the claim then stops the one mechanism
    that could have started the app. Measured on manifold: an account's
    terminal was in its roster, counted missing, and started by nobody,
    while slack beside it came back because no plugin claims slack.

    So here the test is what a plugin DID, not what it owns. An app whose
    owner reported starting it is skipped; one whose owner reported a set
    NOT containing it is the default's to start; and an owner that reported
    nothing intelligible keeps its whole claim, which is the old behaviour
    and the safe direction.
    """
    # THE CALLER'S OWN REGISTRY SNAPSHOT, not a fresh `plugins()` call.
    # `started` is keyed by plugin OBJECT, so resolving the owner from a
    # second call would compare different objects the moment the registry is
    # rebuilt (a plugin reload between the two). It would fail SAFE, since a
    # key miss reads as "reported nothing" and keeps the claim, which is
    # exactly why a check could pass over it: measured, a fixture handing a
    # fresh instance proved nothing at all.
    pl = list(plugins()) if registry is None else list(registry)
    out = set()
    for app in missing:
        v = pview({"app-id": app, "title": "", "pid": -1})
        p = next((q for q in pl if _owns(q, v)), None)
        if p is None:
            continue              # unclaimed: the default has always had it
        apps = launched_apps(started.get(p))
        if apps is None or app in apps:
            out.add(app)
    return out


def _owns(p, v):
    """Does this plugin claim this view? Never raises: a plugin that throws
    from `owns` must not decide a launch, and treating it as "does not own"
    hands the app to the registry default, which is the direction that still
    starts something."""
    try:
        return bool(p.owns(v))
    except Exception:                                      # noqa: BLE001
        return False


def is_owned(app):
    """True if some plugin claims this app-id, so its windows never drop to an
    app_id-only key (the old FORCE_TITLE_APPS rule, now plugin-driven). By app
    alone (chrome/kitty own by app-id; mux is a title-keyed subset of the kitty
    app, already covered)."""
    return _owner({"app": app, "title": "", "pid": -1}) is not None


def relaunch_command_for(v):
    """The OWNING plugin's command for bringing this window back, or None.
    Computed at CAPTURE, because a live window can be asked what it is doing
    and a stored one cannot."""
    v = pview(v)
    p = _owner(v)
    if p is not None:
        try:
            return p.relaunch_command(v)
        except Exception:
            pass
    return None


# --- /proc window introspection (the kitty/mux plugins' stable-identity source)
def _proc_children(pid):
    try:
        return [int(x) for x in
                open(f"/proc/{pid}/task/{pid}/children").read().split()]
    except OSError:
        return []


def _proc_argv0(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            a0 = f.read().split(b"\0", 1)[0]
        return os.path.basename(a0.decode("utf-8", "replace"))
    except OSError:
        return ""


def _term_cwd(pid):
    """The working dir of a kitty window's SHELL: its first non-helper child's
    cwd. kitty itself stays at $HOME (--directory), but the shell's cwd tracks
    the user's cd, so it is where the window 'is'. '' if unreadable/none."""
    if not pid or pid < 0:
        return ""
    for k in _proc_children(pid):
        if _proc_argv0(k) in ("kitten", "kitty"):
            continue                            # skip kitty's atexit helper
        try:
            return os.readlink(f"/proc/{k}/cwd")
        except OSError:
            return ""
    return ""


def _proc_argv(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return [x.decode("utf-8", "replace")
                    for x in f.read().split(b"\0") if x]
    except OSError:
        return []


def _latch_target_in(argv):
    """The HOST[:SESSION] in one process's argv, if it is a mux latch. Pure, so
    the matching is testable without a live process tree, which matters
    because this is what decides whether a window is replayed as a latch or
    falls back to `mux resume`."""
    for i, a in enumerate(argv):
        if os.path.basename(a) == "mux-latch" and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _names_mux(word):
    """Is this word the mux command, HOWEVER it is spelled?

    By BASENAME, so `mux`, `~/.local/bin/mux` and `/usr/local/bin/mux` all
    answer yes and a window started before or after mux changed install mode
    is read the same way. `mux-latch` is mux's own helper and counts.
    """
    return os.path.basename(word) in ("mux", "mux-latch")


def _shell_words(s):
    """`s` split the way a shell would, or on whitespace if it will not parse.

    NEVER RAISES: this reads a live process's argv, which is arbitrary bytes
    that may hold an unbalanced quote, and a placement path must not fall over
    on one.
    """
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def _mux_pending_in(argv):
    """True if this process IS a mux command, or a shell wrapping one.

    PURE, so it is testable without a process tree. Getting it wrong COSTS
    the window its remembered size.

    TWO SHAPES, because spawn_term wraps the command in `ksh -c "<cmd>; exec
    ksh -i"`, so the mux invocation is INSIDE one argv element rather than
    being its own:

        ['/bin/sh', '.../libexec/mux-latch', 'manifold']     a real process
        ['ksh', '-c', '/home/.../mux resume; exec ksh -i']    wrapped

    IT SELF-CLEARS, which is what bounds the deferral: `exec ksh -i` REPLACES
    the wrapper once the mux command ends, so the argv stops naming mux and
    the window becomes an ordinary kitty with no timer involved."""
    for a in argv:
        if _names_mux(a):
            return True
        # THE WRAPPED FORM IS ONE ELEMENT HOLDING A WHOLE COMMAND LINE, so the
        # command has to be dug out of it rather than compared to the element.
        #
        # ANCHORED TO COMMAND POSITION, not matched anywhere in the string: a
        # bare substring test would defer any window whose argv merely
        # mentions a path ending in `mux` (`~/src/mux`), and deferring
        # FOREVER is the direction that costs a window its memory. spawn_term
        # builds `"<cmd>; exec ksh -i"`, so mux is always the FIRST token.
        toks = _shell_words(a)
        if toks and _names_mux(toks[0]):
            return True
    return False


def _term_mux_pending(pid):
    """True while a mux command is still running in this window's tree.

    Same depth as _term_latch_target, and for the same reason: the command
    sits under the shell kitty spawned, not under kitty itself."""
    if not pid or pid < 0:
        return False
    for p in [pid] + _proc_children(pid):
        for kid in [p] + _proc_children(p):
            if _mux_pending_in(_proc_argv(kid)):
                return True
    return False


def _term_latch_target(pid):
    """The HOST[:SESSION] a `mux latch` running in this window is holding, or
    None.

    latch is the ONE mux verb that can be seen after the fact. It is a
    long-lived supervisor with a job (hold the attachment across drops), so it
    stays in the process tree; `mux go` and `mux resume` exec into a tmux
    client and are gone. That asymmetry is the whole basis of the rule below:
    a command we can see, we replay; everything else was a local mux, and the
    command a human would have typed for that is `mux resume`.

    Matched on the argv rather than argv0, because latch runs as
    `/bin/sh .../libexec/mux-latch <target>` and argv0 is the shell. The scan
    itself is _latch_target_in, kept separate so it can be tested without a
    process tree."""
    for p in [pid] + _proc_children(pid):
        for kid in [p] + _proc_children(p):
            hit = _latch_target_in(_proc_argv(kid))
            if hit:
                return hit
    return None


def mux_session_of(title):
    """The mux SESSION from a `session:window` banner: the durable unit that
    `mux go`/`mux ls` name (#{session_name}). Strips a leading [LABEL] context
    prefix, then takes up to the first ":". None if not a session banner."""
    t = re.sub(r"^\[[^\]]*\]\s*", "", title.strip())
    if ":" not in t:
        return None
    return t.split(":", 1)[0].strip() or None


def mux_host_of(title):
    """The HOST a mux session lives on, from the TRAILING `[host]` tag mux
    stamps into the terminal title (its set-titles-string ends in the tmux
    format `[#{host_short}]`). That tag names the tmux SERVER's host, so a
    session reached over ssh reads as the REMOTE box and a local one as this
    box. It is the SERVER's host, never the route taken, and it survives into
    a STORED entry, whose pid is long dead by the time anything replays it.

    None when there is no trailing tag (an older mux, or a title that merely
    looks like a banner); callers treat that as local. ANCHORED AT THE END so
    the LEADING [LABEL] context prefix (a work banner) is never mistaken for
    it."""
    m = re.search(r"\[([^\[\]]+)\]\s*$", title.strip())
    if not m:
        return None
    return m.group(1).strip() or None


# A terminal's SLOT: what it owns a remembered place as. Keyed by the COMMAND
# the window runs, not by the session it is showing.
#
# The session was the obvious key and the wrong one. A window can show many
# sessions over its life (that is what mux is for), so keying on the current
# one meant switching sessions made the window a stranger with no remembered
# place, and purged the slot it used to own. Exactly the Chrome active-tab
# problem, and the cause of "my terminals came back on the wrong desktop".
#
# The command does not change when you switch what the window displays, so the
# slot survives. It is also the SAME fact that says how to bring the window
# back, so identity and relaunch can no longer disagree with each other.
#
# Known consequence, accepted: two windows running the same command share one
# slot. Within a partition that means two local mux windows, which is not a
# thing anyone runs.
TERM_KEY_RE = re.compile(r"^term:")


def _mux_slot(latch_target):
    return f"term:latch {latch_target}" if latch_target else "term:resume"


class ChromePlugin(WindowPlugin):
    """Chrome / Chromium: identity is the active-tab URL read from the SNSS
    session file, keyed by its stable window id. Transient states (a blank
    profile picker) are handled by the usher/exclude config, not here."""
    name = "chrome"

    def owns(self, v):
        return is_chrome(v["app"])

    def resolve(self, v):
        """`chrome:win:<SessionID>`, or why not.

        TWO DISTINCT NO-ANSWERS, which doctor used to hardcode. A window Chrome
        has simply not written to its session file yet is PENDING and resolves
        itself within seconds. An INCOGNITO or GUEST window is NEVER: Chrome
        does not record those anywhere, by design, so no amount of waiting,
        title normalising or tab-set widening will ever join it. Telling them
        apart is the difference between "wait" and "stop asking"."""
        slot = window_slot(v.get("id"), v["title"])
        if slot:
            return Resolution.ready(slot)
        # PENDING, NOT NEVER, and the reason names BOTH causes because usher
        # cannot tell them apart from one observation: a window Chrome has not
        # got round to writing looks identical to one it will never write.
        # Asserting incognito here would be an overclaim.
        return Resolution.pending(
            "Chrome has not written this window to its session file yet; an "
            "incognito or guest window is never written at all")

    def wind_down(self, live):
        """SIGTERM the BROWSER process. Measured on Chrome 154: it exits in
        about a second and records profile.exit_type = "SessionEnded".

        That is the whole point. Killed mid-flight, which is what a bare
        `systemctl reboot` does, since it tears the session down with the
        compositor still needed: the profile keeps exit_type = "Crashed",
        and every subsequent login opens with a "Chrome didn't shut down
        correctly" prompt instead of the windows."""
        # ONLY WHAT WAS ACTUALLY SIGNALLED IS RETURNED, because the caller
        # WAITS on this list and a pid we could not signal would be waited
        # for and then read as having exited. `browser_pids` already narrows
        # to this user, so a refusal here means something moved under us:
        # that is worth a line, not a silent drop.
        asked, refused = [], []
        for p in browser_pids():
            try:
                os.kill(p, signal.SIGTERM)
                asked.append(p)
            except OSError as e:
                refused.append((p, e.strerror))
        for p, why in refused:
            logline(f"wind-down could not signal browser {p} ({why}), so it "
                    f"is left running and NOT waited for")
        return asked

    def relaunch_missing(self, saved, live):
        """Start the browser if the last session had Chrome windows and none
        is running now. Chrome restores its OWN windows, but only once
        something starts it, so on a login where nothing did, usher was
        leaving the largest part of the desk shut. It starts the browser and
        nothing more: which windows come back stays Chrome's business.

        Started PER PROFILE, naming each one. A bare `google-chrome` on a box
        with several profiles and no `Default` opens the profile PICKER and
        waits for a human, restoring nothing at all, so the one thing usher
        had to get right about starting it was which profile to start."""
        # PER USER ON BOTH SIDES, because another account running its own
        # browser on this display answers neither question for us: its saved
        # window is not ours to restore, and its LIVE browser is not evidence
        # that ours is up. Without the second test a personal Chrome would
        # simply not come back on any login where the work one was already
        # running, which is the quiet direction.
        _mine = {w.get("app_id") for w in saved
                 if is_chrome(w.get("app_id")) and w.get("owner") is None}
        if not _mine:
            return set()
        if any(is_chrome(pview(v)["app"])
               and foreign_owner(pview(v).get("pid")) is None for v in live):
            return set()
        exe = next((shutil.which(c) for c in
                    ("google-chrome", "google-chrome-stable", "chromium",
                     "chromium-browser") if shutil.which(c)), None)
        if not exe:
            return set()
        n = 0
        for prof in chrome_profiles_for(saved):
            if n:
                # STAGGER. Chrome is a singleton per user-data-dir: the first
                # invocation becomes the browser process and later ones hand
                # their request to it over a socket that does not exist yet.
                # Firing both in the same second is a race, and the loser does
                # not restore its session. Observed on manifold, where two
                # profiles were launched in the same second and only one came
                # back with its windows.
                time.sleep(CHROME_STAGGER)
            argv = ([exe] + CHROME_FLAGS
                    + ([f"--profile-directory={prof}"] if prof else []))
            _announce("launch  " + " ".join(
                [os.path.basename(exe)] + argv[1:]))
            app_spawn(argv, _SPAWN_WATCH)
            n += 1
        # THE APP-IDS AS THE SAVED ROWS SPELL THEM, not a literal: XWayland
        # reports `Google-chrome` where native Wayland reports
        # `google-chrome` and BOTH are in a real store, so returning one
        # spelling would leave the registry default free to start the
        # browser a second time under the other.
        return _mine if n else set()


class MuxPlugin(WindowPlugin):
    """mux-attached kitty terminals: a kitty window wearing a mux
    `session:window` banner (is_mux_term). Identity is the mux SESSION plus the
    HOST it lives on (`mux@<host>:<session>`), both parsed from the title: the
    session is the durable unit `mux go` names, and the host is the trailing tag
    mux stamps (see mux_host_of). NOT the full title, which churns as you switch
    windows within a session and carries padding.

    Claims a REMOTE session (one whose host is not this box) as readily as a
    local one: it is the same kind of window doing the same job, wants the same
    slot back, and differs only in how it respawns: `mux go` here, the same
    through `ssh` there. Respawn is the sole mux-BINARY touchpoint, best-effort
    so it no-ops without mux (the soft dep)."""
    name = "mux"

    def owns(self, v):
        return is_mux_term(v["app"], v["title"])

    def resolve(self, v):
        """The SLOT, from the command this window runs. See TERM_KEY_RE.

        ALWAYS READY, and that is not an oversight: ownership here already
        requires the banner (is_mux_term) or a mux command in the tree, so by
        the time this is asked the window HAS a command, and the absence of a
        latch is itself the answer (a local mux, replayed as `mux resume`).

        A STORED entry (pid < 0) cannot be asked, but does not need to be: the
        slot was resolved at capture and recorded in the snapshot's `key`."""
        return Resolution.ready(_mux_slot(_term_latch_target(v.get("pid", -1))))

    def relaunch_command(self, v):
        """A latch if one is running here, otherwise nothing, which the
        relaunch reads as `mux resume`. See MUX_RESUME for why that default is
        right rather than merely convenient."""
        t = _term_latch_target(v.get("pid", -1))
        return f"{shlex.quote(MUX_BIN)} latch {shlex.quote(t)}" if t else None

    def relaunch_missing(self, saved, live):
        return mux_relaunch_missing(saved, live)


class KittyPlugin(WindowPlugin):
    """Non-mux kitty terminals: a shell or a program (e.g. Claude Code) in a
    working dir. Claims any kitty window mux did not (registry order). Identity
    is the shell's CWD from /proc (`kitty:<cwd>`), so the window keeps its place
    across restarts regardless of the volatile title. Respawns a missing one as
    a plain shell in that cwd (`kitty --directory`, deliberately NOT re-running
    the captured command).

    A SHELL AT $HOME USED TO BE A SCRATCH TERMINAL, excluded end to end: never
    captured, never placed, never brought back. That was the same kind of
    exception as chrome's retired `^New Tab$` rule and it is retired for the
    same two reasons. Place-vs-settled means a terminal opened during
    normal use is left exactly where it opens, so the whack-a-mole the rule
    was written against cannot happen; and when USHER is the one spawning the
    window at session start, it can put it where it belongs. The goal is every
    window you left open coming back at the right size in the right place, and
    an exception is a window usher gives up on."""
    name = "kitty"

    def owns(self, v):
        return v["app"] == "kitty"

    # NO transient HOOK, deliberately. Retiring the scratch exception left it
    # with nothing genuine to report. What it was reduced to, "I cannot read
    # the cwd", is a DIFFERENT QUESTION that already has an owner.
    #
    # `transient` means "never remember this window". `unidentified` means "I
    # cannot say WHICH window this is, ask again". Conflating them cost real
    # behaviour: a kitty window cannot be identified for its first 0.25s (the
    # shell is not in /proc yet), so it reported transient, and _place_view
    # tests transient BEFORE it tests identity and returns there. Every non-mux
    # terminal was therefore dropped in the one 0.15s window it gets, and only
    # landed if _recheck_all happened along. Measured on manifestor: mapped at
    # 19:28:48, placed at 19:29:12, by an unrelated Chrome session-file write.

    def resolve(self, v):
        """`kitty:<cwd>`, or PENDING while usher cannot yet say WHICH window
        this is.

        PENDING WHILE A MUX COMMAND IS IN FLIGHT, and answering a cwd key
        there is how a terminal loses its size. A relaunched mux terminal MAPS
        BEFORE mux attaches (a latch has to ssh first), so its title is `ksh`
        with no colon and `is_mux_term` is False: claim it and the placer
        matches the bare-kitty slot, RESIZES the window to it, and the capture
        loop learns that size back into `term:latch <host>`. Self-worsening,
        because the next relaunch then ASKS for the shrunken size.

        Declining only ever DEFERS, which is the conservative direction:
        `unidentified` keeps learning and placing off the window,
        grace-from-recognition re-graces it the instant mux paints its banner,
        and MuxPlugin claims it with the right key. Widening MuxPlugin's claim
        to the process tree was the alternative and is worse, since it could
        STEAL a genuine bare-kitty window.

        NOT a `transient` hook: "I cannot tell yet" and "never remember this
        window" are different questions with the same boolean."""
        if not v["pid"] or v["pid"] < 0:
            return Resolution.never(
                "a stored entry's pid is long dead, so its cwd can never be "
                "read; replay uses the key recorded at capture instead")
        if _term_mux_pending(v["pid"]):
            return Resolution.pending(
                "a mux command is still starting in this window, so its real "
                "identity is a terminal slot, not this cwd")
        cwd = _term_cwd(v["pid"])
        if cwd:
            return Resolution.ready(f"kitty:{cwd}")
        return Resolution.pending(
            "the shell's cwd is not readable yet (a kitty needs ~0.25s)")

    def relaunch_missing(self, saved, live):
        return kitty_relaunch_missing(saved, live)


# --- knowledge base: identity -> latest placement -------------------------
# The daemon matches against this, not raw snapshots. Each capture upserts
# every window's (app_id, title) with its newest placement, so it is a
# superset across time (remembers closed windows) but deduplicated with
# recency (the latest observation wins). Entries unseen for TTL age out; no
# LRU is needed, the TTL bounds the store (see learn() for the grouping).
KNOWLEDGE_TTL = 30 * 86400

# Apps a plugin claims (is_owned) legitimately SHARE one app_id, and a momentary
# drop to a single window must NOT collapse them to an app_id-only key (which
# would prune the whole title-keyed set), so they always key by identity. This
# was the hardcoded FORCE_TITLE_APPS set (google-chrome/chromium/kitty); it is
# now plugin-driven, so a user plugin's app gets the same protection for free.
# Distinct --app Chrome ids (chrome-mail.google.com__-Default, ...) are NOT
# owned: they are genuinely unique per app and stay title-independent.
def kkey(app_id, title):
    return f"{app_id}\x00{title}"


# Bump when the key scheme changes. Schema 2 moved Chrome off per-page-title
# keys onto the normalized active-tab URL; schema 3 moved kitty off per-title
# keys onto mux:<session> / kitty:<cwd>; schema 4 QUALIFIED the mux key with the
# host (mux@<host>:<session>), so a same-named session on two boxes stops
# sharing one slot; schema 5 moved a terminal off the session entirely
# onto its COMMAND (term:...), so switching sessions in a window no
# longer forfeits its place; schema 6 did the same for CHROME, moving it
# off the active-tab URL onto the window's SessionID. The old keys can never
# match again, so the migration drops them once (the store is a rebuildable
# cache).
#
# Schema 7 is the first bump that changes NO key shape. It stopped usher
# LEARNING a window its plugin could not identify, which invalidated exactly
# the chrome entries the old title fallback had written: 265 of 326 stored
# placements on manifestor, 287 of 334 on manifold, none of them matchable by
# anything. See _migrate_store: this one is keyed on the SHAPE of the stored
# key, not on the app, because dropping the app wholesale would take the
# working slots with it.
KB_SCHEMA = "7"
_MIGRATE_APPS = {"kitty"}


def _migrate_wholesale(app):
    """True if a PRE-6 store's entry for this app is unmatchable WHATEVER its
    key: chrome and kitty, whose key shapes both changed before schema 6.

    Which apps a bump invalidates wholesale is not always "all of them":
    schema 5 changed only the terminal key and deliberately spared chrome's
    1045 entries, so this is the pre-6 rule only. From 6 onward the shapes
    are current and only _migrate_store's key-SHAPE rule applies.

    CASE-INSENSITIVELY for chrome, which the set-membership test this replaces
    was not. XWayland reports `Google-chrome` where native Wayland reports
    `google-chrome`, and BOTH are in a real store (measured 2026-09-29: every
    one of this box's six profile stores held capitalised entries that every
    bump since schema 2 had quietly walked past). A migration that misses a
    spelling of the app it is migrating leaves exactly the entries it was
    written to remove."""
    return is_chrome(app) or app in _MIGRATE_APPS


def rekey_chrome(kb):
    """Move the store's chrome slots onto the CURRENT session's window ids,
    and return how many moved.

    CHROME DOES NOT KEEP A WINDOW'S SessionID ACROSS A RESTART. It mints a
    fresh block for the restored windows: measured twice on 2026-09-29, on
    the clean-exit and the crash path, zero overlap either way, so after any
    browser restart every `chrome:win:<id>` in the store is a dead key and
    every Chrome window is a stranger with no remembered place. That is not a
    small thing: it is the whole of why Chrome windows stopped being placed at
    login.

    The identity is still right; only the boundary was missing. Chrome leaves
    the PREVIOUS session file beside the new one, so the two can be joined on
    the tabs a window came back with (chrome_bind_windows), and the slot
    follows the window. No new stored state: both sides are files usher
    already parses.

    CONSERVATIVE BY CONSTRUCTION, because this rewrites the store:
      - only slots the current session does NOT know are candidates, so a
        run with nothing stale is a no-op and running it twice is safe;
      - a current window that ALREADY has a slot is left alone: the store's
        own answer for it is at least as good as this guess;
      - nothing binds unless the tab sets agree, and not binding is the safe
        outcome (the slot stays put and ages out on the TTL).
    """
    hist = session_history()
    cur, prev = {}, {}
    for files in hist.values():
        cur.update(chrome_window_tabs(files[0]))
        for f in files[1:]:
            for w, urls in chrome_window_tabs(f).items():
                prev.setdefault(w, urls)     # the newest previous file wins
    if not cur or not prev:
        return 0
    stale = {}
    for k in kb:
        key = k.split("\x00", 1)[-1]
        if is_chrome_slot(key) and int(key.rsplit(":", 1)[1]) not in cur:
            stale[int(key.rsplit(":", 1)[1])] = k
    if not stale:
        return 0
    bound = chrome_bind_windows(
        cur, {w: u for w, u in prev.items() if w in stale})
    moved = 0
    for old, new in bound.items():
        app = stale[old].split("\x00", 1)[0]
        newkey = kkey(app, chrome_slot(new))
        if newkey in kb:
            continue
        e = kb.pop(stale[old])
        # "title" in a kb entry is the KEY-title, i.e. identity(), which is the
        # trap
        # this file keeps falling into. It has to move with the key.
        e["title"] = chrome_slot(new)
        kb[newkey] = e
        moved += 1
    return moved


def _migrate_store(kb, frm):
    """Apply every invalidation between schema `frm` and KB_SCHEMA to one
    store, in place. Returns how many entries it dropped.

    A BUMP MUST DROP ONLY WHAT IT INVALIDATED, and the two rules in play
    invalidated different things, so this needs the FROM version rather than
    one blunt sweep:

      before 6   chrome's and kitty's KEY SHAPES changed, repeatedly (2 moved
                 chrome onto the active-tab URL, 3 moved kitty onto
                 kitty:<cwd>, 4 host-qualified mux, 5 moved terminals onto
                 term:<command>, 6 moved chrome onto its SessionID). Nothing
                 stored for those apps under an older schema can ever match
                 again, so they go wholesale.
      7          NO key shape changed. usher simply stopped LEARNING a chrome
                 window its plugin could not identify, which invalidated
                 exactly what that fallback had written: chrome keyed by a
                 raw window title, and nothing else. Dropping all of chrome
                 here would have discarded 45 working slots across two boxes
                 to relearn them identically, which is the mistake schema 5
                 nearly made.
    """
    before = len(kb)
    try:
        old = int(frm)
    except (TypeError, ValueError):
        old = 0
    if old < 6:
        for k in [k for k in kb
                  if _migrate_wholesale(k.split("\x00", 1)[0])]:
            del kb[k]
    for k in [k for k in kb
              if is_chrome(k.split("\x00", 1)[0])
              and not is_chrome_slot(k.split("\x00", 1)[1])]:
        del kb[k]
    return before - len(kb)


def migrate_stores():
    """Bring EVERY display profile's store up to KB_SCHEMA, not only the one
    for the monitors attached right now. Idempotent via the per-profile schema
    stamp beside each store.

    There is one store per monitor set, and migrating only the set you happen
    to be plugged into leaves the others to rot until those monitors come
    back, which may be never. Measured on manifestor 2026-09-29: five of six
    stores were dormant, three of them still stamped schema 4, and 265 of 326
    entries across the lot were chrome keyed by a raw title: 81% of
    everything the box had learned, none of it matchable. The one store the
    old per-load migration could reach held 58 of those 326 entries."""
    for path in sorted(glob.glob(os.path.join(STATE, "knowledge-*.json"))):
        prof = os.path.basename(path)[len("knowledge-"):-len(".json")]
        sp = schema_path(prof)
        try:
            frm = open(sp).read().strip()
        except OSError:
            frm = ""
        if frm == KB_SCHEMA:
            continue
        try:
            kb = json.load(open(path))
        except (OSError, ValueError):
            continue
        n = _migrate_store(kb, frm)
        try:
            write_json(path, json.dumps(kb))
            write_json(sp, KB_SCHEMA)
        except OSError:
            continue
        logline(f"store {prof}: schema {frm or 'unstamped'} -> {KB_SCHEMA},"
                f" dropped {n} entry(s) it invalidated, {len(kb)} left")


def load_knowledge(profile=None):
    """The knowledge base for a display profile, the current one by default. A
    monitor set with nothing learned yet starts empty (and seeds from the last
    snapshot), which is right: the placements from another desk would not fit
    here anyway.

    TAKE THE PROFILE AS AN ARGUMENT when you intend to HOLD the result, and
    save it back under the same one: see save_knowledge, and kb_for_profile,
    which pairs the two so they cannot be resolved separately."""
    profile = profile or profile_id()
    adopt_legacy_store()
    migrate_stores()      # every profile's store, not just the one we are on
    try:
        kb = json.load(open(kb_path(profile)))
    except (FileNotFoundError, ValueError):
        # A store that does not exist yet is CURRENT by construction, so stamp
        # it NOW. Without this, the first monitor set to be seen writes an
        # unstamped store, and the very next load judges it stale and drops
        # exactly the chrome + kitty entries it has just learned, and every new
        # desk silently losing its browser and terminal placements once.
        try:
            os.makedirs(STATE, exist_ok=True)
            write_json(schema_path(profile), KB_SCHEMA)
        except OSError:
            pass
        snap = load_snapshot()    # seed from the latest snapshot if present
        if snap is None:
            return {}
        kb = {}
        upsert(kb, snap["windows"], snap["time"])
        return kb
    return kb


def is_unique(app, counts):
    """True if this app_id identifies exactly one window (so it can key by
    app_id alone, title-independent). A plugin-owned app is never unique, even
    when momentarily alone: its windows share an app_id (see is_owned).

    AN EMPTY APP-ID IS NOT AN IDENTIFIER, it is the absence of one, and
    treating it as a unique app is how a window with no app-id came to be
    stored under `kkey("", "")`, a key EVERY app-id-less toplevel matches. It
    also DISCARDED the title, which was the only handle such a window had."""
    return bool(app) and counts[app] == 1 and not is_owned(app)


def kb_entry(w, title, appid_only, when):
    """A knowledge record for one identity at window w's current placement.
    `title` is the KEY-title (identity(): a URL for Chrome); `label` keeps the
    human window title for logs, since the key may no longer read as one."""
    return {
        "app_id": w["app_id"], "title": title, "appid_only": appid_only,
        "label": w.get("title", ""),
        "output": w["output"], "workspace": w["workspace"],
        # WHICH MONITOR, as opposed to which cable. The connector name is kept
        # as well, and is still what an entry falls back to: a box with no
        # hwdp records no panel, and an entry learned before this existed has
        # none, so both must keep working. See entry_output.
        "panel": panel_map().get(w["output"], ""),
        # WHOSE SLOT THIS IS, when it is not the session user's. Recorded
        # rather than inferred from the title, so the prune below and the
        # matcher can both ask directly. Absent for the owner's own entries,
        # which is every entry that existed before this.
        **({"source": w["source"]} if w.get("source") else {}),
        # WHICH NAMED SURFACE this placement sits in, at this desk. The rect
        # beside it is per-profile and learned; this name is the part that can
        # travel to another desk, where the same name resolves to a different
        # panel and a different rect. Empty when the desk has no map, which is
        # most desks and is not a fault.
        "surface": surface_of(w, surface_map()[0]),
        "pos": w["pos"], "size": w["size"],
        "sticky": bool(w.get("sticky", False)),
        "inverted": bool(w.get("inverted", False)),
        # FULLSCREEN was captured into the snapshot and stopped here for a long
        # time, so it never reached place() and a window left fullscreen came
        # back windowed at the remembered geometry. Which is not pixel perfect,
        # and is the fifth instance of this file's recurring shape: data
        # captured and never read.
        "fullscreen": bool(w.get("fullscreen", False)),
        "last_seen": when,
    }


def prune_kb(kb, when):
    """Drop aged-out entries, work-tagged entries, and stale per-title entries
    for an app now keyed by app_id (an app_id-only key ends in NUL).

    A plugin-owned app must never carry an app_id-only key. If a stale one
    lingers (e.g. written before the app got a plugin), it is doubly
    corrosive: it mis-matches every window of that app by app_id alone, AND,
    via appid_keyed below, it deletes every per-title entry the app just
    learned, so the app can never relearn (kitty's mux terminals hit exactly
    this). So enforce the invariant rather than assume it: drop such keys
    outright, and keep owned apps out of appid_keyed so their per-title set
    survives.

    A SOURCE KEY IS NOT A STALE PER-TITLE ENTRY, and that exemption is what
    makes another account's slot survivable at all. `slack\0titan` has the
    same SHAPE as a per-title entry for an app now keyed app_id-only, so the
    owner's `slack\0` deleted it on the very pass that wrote it: measured
    2026-11-02, the foreign window was learned and then pruned within one
    call, and `_learn_stamp` alone looked correct. The entry carries `source`
    for exactly this, so the sweep can tell "a leftover title key" from
    "a different account's slot for the same app".

    FOURTH INSTANCE OF THE SAME SHAPE here: a rule scoped to one category,
    met by something outside the category."""
    appid_keyed = {k[:-1] for k in kb
                   if k.endswith("\x00") and not is_owned(k[:-1])}
    cutoff = when - KNOWLEDGE_TTL
    for k in [k for k, v in kb.items()
              if v.get("last_seen", 0) < cutoff
              or SKIP_TITLE.search(v.get("title", ""))
              or is_transient(v)
              or (k.endswith("\x00") and is_owned(k[:-1]))
              or ("\x00" in k and not k.endswith("\x00")
                  and not v.get("source")
                  and k.split("\x00", 1)[0] in appid_keyed)]:
        del kb[k]


def upsert(kb, windows, when):
    """One-shot knowledge update (no view-id grouping): record each window's
    CURRENT identity. Unique-app_id windows key by app_id alone; the rest by
    title. Used by `usher capture` and the seed-from-snapshot path;
    the watch daemon uses learn() instead, which groups a window's tabs by
    view id."""
    counts = Counter(w["app_id"] for w in windows
                      if not w.get("source") and
                      w.get("owner") is None)
    for w in windows:
        app = w["app_id"]
        key = _single_id(w)   # plugin single identity (chrome/mux/kitty)
        # A FOREIGN WINDOW IS KEYED ON ITS SOURCE AND NEVER app_id-ONLY.
        # `kkey(app, "")` is the OWNER's key and matches every window of that
        # app, so writing a foreign window there overwrites the owner's slot
        # with it.
        #
        # MEASURED, because `is_unique` looks only at the app and cannot know
        # whose window it is: with one Slack of each, `counts` saw ONE (it
        # excludes foreign rows by design), `is_unique` was therefore True for
        # BOTH, and the foreign window took the owner's key. Asked here rather
        # than inside `is_unique`, whose question really is about the app.
        _src_w = source_of(w)
        if _src_w:
            # THE RESOLVED KEY, NOT THE BARE SOURCE, so a per-window identity
            # the account reported is what gets stored. `w["key"]` is what
            # `snapshot` stamped while the window was live, which is the only
            # moment it could be computed: the title this joins on is redacted
            # in this very row, so re-deriving here would answer the
            # source-alone key for every window.
            _k_w = w.get("key") or _src_w
            if _k_w != _src_w and not _k_w.startswith(_src_w + ":"):
                _k_w = _src_w      # not this source's: never cross-file it
            kb[kkey(app, _k_w)] = kb_entry(w, _k_w, False, when)
        elif is_unique(app, counts):
            kb[kkey(app, "")] = kb_entry(w, w["title"], True, when)
        elif key:
            kb[kkey(app, key)] = kb_entry(w, key, False, when)
        elif w["title"]:
            kb[kkey(app, w["title"])] = kb_entry(w, w["title"], False, when)
    prune_kb(kb, when)


def _learn_degroup(kb, groups, ambiguous, live):
    """Drop titles two live views share, and retire groups whose window closed.
    A title on two windows at once is not a discriminator."""
    # Degroup: purge now-ambiguous titles from every group and the store.
    for app, title in ambiguous:
        kb.pop(kkey(app, title), None)
    for g in groups.values():
        g["titles"] -= {t for a, t in ambiguous if a == g["app"]}

    # Retire groups whose window closed (their kb entries linger under the TTL).
    for vid in [v for v in groups if v not in live]:
        del groups[vid]


def _learn_fold(groups, windows, ambiguous):
    """Fold each live view's current title into its group."""
    # Fold each live view's current title into its group.
    for w in windows:
        vid = w.get("id")
        if vid is None:
            continue
        g = groups.setdefault(vid, {"app": w["app_id"], "titles": set()})
        g["app"] = w["app_id"]
        if w["title"] and (w["app_id"], w["title"]) not in ambiguous:
            if is_mux_term(w["app_id"], w["title"]):
                g["titles"] = {w["title"]}   # terminal: only current session
            else:
                g["titles"].add(w["title"])


def _learn_stamp(kb, groups, windows, counts, when, hold=()):
    """Write each live view's placement under the right key. `hold` is the set
    of view ids whose CURRENT position must not be believed yet: see the
    watcher's _held: a window the placer has not got to is sitting where its
    app dropped it, and writing that overwrites the slot the placer is about
    to aim at."""
    # Stamp: unique-app_id -> app_id key; a plugin single-identity (Chrome ->
    # its ONE active-tab URL, no title accumulation, restored whatever tab was
    # active) -> that key; other shared apps (mux terminals) -> every title in
    # the view's group, all at the view's current placement.
    for w in windows:
        app, vid = w["app_id"], w.get("id")
        if vid in hold:
            continue
        # A WINDOW usher CANNOT IDENTIFY IS NOT LEARNED, WHATEVER KEY SHAPE
        # IT WOULD HAVE TAKEN, and the gate belongs HERE rather than inside one
        # branch of the dispatch below.
        #
        # Falling through to the title path stored a key known to be wrong.
        # Chrome hits this whenever its session file has not caught up with a
        # window, which is often, and every title change then minted another
        # entry: measured on manifold 2026-09-29, 286 of a 333-entry store were
        # chrome keyed by raw TITLE, 86% of everything usher knew, none of it
        # matchable. The window is simply not remembered until its id resolves,
        # which is normally seconds, and the cost is a window whose session
        # file never catches up never being remembered. That is the right
        # trade: an entry nothing can ever match is not memory, it is litter,
        # and it crowds out the entries that work.
        #
        # IT USED TO SIT THIRD, reached only after is_unique and the plugin key
        # had both declined, which made it a rule about OWNED windows whose
        # plugin could not answer. An app_id-only window never reached it,
        # because for that key shape there is no identity to be unsure about:
        # the app-id IS the handle.
        #
        # THAT STOPPED BEING TRUE when `unidentified` gained a second reason. A
        # window belonging to ANOTHER ACCOUNT must not be keyed at all, and a
        # single-window unowned app is exactly the case that bypassed the
        # check: measured 2026-11-02, a work account's Slack was still learned
        # into `slack\0` with the resolution fix in place and the daemon
        # confirmed current, because this branch never asked. Third instance of
        # the shape in this file: a gate scoped to one category, met by
        # something outside the category.
        if unidentified(w):
            continue
        key = _single_id(w)
        # A FOREIGN WINDOW IS KEYED ON ITS SOURCE AND NEVER app_id-ONLY.
        # `kkey(app, "")` is the OWNER's key and matches every window of that
        # app, so writing a foreign window there overwrites the owner's slot
        # with it.
        #
        # MEASURED, because `is_unique` looks only at the app and cannot know
        # whose window it is: with one Slack of each, `counts` saw ONE (it
        # excludes foreign rows by design), `is_unique` was therefore True for
        # BOTH, and the foreign window took the owner's key. Asked here rather
        # than inside `is_unique`, whose question really is about the app.
        _src_w = source_of(w)
        if _src_w:
            # THE RESOLVED KEY, NOT THE BARE SOURCE, so a per-window identity
            # the account reported is what gets stored. `w["key"]` is what
            # `snapshot` stamped while the window was live, which is the only
            # moment it could be computed: the title this joins on is redacted
            # in this very row, so re-deriving here would answer the
            # source-alone key for every window.
            _k_w = w.get("key") or _src_w
            if _k_w != _src_w and not _k_w.startswith(_src_w + ":"):
                _k_w = _src_w      # not this source's: never cross-file it
            kb[kkey(app, _k_w)] = kb_entry(w, _k_w, False, when)
        elif is_unique(app, counts):
            kb[kkey(app, "")] = kb_entry(w, w["title"], True, when)
        elif key:
            kb[kkey(app, key)] = kb_entry(w, key, False, when)
        elif vid is not None and vid in groups:
            for t in groups[vid]["titles"]:
                kb[kkey(app, t)] = kb_entry(w, t, False, when)


def _learn_purge_terminals(kb, windows, seen):
    """Drop the terminal entries whose window we WATCHED GO.

    NOT "is it here?" BUT "did we see it go?". Absence from one snapshot is
    not evidence of a closed window: the daemon captures as soon as it is
    watching, which is before the terminals it just launched have mapped, and
    purging on absence there deletes the slot the placer is about to aim at.
    `seen` is this generation's set of terminal identities observed ALIVE, and
    only what is in it may be dropped. An entry never seen cannot be told
    apart from one whose window has not mapped yet, so it is left alone and
    prune_kb's TTL is the backstop. A reload starts a fresh generation, so the
    purge is briefly quiet until each terminal is seen once; that is the
    fail-safe direction.

    BOTH SIDES MUST BE IDENTITIES. A kb entry's "title" field is the KEY-title
    (kb_entry stamps identity(), not the window title), so comparing it to raw
    window titles matches nothing and silently deletes every terminal entry.
    And the entry is selected by its KEY SHAPE, never by is_mux_term on that
    key: is_mux_term only asks "kitty, with a colon?", which a kitty:<cwd> key
    also satisfies, so that sweeps plain kitty windows out as collateral."""
    live_terms = {identity(w) for w in windows
                  if is_mux_term(w["app_id"], w["title"])}
    seen.update(live_terms)
    for k in [k for k, v in kb.items()
              if TERM_KEY_RE.match(v.get("title", ""))
              and v.get("title") in seen
              and v.get("title") not in live_terms]:
        del kb[k]


def unreadable_placement(w, outputs):
    """True when window w's recorded placement cannot be believed, because the
    output it names is not among those attached.

    place_of's no-such-output branch answers ws[0, 0] with the RAW geometry as
    the position, and that reads exactly like a real answer: a plausible slot
    that is wrong in both coordinates. So a window whose output has gone needs
    holding back from what we LEARN, the same rule as a window whose identity
    the plugin cannot resolve.

    THIS IS THE NORMAL STATE BETWEEN AN UNDOCK AND A REDOCK, not an edge case.
    wayfire's preserve-output plugin parks the views of an unplugged monitor on
    a `null` output and keeps their real geometry itself, so every
    external-monitor window reports an output nobody has while the dock is
    out. Learning those would write a store full of slots naming `null`, which
    nothing can ever place.

    NO OUTPUT LIST CONCLUDES NOTHING, which is the fail-safe direction and the
    same guard recorded_window_ids and seen_terms take: an empty list means we
    were not told what is attached, not that nothing is."""
    names = {o.get("name") for o in (outputs or [])}
    return bool(names) and w.get("output") not in names


def learn(kb, groups, windows, when, hold=(), seen=None, outputs=None):
    """Watch-time knowledge update with view-id tab-grouping.

    Each live view: keyed by its wayfire id, stable for the window's whole
    life: owns the set of titles it has shown. Every title in the set is
    stamped to the view's CURRENT placement, so a window drags its whole learned
    tab-set with it when it moves (no stragglers pointing at the old screen),
    and on restore it lands correctly whatever tab happens to be active.

    A title shown by two live views at once is not a window discriminator, so it
    is dropped from every group and from the store (the degroup rule). Groups
    are in-session only (view ids do not survive a restart); they re-form under
    fresh ids next session, self-healing. Unique-app_id windows (--app Gmail)
    stay keyed by app_id alone; kitty is forced to per-title keys; Chrome keys
    by its active-tab URL identity (see identity(), stamped below)."""
    counts = Counter(w["app_id"] for w in windows
                      if not w.get("source") and
                      w.get("owner") is None)
    tcount = Counter((w["app_id"], w["title"]) for w in windows if w["title"])
    ambiguous = {k for k, c in tcount.items() if c >= 2}
    live = {w["id"] for w in windows if w.get("id") is not None}
    # A WINDOW ON AN OUTPUT NOBODY HAS JOINS THE HOLD, which is the right
    # mechanism rather than a second one: `hold` deliberately does not reach
    # the degroup or the terminal purge, and those ask "is this window still
    # HERE", which a parked window plainly is. A purge on absence would
    # otherwise drop the slot of every terminal on the unplugged monitor.
    hold = set(hold) | {w["id"] for w in windows if w.get("id") is not None
                        and unreadable_placement(w, outputs)}
    _learn_degroup(kb, groups, ambiguous, live)
    _learn_fold(groups, windows, ambiguous)
    _learn_stamp(kb, groups, windows, counts, when, hold)
    # `hold` deliberately does NOT reach the degroup or the terminal purge:
    # those ask "is this window still HERE", which a held window plainly is.
    # Hiding it from them would drop the very entry we are protecting.
    #
    # `seen` is the daemon generation's memory of which terminals have actually
    # been observed alive, and it is what makes "gone" decidable. A caller that
    # keeps no such memory can conclude nothing, so it purges NOTHING: that is
    # the fail-safe direction, since the cost of keeping a stale entry is one
    # phantom relaunch and the cost of dropping a live one is losing its slot.
    _learn_purge_terminals(kb, windows, set() if seen is None else seen)
    prune_kb(kb, when)


def kb_for_profile(profile=None):
    """The store AND the profile it belongs to, as one pair.

    Anything holding a store for longer than one verb needs both, and asking
    for them separately is what let them disagree: see save_knowledge."""
    profile = profile or profile_id()
    return load_knowledge(profile), profile


def save_knowledge(kb, profile):
    """Write the store back to the profile it CAME FROM.

    THE PROFILE IS AN ARGUMENT, with no default, because resolving it HERE was
    a bug rather than a convenience. The daemon loads `self.kb` once at worker
    init and the capture loop saves it every second; kb_path() resolved
    profile_id() fresh on every write, so the in-memory store was bound to the
    profile it was loaded under and the file it landed in was not.

    Measured on a seeded sandbox: one capture after a display change wrote the
    OLD profile's whole store into the NEW profile's file, so the new
    profile's own learned entries were gone and every surviving slot named an
    output that was not attached. A docked laptop does that twice a day, and
    the two stores then converge until per-profile stores have stopped
    existing.

    Writing where the data came from is the fail-safe direction. If nothing
    tells us the monitors changed, we go on maintaining the store for the desk
    we loaded, which is wrong but costs only staleness; the other desk's
    layout is untouched either way.
    """
    write_json(kb_path(profile), json.dumps(kb, indent=2))


def forget_matches(kb, selectors):
    """The store keys `selectors` select, as a sorted list.

    A SELECTOR IS A GLOB OVER THE IDENTITY, which is the half a reader has
    actually seen: `chrome:win:327645084`, `kitty:/src/x`, `term:resume` are
    what doctor and `restore --dry-run` print. An APP-ID-ONLY entry has no
    identity, so there the glob is matched against the app-id instead, which
    is what makes `usher forget signal` mean the obvious thing.

    A STORE KEY IS `app_id` NUL `identity` AND `term:` IS NOT A PREFIX OF IT.
    That exact confusion cost an investigation here: `startswith('term:')`
    over the keys answers [] whether or not any terminal slot exists. Doing
    the split in ONE place is most of why this verb is worth having over a
    hand-edit."""
    out = []
    for k in kb:
        app, _, ident = k.partition("\x00")
        subject = ident or app
        if any(fnmatch.fnmatchcase(subject, s) for s in selectors):
            out.append(k)
    return sorted(out)


def backup_knowledge():
    """Copy the store aside before an edit, and return the path. Cheap, and
    the only reason a mistake here is recoverable."""
    src = kb_path()
    dst = f"{src}.pre-forget-{time.strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(src, dst)
    return dst


def forget_apply(kb, selectors, profile=None):
    """Drop what `selectors` select from `kb` IN PLACE, back the store up,
    save, and return the dropped keys. Each drop is logged, because the store
    is learned data and watch.log is what says who removed it.

    `profile` is the one `kb` was loaded under, for the daemon, which holds a
    store across display changes. None means resolve it now, which is right
    for the client path: it loads and saves within the same breath."""
    profile = profile or profile_id()
    gone = forget_matches(kb, selectors)
    if not gone:
        return []
    # THE BACKUP IS ANNOUNCED, because it RETAINS WHAT WAS JUST DROPPED and
    # nothing else says where it is. That is the right default for the case
    # this verb was built for (an entry dropped by mistake can be read back),
    # and exactly wrong for a PRIVACY purge, where the backup is a copy of
    # the thing being removed. Met for real: purging another account's leaked
    # titles left them sitting in `knowledge-<profile>.json.pre-forget-...`,
    # found only by sweeping the whole state directory afterwards. A side
    # effect nobody is told about is one nobody cleans up.
    _bk = os.path.basename(backup_knowledge())
    logline(f"forget: backed the store up to {_bk}")
    for k in gone:
        del kb[k]
        app, _, ident = k.partition("\x00")
        logline(f"forget: dropped {app} | {ident or '(by app-id)'}")
    save_knowledge(kb, profile)
    return gone


def persist(snap, roll=True):
    """Write the snapshot to current.json always. Roll the history ring and the
    daily milestone only for layout-significant changes (roll=True); tab-switch
    captures pass roll=False so the 20-deep recent-layout ring is not flooded
    with title churn. Knowledge is updated separately."""
    blob = json.dumps(snap, indent=2)
    write_json(os.path.join(STATE, "current.json"), blob)
    if not roll:
        return
    hist = os.path.join(STATE, "history")
    mile = os.path.join(STATE, "milestones")
    os.makedirs(hist, exist_ok=True)
    os.makedirs(mile, exist_ok=True)
    write_json(os.path.join(hist, f"{snap['time']}.json"), blob)
    prune(hist, HISTORY_KEEP)
    ms = os.path.join(mile, f"{date.today().isoformat()}.json")
    if not os.path.exists(ms):
        write_json(ms, blob)
    prune(mile, MILESTONE_DAYS)


def do_capture():
    snap = snapshot(ipc())
    os.makedirs(STATE, exist_ok=True)
    persist(snap)
    kb, prof = kb_for_profile()
    upsert(kb, snap["windows"], snap["time"])
    save_knowledge(kb, prof)
    print(f"usher: captured {len(snap['windows'])} window(s); "
          f"{len(kb)} known -> {STATE}")


def app_of(v):
    return v.get("app-id") or v.get("app_id") or ""


# --- init-launch: bring terminals back (Chrome self-restores on its own) ----

# mux's command names, in one place. `mux resume` is the LOCAL default for a
# terminal whose command was not recorded: it rebuilds the whole recorded set
# rather than the one session a titlebar happened to name, and it is what a
# human types after a reboot. The remote counterpart is `mux latch <host>`,
# which mux itself maps to a `mux resume` on the far side.
# A BARE NAME, RESOLVED BY PATH, never a prefix. This was
# `~/.local/bin/mux` and mux moved to a machine-wide install, which broke four
# things at once from one string (measured 2026-11-02, reported as "usher
# resume fails to bring it back"):
#
#   the relaunch        spawned a command that does not exist, so the terminal
#                       died instantly: the documented `[kitty] <defunct>`
#                       beside a cheerful `launch` line
#   mux_sessions        `<old path> resume --list` failed into its own
#                       `except: return set()`, so the durable session SET came
#                       back EMPTY and the whole relaunch had nothing to
#                       relaunch. That is the 2026-09-15 failure exactly, by a
#                       path instead of by a glyph
#   _mux_pending_in     scanned argv for the OLD absolute path, so a window
#                       started from the new one never deferred and KittyPlugin
#                       claimed it with a confident `kitty:<cwd>` key: the
#                       2026-10-03 shrink bug, back
#   doctor              reported on a path nothing uses
#
# TWO OF THOSE ARE REGRESSIONS OF BUGS THIS PACKAGE ALREADY FIXED ONCE, which
# is what a hardcoded prefix buys. The bare name is resolved by the SHELL at
# spawn time and by execvp for a direct call, so it is correct before and after
# any future move with nothing to update. Same reasoning as the bare
# `usher-mgr` the compositor autostart now carries.
MUX_BIN = "mux"
MUX_RESUME = f"{MUX_BIN} resume"


def _announce(msg):
    """Say it on stdout AND in the daemon's log. Both matter: stdout is what a
    person running `usher launch` by hand reads, and the log is the only
    copy that survives, since the compositor autostart discards the worker's
    stdout entirely."""
    print(msg, flush=True)
    logline(msg)


def load_snapshot():
    """The last snapshot, or None if there is not a readable one we understand.
    The single reader of current.json, so relaunch and doctor always look at
    the same thing.

    THE VERSION STAMP IS CHECKED. snapshot() has written `version` since the
    beginning and nothing read it, which made the stamp a decoration: a future
    format could not be detected, only misread, and the relaunch paths would
    act on fields that had moved. Refusing is the safe failure: no snapshot
    means no relaunch, rather than a wrong one, and it is loud in the log."""
    try:
        with open(os.path.join(STATE, "current.json")) as f:
            snap = json.load(f)
    except (OSError, ValueError):
        return None
    got = snap.get("version")
    if got != SNAPSHOT_VERSION:
        logline(f"snapshot version {got!r} is not {SNAPSHOT_VERSION}:"
                f" refusing to read it rather than guess at its shape")
        return None
    return snap


def saved_sizes(saved):
    """identity -> [w, h] from the last snapshot, so a respawned window can be
    ASKED FOR at the size it had instead of mapping at kitty's configured
    default and waiting to be corrected. Measured: a relaunched terminal mapped
    at 1085x672 (the 80c x 24c in kitty.conf) against a remembered 2132x1690,
    and sat that way until placement caught up."""
    out = {}
    for w in saved:
        k, s = saved_key(w), w.get("size")
        if k and s and len(s) == 2 and s[0] and s[1]:
            out.setdefault(k, [int(s[0]), int(s[1])])
    return out


def _size_opts(size):
    """kitty's initial-size flags. Plain numbers are PIXELS (kitty.conf here
    uses the `c` suffix for cells). kitty rounds to whole cells and adds its
    padding, so this lands CLOSE rather than exact: 2176x1761 for a 2132x1690
    request when measured, and the normal placement pass makes it exact. The
    point is that the window never appears at the wrong size."""
    if not size:
        return []
    return ["-o", f"initial_window_width={int(size[0])}",
            "-o", f"initial_window_height={int(size[1])}"]


def spawn_term(cmd, size=None):
    """Open a terminal running `cmd`, launched through a shell so that the
    command ENDING drops back to that shell instead of closing the window.
    kitty running mux as its direct child would exit on detach (mux exits ->
    kitty exits -> window vanishes). Running it inside `ksh -c '... ; exec ksh
    -i'` leaves an interactive shell after detach: the window survives and,
    re-sourcing kshrc, becomes a plain untracked terminal, which is exactly
    what a detached scratch terminal should be. TMUX is cleared so mux does a
    fresh attach, not a switch-client that hijacks another window.

    The command is passed in rather than derived here. Every mux verb needs a
    TTY (arranging one is what mux is FOR) so a window is the right place
    for all of them, local and remote alike, and usher's job is only to put a
    window around the command it recorded."""
    # A RECORDED COMMAND WHOSE PROGRAM IS GONE MUST NOT BE SPAWNED, and the
    # reason is that the failure is INVISIBLE rather than noisy: kitty starts,
    # `ksh -c` cannot find the program, the shell exits, `exec ksh -i` never
    # runs, and the window vanishes. What a reader finds afterwards is
    # `[kitty] <defunct>` in the process table beside a cheerful `launch` line
    # in watch.log, which this file already records as reading like a
    # successful relaunch.
    #
    # MEASURED 2026-11-02: mux changed install mode, every recorded mux
    # command named a path that no longer existed, and `usher resume` brought
    # nothing back with nothing anywhere saying why. usher tracks where a
    # window WAS; it did not notice that the command to recreate it had been
    # replaced, which is the general fault and not a mux one.
    #
    # BOTH TESTS, because a recorded command may name either a program on PATH
    # or an absolute path to one: `which` answers the first, `os.path.exists`
    # the second, and refusing when neither holds is the only safe reading.
    prog = _shell_words(cmd)[:1]
    if prog and not shutil.which(prog[0]) and not os.path.exists(prog[0]):
        logline(f"NOT launching {cmd!r}: {prog[0]} is not on PATH, so the "
                f"window would open and close. The recorded command names a "
                f"program this box no longer has (did it change install "
                f"mode?)")
        return False
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    subprocess.Popen(["kitty"] + _size_opts(size)
                     + ["ksh", "-c", f"{cmd}; exec ksh -i"],
                     env=env, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def saved_key(w):
    """The identity a saved snapshot window was recorded under. Prefers the
    `key` snapshot() now stores; falls back to re-deriving it for a snapshot
    written before that field existed (which works for a title-derived identity
    like mux's, and honestly yields nothing for a /proc-derived one, whose pid
    is gone)."""
    k = w.get("key")
    if k:
        return k
    return identity(w) or ""


def mux_session_set():
    """The session names mux would rebuild on this box: `mux resume --list`,
    one bare NAME per line.

    THE DURABLE SET, NOT THE LIVE SERVER, which is the point: the case that
    matters is a COLD BOOT, where no session is live but `mux go` rebuilds
    from exactly this set.

    NEVER SCRAPE `mux ls` FOR THIS. It is a HUMAN listing and leads each line
    with an agent-state glyph, so a scrape of it matches nothing and leaves
    this whole path dead with no symptom. selftest asserts the bare-name shape
    against the real binary, so a change to mux's output fails LOUD here.

    Empty when mux is absent or errors: the soft-dep no-op."""
    try:
        out = subprocess.run(
            [MUX_BIN, "resume", "--list"],
            capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return set()
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def live_keys(live):
    """The resolved identities of the windows currently on screen: the ONE
    definition of "already showing" that every relaunch path tests against, so
    the question is answered the same way for each. Comparing identities rather
    than raw state is what keeps the plugins from tripping over each other: a
    mux-attached window keys mux@... (its owner is the mux plugin), so it can
    never be mistaken for a kitty:<cwd> window whose shell happens to sit in the
    same place."""
    out = set()
    for v in live:
        k = identity(pview(v))
        if k:
            out.add(k)
    return out


def mux_cmd_of_saved(w):
    """The command that brings a saved terminal window back: the one recorded
    at capture, or `mux resume` when there is none.

    THE DEFAULT IS THE POINT. A window with no recorded command was running a
    LOCAL mux, and `mux resume` is what a human types for that: it rebuilds the
    whole recorded set rather than the single session the titlebar happened to
    name. Deriving `mux go <session>` from the title instead is what restored
    one session out of six, because a title can only ever name one.

    Within a partition the sessions are the same set whichever window you look
    from, so the only thing lost by not naming one is which session gets
    initial focus, and running two windows on the same box in the same
    partition is not a thing anyone does. KNOWN HOLE: telling local mux
    windows apart ACROSS partitions. Narrower than it sounds, because the work
    partition is excluded end to end by SKIP_TITLE and never captured at all."""
    return w.get("cmd") or MUX_RESUME


def mux_cmd_of_live(v):
    """The same question asked of a window that is on screen right now."""
    t = _term_latch_target(pview(v).get("pid", -1))
    return f"{shlex.quote(MUX_BIN)} latch {shlex.quote(t)}" if t else MUX_RESUME


def mux_candidates(saved, live):
    """The commands to run, one per terminal window that is missing.

    COUNTED PER COMMAND, not matched per session. usher owns windows; which
    session a window shows is mux's business and changes under it, so the
    question is "how many windows was I running this command in, and how many
    are up?" rather than "is session X on screen". That also means a window
    keeps coming back after you switch what it displays, which the old
    identity match could not do.

    Returns a list of (cmd, size), size being the remembered geometry of the
    first window recorded for that command, or None."""
    want, sizes = Counter(), {}
    for w in saved:
        if w.get("app_id") != "kitty":
            continue
        if not TERM_KEY_RE.match(saved_key(w)):
            continue
        c = mux_cmd_of_saved(w)
        want[c] += 1
        s = w.get("size")
        if c not in sizes and s and len(s) == 2 and s[0] and s[1]:
            sizes[c] = [int(s[0]), int(s[1])]
    have = Counter()
    for v in live:
        vv = pview(v)
        if is_mux_term(vv["app"], vv["title"]):
            have[mux_cmd_of_live(v)] += 1
    out = []
    for c, n in want.items():
        for _ in range(max(0, n - have[c])):
            out.append((c, sizes.get(c)))
    return out


def mux_relaunch_missing(saved, live):
    """Reopen each terminal window that was up at the last snapshot and is
    not now, running the command it was running."""
    n = 0
    for cmd, size in mux_candidates(saved, live):
        # COUNTED AND ANNOUNCED ONLY IF IT ACTUALLY STARTED. `launch  <cmd>`
        # is the line a reader trusts to mean a window was opened, and the
        # refusal above logs its own reason, so announcing both would be two
        # claims about one event with only one of them true.
        if not spawn_term(cmd, size):
            continue
        n += 1
        _announce(f"launch  {cmd}")
    # THIS PLUGIN'S OWN APP, which is what it just put on screen. Not read
    # from the saved rows because `mux_candidates` yields commands rather
    # than rows, and a terminal this reopens is a kitty by construction.
    return {"kitty"} if n else set()


def _spawn_kitty(cwd, size=None):
    """Open a plain kitty shell in cwd (a fresh per-window id). Deliberately NOT
    re-running the window's captured program: restoring the place + directory,
    not the command."""
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    subprocess.Popen(["kitty"] + _size_opts(size) + ["--directory", cwd],
                     env=env, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def kitty_candidates(saved, livekeys):
    """The cwds to reopen a plain kitty shell in: every non-mux kitty window in
    the last snapshot that is not already on screen (`livekeys`, from
    live_keys). Pure, for the same reason mux_candidates is."""
    seen, out = set(), []
    for w in saved:
        if w.get("app_id") != "kitty":
            continue
        k = saved_key(w)
        if not k.startswith("kitty:"):
            continue
        cwd = k[len("kitty:"):]
        if not cwd or cwd in seen or k in livekeys or not os.path.isdir(cwd):
            continue
        seen.add(cwd)
        out.append(cwd)
    return out


def kitty_relaunch_missing(saved, live):
    """The kitty plugin's relaunch: reopen a non-mux kitty window (identity
    'kitty:<cwd>') that was open at the last snapshot but is not on screen, as a
    plain shell in that cwd. Deduped by cwd; skips one a live window shows."""
    n = 0
    sizes = saved_sizes(saved)
    for cwd in kitty_candidates(saved, live_keys(live)):
        _spawn_kitty(cwd, sizes.get(f"kitty:{cwd}"))
        n += 1
        _announce(f"launch  kitty {cwd}")
    return {"kitty"} if n else set()


# --- the DEFAULT relaunch: any app, from the freedesktop registry ---------
# THE GOAL IS EVERYTHING YOU LEFT OPEN COMING BACK, and until now an app no
# plugin claimed came back only if you reopened it yourself. calibre was the
# case that prompted this: usher remembers its slot perfectly and had no way
# to start it.
#
# THE ONLY COMMAND usher EVER RUNS IS AN `Exec=` OUT OF A DESKTOP FILE IT
# READ. That invariant comes from the session-start seam and it is what makes
# a generic relaunch safe rather than reckless. The obvious alternative,
# replaying /proc/<pid>/cmdline, was measured and is worse in four ways:
#
#   chrome REWRITES its own argv into one space-joined string
#   kitty's cmdline carries the -o initial_window_* flags USHER injected
#   all six chrome windows report ONE pid, so it is a per-APP fact anyway
#   a one-off `loupe /tmp/x.png` would reopen a file that is gone
#
# A desktop entry has none of those problems, and its field codes (%U, %f) are
# a FEATURE: stripping them is exactly the no-document launch we want.
#
# IT IS NOT A PLUGIN IN THE REGISTRY, and that distinction is load-bearing.
# `owns()` gates identity as well as relaunch, and `is_unique()` reads
# `is_owned()` to decide whether an app may key by app_id ALONE. A catch-all
# plugin would therefore make is_owned true everywhere, flip every unowned app
# off its app_id-only key, and silently invalidate those slots: Signal is
# stored as `signal\0` today and would become title-keyed. So this is
# plugin-SHAPED (same hooks, same contract) and consulted only for windows no
# plugin claimed. A specific plugin overrides it by claiming the app, which is
# what the registry already does.
DESKTOP_DIRS = ("/usr/local/share/applications", "/usr/share/applications",
                "~/.local/share/applications",
                "/var/lib/flatpak/exports/share/applications",
                "/var/lib/snapd/desktop/applications")

# The field codes a launcher is required to substitute or drop. We launch with
# NO document, so every one of them is dropped, which is the whole reason this
# cannot reopen a file that has since been deleted.
_FIELD_CODES = ("%f", "%F", "%u", "%U", "%d", "%D", "%n", "%N", "%i", "%c",
                "%k", "%v", "%m")


def desktop_entries(dirs=None):
    """{entry name: parsed [Desktop Entry] dict} over the registry.

    MAIN GROUP ONLY. An action group ([Desktop Action new-window]) carries its
    own Name and Exec, and folding those in picks up a command the user did not
    ask for. The greeter work met the same trap and its check for it passed
    for the wrong reason until the fixture carried a key the main group
    lacked."""
    import configparser
    out = {}
    _user_dir = os.path.expanduser("~/.local/share/applications")
    for d in (dirs if dirs is not None else DESKTOP_DIRS):
        for path in sorted(glob.glob(os.path.join(os.path.expanduser(d),
                                                  "*.desktop"))):
            cp = configparser.RawConfigParser(strict=False)
            try:
                cp.read(path, encoding="utf8")
                if not cp.has_section("Desktop Entry"):
                    continue
                d = dict(cp["Desktop Entry"])
                # WHO AUTHORED IT, which decides how NoDisplay is read below.
                # The key is namespaced so it cannot collide with a real
                # desktop key, present or future.
                d["x-usher-user-authored"] = str(path.startswith(_user_dir))
                out[os.path.basename(path)[:-8]] = d
            except Exception:
                continue        # a malformed entry is skipped, never fatal
    return out


def strip_field_codes(ex):
    """An Exec= line as an argv, with the field codes dropped.

    Minimal splitting on purpose: a desktop Exec may quote arguments, and
    shlex handles that, but it must NOT be handed to a shell. We exec a list."""
    try:
        argv = shlex.split(ex)
    except ValueError:
        return []
    return [a for a in argv if a not in _FIELD_CODES]


def desktop_launch_for(app, entries):
    """(argv, why-not) for an app-id: the command that starts it, or why not.

    EVERY REFUSAL IS A CASE MEASURED ON A REAL STORE, not a hypothetical:

      several entries match   never guess, the rule everywhere else here
      no entry                gamescope, gnome-disks, lxqt-policykit-agent
      NoDisplay / Hidden      nm-applet (a tray applet already in autostart)
                              and xdg-desktop-portal-gtk, whose "window" is a
                              transient file dialog a portal opens on demand.
                              THIS FILTER IS THE POLICY: the registry already
                              knows which entries are user-facing, and
                              honouring its own visibility rules is what the
                              greeter resolution does for the same reason.
      Type != Application     a Link or Directory entry is not a program
      Terminal=true           needs a terminal arranged around it, which is a
                              different launch than this one
      argv0 unresolvable      a stale entry pointing at something uninstalled
    """
    low = (app or "").lower()
    if not low:
        return None, "the window has no app-id"
    hits = [(n, e) for n, e in entries.items() if n.lower() == low]
    if not hits:
        # StartupWMClass is the sanctioned reverse join and it is not
        # cosmetic: Signal's app-id is `signal` and its entry is
        # `signal-desktop`, so without this the clearest case fails.
        hits = [(n, e) for n, e in entries.items()
                if (e.get("startupwmclass") or "").lower() == low]
    if not hits:
        return None, "no desktop entry names this app"
    if len(hits) > 1:
        return None, (f"{len(hits)} desktop entries match "
                      f"({', '.join(sorted(n for n, _ in hits))})")
    name, e = hits[0]
    if e.get("type", "Application") != "Application":
        return None, f"{name}.desktop is Type={e.get('type')}, not Application"
    # HIDDEN IS A TOMBSTONE AND IS ALWAYS HONOURED. The spec's words: it
    # means the user DELETED (at their level) something that was present, so
    # a launcher must behave as though the entry does not exist.
    if (e.get("hidden") or "false").lower() == "true":
        return None, f"{name}.desktop is Hidden=true (a deleted entry)"
    # NODISPLAY IS ADVISORY, AND ONLY FOR SOMEBODY ELSE'S ENTRY. The spec says
    # it means "this application exists, but don't display it in the menus",
    # which says nothing about launching. Reading it as "do not start this" is
    # a REPURPOSING, and it is a good one for a SYSTEM entry: there, hidden
    # correlates almost perfectly with not-an-app (nm-applet is a tray applet
    # already in autostart, xdg-desktop-portal-gtk is a D-Bus service whose
    # window is a transient dialog), and those are exactly what must not be
    # started at login.
    #
    # In the user's OWN applications dir that correlation does not hold: an
    # entry there is the user's declaration, and the obvious reason to author
    # one with NoDisplay is to let usher relaunch a CLI-launched app WITHOUT
    # cluttering the app menu. Refusing it second-guesses the only person who
    # knows. The DIRECTORY is the authorship signal, so it is what decides.
    if (e.get("nodisplay") or "false").lower() == "true":
        if e.get("x-usher-user-authored") != "True":
            return None, (f"{name}.desktop is NoDisplay=true: the registry "
                          f"says it is not a user-facing app")
    if (e.get("terminal") or "false").lower() == "true":
        return None, f"{name}.desktop needs a terminal (Terminal=true)"
    argv = strip_field_codes(e.get("exec") or "")
    if not argv:
        return None, f"{name}.desktop has no usable Exec"
    if not (shutil.which(argv[0]) or os.path.exists(argv[0])):
        return None, f"{name}.desktop Exec names {argv[0]}, which is not here"
    return argv, None


def desktop_relaunch_missing(saved, live, spawn=None, claimed=None):
    """Start any saved app that no plugin claims and that is not running.

    PER APP, NOT PER WINDOW, which falls out of the measurement rather than
    being a simplification: all six chrome windows report one pid, and a
    desktop entry describes an APP. One invocation per missing app, and the
    app brings back whatever windows it brings back."""
    # AN OFF SWITCH, because this STARTS PROGRAMS at session login, which is a
    # bigger behaviour change than anything else usher does by default. Per-app
    # opt-out already exists two ways (a plugin that claims the app overrides
    # it, and usher/exclude drops the window end to end); this is the blunt
    # one, for a box where the whole idea is unwanted.
    if os.environ.get("USHER_NO_DEFAULT_RELAUNCH") == "1":
        return set()
    want = {}
    for w in saved:
        app = w.get("app_id") or ""
        if not app or is_transient(w):
            continue
        # WHOSE APP IS IT. With no `claimed` set this is a RESTORE, where any
        # app a plugin owns is the plugin's to start: it has a recorded
        # command per window and starting it here too would double-launch.
        # With one, the caller has asked each plugin what it actually DID,
        # so the test is that answer rather than the claim. See
        # roster_claimed, and the terminal an owned-but-inactive plugin left
        # unstarted.
        if app in claimed if claimed is not None else is_owned(app):
            continue
        # NOT OURS, NOT OURS TO START. The saved entry carries an app-id and
        # nothing else, so resolving it in OUR desktop registry and running it
        # would open a second, PERSONAL copy of another account's application:
        # a work Slack remembered, a personal Slack started, both on the same
        # desk. `snapshot` stamps `owner` for exactly this.
        if w.get("owner") is not None:
            continue
        want.setdefault(app, w)
    if not want:
        return set()
    have = {app_of(v) for v in live}
    entries = desktop_entries()
    started = set()
    for app, w in sorted(want.items()):
        if app in have:
            continue            # already running; its windows are its own
        argv, why = desktop_launch_for(app, entries)
        if argv is None:
            logline(f"no relaunch for {app}: {why}")
            continue
        _announce(f"launch  {' '.join(argv)}")
        if spawn is None:
            app_spawn(argv, _SPAWN_WATCH)
        else:
            spawn(argv)
        started.add(app)
    return started


# THE SOURCE SEAM. usher can PLACE another account's window (the IPC is
# compositor-side and needs no cooperation from a client usher cannot talk to)
# and it cannot START one: that needs the other account's privilege, which
# usher must not acquire. So it asks, and WHAT IT ASKS FOR IS A TRIGGER.
#
#   usher/source-trigger <SOURCE> capture|resume
#     exit 0        accepted; that account is doing it
#     anything else could not, and usher says so
#
# NO CONTENT CROSSES THIS SEAM, which is its whole security content and was
# the second design rather than the first. The first handed over APP-IDS, and
# that is an escalation: a recognised terminal app-id resolves to a terminal
# on the far side, so the owner could get arbitrary code run as the other
# account, which is exactly what the account boundary exists to prevent. Both
# words here come from a CLOSED SET usher itself defines, so there is nothing
# for the far side to validate and nothing for this side to inject.
#
# THE AUTHORITY MOVED WITH IT. The account decides what it had open and what
# to start, in its own home, which the owner can neither read nor write (see
# `do_source_capture` below, which is what the far side runs). The owner's
# half is now only knowing WHICH ACCOUNTS have windows here, which is the one
# question it can answer and the other cannot.
#
# AND usher NAMES NO MECHANISM. Whether the integrator reaches that account by
# sudo, by a transient unit, or by dropping a request in a shared directory is
# its business, and so is which system account a source name means: that
# mapping is the integrator's vocabulary, not usher's.
SOURCE_TRIGGER_HOOK = config_path("source-trigger")
SOURCE_ACTIONS = ("capture", "resume")
# How many lines of the far side's own report to relay. Two per app, so this
# is "forty apps", which is far past any real roster; the point is that the
# bound exists rather than that it is tight, since a truncated report reads
# as work that did not happen.
SOURCE_RELAY_LINES = 80
# The line prefix a source uses to report one of its own windows, and how
# much of the digest to carry. 16 hex is 64 bits, which is far past collision
# risk over the handful of windows one account has open.
SOURCE_WINDOW_WORD = "window"
SOURCE_REKEY_WORD = "rekey"
FINGERPRINT_LEN = 16
# How often, at most, to ask one source to identify its windows again. The
# ask is a sudo subprocess, and a window that can NEVER be identified
# (incognito) would otherwise make a loop out of asking about it.
SOURCE_REFRESH_EVERY = 60
# How long that account's window set must be UNCHANGED before asking. The
# ask is a capture, which replaces its roster, so asking mid-login would
# record a partial desk. 10s against a measured restore that reaches its
# last placement in 2s median and 9s at p90 across both boxes' whole logs.
SOURCE_SETTLE = 10


def title_fingerprint(title):
    """An OPAQUE, stable handle for a window title. PURE.

    This is how the owner and another account agree on WHICH window they are
    both looking at without a readable title crossing the boundary: each side
    hashes the LIVE title it can already see for itself. The owner reads it
    off the compositor, the source off its own toplevel list, and neither
    learns anything from the other that it did not already have.

    HASHING THE LIVE TITLE ON BOTH SIDES is what makes this work where
    hashing a RECORDED one would not: Chrome writes a title at navigation
    time, so its session file disagrees with the screen for hours at a
    stretch (measured, 2026-10-09). Both sides read the same live string
    instead, so the only staleness left is the interval between the two
    reads.
    """
    return hashlib.sha256(
        (title or "").encode("utf-8", "replace")).hexdigest()[:FINGERPRINT_LEN]


def source_window_lines(rows, resolve=None, chrome_test=None):
    """`window <fingerprint> <identity>` for each of THIS account's windows
    that it can resolve to a per-window identity. PURE given its two seams.

    WHY THE SOURCE HAS TO ANSWER THIS AT ALL: several windows of one app
    share one key on the owner's side, because the handle that tells them
    apart lives in the app's own state and that state is inside a home the
    owner may not read. This account CAN read it, so it is the only thing
    that can say which window is which, and it says so in terms (a digest
    and an opaque id) that disclose nothing.

    GATED ON THE APP, because the resolver joins against ONE app's recorded
    state: handing it a terminal's title would match by coincidence or not at
    all, and a coincidence here is a wrong slot that sticks.
    """
    res = chrome_window_for if resolve is None else resolve
    is_br = is_chrome if chrome_test is None else chrome_test
    out = []
    for r in rows:
        title = r.get("title") or ""
        if not title or not is_br(r.get("app_id") or ""):
            continue
        try:
            ident = res(title)
        except Exception:                                  # noqa: BLE001
            ident = None
        if ident:
            out.append(f"{SOURCE_WINDOW_WORD} {title_fingerprint(title)} "
                       f"{ident}")
    return out


def source_rekey_lines(hist=None, tabs=None, bind=None):
    """`rekey <old> <new>` for THIS account's own browser restart.

    A SessionID is per browser RUN, so every per-window key the owner stored
    for this account before a restart names a dead id. The owner cannot do
    the join that fixes that: it needs this account's two session files, and
    they are in a home it may not read. So the account does it, with exactly
    the machinery `rekey_chrome` uses on the owner's own store, and reports
    the binding as a pair of opaque ids.

    THE PAIRS ARE REPORTED UNFILTERED, because only the owner knows which of
    its stored keys are stale. Reporting more than it needs costs a line;
    guessing on this side would need the owner's store.

    NOTHING BINDS UNLESS THE TAB SETS AGREE, which is `chrome_bind_windows`'s
    own more-than-half rule, and not binding is the safe outcome: the slot
    stays where it is and ages out on the TTL.
    """
    _hist = session_history if hist is None else hist
    _tabs = chrome_window_tabs if tabs is None else tabs
    _bind = chrome_bind_windows if bind is None else bind
    cur, prev = {}, {}
    for files in (_hist() or {}).values():
        if not files:
            continue
        cur.update(_tabs(files[0]))
        for f in files[1:]:
            for w, urls in _tabs(f).items():
                prev.setdefault(w, urls)     # the newest previous file wins
    # NO EMPTY-SIDE GUARD HERE, deliberately: `chrome_bind_windows` already
    # answers {} when either side is empty (measured), so one would be dead
    # code, which a planted regression removing it demonstrated by changing
    # nothing. `rekey_chrome` keeps its own because there the early return
    # also skips building a dict over the whole store.
    return [f"{SOURCE_REKEY_WORD} {chrome_slot(old)} {chrome_slot(new)}"
            for old, new in sorted(_bind(cur, prev).items())]


def parse_source_rekey(text):
    """{old identity: new identity} out of a source's report. PURE.

    BOTH SIDES VALIDATED, for the same reason the window map's identity is:
    these rewrite store KEYS, so a source that reported anything else would
    be editing the owner's store in a shape the owner never chose.
    """
    out = {}
    for ln in (text or "").splitlines():
        parts = ln.split()
        if (len(parts) == 3 and parts[0] == SOURCE_REKEY_WORD
                and is_chrome_slot(parts[1]) and is_chrome_slot(parts[2])
                and parts[1] != parts[2]):
            out[parts[1]] = parts[2]
    return out


def rekey_source(kb, src, binding):
    """Move `src`'s per-window slots onto the ids its browser has NOW, and
    return how many moved.

    THE SAME THREE CONSERVATISMS AS `rekey_chrome`, because this rewrites
    the store too: a slot the current session already knows is left alone
    (its own answer is at least as good), a second run is a no-op, and a
    pair that does not match anything stored changes nothing.

    AND ONLY THIS SOURCE'S KEYS, which the prefix decides. A source
    reporting a binding can move its own windows' slots and can never touch
    the owner's or another account's.
    """
    if not binding:
        return 0
    moved = 0
    for k in list(kb):
        app, _, ident = k.partition("\x00")
        if not ident.startswith(src + ":"):
            continue
        new = binding.get(ident[len(src) + 1:])
        if not new:
            continue
        newkey = kkey(app, f"{src}:{new}")
        if newkey in kb:
            continue
        e = kb.pop(k)
        # "title" in a kb entry is the KEY-title, i.e. the identity, which
        # is the trap this file keeps falling into. It moves with the key.
        e["title"] = f"{src}:{new}"
        kb[newkey] = e
        moved += 1
    return moved


def source_refresh_plan(live, last, now, seen=None,
                        every=SOURCE_REFRESH_EVERY, settle=SOURCE_SETTLE):
    """Which sources to ask to identify their windows, and the updated
    stability state. PURE, returning (sources, seen).

    DEMAND-DRIVEN: asked only where a source has a window whose per-window
    identity we do not have, so a desk where everything is identified never
    asks at all and a settled session makes no subprocess.

    AND ONLY ONCE THAT ACCOUNT'S WINDOW SET HAS STOPPED CHANGING, which is
    the constraint that shapes this. The ask is a `capture`, and a capture
    REPLACES the roster with what is live, so asking while a login is still
    bringing windows up records a partial desk. The next logoff capture
    normally repairs that and CAN REFUSE (a source whose display socket has
    already gone), and then the partial roster is what the NEXT login
    restores from.

    THE FIRST VERSION TESTED THE OWNER'S EXPECTATION INSTEAD, requiring
    every app SAVED for that source to be live, and it never fired at a
    login: measured on manifold, 9 of that account's 14 saved apps are Wine
    installers and dialogs that never come back, so the feature was silently
    off at exactly the event it exists for. A test that can block forever is
    the wrong shape for a precondition; `settle` is bounded by construction.

    NOR IS THE REPEAT A SAFETY NET, which is why the bound has to be here:
    after one successful ask every window is identified, so demand goes
    false and nothing asks again. There is no second chance to correct a
    partial roster with.
    """
    seen = dict(seen or {})
    want, have = set(), {}
    for w in live:
        src = w.get("source")
        if not src:
            continue
        have.setdefault(src, set()).add(w.get("app_id") or "")
        if is_chrome(w.get("app_id") or "") and (w.get("key") or "") == src:
            want.add(src)
    out = []
    for src in sorted(want):
        apps = frozenset(have.get(src, set()))
        was, since = seen.get(src, (None, now))
        if apps != was:
            seen[src] = (apps, now)      # changed: start the clock again
            continue
        if now - since < settle:
            continue
        if now - last.get(src, 0) < every:
            continue
        out.append(src)
    # A SOURCE WITH NOTHING WANTED KEEPS NO CLOCK, so its windows arriving
    # later start one fresh rather than inheriting a stale "stable since".
    for src in list(seen):
        if src not in want:
            del seen[src]
    return out, seen



# source -> {old identity: new identity}, as last reported and NOT yet
# applied. The worker owns the store, so the trigger records the binding
# here and the worker drains it.
_SOURCE_REKEY = {}


def take_source_rekey(src):
    """The binding `src` last reported, removing it. Draining rather than
    reading, because applying it is a one-shot edit to the store and a
    binding left behind would be re-applied on every pass."""
    return _SOURCE_REKEY.pop(src, {})


def parse_source_windows(text):
    """{fingerprint: identity} out of a source's own report. PURE.

    LENIENT BY DESIGN, because this shares a channel with prose a human
    reads: anything that is not exactly the three-word shape is somebody
    else's line and is skipped rather than being an error.

    AND THE IDENTITY SHAPE IS VALIDATED HERE, which is what makes the
    opacity OURS rather than the far side's to honour. These identities
    become store keys and reach `watch.log`, so a source that reported a
    window TITLE instead of a slot would reinstate the very leak the digest
    exists to avoid. Enforcing the shape on arrival means a buggy or hostile
    source can withhold an identity and can never inject one.
    """
    out = {}
    for ln in (text or "").splitlines():
        parts = ln.split()
        if (len(parts) == 3 and parts[0] == SOURCE_WINDOW_WORD
                and is_chrome_slot(parts[2])):
            out[parts[1]] = parts[2]
    return out


# source -> {fingerprint: identity}, as last reported. Filled only by an
# explicit trigger: `resolution` must stay cheap enough for every event, so
# it reads this and never asks the far side itself.
_SOURCE_WINDOWS = {}
# (source, view id) -> identity, resolved ONCE for the life of that view.
# Same reason chrome's own `_slot_cache` exists: a title changes constantly
# and the window behind it does not, so re-deriving per event would make the
# key as volatile as the string. Dropped on view-unmapped.
_SOURCE_SLOT = {}


def set_source_windows(src, mapping):
    """Record what a source last said about its own windows."""
    _SOURCE_WINDOWS[src] = dict(mapping or {})


def forget_source_window(vid):
    """Drop a view's remembered identity. Called on view-unmapped, because a
    cache that only grows is a leak in a process that runs for weeks."""
    for k in [k for k in _SOURCE_SLOT if k[1] == vid]:
        del _SOURCE_SLOT[k]


def source_window_identity(src, v):
    """Which of `src`'s windows this view is, or None.

    STICKY ON SUCCESS, never on failure: a window the source has not
    reported yet is retried, and one it has is answered the same way for the
    life of the view even after its title moves on.
    """
    vid = v.get("id")
    if vid is not None and (src, vid) in _SOURCE_SLOT:
        return _SOURCE_SLOT[(src, vid)]
    fps = _SOURCE_WINDOWS.get(src) or {}
    if not fps:
        return None
    ident = fps.get(title_fingerprint(v.get("title") or ""))
    if ident and vid is not None:
        _SOURCE_SLOT[(src, vid)] = ident
    return ident


def source_window_report(views, windows):
    """How many of this source's windows the owner can now tell apart. PURE.

    A MEASUREMENT RATHER THAN A SILENT CAPABILITY, because the join rate is
    the whole question: the two sides hash a live title each, and whether
    those strings agree in practice is not something to assume. It is
    reported per source so a rate of zero cannot read as "no such windows".
    """
    out = []
    for src in sorted(windows):
        fps = windows[src]
        mine = [v for v in views if source_of(v) == src
                and is_chrome(app_of(v))]
        hit = sum(1 for v in mine
                  if title_fingerprint(v.get("title") or "") in fps)
        out.append(f"{src}: {hit} of {len(mine)} window(s) identified "
                   f"({len(fps)} reported)")
    return out


def source_trigger_plan(rows):
    """The sources named by these windows, sorted. PURE.

    A SOURCE WITH NOTHING HERE IS NOT TRIGGERED AT ALL, which is what keeps a
    box with no enclaves silent and keeps usher from waking an account the
    human has never used on this desk.
    """
    return sorted({s for s in (source_of(w) for w in rows) if s})


def source_trigger(sources, action, run=None, hook=None, windows=None):
    """Ask each source to capture or resume ITSELF. Returns how many accepted.

    NEVER FATAL AND NEVER SILENT. A missing hook is reported only when there
    is something it would have been asked, so a box with no other accounts
    gains no new line at every login, and a box with them never loses the
    reason nothing came back.

    `windows`, when given, is FILLED IN with {source: {fingerprint: identity}}
    from each report. An out-parameter rather than a second return value
    because the int return is what two callers read and what every check
    asserts on, and widening that for data most callers do not want is the
    shape this tree bans two copies of.
    """
    if action not in SOURCE_ACTIONS:
        raise ValueError(f"source_trigger: no such action {action!r}")
    if not sources:
        return 0
    path = SOURCE_TRIGGER_HOOK if hook is None else hook
    if not path or not os.access(path, os.X_OK):
        for src in sorted(sources):
            logline(f"cannot ask {src} to {action}: no source-trigger hook "
                    f"at {path}, and usher has no privilege to act as "
                    "another account")
        return 0
    n = 0
    for src in sorted(sources):
        try:
            r = (subprocess.run if run is None else run)(
                [path, src, action], capture_output=True, text=True,
                timeout=30)
        except Exception as e:                                 # noqa: BLE001
            logline(f"source-trigger {action} for {src} failed: {e}")
            continue
        if r.returncode != 0:
            logline(f"source-trigger {action} for {src} refused (rc "
                    f"{r.returncode}): {(r.stderr or '').strip()[:160]}")
            continue
        _announce(f"asked {src} to {action}")
        # AND RELAY WHAT IT SAID, which is not a nicety: the far side writes
        # its own watch.log inside a home THIS user cannot read, so dropping
        # its stdout on success leaves no record here at all of what happened.
        # "asked titan to resume" with nothing after it is indistinguishable
        # from a resume that found no roster, refused every app, or launched
        # something that died, and those are exactly the cases somebody reads
        # this log to tell apart.
        #
        # SAFE TO RELAY, checked rather than assumed: the far side prints
        # APP-IDS and desktop `Exec=` commands and never a window title, and
        # both are already in the owner's store. A title would be that
        # account's content and is redacted at the source.
        #
        # THE TWO STREAMS NEED DIFFERENT CAPS, and one cap for both HID HALF
        # OF A REAL RESUME: the far side prints two lines per app, so a
        # four-app roster emits eight and a cap of four relayed the first two
        # apps. Measured on manifold 2026-11-03, where the log read as two
        # launches while four windows came back, which is the shape that
        # invites a hunt for a mystery there is none of.
        #
        # So stdout is capped at what the far side can legitimately say, which
        # the ROSTER bounds (two lines per app, and an account runs tens of
        # apps at most), while stderr stays tight because nothing bounds it: a
        # traceback or a chatty provider must not turn the log into the
        # problem. stderr is relayed at all because "worked, with a complaint"
        # is a case a bare rc hides.
        _w = parse_source_windows(r.stdout)
        if _w:
            # RECORDED WHETHER OR NOT THE CALLER ASKED, because the cache is
            # what `resolution` reads and the caller's interest in the map is
            # a separate question from the daemon needing it.
            set_source_windows(src, _w)
            if windows is not None:
                windows[src] = _w
        _rk = parse_source_rekey(r.stdout)
        if _rk:
            # LEFT FOR THE WORKER, which owns the store. Merged rather than
            # replaced, so a binding reported while the previous one is still
            # undrained is not lost.
            _SOURCE_REKEY.setdefault(src, {}).update(_rk)
        for _stream, _txt, _cap in (("", r.stdout, SOURCE_RELAY_LINES),
                                    ("stderr: ", r.stderr, 4)):
            _lines = (_txt or "").strip().splitlines()
            for _ln in _lines[:_cap]:
                logline(f"  {src} {action}: {_stream}{_ln.strip()[:150]}")
            if len(_lines) > _cap:
                logline(f"  {src} {action}: {_stream}... and "
                        f"{len(_lines) - _cap} more line(s)")
        n += 1
    return n


# --- the OTHER side of that seam: this account's own roster ----------------
# Everything above is the OWNER asking a source to act. These two verbs are
# what the source RUNS, as itself, and they are the half that makes the ask
# safe: the record of what an account had open is written BY that account, in
# its own home, which the owner can neither read nor write. So the owner
# supplies a TRIGGER and never CONTENT, and cannot introduce an app the human
# did not run inside the enclave. An app-id list crossing the boundary was the
# first design and it was an escalation: a recognised terminal app-id resolves
# to a terminal, and arbitrary code as the enclave user is exactly what the
# account boundary exists to prevent.
#
# A ROSTER AND NOT A LAYOUT, because that is all there is to be had. NO
# WAYLAND PROTOCOL EXPOSES A WINDOW'S POSITION, not even to the window's own
# client (`xdg_toplevel.configure` is width, height and states), and the
# compositor that does know is reachable only over an IPC socket sitting in
# the session user's 0700 runtime dir. So this side can neither read a
# position nor act on one, and the owner doing all the placing is the only
# split available. Hence two verbs of their own rather than `save` and
# `restore` meaning something different depending on who typed them: one name
# for two operations is the split this package already made once.
# NOT because of the security-context allowlist, which an earlier version of
# this comment cited: that filters wayland GLOBALS and never governed the IPC
# socket at all.
#
# PLACEMENT IS STILL THE OWNER'S, and nothing here duplicates it. The owner's
# daemon sees every window on the desk, enclave windows included, and already
# keys and places them by source. This only ever STARTS things.
#
# NO ARGUMENTS, EVER. Both verbs discover everything: who they are from the
# euid, which windows are theirs from the compositor's own filtering, what to
# start from their own roster. That is what lets the sudoers grant name a
# fixed command with no wildcard and nothing to validate.
ROSTER_VERSION = 1


def roster_path():
    return os.path.join(STATE, "roster.json")


def save_roster(apps, when=None, path=None):
    """Record which apps this account has open. Returns what was written."""
    kept = sorted({a for a in apps if a})
    p = roster_path() if path is None else path
    os.makedirs(os.path.dirname(p), exist_ok=True)
    write_json(p, json.dumps({"version": ROSTER_VERSION,
                              "when": time.time() if when is None else when,
                              "apps": kept}, indent=2))
    return kept


def load_roster(path=None):
    """(apps, why) from this account's roster.

    THREE STATES AND NOT TWO. An empty list with why == "" means the account
    was captured and had nothing open; why != "" means it could not be read at
    all, and the caller must not start anything on the strength of that.
    """
    p = roster_path() if path is None else path
    try:
        with open(p) as f:
            blob = json.load(f)
    except FileNotFoundError:
        return [], (f"no roster at {p}, so this account has never been "
                    "captured: nothing can be brought back yet")
    except (OSError, ValueError) as e:
        return [], f"cannot read the roster at {p}: {e}"
    if not isinstance(blob, dict):
        return [], f"the roster at {p} is not an object"
    got = blob.get("version")
    if got != ROSTER_VERSION:
        return [], (f"the roster at {p} is version {got!r} and this usher "
                    f"writes {ROSTER_VERSION}")
    apps = blob.get("apps")
    if not isinstance(apps, list):
        return [], f"the roster at {p} carries no app list"
    return sorted({a for a in apps if isinstance(a, str) and a}), ""


def roster_plan(saved, live):
    """The apps to start: remembered, and not up now. PURE, so the decision
    is checkable with no compositor and no other account."""
    return sorted({a for a in saved if a} - {a for a in live if a})


def roster_launch(apps, live, spawn=None):
    """Start each remembered app of this account's that is not running.

    THROUGH THE SAME MACHINERY THE OWNER USES, so the standing invariant holds
    on this side too: the only command usher ever runs is an `Exec=` out of a
    desktop file it read. Here that registry is the ENCLAVE'S OWN, which is
    the whole point, since the owner cannot read it and so must not be the one
    resolving an app-id into a command.

    DELIBERATELY NOT `launch_missing`, whose last step asks every OTHER source
    to start its own apps. An account reached through that seam must not reach
    back through it: one enclave triggering another is a loop, and nothing
    here is the owner.

    A ROSTER ROW IS app_id AND NOTHING ELSE, which the plugins already cope
    with correctly rather than by accident: chrome reads `owner` (absent, so
    ours) and falls back to one unnamed launch carrying its restore flags, and
    the terminal plugins key on a recorded `cmd` a roster does not have, so
    they find nothing instead of guessing.
    """
    missing = roster_plan(apps, live)
    if not missing:
        return 0
    saved = [{"app_id": a} for a in missing]
    seen = [{"app-id": a, "pid": -1} for a in live if a]
    n = 0
    # ARMED BEFORE THE PLUGINS RUN, because ChromePlugin starts the browser
    # and that is the app this exists for: arming after the loop covered
    # three of the four and left the main one launching the old way.
    global _SESSION_LAUNCH, _SPAWN_WATCH
    watch = [] if spawn is None else None
    if watch is not None:
        _SESSION_LAUNCH = True
        _SPAWN_WATCH = _spawn_watched(watch)
    # ONE SNAPSHOT OF THE REGISTRY, used for both the loop and the claim,
    # so `started`'s keys and the owner lookup cannot be different objects.
    pl = list(plugins())
    started = {}
    for p in pl:
        try:
            started[p] = p.relaunch_missing(saved, seen)
            n += launched_count(started[p])
        except Exception as e:                                 # noqa: BLE001
            logline(f"relaunch ({getattr(p, 'name', '?')}) error: {e}")
            # A RAISE IS NOT "IT STARTED NOTHING". The plugin may have
            # launched some of its apps before failing, so its claim is left
            # whole and the default does not touch them: the same safe
            # direction `launched_apps` takes for the old contract.
            started[p] = None
    # A RELAUNCHED APP'S STDERR IS KEPT, BRIEFLY, which is the one thing that
    # makes an instant death diagnosable. `desktop_relaunch_missing` sends it
    # to DEVNULL, so an app that starts and exits in 100ms leaves NOTHING
    # anywhere: measured on manifold, four enclave apps died in 0.05 to 0.27
    # seconds with not one line in the journal, and the only way to see it at
    # all was polling /proc from outside.
    #
    # THIS SIDE IS WHERE IT MATTERS, because the enclave's apps are started
    # from a sudo with almost no session environment, where the owner's are
    # started by a daemon that has one. So the failure is plausible here and
    # has never happened there.
    # AN INJECTED SPAWN ALWAYS WINS, which is what keeps the suite from
    # launching anything real: watching is only for the production path.
    try:
        # THE DEFAULT GETS WHAT THE PLUGINS DID NOT START. A roster row is an
        # app-id and nothing else, so a plugin keyed on a recorded command
        # no-ops and its CLAIM would otherwise be the only thing standing
        # between the app and the one mechanism that can start it.
        n += launched_count(desktop_relaunch_missing(
            saved, seen, spawn,
            claimed=roster_claimed(missing, started, pl)))
    except Exception as e:                                     # noqa: BLE001
        logline(f"relaunch (desktop default) error: {e}")
    if watch:
        _report_quick_deaths(watch)
    return n


# ARMED ONLY FOR THIS ACCOUNT'S OWN RESUME. A module flag rather than an
# argument because the two launch sites are SHARED with the owner's restore
# (ChromePlugin's browser start and the registry default), and threading a
# launcher through a plugin's documented `relaunch_missing` signature to say
# one thing would be a worse trade. Safe as a global because `_source-resume`
# is a ONE-SHOT process: it is set once, before anything launches, and the
# daemon never sets it.
_SESSION_LAUNCH = False
# The stderr-keeping spawn, when one is armed. Same reasoning as the flag
# above: the two launch sites are shared with the owner's restore, so the
# enclave-only behaviour is armed here rather than threaded through a
# plugin's signature.
_SPAWN_WATCH = None


def _session_env():
    """The environment a launched app should get, with XDG_RUNTIME_DIR
    DERIVED when we were not told one.

    `sudo` strips the caller's environment (measured: five variants of the
    trigger produced byte-identical app stderr), so an app started from one
    has no runtime dir and therefore no way to reach its own user bus. The
    spec DEFINES that path per uid, so this is a derivation and not a guess,
    and it is only filled in when the directory actually exists.
    """
    env = dict(os.environ)
    if not env.get("XDG_RUNTIME_DIR"):
        cand = toplevels.standard_runtime_dir()
        if os.path.isdir(cand):
            env["XDG_RUNTIME_DIR"] = cand
    return env


def _session_spawn(argv):
    """Start argv inside THIS account's own systemd user session.

    (ok, detail). The point is the ENVIRONMENT: a transient unit is started
    by the account's own user manager and inherits that manager's
    environment, which is the session the account really has. An app started
    as a bare child of a `sudo` inherits almost nothing instead, and dies:
    measured on manifold, Chrome and Slack both chose the X11 ozone backend,
    found no X display, and exited in under 0.3s.

    SO THE ENVIRONMENT IS INHERITED RATHER THAN LISTED, which is the whole
    reason for this shape. Enumerating the variables an app needs would be a
    copy of another component's facts maintained here, and the copy nobody
    looks at is the one that drifts.

    SYNCHRONOUS ON PURPOSE: `systemd-run` registers the unit and returns, so
    its exit status says whether the app was STARTED, which a bare spawn
    cannot tell us at all. A failure here is reported and falls back.
    """
    runner = shutil.which("systemd-run")
    if not runner:
        return False, "systemd-run is not installed"
    try:
        r = subprocess.run(
            [runner, "--user", "--quiet", "--collect", "--"] + list(argv),
            capture_output=True, text=True, timeout=20, env=_session_env())
    except Exception as e:                                     # noqa: BLE001
        return False, f"systemd-run could not run: {e}"
    if r.returncode != 0:
        return False, (f"systemd-run rc={r.returncode}: "
                       f"{(r.stderr or '').strip()[:140]}")
    return True, "started in this account's own session"


def app_spawn(argv, watch=None):
    """THE one place an app is started, so a launch policy has one home.

    Direct and unchanged for the owner's restore, where this process already
    has a full session environment and the current behaviour works. Routed
    through the account's own session manager for a sudo'd enclave resume,
    where it does not and does not.
    """
    if _SESSION_LAUNCH:
        ok, why = _session_spawn(argv)
        _announce(f"  via session: {why}")
        if ok:
            return
    if watch is None:
        subprocess.Popen(argv, start_new_session=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return
    watch(argv)


def _spawn_watched(watch):
    """A spawn that keeps each child's stderr in a temp file for a moment.

    Returns a callable of the shape `desktop_relaunch_missing` expects, and
    records (proc, path, argv) so the caller can report whatever died fast.
    """
    import tempfile

    def _spawn(argv):
        fh = tempfile.NamedTemporaryFile(
            prefix="usher-relaunch-", suffix=".err", delete=False)
        proc = subprocess.Popen(argv, start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=fh)
        fh.close()
        watch.append((proc, fh.name, argv))
    return _spawn


def _report_quick_deaths(watch, grace=3.0, lines=4, width=150):
    """Log the stderr of anything that exited within `grace` seconds.

    ONE BOUNDED WAIT FOR THE WHOLE SET, not one per app, so a login costs a
    few seconds once rather than a few per app. An app still RUNNING is the
    normal case and says nothing: its file is removed and its stderr goes
    nowhere from then on, which is the pre-existing behaviour and the reason
    this cannot grow without bound.
    """
    time.sleep(grace)
    for proc, path, argv in watch:
        rc = proc.poll()
        try:
            if rc is not None:
                # _announce, NOT logline, and this is the whole reason it
                # matters: on the enclave side `logline` writes into THAT
                # ACCOUNT'S state dir, inside a 0700 home the session user
                # cannot open. A death reported only there is reported
                # nowhere a reader can reach. Only STDOUT crosses, because
                # the trigger relays it.
                #
                # MADE THIS EXACT MISTAKE ONE COMMIT AFTER FIXING IT. The
                # relay exists because the far side's log is unreadable, and
                # then the first diagnostic added to the far side used the
                # log. Anything the enclave verbs want a human to see must
                # be announced.
                _announce(f"relaunch DIED rc={rc} within {grace:g}s: "
                          f"{' '.join(argv)[:120]}")
                with open(path, errors="replace") as fh:
                    tail = [ln.strip() for ln in fh if ln.strip()][-lines:]
                for ln in tail:
                    _announce(f"  its stderr: {ln[:width]}")
                if not tail:
                    _announce("  its stderr: (nothing at all)")
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)


def do_source_capture():
    """Record this account's own open apps. Takes no arguments.

    RUN AS THE SESSION USER THIS WORKS AND IS MEANINGLESS, and it is left
    that way deliberately. An unsandboxed client sees every toplevel, so the
    roster would list other accounts' apps, and nothing on the owner's side
    reads a roster at all. `doctor` reports a roster in the owner's state,
    which is how one got noticed, and that is the whole of the protection.

    AN ADVISORY FOR IT WAS BUILT AND REMOVED THE SAME DAY. It tested
    `window_origin(os.getpid())`, which is uid-relative to the CALLER and so
    can never report a process as foreign to itself: it therefore fired on
    the FIRST REAL RUN, through the integrator's own seam, as noise on the one
    path the verb exists for. Being a print rather than a refusal is the only
    reason that was noise instead of a breakage, which is the asymmetry it
    was commented with, paying off within the hour.

    A CORRECT VERSION IS AVAILABLE AND NOT WORTH IT: the source hook does
    answer for a non-window process of an enclave (measured, rc=0 by uid), so
    asking it about our own pid would work, at one subprocess per capture and
    a fresh false positive on any box with no hook. The convenience was for a
    one-time integration that has now happened."""
    rows, why = toplevels.list_toplevels()
    if why:
        print(f"usher: cannot read this account's own windows: {why}",
              file=sys.stderr)
        return EXIT_CANNOT
    apps = sorted({r["app_id"] for r in rows if r["app_id"]})
    # AN EMPTY OBSERVATION NEVER OVERWRITES A REMEMBERED DESK. The ordering
    # discipline is the real protection (capture while the session is intact,
    # THEN tear it down), and this is the backstop for getting it wrong: an
    # enclave captured after its apps are killed records an empty desk, and
    # the next login then restores nothing from a record that looks perfectly
    # valid. That is September's browser-less capture, one account over.
    #
    # IT STILL SELF-CORRECTS, which is what keeps the rule narrow: any
    # observation with at least one window REPLACES the roster wholesale, so
    # an app the human really did close stops coming back at the next capture.
    # Only the all-zero case is refused, and refusing costs at most one
    # unwanted window, where accepting costs the whole restore.
    if not apps:
        had, _why = load_roster()
        if had:
            print(f"usher: this account shows no windows, and its roster "
                  f"remembers {len(had)} app(s), so it is NOT being "
                  f"overwritten: {' '.join(had)}", file=sys.stderr)
            print(f"usher: capture while the session is still intact, "
                  "before anything is torn down.", file=sys.stderr)
            return EXIT_CANNOT
    save_roster(apps)
    print(f"usher: recorded {len(apps)} app(s) for this account"
          + (": " + " ".join(apps) if apps else ""))
    # AND WHICH WINDOW IS WHICH, for the apps where that is answerable here
    # and nowhere else. Printed rather than stored, because the owner cannot
    # read this account's files and the report is what already crosses.
    for _ln in source_window_lines(rows):
        print(_ln)
    # AND HOW THIS ACCOUNT'S OWN IDS MOVED ACROSS ITS LAST BROWSER RESTART,
    # which is what makes the per-window keys survive a login: they name the
    # previous run's ids, and only this side can do the join that rebinds
    # them.
    try:
        for _ln in source_rekey_lines():
            print(_ln)
    except Exception as _e:                                # noqa: BLE001
        # NEVER FATAL: the roster above is the part a restore cannot do
        # without, and a session-file problem here must not cost it.
        print(f"usher: could not bind this account's window ids: {_e}",
              file=sys.stderr)
    return EXIT_OK


def do_source_resume():
    """Start this account's remembered apps. Takes no arguments."""
    apps, why = load_roster()
    if why:
        print(f"usher: {why}", file=sys.stderr)
        return EXIT_CANNOT
    if not apps:
        print(f"usher: this account's roster is empty, so there is nothing "
              "to start")
        return EXIT_OK
    # LIVENESS IS REQUIRED, NOT OPTIONAL. Without it we cannot tell a cold
    # start from a second trigger, and starting a second copy of everything is
    # worse than starting nothing: this is the only path here that acts.
    rows, lwhy = toplevels.list_toplevels()
    if lwhy:
        print(f"usher: cannot see which of this account's apps are already "
              f"running, so it is not starting any: {lwhy}", file=sys.stderr)
        return EXIT_CANNOT
    live = [r["app_id"] for r in rows if r["app_id"]]
    want = roster_plan(apps, live)
    if not want:
        print(f"usher: all {len(apps)} remembered app(s) are already running")
        return EXIT_OK
    n = roster_launch(apps, live)
    print(f"usher: asked for {n} of {len(want)} missing app(s): "
          + " ".join(want))
    return EXIT_OK if n else EXIT_FAIL


def launch_missing(snap=None):
    """Ask every plugin to respawn any of its saved-but-absent windows. Takes
    the last snapshot + the live views ONCE and hands both to each plugin's
    relaunch_missing; sums the counts. Chrome self-restores (its plugin returns
    0); mux reopens terminals.

    PASS THE SNAPSHOT IN. Reading it here is a race the daemon loses: by the
    time the worker reaches its relaunch, its own capture loop has already
    written a snapshot of a session where nothing has mapped yet, so this read
    zero saved windows and relaunched nothing. The caller holds the one taken
    before any of that started. Falling back to a read keeps the one-shot verbs
    working, where nothing else is running to clobber it."""
    saved = ((snap if snap is not None else load_snapshot()) or {}).get(
        "windows", [])
    try:
        live = ipc().list_views(filter_mapped_toplevel=True)
    except Exception:
        live = []
    n = 0
    for p in plugins():
        try:
            n += launched_count(p.relaunch_missing(saved, live))
        except Exception as e:
            logline(f"relaunch ({getattr(p, 'name', '?')}) error: {e}")
    # THEN THE DEFAULT, for everything no plugin claimed. Last, so a specific
    # plugin always wins: it has already handled its own app by here, and
    # desktop_relaunch_missing skips every is_owned app anyway.
    try:
        # NO `claimed` HERE, DELIBERATELY: this is a restore, where a
        # plugin owning an app really is the thing that starts it, from a
        # recorded command per window. Passing the roster's policy would
        # have the default spawn a BARE kitty at $HOME for a saved terminal
        # whose cwd is unreadable, where today it spawns nothing.
        n += launched_count(desktop_relaunch_missing(saved, live))
    except Exception as e:
        logline(f"relaunch (desktop default) error: {e}")
    # AND ANOTHER ACCOUNT IS ASKED TO START ITS OWN. Last, because it is the
    # only one that leaves this process: everything above has already decided
    # about the owner's own windows.
    #
    # DRIVEN BY THE SAVED SNAPSHOT, NOT BY WHAT IS MISSING. Which of that
    # account's apps are absent is ITS question, answered against its own
    # roster and its own live windows, so asking is idempotent and the owner
    # does not need (and must not have) an opinion about the contents.
    try:
        n += source_trigger(source_trigger_plan(saved), "resume")
    except Exception as e:
        logline(f"relaunch (source) error: {e}")
    return n


# --- restoring from a stored snapshot ---------------------------------------
# persist() has always rolled a history ring and a daily milestone, and NOTHING
# ever read either one: 14 days of "how the desk looked that morning" sat on
# disk with no way to ask for it back. These are the read side.

def entries_from_snapshot(snap):
    """kb-shaped entries from a stored snapshot, so a milestone can drive the
    same placement path the knowledge base does.

    Keys come from saved_key (the recorded identity), NOT from re-deriving
    them: the windows are long dead, so /proc-derived identities like kitty's
    cannot be recomputed. A snapshot written before the `key` field existed
    degrades to what its raw title yields, which for terminals will simply not
    match anything: honest, and better than matching the wrong window."""
    windows = snap.get("windows", [])
    counts = Counter(w.get("app_id", "") for w in windows
                      if not w.get("source") and
                      w.get("owner") is None)
    out = []
    for w in windows:
        app = w.get("app_id", "")
        if is_unique(app, counts):
            out.append(kb_entry(w, w.get("title", ""), True, snap["time"]))
            continue
        key = saved_key(w)
        if key:
            out.append(kb_entry(w, key, False, snap["time"]))
    return out


def _spec_to_date(spec, today=None):
    """The milestone DATE a --from spec names, or None if it names none."""
    today = today or date.today()
    if spec == "today":
        return today.isoformat()
    if spec == "yesterday":
        return date.fromordinal(today.toordinal() - 1).isoformat()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", spec):
        return spec
    return None


def _available():
    miles = sorted(os.path.basename(p)[:-5] for p in
                   glob.glob(os.path.join(STATE, "milestones", "*.json")))
    hist = sorted(glob.glob(os.path.join(STATE, "history", "*.json")))
    return miles, hist


def resolve_snapshot(spec):
    """(label, snapshot) for a --from spec. `latest` is the newest rolled
    snapshot (undo a shuffle you just made); a date (or today/yesterday)
    is that day's FIRST snapshot, the stable 'how it looked that morning'."""
    miles, hist = _available()
    if spec in ("list", ""):
        print("milestones: " + (", ".join(miles) or "(none)"))
        print(f"history:    {len(hist)} rolled snapshot(s); `--from latest`"
              " is the newest")
        sys.exit(0)
    if spec == "latest":
        if not hist:
            sys.exit("usher: no history snapshots yet")
        path, label = hist[-1], "latest (history)"
    else:
        d = _spec_to_date(spec)
        if d is None:
            sys.exit(f"usher: unknown --from '{spec}' (want: latest, "
                     f"today, yesterday, or YYYY-MM-DD). Have: "
                     f"{', '.join(miles) or 'no milestones yet'}")
        path, label = os.path.join(STATE, "milestones", f"{d}.json"), d
        if not os.path.exists(path):
            sys.exit(f"usher: no milestone for {d}. Have: "
                     f"{', '.join(miles) or 'none'}")
    try:
        with open(path) as f:
            return label, json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"usher: cannot read {path}: {e}")


def match(live, entries):
    """Greedily match each live window to a knowledge entry, consume-once. An
    app_id-keyed entry matches on app_id alone (unique-app_id apps whose title
    drifts); the rest need an exact identity too (raw title, or, for Chrome,
    the active-tab URL via identity()). Returns (pairs, unmatched_live,
    unmatched_entries)."""
    rem = list(entries)
    pairs, unlive = [], []
    for lv in live:
        app = app_of(lv)
        key = identity(lv)
        src = window_origin(lv.get("pid"))[0] if isinstance(lv, dict) else ""
        idx = next((i for i, e in enumerate(rem)
                    if entry_matches(e, app, key, src or "")), None)
        if idx is None:
            unlive.append(lv)
        else:
            pairs.append((lv, rem.pop(idx)))
    return pairs, unlive, rem


def target_geometry(e, o):
    """The geometry (current-workspace-relative, the frame set_geometry uses)
    that lands entry e on its stored absolute workspace of output o."""
    ow = o["geometry"]["width"] or 1
    oh = o["geometry"]["height"] or 1
    cur = o["workspace"]
    i, j = e["workspace"]
    px, py = e["pos"]
    w, h = e["size"]
    return {"x": (i - cur["x"]) * ow + px, "y": (j - cur["y"]) * oh + py,
            "width": w, "height": h}


def place(sock, view_id, e, o):
    geom = target_geometry(e, o)
    sock.send_json({
        "method": "window-rules/configure-view",
        "data": {"id": view_id, "output_id": o["id"], "geometry": geom,
                 "sticky": bool(e.get("sticky", False))},
    })
    return geom


# How close counts as landed. wayfire reports geometry as floats and a client
# may shave a pixel, so an exact-match test would read a successful placement
# as a failure and re-issue it forever.
PLACE_TOL = 8


def live_holder(holder, vid, live_ids):
    """Does `holder` still own the slot that `vid` is asking for? One of
    "free", "stale" or "held".

    THE LEDGER IS NOT A LEASE, which is the fault this answers. It was
    released only on `view-unmapped`, so a holder whose unmap never reached
    us kept the slot for the whole worker generation and the real window was
    refused FOREVER. Measured on manifold 2026-10-30: calibre's library
    window was refused 18 times over 27 seconds, 22 of those seconds after
    the holder had already left the snapshot, and it ended at wayfire's
    cascade with the capture loop then learning that as its home.

    So liveness is asked of the VIEW LIST, which the placer already reads,
    instead of waiting for an event to arrive.

        holder is None, or it IS us   -> "free"   nobody else holds it
        holder not among live ids     -> "stale"  the holder is gone
        otherwise                     -> "held"   a live window owns it

    NO EVIDENCE REFUSES. An empty `live_ids` means the list could not be
    read, not that every window died, so it answers "held": reading it the
    other way would hand the slot to whoever asked during an IPC blip and
    reintroduce the silent stacking the ledger exists to prevent. Checked
    AFTER the two cheap answers, so a window with no rival is never refused
    for want of a view list.

    LAST-WINS WAS THE OTHER CANDIDATE AND IS WORSE. It mirrors the same
    failure (a transient mapping LATER would steal the slot from the real
    window) and for two genuine windows it restores the perfect stacking of
    2026-10-05. Precedence stays first-wins; only liveness changes.
    """
    if holder is None or holder == vid:
        return "free"
    if not live_ids:
        return "held"
    return "held" if holder in live_ids else "stale"


def placement_landed(v, e, o, tol=PLACE_TOL):
    """Did view v actually END UP on the slot e asks for, on output o?

    A placement is a REQUEST and the compositor may ignore it. wayfire's own
    `place` plugin assigns a position to every newly-mapped view, so one that
    runs after usher simply overwrites the slot.

    "DID MY OWN REQUEST LAND" IS A DIFFERENT QUESTION from "did usher move it
    or the human", and a far easier one: a read-back a moment after issuing
    cannot be confounded by a person, because nobody drags a window in 600ms.

    THE SIZE IS DELIBERATELY NOT COMPARED. A client may legitimately refuse a
    size (kitty rounds to whole cells and adds padding), and that is not
    evidence the placement failed. The workspace and the position are what a
    placement is for, and what a lost race destroys.
    """
    if v is None or not e or not o:
        return False
    # Ask the output question BEFORE place_of, whose no-such-output fallback
    # answers ws[0, 0] with the raw geometry as the position, which reads
    # exactly like a real answer.
    #
    # AGAINST THE OUTPUT WE AIMED AT, not against the name in the entry. Those
    # differ exactly when a slot resolved through its PANEL onto a connector
    # that has been renamed, which is the case entry_output exists for;
    # comparing the stored name there would read a correct placement as failed
    # and burn the whole retry budget re-issuing it.
    if o is None or v.get("output-name") != o.get("name"):
        return False
    got = place_of(v, {o["name"]: o})
    if [int(n) for n in got["workspace"]] != [int(n) for n in e["workspace"]]:
        return False
    return (abs(got["pos"][0] - e["pos"][0]) <= tol and
            abs(got["pos"][1] - e["pos"][1]) <= tol)


def apply_fullscreen(sock, view_id):
    """Put a just-restored window back into fullscreen.

    ONLY EVER SET, NEVER CLEARED, exactly as apply_invert is. A remembered
    entry saying "not fullscreen" is not evidence that a window which IS
    fullscreen should be dragged out of it: the human may have pressed F11
    ten seconds ago, and this runs once per map, so it cannot fight them.

    AFTER place(), not instead of it. A fullscreen window's captured geometry
    is the whole output, so the geometry alone makes it LOOK right while
    leaving the window not actually fullscreen: no decoration change, and the
    state lost on the next toggle. Best effort, like every other restore step:
    an IPC hiccup must never abort the rest of a restore."""
    try:
        sock.set_view_fullscreen(int(view_id), True)
    except Exception as e:
        logline(f"fullscreen apply error (view {view_id}): {e}")


def apply_invert(sock, view_id):
    """Re-apply the colour-invert shader to a just-restored window, then record
    the view's new id in toggle_invert_focused's store so the two mechanisms
    share one registry (a later Super+N un-inverts on the first press). Both
    halves are best-effort: a filters/IPC hiccup must never abort a restore."""
    try:
        WPE(sock).set_view_shader(int(view_id), INVERT_SHADER)
    except Exception as e:
        logline(f"invert apply error (view {view_id}): {e}")
        return
    try:
        st = load_inverts()
        st[str(view_id)] = INVERT_VALUE
        write_json(INVERT_STORE, json.dumps(st))
    except OSError as e:
        logline(f"invert store write error: {e}")


def _unlayout_split(unlayout, recorded=None):
    """(still listed, unreachable) over the remembered-but-not-live entries.

    A dry run on a browsing box is 185 UNMATCHED-LAYOUT lines against 12 of
    signal (manifold, 2026-10-13), so the one UNMATCHED-LIVE row that means
    something is buried. Collapsing is presentational only: the header count
    stays the true total.

    COLLAPSE ONLY WHAT CANNOT MATCH, WHICH IS A PROOF AND NOT A HEURISTIC.
    A chrome slot whose SessionID no session file on disk names can never be
    matched again (see recorded_window_ids). Everything else is listed:
    a title, an app-id or a kitty cwd matches again the moment such a window
    opens, and a chrome id a file still names is one rekey_chrome may bind,
    so neither is ours to hide.

    NO EVIDENCE COLLAPSES NOTHING. An empty `recorded` means no session file
    was parsed, not that every slot is dead, and reading it the other way
    would hide exactly the slots a browser about to start is going to claim."""
    recorded = recorded_window_ids() if recorded is None else recorded
    if not recorded:
        return list(unlayout), []
    listed, gone = [], []
    for e in unlayout:
        key = e.get("title") or ""
        if (is_chrome_slot(key)
                and int(key.rsplit(":", 1)[1]) not in recorded):
            gone.append(e)
        else:
            listed.append(e)
    return listed, gone


def _restore_report(pairs, live, unlive, unlayout, unplaceable, outs, dry,
                    acted):
    """The summary a restore prints. Lifted out because a restore that places
    nothing and a restore that COULD place nothing look identical until this
    says which, and it is the part most likely to grow."""
    print(f"matched {len(pairs)}/{len(live)}  unmatched-live {len(unlive)}  "
          f"unmatched-layout {len(unlayout)}  "
          f"unplaceable {len(unplaceable)}  "
          f"{'acted ' + str(acted) if not dry else ''}")
    for lv in unlive:
        # THROUGH `log_title`, because this is the one row here that renders a
        # LIVE view's own title. The matched rows are app-id plus geometry and
        # UNMATCHED-LAYOUT is a stored entry's KEY-title, which for another
        # account is already its source name; this row was the exception the
        # 2026-11-02 audit missed, and it printed six of the work account's
        # window titles in full on manifold.
        print(f"  UNMATCHED-LIVE   {app_of(lv)[:20]:20} | "
              f"{log_title(lv)[:42]}")
    listed, gone = _unlayout_split(unlayout)
    for e in listed:
        print(f"  UNMATCHED-LAYOUT {e['app_id'][:20]:20} | {e['title'][:42]}")
    if gone:
        print(f"  UNREACHABLE      {'google-chrome':20} | {len(gone)} slot(s)"
              f" from previous browser runs, ageing out on the TTL")
    have = ", ".join(sorted(outs)) or "none"
    for lv, e in unplaceable:
        print(f"  UNPLACEABLE      {app_of(lv)[:20]:20} | saved on "
              f"{e['output']}, not attached (have: {have})")


PROFILE_MARK = "usher.profile"   # last profile we acted on, per boot


def redisplay_plan(was, now, running):
    """What a display event calls for: "none", "ask" or "here".

    Pure, so the whole table is checkable with no compositor and no hwdp. The
    cell that matters is the first: this hook fires on EVERY output burst (a
    screen blanking and waking, a kanshi reapply, a re-detect), and acting on
    those was a measured mistake, so only a real profile change does anything.

    THE DAEMON DOES THE WORK WHEN THERE IS ONE, because it owns the store and
    the placer; the hook placing windows itself is a second placer with no
    verification. With no daemon there is no service to ask and a one-shot
    restore here is all that can happen, which is the same two-branch shape
    `forget` takes."""
    if not now or was == now:
        return "none"
    return "ask" if running else "here"


def do_transpose():
    """Ask the daemon to TRANSPOSE: sweep the existing windows onto where they
    belong now. The client never sweeps itself, for the reason `reload` does
    not start a daemon: placement is the service's job and the service is the
    one holding the store and the placer's socket.

    REFUSES WITH NO DAEMON rather than reporting success, which is the lesson
    the mode verbs taught: `usher settle` used to write the arm file and print
    `settled to settled` having done nothing, because the clock lives in the
    worker. Nothing was assessed here either, so it is EXIT_CANNOT."""
    if not watcher_pid():
        print("usher: no daemon is running, so there are no windows to "
              "transpose: start one with `usher-mgr watch`", file=sys.stderr)
        return EXIT_CANNOT
    try:
        os.makedirs(os.path.dirname(SWEEP_FILE), exist_ok=True)
        with open(SWEEP_FILE, "w") as f:
            f.write(f"{time.time()}\n")
    except OSError as e:
        print(f"usher: cannot ask for a transpose: {e}", file=sys.stderr)
        return EXIT_FAIL
    print("usher: asked the daemon to transpose (sweep the open windows)")
    return EXIT_OK


def do_display_changed():
    """The display-change entry point, for hwdp's `changed` hook.

    That edge fires on EVERY output burst: a monitor blanking and waking, a
    kanshi reapply, a re-detect, not only when the set of monitors actually
    differs. Re-arming the placing window on each of those was a mistake:
    place means every mapped window is put back where it is remembered, so
    a window deliberately moved during the session would be yanked home every
    time a screen blinked, which is exactly the teleporting the settled state
    exists to prevent.

    So act only on a REAL profile change. The marker lives in the runtime dir,
    so it is per-boot: the first display event after login has nothing to
    compare against and is treated as a change, which is what you want at
    login anyway.
    """
    now = profile_id(fresh=True)
    mark = os.path.join(runtime_dir(), PROFILE_MARK)
    try:
        with open(mark) as f:
            was = f.read().strip()
    except OSError:
        was = ""
    act = redisplay_plan(was, now, watcher_pid())
    if act == "none":
        return 0                     # same monitors; nothing to do, silently
    try:
        with open(mark, "w") as f:
            f.write(now + "\n")
    except OSError as e:
        logline(f"display-changed: cannot record the profile: {e}")
    if act == "ask":
        try:
            os.makedirs(os.path.dirname(REDISPLAY_FILE), exist_ok=True)
            with open(REDISPLAY_FILE, "w") as f:
                f.write(now + "\n")
            logline(f"display changed: profile {was or '(none)'} -> {now}; "
                    "asked the daemon to re-place")
            return 0
        except OSError as e:
            logline(f"display-changed: cannot ask the daemon: {e}")
    logline(f"display changed: profile {was or '(none)'} -> {now}; "
            "no daemon, restoring here")
    try:
        do_restore(dry=False)
    except Exception as e:
        logline(f"display-changed: restore failed: {e}")
    return 0


# Seconds to wait for every app a plugin asked to quit. Bounded on purpose:
# this runs between a human pressing Reboot and the machine rebooting, so it
# must never be the reason that does not happen.
WIND_DOWN_TIMEOUT = float(os.environ.get("USHER_WIND_DOWN_TIMEOUT", 8))


def _wind_down_wait(pids):
    """Wait for everything a plugin asked to quit, under ONE bounded deadline.
    Bounded because this runs between a human pressing Reboot and the machine
    rebooting, so it must never be the reason that does not happen.

    EPERM IS NOT ESRCH, and reading them as one thing is how this reported a
    clean stop it had not performed. `os.kill(p, 0)` answers three ways and
    only two of them used to be distinguished:

        gone            ProcessLookupError (ESRCH, errno 3)   what we waited
                                                              for
        there, not ours PermissionError    (EPERM, errno 1)   NOT gone
        there, ours     no exception

    Measured: against a live process of another uid the probe raises EPERM,
    and against a dead pid ESRCH, so a bare `except OSError` counts a running
    process somebody else owns as having exited. That became reachable the day
    a second account ran its own browser on this display.

    A FOREIGN PID IS REPORTED AND NOT WAITED FOR, rather than waited for and
    then given up on: we can never signal it, so the deadline would be spent
    learning nothing while a human waits to reboot. Its own session is what
    winds it down."""
    if not pids:
        _announce("usher: nothing asked to quit; session captured")
        return 0
    _announce(f"usher: asked {len(pids)} process(es) to quit")
    foreign = set()
    end = time.time() + WIND_DOWN_TIMEOUT
    while time.time() < end:
        alive = []
        for p in pids:
            try:
                os.kill(p, 0)
                alive.append(p)
            except ProcessLookupError:
                pass                     # exited, which is the whole point
            except PermissionError:
                foreign.add(p)           # THERE, and not ours to stop
            except OSError:
                pass
        pids = alive
        if not pids:
            break
        time.sleep(0.2)
    if foreign:
        _announce(f"usher: {len(foreign)} process(es) belong to another "
                  f"user and "
              f"cannot be stopped from here, so they were NOT waited for "
              f"({' '.join(str(p) for p in sorted(foreign))}); that account's "
              f"own session is what winds them down")
    if pids:
        _announce(f"usher: {len(pids)} still running after "
              f"{WIND_DOWN_TIMEOUT:g}s; going ahead anyway")
    elif foreign:
        # NOT "all exited cleanly", which would be the same overclaim one
        # level up: everything we could reach went, and something we could
        # not reach is still there.
        _announce("usher: everything this session owns exited cleanly")
    else:
        _announce("usher: all exited cleanly")
    return 0


def do_wind_down():
    """Bring the session to a clean stop: capture, stand down, let go.

    The counterpart of the relaunch path, and the same shape: each plugin
    knows how to release its own app, exactly as it knows how to bring it back.

    THE ORDER IS THE WHOLE THING:

    1. CAPTURE while the session is still intact. This is the last moment the
       layout is true, and the only snapshot guaranteed to describe a desk
       somebody actually had.
    2. STOP THE WATCHER. Without this it keeps capturing as the apps go away
       and faithfully records a session with no browser in it, which is then
       what the next login restores. The capture above would be overwritten by
       the session dying.
    3. Ask each plugin to release its app, then wait once, bounded.

    Deliberately does NOT reboot, log out, or stop anything else. Power is the
    caller's business; usher's is knowing what the session was and letting it
    go tidily. Always exits 0: a failure here must never strand somebody at a
    machine that will not shut down."""
    try:
        do_capture()
        # THE COUNT, IN THE LOG, because "captured 0 window(s)" is the exact
        # signature of the failure this ordering exists to prevent and the
        # power menu discards this process's stdout entirely.
        _announce("usher: wind-down captured %d window(s) with the session "
                  "still intact"
                  % len((load_snapshot() or {}).get("windows", [])))
    except Exception as e:
        _announce(f"usher: CAPTURE FAILED, winding down anyway: {e}")
    # STEP 1 NOW REACHES ACROSS ACCOUNTS, and the order is the same feature it
    # has always been, one account over. An enclave captured AFTER its apps
    # are killed records an empty desk, and the next login then restores
    # nothing from a record that looks perfectly valid: September's
    # browser-less capture, on somebody else's uid.
    #
    # ASKED FOR THE ACCOUNTS WITH WINDOWS HERE RIGHT NOW, read live rather
    # than from the snapshot just written, because this is the last moment
    # they are true and a stale source would be woken for nothing.
    #
    # BOUNDED AND NEVER FATAL, like every other step here: a source that
    # cannot be reached is logged and the machine still goes down. `usher
    # cleanly` must never be the reason a box will not reboot.
    try:
        _lv = ipc().list_views(filter_mapped_toplevel=True)
        _win = {}
        source_trigger(source_trigger_plan(_lv), "capture", windows=_win)
        # AND SAY WHETHER THE TWO SIDES AGREED, from the one place that holds
        # both: the source hashed the titles IT saw, and whether those are the
        # strings the compositor reports here is a measurement rather than an
        # assumption. A rate reported per source cannot read as "no windows".
        for _r in source_window_report(_lv, _win):
            _announce(f"usher: window identity, {_r}")
    except Exception as e:
        print(f"usher: could not ask other accounts to capture: {e}",
              file=sys.stderr)
    try:
        do_stop()
    except Exception:
        pass
    try:
        live = ipc().list_views(filter_mapped_toplevel=True)
    except Exception:
        live = []
    pids = []
    for p in plugins():
        try:
            pids += list(p.wind_down(live) or [])
        except Exception as e:
            print(f"usher: wind-down ({getattr(p, 'name', '?')}): {e}",
                  file=sys.stderr)
    return _wind_down_wait(pids)


# --- the seated session -------------------------------------------------
# MOVED DOWN FROM cli (2026-10-03) because the DAEMON needs it too, and the
# module edge is one-way: cli imports engine, never the reverse.
#
# WHY THE DAEMON CANNOT JUST USE `loginctl lock-session` WITH NO ARGUMENT:
# that acts on the CALLER's session, which is whatever started it. Under the
# compositor autostart that happens to be the right one; started by hand from
# an ssh shell it is the SSH session, which has no seat, so locking it protects
# nothing. Measured while building this: the daemon's XDG_SESSION_ID was 15,
# the ssh connection. Resolve the seat explicitly instead of inheriting it.
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


# --- locking a summoned session -----------------------------------------
# A LOGIN YOU SUMMONED IS ONE YOU ARE NOT SITTING AT, so `usher cleanly login`
# leaves a logged-in console unattended and unlocked. usher created that
# exposure, so usher owes the lock and, more importantly, owes the WARNING
# when it cannot deliver one. Leaving it to something else means nobody warns.
#
# usher DOES NOT LOCK ANYTHING ITSELF. It asks logind, and whatever the session
# registered as its locker does the work (vigilance here). Same split as "mux
# owns sessions, usher owns windows": a configured lock COMMAND would be a
# second copy of a fact the session already publishes, and the copy nobody
# looks at is the one that drifts.
#
# THE GATE IS CAPABILITY, NOT CONFIGURATION (the user's call, and the sharper
# rule): it does not matter whether a command is written down, it matters
# whether this box can actually be locked. So the answer is MEASURED, not
# declared, and the measurement is the lock itself plus LockedHint read back.
LOCK_WAIT = 8.0            # seconds to wait for LockedHint after asking
LOCKED_MARKER = "usher.locked"
SUMMON_MARKER = "usher.summoned"


def summon_marker():
    """The one path both sides of the summoned contract name. Resolved on
    call, not at import, because runtime_dir() is what the tests sandbox."""
    return os.path.join(runtime_dir(), SUMMON_MARKER)


def arm_summoned():
    """Record that the login about to start was summoned. Best effort: a
    failure here costs the lock and must never stop the login, which is the
    same reasoning as `cleanly`'s refusal never blocking a power action."""
    try:
        with open(summon_marker(), "w") as f:
            f.write("1")
        return True
    except OSError as e:                                   # noqa: BLE001
        print(f"usher: could not record the summon ({e}); the console may "
              "come up UNLOCKED", file=sys.stderr)
        return False


def take_summoned():
    """Was THIS session summoned? Consumed as it is read, like take_mode.

    TWO SOURCES, because the first one stops working the moment the session
    is composed of UNITS rather than a process tree:

        USHER_SUMMONED=1   `usher-greetd` sets it into greetd's session
                           environment, so it reaches the daemon by plain
                           exec inheritance: greetd -> the session command ->
                           the compositor -> the autostart.
        the MARKER         `cleanly login` writes it before exec'ing the
                           provider, in usher's own runtime dir.

    A UNIT IS NOT A CHILD, which is what the marker is for. Under uwsm (or any
    design where the compositor is a `--user` unit) the daemon is started by
    the user manager and inherits the ACTIVATION environment, not greetd's.
    Measured in uwsm 0.25.2: `env_session.conf` carries exactly
    `Varnames.session_specific` (XDG_SEAT, XDG_SEAT_PATH, XDG_SESSION_ID,
    XDG_SESSION_PATH, XDG_VTNR) from the launching context, and everything
    else in a unit's environment is what the env preloader COMPUTES. A
    per-login flag fits none of that, so the env var silently becomes absent
    and a summoned console is left UNLOCKED with nobody at it.

    THE OBVIOUS FIX IS WRONG IN THE OTHER DIRECTION: naming it in a static
    env file makes EVERY console login read as summoned, so usher would lock a
    console the user is sitting in front of. Worse than the gap it closes.

    WRITTEN BY `cleanly login` AS THE USER, not by the root provider, which
    keeps the privilege rule trivial: the file lives in the user's own runtime
    dir beside every other usher marker, so there is no root-owned file in a
    user tree and no user-writable file in a root tree. It is tmpfs, so it
    cannot survive a boot.

    CONSUMED RATHER THAN DATED, and this is the decision worth keeping. A
    freshness window looks like the way to stop a stale marker locking a later
    CONSOLE login, and it cannot work: the interval between the write and this
    read contains A HUMAN TYPING A PASSWORD at the provider's prompt, so any
    timeout tight enough to reject a stale marker is also tight enough to
    reject a real one, and those two errors are not symmetric (a wrong lock is
    an annoyance; a missed one is the exposure this exists to close). One-shot
    consumption bounds the stale case to a single extra lock instead.
    """
    p = summon_marker()
    present = os.path.exists(p)
    if present:
        # BEFORE acting on it, so a crash between here and the lock cannot
        # leave it to be re-consumed by a later login.
        try:
            os.remove(p)
        except OSError:
            pass
    return present or os.environ.get("USHER_SUMMONED") == "1"


def _loginctl(*args, timeout=10):
    """(rc, stdout) from loginctl, or (None, "") if it cannot be run."""
    try:
        r = subprocess.run(["loginctl", *args], capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def lock_plan(have_loginctl, seated, hint, forced=False):
    """What to do about locking a summoned session. PURE, so the whole matrix
    is checkable with no session, no logind and no compositor.

    `hint` is the session's CURRENT LockedHint: "yes", "no", or None when it
    could not be read at all. The asymmetry that drives this: refusing to lock
    costs a lock, and locking the WRONG thing (or believing a lock that did
    not happen) costs the console. So every uncertain cell declines and says
    so, and only `forced` suppresses the complaint.

        loginctl  seated  hint   ->
        no        -       -         "no-loginctl"   cannot ask anyone
        yes       no      -         "no-session"    nothing seated to lock
        yes       yes     yes       "already"       somebody already locked it
        yes       yes     no        "lock"          ask, then VERIFY
        yes       yes     None      "unverifiable"  can ask, cannot confirm
    """
    if not have_loginctl:
        return "no-loginctl"
    if not seated:
        return "no-session"
    if hint == "yes":
        return "already"
    if hint is None:
        return "forced-unverifiable" if forced else "unverifiable"
    return "lock"


def session_locked_hint(sid):
    """The session's LockedHint as "yes"/"no", or None if unreadable.

    ONLY TRUSTWORTHY FOR A LOGIND-INITIATED LOCK, which is what usher does.
    A locker started some other way (wlogout's power menu runs a bare
    swaylock) locks the screen without telling logind, so the hint stays "no"
    over a genuinely locked session. That is a real inconsistency in the
    caller, not here, and it is why this is never read as "is the screen
    locked" in general: only as "did the lock I just requested take"."""
    rc, out = _loginctl("show-session", str(sid), "-p", "LockedHint",
                        "--value")
    if rc != 0:
        return None
    v = out.strip()
    return v if v in ("yes", "no") else None


def _seated_now():
    """(session id, leader) for this user's seated session, or None. One
    place, because lock_now, lock_capability and the summoned-lock marker all
    ask the same question and a second spelling is how they come to differ."""
    import getpass
    rc, out = _loginctl("list-sessions", "--no-legend")
    if rc is None:
        return None
    return seated_session(getpass.getuser(), out)


def lock_capability():
    """(ok, plan, detail): can this box lock its seated session right now?

    Deliberately asks the SAME questions lock_now() will, so a pre-flight
    answer and the real attempt cannot disagree. It genuinely cannot prove a
    LOCKER exists, because logind's Lock is a signal and its subscribers are
    not enumerable, so this is honest about the limit: it reports that a lock
    can be REQUESTED, and the only proof of one being HONOURED is doing it
    and reading the hint back."""
    import getpass
    rc, out = _loginctl("list-sessions", "--no-legend")
    have = rc is not None
    seated = seated_session(getpass.getuser(), out) if have else None
    hint = session_locked_hint(seated[0]) if seated else None
    plan = lock_plan(have, seated, hint)
    detail = {
        "no-loginctl": "loginctl cannot be run, so no lock can be requested",
        "no-session": "no seated login session on the physical display",
        "already": "the seated session is already locked",
        "unverifiable": "LockedHint cannot be read, so a lock cannot be "
                        "confirmed",
        "lock": "a lock can be requested and confirmed",
    }.get(plan, plan)
    return plan in ("lock", "already"), plan, detail


def lock_now(wait=LOCK_WAIT, forced=False):
    """Lock the seated session and VERIFY it took. (locked, plan, detail).

    REPORTS THE END STATE, NEVER THE CALL RETURNING, which is the lesson the
    plymouth core-capture script taught the same week: `loginctl lock-session`
    exits 0 whether or not anything is listening, so its status says nothing
    at all. The hint read back is the only evidence."""
    import getpass
    rc, out = _loginctl("list-sessions", "--no-legend")
    have = rc is not None
    seated = seated_session(getpass.getuser(), out) if have else None
    hint = session_locked_hint(seated[0]) if seated else None
    plan = lock_plan(have, seated, hint, forced=forced)
    if plan == "already":
        return True, plan, "already locked"
    if plan not in ("lock", "forced-unverifiable"):
        _, _, detail = lock_capability()
        return False, plan, detail
    sid = seated[0]
    lrc, _ = _loginctl("lock-session", str(sid))
    deadline = time.time() + wait
    while time.time() < deadline:
        if session_locked_hint(sid) == "yes":
            return True, "locked", f"session {sid} locked and confirmed"
        time.sleep(0.25)
    if plan == "forced-unverifiable":
        return False, "forced-unverifiable", (
            f"asked logind to lock session {sid} (rc {lrc}); LockedHint is "
            f"unreadable, so this is NOT confirmed")
    return False, "not-honoured", (
        f"asked logind to lock session {sid} (rc {lrc}) and LockedHint never "
        f"became yes within {wait:.0f}s: nothing is handling the Lock signal")


def do_lock(forced=False):
    """Lock the seated session, and SAY what happened. Non-zero if it did not.

    A verb of its own because the mechanism has to be checkable by hand: the
    daemon does this at a moment nobody is watching, so "does locking work on
    this box" must be answerable without arranging a summoned login."""
    locked, plan, detail = lock_now(forced=forced)
    print(f"usher: {'locked' if locked else 'NOT locked'} ({plan})")
    print(f"  {detail}")
    if not locked and plan == "not-honoured":
        print("  Nothing is handling logind's Lock signal for this session.")
        print("  On this fleet that is vigilance-logind.service; check it is")
        print("  running, or lock from the desktop once to confirm the path.")
    return 0 if locked else 1


def lock_summoned_session():
    """Lock the console if THIS session was summoned, once per boot.

    WHY HERE AND NOT IN `cleanly login`: that command execs a provider and
    returns before any session exists, so it cannot lock what has not started.
    The daemon runs INSIDE the session and is the first usher code to do so.

    LOCK BEFORE PLACING, because the gap before the lock is the whole
    exposure and placement works perfectly well under one: both a window MOVE
    and the entire relaunch chain have been measured landing against an active
    swaylock.

    ONCE PER SESSION via a runtime marker, because a reload re-execs the
    supervisor and would otherwise lock the user out mid-session on every
    deploy."""
    if not take_summoned():
        return None
    # THE MARKER CARRIES THE SESSION ID, and must: the login user LINGERS on
    # this fleet (so the ssh agent survives the last logout), so
    # XDG_RUNTIME_DIR SURVIVES A LOGOUT and a marker that only asked "does the
    # file exist" would suppress the lock on every summoned login after the
    # first, with no reboot in between, leaving a console open for somebody
    # who is not in front of it. A different session id means not-yet-locked.
    marker = os.path.join(runtime_dir(), LOCKED_MARKER)
    seated = _seated_now()
    sid = seated[0] if seated else ""
    try:
        with open(marker) as f:
            done_for = f.read().strip().split("\n")[-1]
    except OSError:
        done_for = None
    if done_for is not None and done_for == f"session={sid}":
        return None
    locked, plan, detail = lock_now()
    # THE FAILURE IS LOUD AND THE SUCCESS IS NOT SILENT EITHER. An unlocked
    # console after a summoned login is a security state, so it is recorded
    # where the forensic record already lives rather than only on a stdout
    # the autostart discards.
    if locked:
        logline(f"summoned login: locked the console ({plan})")
    else:
        logline(f"summoned login: COULD NOT LOCK THE CONSOLE ({plan}): "
                f"{detail}")
    try:
        with open(marker, "w") as f:
            f.write(f"{plan}\nsession={sid}")
    except OSError:
        pass
    return locked


# --- predict / verify: the only non-circular end-to-end check ------------
# `restore --dry-run` compares the STORE against the SCREEN, so it is CIRCULAR:
# when something teaches the store the wrong answer, both agree and it reports
# everything ok. It did exactly that on manifestor (9/9 ok over a store that
# had been taught a cascade position) and on manifold (ok while two terminal
# slots had been shrunk to kitty's default).
#
# A PREDICTION BREAKS THE CIRCLE BY PREDATING THE EVENT. Record what SHOULD
# come back, reboot, then diff. The reference cannot have been corrupted by
# the thing under test, because it was written before it ran. This is the
# check that made the 2026-10-03 shrink bug a one-line diff instead of an
# argument about what the layout used to be.
PREDICTION = os.path.join(STATE, "prediction.json")


def _prediction_rows():
    """One row per live window: what it IS now and where it SHOULD land.

    Both halves matter. `label` is the RAW title, which is how a chrome window
    is recognised AFTER a restart (its `chrome:win:<id>` key is minted fresh
    by the new browser process, so the key cannot be the only handle). `key`
    is how a TERMINAL is recognised, since `term:resume` is stable across
    restarts where its banner title is not. Verify tries key first, then
    label, and says which one hit."""
    kb = load_knowledge()
    sock = ipc()
    outs = {o["name"]: o for o in sock.list_outputs()}
    panels = panel_map()
    rows = []
    for w in snapshot(sock)["windows"]:
        app = w.get("app_id") or ""
        # An app_id-ONLY key ends in NUL (see kkey / appid_only), which is how
        # a uniquely-identified app like Signal is stored, so both shapes have
        # to be tried or those windows read as having no slot.
        e = next((kb[k] for k in
                  match_keys(app, w.get("key") or "", w.get("source") or "")
                  if k in kb), None)
        # THE RESOLVED output, not the stored name. Those differ exactly when
        # a panel has moved connector, and a prediction quoting the stale name
        # would report every such window as WRONG on the next verify.
        eo = entry_output(e, outs, panels) if e else None
        rows.append({
            "key": w.get("key"),
            "app_id": w.get("app_id"),
            "label": w.get("title"),
            "cmd": w.get("cmd"),
            "expect_workspace": e.get("workspace") if e else None,
            "expect_pos": e.get("pos") if e else None,
            "expect_size": e.get("size") if e else None,
            "expect_output": eo["name"] if eo else None,
        })
    return rows


def do_predict(out=None):
    """Write what the next restore SHOULD produce. Exits 0 always: this
    records, it does not judge."""
    path = out or PREDICTION
    rows = _prediction_rows()
    doc = {"recorded": time.time(), "host": os.uname().nodename,
           "profile": profile_id(), "windows": rows}
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    os.replace(tmp, path)
    noslot = [r["key"] for r in rows if r["expect_workspace"] is None]
    print(f"predicted {len(rows)} window(s) -> {path}")
    print(f"  profile {doc['profile']}  host {doc['host']}")
    if noslot:
        # A window with no slot cannot be predicted, and saying so here beats
        # reporting it as a failure later: it was never going to be placed.
        print(f"  {len(noslot)} with NO remembered slot (will not be placed):")
        for k in noslot:
            print(f"      {str(k)[:60]}")
    return 0


def _verify_find(row, live_by_key, live_by_label):
    """The live window a predicted row refers to, and which matcher found it.

    KEY FIRST, because it is the thing usher actually places on. LABEL second,
    for the apps whose key is only valid within one process lifetime."""
    k = row.get("key")
    if k and k in live_by_key:
        return live_by_key[k], "key"
    lab = (row.get("label") or "").strip()
    if lab and lab in live_by_label:
        return live_by_label[lab], "label"
    return None, None


def do_verify(against=None, tol=2):
    """Diff the live layout against a prediction. Non-zero on any miss.

    TOLERANCE, because an exact pixel match is the wrong bar: kitty rounds to
    whole cells and adds padding, so a window asked for 2138x1672 legitimately
    comes back a pixel or two off (the notes measured 2176x1761 for a 2132x1690
    request). A few pixels is agreement; 1085x672 against 2138x1672 is the bug
    this exists to catch, and no tolerance hides that."""
    path = against or PREDICTION
    if not os.path.exists(path):
        print(f"usher: no prediction at {path}", file=sys.stderr)
        print("usher: run `usher predict` BEFORE the thing you want to "
              "test", file=sys.stderr)
        return EXIT_CANNOT
    doc = json.load(open(path))
    rows = doc["windows"]
    live = snapshot(ipc())["windows"]
    by_key = {w.get("key"): w for w in live if w.get("key")}
    by_label = {(w.get("title") or "").strip(): w for w in live
                if (w.get("title") or "").strip()}

    age = (time.time() - doc.get("recorded", 0)) / 3600.0
    print(f"against {path} ({age:.1f}h old, host {doc.get('host')}, "
          f"profile {doc.get('profile')})")
    if doc.get("profile") != profile_id():
        # The single likeliest reason a whole layout fails to come back, and
        # it is NOT a bug: a different monitor set has its own store, which
        # starts empty. Say it loudly rather than printing 17 failures.
        print(f"  PROFILE CHANGED: predicted {doc.get('profile')}, now "
              f"{profile_id()}")
        print("  A different monitor set has its own (empty) store, so "
              "nothing was placed from the predicted one.")

    ok = miss = moved = noslot = 0
    for r in rows:
        name = (r.get("label") or r.get("key") or "?")[:40]
        if r.get("expect_workspace") is None:
            noslot += 1
            print(f"  skip   {name}  (had no slot when predicted)")
            continue
        w, how = _verify_find(r, by_key, by_label)
        if w is None:
            miss += 1
            print(f"  GONE   {name}")
            continue
        bad = []
        for field, exp in (("workspace", r["expect_workspace"]),
                           ("pos", r["expect_pos"]),
                           ("size", r["expect_size"])):
            got = w.get(field)
            if exp is None or got is None:
                continue
            if any(abs(float(a) - float(b)) > tol for a, b in zip(got, exp)):
                bad.append(f"{field} {got} != {exp}")
        if bad:
            moved += 1
            print(f"  WRONG  {name}  (by {how})")
            for b in bad:
                print(f"           {b}")
        else:
            ok += 1
            print(f"  ok     {name}  (by {how})")

    print(f"verify: {ok} ok, {moved} wrong, {miss} gone, {noslot} unpredicted")
    return 0 if (moved == 0 and miss == 0) else 1


def do_restore(dry, only=None, source=None):
    sock = ipc()
    if source is None:
        entries = list(load_knowledge().values())
        print(f"from the knowledge base (profile {profile_id()})")
    else:
        label, snap = source
        entries = entries_from_snapshot(snap)
        print(f"from milestone {label} ({len(entries)} remembered window(s))")
    live = sock.list_views(filter_mapped_toplevel=True)
    outs = {o["name"]: o for o in sock.list_outputs()}
    # Read ONCE for the whole report, so every line is resolved against the
    # same answer rather than re-asking per entry.
    panels = panel_map()

    pairs, unlive, unlayout = match(live, entries)
    acted = 0
    unplaceable = []
    for lv, e in pairs:
        if only and (only not in (lv.get("title") or "")) \
                and (only not in app_of(lv)):
            continue
        o = entry_output(e, outs, panels)
        if not o:
            # The window matched a remembered slot on an output that is NOT
            # attached right now (undocked, a monitor off, a different desk).
            # Nothing sane to do with it, but SAY SO: skipping in silence is
            # how a layout learned on another monitor set looks like usher
            # simply not working. See `doctor` and the per-profile store.
            unplaceable.append((lv, e))
            continue
        geom = target_geometry(e, o)
        g = lv.get("geometry", {}) or {}
        same = (g.get("x") == geom["x"] and g.get("y") == geom["y"] and
                lv.get("output-name") == o["name"])
        label = f"{app_of(lv)[:18]:18} -> {o['name']} " \
            f"ws{tuple(e['workspace'])} pos{tuple(e['pos'])}" \
            + (" [inv]" if e.get("inverted") else "")
        if dry:
            print(("  ok   " if same else "  MOVE ") + label)
            continue
        if not same:
            place(sock, lv["id"], e, o)
            acted += 1
            print("  placed " + label)
        # Invert follows the WINDOW, not the move. A window Chrome already
        # restored at its target position is matched-but-not-moved, and must
        # still get its inversion back: the "forgets some" bug was applying
        # invert only inside the move branch.
        if e.get("inverted"):
            apply_invert(sock, lv["id"])
            if same:
                print("  inverted " + label)
        if e.get("fullscreen"):
            apply_fullscreen(sock, lv["id"])
            if same:
                print("  fullscreen " + label)

    _restore_report(pairs, live, unlive, unlayout, unplaceable,
                    outs, dry, acted)


# --- place vs settled placement (the anti-whack-a-mole state machine) ----
# Placement is PLACE (place any known, non-excluded window) for a window
# after session start (or a `usher place` kick), then goes SETTLED
# (place ONLY usher/include anchors). A GLOBAL phase, orthogonal to the per-
# view PLACE_GRACE. Settled when the FLOOR has passed AND it has been quiet (no
# new window mapped) for IDLE_SETTLE, but never past the CAP:
#   place := not( (now-armed >= FLOOR and now-last_map >= SETTLE)
#                      or now-armed >= CAP )
# FLOOR is a floor, not a race: activity EXTENDS it, so a staggered restore
# keeps place alive as long as windows keep arriving within IDLE_SETTLE of
# each other, and `usher place` re-arms it by hand whenever that is not
# enough. All three are env-overridable.
#
# MEASURED BEFORE SHORTENING, over both boxes' whole logs (2026-10-30):
# restoration finishes in SECONDS, not minutes. The last placement after a
# daemon start was a median of 2s and a p90 of 7-9s, and the richest cold
# login in either log put TWELVE windows back in one second and was entirely
# done by three. The old 300s floor was sized for a job that takes 3s.
#
# AND THE OUTLIERS WERE NOT RESTORATION, which is what makes shortening safe
# rather than merely cheap: the only placements past 60s in either log were
# terminals the user opened at +67s and +87s, and an nm-applet Wi-Fi auth
# dialog at +386s. A window you open a minute in IS a mid-session window, and
# leaving it where it opens is what `settled` is FOR, so those were place mode
# reaching past its purpose rather than earning its length.
#
# A LATE IDENTITY NO LONGER NEEDS THE CLOCK, which is the other half. `late_ok`
# gives any window that MAPPED during place one placement at first
# identification whatever the clock says, so the slow cases this used to
# cover (a mux latch waiting on ssh, a browser that names a window late) are
# held by that instead. Only a late MAP depends on the floor now.
START_FLOOR = float(os.environ.get("USHER_START_FLOOR", 30))   # 30 s
# HOW BIG A GAP IN ARRIVALS MEANS THE STORM IS OVER, which is a property of
# how APPS SPAWN rather than of how long anyone wants placing. Measured over
# both boxes' logs: inter-arrival gaps during a restore run a median of 0s and
# a p90 of 2s, with a largest real gap of 4-5s (Chrome's own profile stagger
# is 4s, USHER_CHROME_STAGGER). The only larger gaps in either log, 20s and
# 65s, were the human opening terminals a minute after login, which is the
# opposite of a storm. So 15s is three times the widest real gap.
#
# DELIBERATELY NOT DERIVED FROM START_FLOOR, though it is half of it today.
# They answer different questions from different bases, a preference against a
# spawn rate, and a derived knob stops being a knob: this one is public,
# documented and pinned, and the choice is between deleting it or inventing
# "set it to override the derivation", which is worse than either.
IDLE_SETTLE = float(os.environ.get("USHER_IDLE_SETTLE", 15))   # 15 s quiet
PLACE_CAP = float(os.environ.get("USHER_PLACE_CAP", 180))      # 3 min cap

# Runtime seams (ephemeral, like the singleton lock): the kick writes ARM_FILE,
# the worker reads it and publishes STATUS_FILE for `usher status` + the
# (Phase-2) tray gadget.
RUNTIME_DIR = os.environ.get("XDG_RUNTIME_DIR") or STATE
ARM_FILE = os.path.join(RUNTIME_DIR, "usher.arm")
# The tray indicator READS this every second, so the name is a contract with
# usher_indicator.STATUS_FILE and the two must move together. It is runtime
# state under XDG_RUNTIME_DIR, recreated each boot, so renaming it needed no
# migration: an old file simply stops being written and goes at reboot.
STATUS_FILE = os.path.join(RUNTIME_DIR, "usher.status")
# A REQUEST, not a store: `usher forget` writes selectors here and the WORKER
# applies them. The daemon is the only writer of the knowledge base while it
# runs, so asking it to make the edit is the one way to do this with no race;
# editing the file under it loses the edit to the next capture, which rewrites
# the whole store from memory. Consumed and removed, like ADOPT_FLAG.
FORGET_FILE = os.path.join(RUNTIME_DIR, "usher.forget")
# THE SAME SHAPE, for the display-change edge: hwdp's hook writes the new
# profile here and the WORKER does the work. It used to place windows from the
# hook process itself, which is a second placer racing the daemon's, and the
# only placement path that never went through _place_view and so never had its
# read-back verified: that is precisely the condition that lost a placement to
# wayfire's own cascade (see PLACE_VERIFY), running at the one moment the
# compositor is re-laying-out every window it has.
REDISPLAY_FILE = os.path.join(RUNTIME_DIR, "usher.redisplay")
# AND ONE FOR A SWEEP ASKED FOR BY HAND. Separate from the redisplay request
# rather than reusing it with the current profile, because the two mean
# different things: a redisplay RELOADS the store and HOLDS learning while the
# displays settle, where a hand-asked transpose does neither. A request that
# had to claim the profile changed in order to ask for a sweep would be
# lying to the thing it asks.
SWEEP_FILE = os.path.join(RUNTIME_DIR, "usher.sweep")


LOG_CAP = 256 * 1024   # rotate watch.log past this; bounds it to ~2x LOG_CAP


def logline(msg):
    """Append a timestamped line to the daemon's own log. Autostart discards a
    child's stdout/stderr, so without this a death (or a skipped event) is
    invisible, which is exactly how a slow-login crash went unnoticed. Best
    effort: logging must never itself take the daemon down. Rotated at LOG_CAP
    (one generation kept) so a respawn loop cannot fill the disk: the tree
    has a 14G-session-log scar behind that caution."""
    try:
        os.makedirs(STATE, exist_ok=True)
        path = os.path.join(STATE, "watch.log")
        try:
            if os.path.getsize(path) > LOG_CAP:
                os.replace(path, path + ".1")
        except OSError:
            pass
        with open(path, "a") as f:
            f.write(f"{time.strftime('%F %T')} {msg}\n")
    except OSError:
        pass


def pick_socket(names, env=None):
    """Which compositor socket to use, given the candidate paths.

    PURE, so the decision is testable without a compositor. Returns a path, or
    None when there is nothing to pick (the caller lets pywayfire report it).

    AN EXPLICIT WAYFIRE_SOCKET ALWAYS WINS, because someone who set it means it.
    """
    env = os.environ if env is None else env
    if env.get("WAYFIRE_SOCKET"):
        return env["WAYFIRE_SOCKET"]
    if len(names) == 1:
        return names[0]
    if len(names) > 1:
        # A stale socket from a previous session would have us talk to the
        # wrong compositor, or fail in a way that reads like a bug. Say so
        # rather than picking.
        raise RuntimeError(
            f"{len(names)} wayfire sockets present, so which session to use "
            "is ambiguous. Set WAYFIRE_SOCKET and run again: "
            + ", ".join(names))
    return None


# Set by wayfire_socket() when it had to HUNT rather than read the environment,
# so the daemon can log it and doctor can report it. A path, not a bool: the
# directory searched is the useful half of the message.
SOCKET_HUNTED = None
_HUNT_WARNED = False


def _warn_hunted(rundir, found):
    """Say ONCE, on stderr, that the environment was not clean.

    THE FALLBACK WORKING SILENTLY IS HOW THE ORIGINAL BUG HID. A missing
    WAYFIRE_SOCKET is a FAULT IN WHOEVER SET UP THE SHELL, not a normal
    condition, and the cost of papering over it quietly is that nobody fixes
    the shell: usher keeps working, and the next tool that needs the variable
    fails for a reason nobody connects to this.

    stderr, not the log: a CLI verb must not append to watch.log, which is the
    forensic record of what usher did to a session. The daemon has its stdio
    discarded by the compositor autostart, so watch.py logs this separately at
    startup from SOCKET_HUNTED.
    """
    global _HUNT_WARNED
    if _HUNT_WARNED:
        return
    _HUNT_WARNED = True
    print(f"usher: WAYFIRE_SOCKET is unset, so the socket was found by "
          f"searching {rundir}", file=sys.stderr)
    print(f"usher:   using {found}", file=sys.stderr)
    print("usher:   nothing is broken here, but a tool that does NOT search "
          "will fail", file=sys.stderr)
    print("usher:   in this shell. Export it, or have whatever manages this "
          "shell's", file=sys.stderr)
    print("usher:   environment carry it.", file=sys.stderr)


def wayfire_socket():
    """Find the compositor socket: the environment, else the runtime dir.

    PYWAYFIRE DOES NOT FIND IT, which is the whole reason this exists.
    WayfireSocket() reads WAYFIRE_SOCKET and otherwise gives up; its
    `allow_manual_search` searches /tmp ONLY, and this compositor puts its
    socket in XDG_RUNTIME_DIR, so that option cannot help here either.

    WHY IT MATTERS AWAY FROM THE DAEMON: the compositor exports
    WAYFIRE_SOCKET only to what IT starts, so a shell often does not have it,
    and that is exactly where a person types `usher cleanly logoff`.

    DO NOT ASSERT A CAUSE IN THE WARNING. Report what was observed and what
    the reader can do; an inferred cause sends them after a remedy that
    cannot help.

    XDG_RUNTIME_DIR with a /run/user/<uid> default, since that is the standard
    name for the directory and a shell that has lost one may have lost both.
    """
    global SOCKET_HUNTED
    if os.environ.get("WAYFIRE_SOCKET"):
        return os.environ["WAYFIRE_SOCKET"]
    rundir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    found = pick_socket(sorted(glob.glob(
        os.path.join(rundir, "wayfire-*.socket"))))
    if found:
        SOCKET_HUNTED = rundir
        _warn_hunted(rundir, found)
    return found


def ipc():
    """One IPC socket, now, with the path DISCOVERED. For the one-shot verbs.

    `connect` is the daemon's door (it retries while the compositor comes up);
    this is every other caller's. Both exist so that NOTHING ELSE constructs a
    WayfireSocket: five call sites used to do it directly and therefore skipped
    the discovery, which is why `usher cleanly logoff` could not reach a
    compositor that `usher-mgr` was talking to happily. A selftest check now
    asserts these two are the only constructors.
    """
    return WayfireSocket(wayfire_socket())


def connect(retries=25, delay=0.2):
    """Open an IPC socket, retrying while the compositor's socket comes up. At
    autostart the ipc plugin may not have exported WAYFIRE_SOCKET yet, and
    WayfireSocket() raises at once with no retry of its own, so a daemon that
    connects eagerly can die before it ever watches (kanshi-mgr retries the
    same way, ~5s). Only the initial connect retries; a mid-session drop is a
    real teardown and is handled by the caller.

    The socket is DISCOVERED (see wayfire_socket) rather than left to
    pywayfire, which only reads the environment. Re-resolved on every attempt,
    because the retry loop exists for the case where it does not exist yet."""
    last = None
    for _ in range(retries):
        try:
            return WayfireSocket(wayfire_socket())
        except Exception as e:      # socket absent/unready: wait and retry
            last = e
            time.sleep(delay)
    raise last


def is_desync_error(e):
    """True if e means the IPC socket is POISONED (off-by-one) and only a
    reconnect can cure it, as opposed to a benign server error-response (e.g.
    "view is not toplevel") that leaves the socket in sync. The desync CAUSE is
    a request timeout, whose response is left unread in the buffer; the SYMPTOM,
    on the next call, is wrong-shaped data (KeyError/TypeError/IndexError) or a
    framing/decoding failure. A clean server error-response is none of these, so
    we must NOT reconnect on it (that would churn a fresh socket on every popup
    the compositor declines to place)."""
    if isinstance(e, (KeyError, IndexError, TypeError, AttributeError)):
        return True
    msg = str(e).lower()
    return "timeout" in msg or "json decod" in msg or "empty response" in msg


def acquire_singleton():
    """One watcher only. Two would double-place every window and race the
    knowledge writes: a hand-launched stopgap outliving the next autostart is
    the concrete case. flock auto-releases when the holder exits (even a
    crash), so the slot frees itself with no stale-pidfile cleanup. Returns the
    held fd (keep it for the process lifetime), None if another watcher holds
    it, or "unlocked" if the lock infra itself is unavailable (never let a lock
    failure disable restore: degrade to unlocked and say so)."""
    import fcntl
    d = os.environ.get("XDG_RUNTIME_DIR") or STATE
    try:
        os.makedirs(d, exist_ok=True)
        fd = os.open(os.path.join(d, "session-watch.lock"),
                     os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as e:
        logline(f"singleton: cannot open lock ({e}); continuing unlocked")
        return "unlocked"
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def runtime_dir():
    """XDG_RUNTIME_DIR (session-private tmpfs) or STATE as fallback: the one
    place the lock file and the adopt flag live."""
    return os.environ.get("XDG_RUNTIME_DIR") or STATE


ADOPT_FLAG = "session-adopt"   # armed by resume/reload, consumed at init.
#                                Its CONTENT is the mode; empty reads as adopt,
#                                which is what the flag used to mean.

# How a worker generation starts. There are THREE answers, and for a long time
# there were only two, which cost real data:
#
#   restore  place what is already open against the store   (`watch`)
#   adopt    take the current layout as the new truth       (`resume`)
#   quiet    touch nothing at all                           (`reload`)
#
# `quiet` exists because a CODE DEPLOY needs to restart the daemon without
# expressing an opinion about the layout, and neither of the other two can do
# that. `adopt` looks harmless (it moves no windows) but it CAPTURES, so it
# overwrites every remembered slot with wherever that window currently sits,
# and it deliberately grants no grace deadline, so those windows are never
# placed afterwards either. Used as a deploy reload (five times on manifold on
# 2026-09-24) it quietly rewrote a layout learned over days to match one that
# had failed to restore, and then reported everything as correct, because by
# then it WAS self-consistent.
MODES = ("restore", "adopt", "quiet")


def do_forget(selectors, apply=False):
    """Drop remembered slots the selectors name. Previews unless `apply`.

    WHY A VERB AND NOT A HAND EDIT. Five separate repair recipes in this
    project's notes begin "stop the daemon, edit the store, restart", and
    every one of them risks the same two traps: the capture loop rewrites the
    whole store from memory, so an edit under a running daemon is lost, and a
    restart cannot be quiet (the `watch` verb arms RESTORE itself), so it ends
    in a placement pass that moves windows nobody asked to move.

    SO THE RACE IS AVOIDED TWO WAYS, one per state, and it says which:
      daemon UP   write a request; the WORKER applies it, so the only writer
                  of the store is still the only writer. No stop, no restart,
                  no placement pass.
      daemon DOWN apply it here, because nothing else is writing.

    PREVIEWS BY DEFAULT, since this deletes learned data: a slot can be
    relearned only by putting that window back by hand. `--apply` is the
    explicit act, and the store is copied aside first either way."""
    if not selectors:
        print("usher: forget needs a selector, e.g."
              " 'chrome:win:*' or 'kitty:/src/*'", file=sys.stderr)
        return EXIT_FAIL
    kb = load_knowledge()
    hits = forget_matches(kb, selectors)
    if not hits:
        print(f"nothing matches {' '.join(selectors)} in {len(kb)} entries")
        return EXIT_OK
    for k in hits:
        app, _, ident = k.partition("\x00")
        e = kb[k]
        print(f"  {app[:20]:20} | {(ident or '(by app-id)')[:40]:40}"
              f" ws{[int(x) for x in e['workspace']]}")
    if not apply:
        print(f"{len(hits)} of {len(kb)} entries would be dropped."
              " Re-run with --apply to do it.")
        return EXIT_OK
    if watcher_pid():
        os.makedirs(RUNTIME_DIR, exist_ok=True)
        with open(FORGET_FILE, "w") as f:
            f.write("\n".join(selectors) + "\n")
        print(f"asked the running daemon to drop {len(hits)}; it owns the"
              " store while it runs, so it makes the edit")
        return EXIT_OK
    gone = forget_apply(kb, selectors)
    print(f"dropped {len(gone)} (no daemon running, so applied here)")
    return EXIT_OK


def arm_mode(mode):
    """Arm how the next worker generation starts. One-shot, consumed at init."""
    p = os.path.join(runtime_dir(), ADOPT_FLAG)
    try:
        os.makedirs(runtime_dir(), exist_ok=True)
        if mode == "restore":
            if os.path.exists(p):
                os.remove(p)
        else:
            with open(p, "w") as f:
                f.write(mode + "\n")
    except OSError:
        pass


def take_mode():
    """The armed mode, cleared as it is read, so only the FIRST worker after
    the arming acts on it and a later respawn restores. An empty flag file is
    read as `adopt`: that is what its mere presence used to mean."""
    p = os.path.join(runtime_dir(), ADOPT_FLAG)
    try:
        with open(p) as f:
            mode = f.read().strip()
    except OSError:
        return "restore"
    try:
        os.remove(p)
    except OSError:
        pass
    return mode if mode in MODES else "adopt"


def watcher_pid():
    """The running supervisor's pid, or None. Reads the same lock file
    _signal_watcher does, but to ASK ABOUT the daemon rather than act on it,
    so it answers None instead of exiting."""
    d = os.environ.get("XDG_RUNTIME_DIR") or STATE
    try:
        pid = int(open(os.path.join(d, "session-watch.lock")).read().strip())
    except (OSError, ValueError):
        return None
    return pid if os.path.isdir(f"/proc/{pid}") else None


def daemon_code_age(pkg_dir=None):
    """(verdict, detail): is the RUNNING daemon on the code THIS process
    loaded? One of "none", "current", "stale", "unknown".

    INSTALLED IS NOT RUNNING, and nothing used to be able to see the gap. A
    pkg install replaces the venv while the live daemon keeps the code it
    started with, so a fix can sit deployed and inert: measured 2026-10-07 on
    both boxes at once, one of them 41 hours behind, which quietly invalidated
    two verifications that day.

    THE WORKER, NOT THE SUPERVISOR, and getting this backwards is the easy
    mistake: a reload RE-EXECS the supervisor IN PLACE, so its pid and start
    time never change, and comparing those would report stale forever after
    the first reload. The worker is respawned, so its start time is the only
    one that moves.

    `/proc/<pid>` is stat'ed for the start time rather than parsed out of
    `stat`, since its mtime IS that moment, and the children come from
    `/proc/<pid>/task/<pid>/children` rather than a scan of the process table,
    which in this tree has produced a self-match five times.

    `pkg_dir` exists so the three verdicts are checkable without installing
    anything, the same injectable-seam habit pick_session and greeter_choice
    use. It defaults to the package THIS process loaded, which is the honest
    question: is the daemon running the code I am?"""
    pid = watcher_pid()
    if pid is None:
        return "none", "no daemon is running"
    try:
        started = os.stat(f"/proc/{pid}").st_mtime
        kids = open(f"/proc/{pid}/task/{pid}/children").read().split()
        for k in kids:
            try:
                started = max(started, os.stat(f"/proc/{int(k)}").st_mtime)
            except (OSError, ValueError):
                pass
        # THE *.py FILES, NOT THE DIRECTORY, which is the same trap
        # plugins_sig records: IMPORTING this package writes a __pycache__
        # inside it, which bumps the directory's mtime to NOW, so the
        # directory reading called every daemon stale the instant it was
        # asked. A measurement must not be moved by the act of taking it.
        here = pkg_dir or os.path.dirname(os.path.abspath(__file__))
        built = max(os.stat(f).st_mtime
                    for f in glob.glob(os.path.join(here, "*.py")))
    except (OSError, ValueError) as e:
        return "unknown", f"could not read the times ({e})"
    if started >= built:
        return "current", f"worker started {int(started - built)}s after it"
    return "stale", (f"the worker predates this code by "
                     f"{int(built - started)}s, so a reload is owed")


def session_agent_sock():
    """(agent socket or None, where we looked) for the agent a RESPAWNED
    terminal would inherit.

    THE CALLER'S ENVIRONMENT IS THE WRONG ONE TO ASK, and asking it made
    `usher doctor` over ssh report a missing agent on a box whose session had
    one: an ssh shell has no SSH_AUTH_SOCK, and over ssh is exactly where this
    report gets run. The question is whether a window the DAEMON spawns can
    authenticate, and spawn_term inherits the DAEMON's environment, so that is
    the environment to read. Same fault as doctor calling itself blind from an
    unset WAYFIRE_SOCKET, and as the greeter resolution reading the caller's
    XDG_DATA_DIRS: THE ANSWER MUST NOT DEPEND ON WHO ASKS.

    /proc/<pid>/environ is the EXEC-TIME environment, which is the right
    reading here rather than the trap it is elsewhere: it is precisely what
    the daemon's children inherit.

    Falls back to our own environment with no daemon running, and SAYS which
    it used, because the two answers mean different things."""
    pid = watcher_pid()
    if pid is not None:
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                for kv in f.read().split(b"\0"):
                    if kv.startswith(b"SSH_AUTH_SOCK="):
                        return (kv.split(b"=", 1)[1].decode("utf-8", "replace"),
                                f"the daemon (pid {pid})")
            return None, f"the daemon (pid {pid})"
        except OSError:
            pass
    return os.environ.get("SSH_AUTH_SOCK"), "this shell; no daemon is running"


def _signal_watcher(sig, action, done):
    """Signal the running supervisor, whose pid is in the lock file (the single
    place that path lives). Exit if none is running or the signal fails."""
    d = os.environ.get("XDG_RUNTIME_DIR") or STATE
    path = os.path.join(d, "session-watch.lock")
    try:
        pid = int(open(path).read().strip())
    except (OSError, ValueError):
        sys.exit(f"usher: no running watcher to {action}")
    try:
        os.kill(pid, sig)
    except OSError as e:
        sys.exit(f"usher: cannot signal watcher pid {pid}: {e}")
    print(f"usher: {done} watcher (pid {pid})")


def do_stop():
    """Stop the watcher cleanly: SIGTERM the supervisor, whose stop handler
    terminates the worker and exits (releasing the lock). Replaces the
    `pkill -f 'usher-mgr watch'` dance, which races the respawn and can
    match the wrong process: including the shell running the pkill.

    AND IT DISARMS THE MODE, because an armed mode is an instruction to the
    NEXT GENERATION OF THE DAEMON BEING STOPPED, and stopping it voids that
    instruction. Without this, `usher reload` (which arms quiet) followed by a
    stop before the worker consumed it left a LANDMINE: the marker survives in
    the runtime dir, so the next LOGIN started quiet and restored nothing,
    with the session coming up unplaced for no visible reason. Found live
    while testing the reload paths: a `quiet` marker sitting armed with no
    daemon running.

    A later start is a FRESH intent, and a login means restore."""
    _signal_watcher(signal.SIGTERM, "stop", "stopped")
    arm_mode("restore")          # "restore" is the disarm: it removes the flag


def do_reload():
    """Reload the running watcher: arm quiet, then SIGHUP the supervisor,
    which re-execs and picks up new code.

    A CLIENT ACTION, the sibling of do_stop, and it SIGNALS rather than runs
    anything. `usher` is the command interface; it must never become the
    thing it talks to. This used to call `watch.do_watch()`, the SERVICE's
    entry point, which acquires the singleton and BECOMES the supervisor when
    none is running, in the FOREGROUND: a client silently turning into a
    daemon, and indistinguishable from a hang to whoever typed it.

    THE SERVICE KEEPS THAT DUAL NATURE AND SHOULD. `usher-mgr watch` run
    against a live instance signals it instead of starting a second one,
    which is the idempotence the autostart relies on. The mistake was the
    CLIENT borrowing that path, not the path existing.

    IT REFUSES rather than starting one, because a daemon started from a
    command shell inherits THAT shell's environment, and an ssh with no
    WAYLAND_DISPLAY is the recorded cause of a respawned terminal dying
    instantly with nothing but `[kitty] <defunct>` to show for it. The session
    starts the daemon because the session is what has the environment.

    ARMED ONLY ONCE THE SIGNAL IS GOING TO BE SENT. arm_mode writes a marker
    the next worker generation CONSUMES, so arming and then not reloading
    leaves it for the next LOGIN to eat, which would start quiet and restore
    nothing."""
    if watcher_pid() is None:
        print("usher: no daemon is running, so there is nothing to reload.",
              file=sys.stderr)
        print("usher: the session starts it (usher-mgr watch), and a login "
              "picks up new code by itself.", file=sys.stderr)
        sys.exit(EXIT_CANNOT)
    arm_mode("quiet")
    _signal_watcher(signal.SIGHUP, "reload", "reloaded")


