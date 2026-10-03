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
                     chrome_session_titles, chrome_window_for,
                     chrome_window_tabs, forget_window, is_browser_cmdline,
                     is_chrome, is_chrome_slot, parse_snss, session_files,
                     session_history, snss_build, window_slot)

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

    POLICY ONLY, as of the Resolution rework. This used to also consult a
    plugin `transient()` hook, which NO plugin implemented: the last one
    (kitty's scratch-terminal test) was retired, and what it had been reduced
    to ("I cannot read the cwd") is a READINESS question that Resolution now
    owns. Keeping the two apart matters, because they are different facts with
    the same consequence: "the user does not want this window remembered" is
    not "usher cannot identify this window"."""
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


# --- anchor (include) rules: the OPT-IN set placed in STEADY state -----------
# usher/include mirrors usher/exclude's '<app-regex> :: <title-regex>'
# format. It is the steady-state whitelist: once the aggressive start window
# ages out, ONLY windows matching an anchor rule are (re)placed; everything else
# opens where you are and stays (default follow-me: an empty/absent file
# anchors nothing). Exclude still wins: a window matching both is never placed.
INCLUDE_FILE = os.environ.get(
    "USHER_INCLUDE_FILE", config_path("include"))

ANCHOR_RULES, ANCHOR_ERRORS = load_exclude_rules(INCLUDE_FILE)


def is_anchored(app, title):
    """True if the window matches a usher/include rule: the opt-in set that
    is STILL placed in the conservative steady state."""
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

    MERGES, and that is the whole point. The first version only adopted when
    the profile store did not exist yet, so if anything created one first: a
    seed from a snapshot, a run before the displays came up: adoption was
    skipped FOREVER and the legacy store was orphaned in silence. Measured on
    manifold: 1019 learned placements sat in a file nothing read while the live
    store knew 24, so almost nothing was ever placed and it looked like usher
    had stopped working.

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
        windows.append({
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
        })
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

    The third row is the 2026-10-03 shrink bug and it is the sharpest
    argument: KittyPlugin returned a CONFIDENT WRONG KEY, which the old
    contract allowed, so the placer resized a mux terminal onto a bare-kitty
    slot and the capture loop learned that size back. "Ready with a key I am
    not sure about" is now unrepresentable.

    THE REASON IS CARRIED, not just the state, which is what makes this a
    framework rather than a safer `identity`. `doctor` used to hardcode
    chrome's "incognito and guest windows are never recorded" text, which is
    the same drift PLUGIN_HOOKS was created to kill: the plugin that KNOWS
    why supplies the sentence, and the report just prints it.

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
        return 0          # respawn this app's saved-but-absent windows; count

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

    NOT THE DIRECTORY'S OWN MTIME, which was the first attempt and was wrong in
    an instructive way: importing a plugin writes a `__pycache__` directory
    beside it, that bumps the directory's mtime, and the watch therefore fired
    a second time on a change its own reload had caused. Measured: two
    "plugins reloaded" lines a second apart. A trigger must not include
    anything the action it triggers modifies."""
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


def resolution(v):
    """What usher knows about this window's identity. See Resolution.

    THE ONE PLACE A PLUGIN IS ASKED. identity(), unidentified() and
    _single_id() each used to dispatch to the owner themselves, which is three
    copies of the same question and exactly how two call sites come to
    disagree about a window's key. They are all thin readers of this now.

    An UNOWNED app resolves Ready(title), because the title is the only handle
    there is and for those it is the right one. A plugin raising is treated as
    Pending rather than Ready: a broken plugin must not be able to get a
    window remembered under a guessed key."""
    v = pview(v)
    p = _owner(v)
    if p is None:
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
    v = pview(v)
    if _owner(v) is None:
        return None       # unowned: the title-grouping path, as before
    r = resolution(v)
    return r.key if r.is_ready else None


def unidentified(v):
    """True if this window's app HAS a plugin and that plugin declined to
    identify it, so usher does not know WHICH window this is, and must
    neither remember it nor match it against anything remembered.

    identity() always answers, falling back to the raw title, and for an app no
    plugin claims that is right: the title is the only handle there is. This is
    the stricter question, and the one both LEARNING and PLACING have to ask,
    because for an owned app a title the plugin declined to resolve is known to
    be the wrong key. Chrome hits it whenever its session file has not caught up
    with a window.

    ONE PREDICATE, TWO CALL SITES, deliberately. Every silent failure in this
    file's history came from two places disagreeing about what a window's key
    is (see the RAW TITLE vs IDENTITY notes), and a store that can be written
    under a key the matcher will never look up, or matched under a key the
    writer will never produce: is that same fault wearing a new hat."""
    v = pview(v)
    return is_owned(v["app"]) and not resolution(v).is_ready


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


def _mux_pending_in(argv):
    """True if this process IS a mux command, or a shell wrapping one.

    PURE, so it is testable without a process tree, for the same reason
    _latch_target_in is: this decides whether a terminal is allowed to be
    keyed yet, and getting it wrong COSTS the window its remembered size.

    TWO SHAPES, because spawn_term wraps the command in `ksh -c "<cmd>; exec
    ksh -i"`, so the mux invocation is INSIDE one argv element rather than
    being its own:

        ['/bin/sh', '.../libexec/mux-latch', 'manifold']     a real process
        ['ksh', '-c', '/home/.../mux resume; exec ksh -i']    wrapped

    IT SELF-CLEARS, which is what bounds the deferral: `exec ksh -i` REPLACES
    the wrapper once the mux command ends, so the argv stops naming mux and
    the window becomes an ordinary kitty with no timer involved."""
    for a in argv:
        if os.path.basename(a) == "mux-latch":
            return True
        if MUX_BIN and MUX_BIN in a:
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
    box.

    mux added the tag for exactly this consumer: its own comment says a local
    session and an ssh'd one sharing a name "would otherwise snap the two
    windows onto each other", so reading it is the whole local/remote story;
    no /proc sniffing is needed, and unlike /proc it still works for a STORED
    entry, whose pid is long dead.

    None when there is no trailing tag (an older mux, or a title that merely
    looks like a banner). Callers treat that as local, which is what it was
    before mux stamped the host. Anchored at the END so the LEADING [LABEL]
    context prefix (a work banner) is never mistaken for it."""
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
        # PENDING, NOT NEVER, and the reason names both causes because usher
        # genuinely CANNOT tell them apart from one observation: a window
        # Chrome has not got round to writing looks identical to one it will
        # never write. doctor decides which by watching how long it stays
        # pending, because that is a judgement over TIME and belongs in the
        # report, not in a per-window answer. The old code asserted incognito
        # for every unresolved chrome window, which was an overclaim.
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
        pids = browser_pids()
        for p in pids:
            try:
                os.kill(p, signal.SIGTERM)
            except OSError:
                pass
        return pids

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
        if not any(is_chrome(w.get("app_id")) for w in saved):
            return 0
        if any(is_chrome(pview(v)["app"]) for v in live):
            return 0
        exe = next((shutil.which(c) for c in
                    ("google-chrome", "google-chrome-stable", "chromium",
                     "chromium-browser") if shutil.which(c)), None)
        if not exe:
            return 0
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
            subprocess.Popen(argv, start_new_session=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            n += 1
            _announce("launch  " + " ".join(
                [os.path.basename(exe)] + argv[1:]))
        return n


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
    same two reasons. Aggressive-vs-steady means a terminal opened during
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

        NONE WHILE A MUX COMMAND IS IN FLIGHT, which is a PRODUCT bug fixed
        2026-10-03 after it cost manifold both terminal sizes on a real
        reboot. A relaunched mux terminal MAPS BEFORE mux attaches (a latch
        has to ssh first), so its title is `ksh` with no colon, `is_mux_term`
        is False, and this plugin claimed it and answered CONFIDENTLY with a
        cwd key. The placer then matched the bare-kitty slot and RESIZED the
        window down to it, and the capture loop learned that size back into
        `term:latch <host>`. Self-worsening: once the slot says 1085x672 the
        next relaunch ASKS for 1085x672, so it never recovers.

        Declining is the whole fix and it is the conservative direction: it
        only ever DEFERS. `unidentified` then keeps both learning and placing
        off the window, grace-from-recognition re-graces it the instant mux
        paints its banner, and MuxPlugin claims it with the right key. The
        alternative (widening MuxPlugin's claim to the process tree) could
        STEAL a genuine bare-kitty window, which is worse than waiting.

        NOT a `transient` hook: "I cannot tell yet" and "never remember this
        window" are different questions, and conflating them is what broke
        non-mux terminals once already."""
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


def load_knowledge():
    """The knowledge base for the CURRENT display profile. A monitor set with
    nothing learned yet starts empty (and seeds from the last snapshot), which
    is right: the placements from another desk would not fit here anyway."""
    adopt_legacy_store()
    migrate_stores()      # every profile's store, not just the one we are on
    try:
        kb = json.load(open(kb_path()))
    except (FileNotFoundError, ValueError):
        # A store that does not exist yet is CURRENT by construction, so stamp
        # it NOW. Without this, the first monitor set to be seen writes an
        # unstamped store, and the very next load judges it stale and drops
        # exactly the chrome + kitty entries it has just learned, and every new
        # desk silently losing its browser and terminal placements once.
        try:
            os.makedirs(STATE, exist_ok=True)
            write_json(schema_path(), KB_SCHEMA)
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
    when momentarily alone: its windows share an app_id (see is_owned)."""
    return counts[app] == 1 and not is_owned(app)


def kb_entry(w, title, appid_only, when):
    """A knowledge record for one identity at window w's current placement.
    `title` is the KEY-title (identity(): a URL for Chrome); `label` keeps the
    human window title for logs, since the key may no longer read as one."""
    return {
        "app_id": w["app_id"], "title": title, "appid_only": appid_only,
        "label": w.get("title", ""),
        "output": w["output"], "workspace": w["workspace"],
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
    survives."""
    appid_keyed = {k[:-1] for k in kb
                   if k.endswith("\x00") and not is_owned(k[:-1])}
    cutoff = when - KNOWLEDGE_TTL
    for k in [k for k, v in kb.items()
              if v.get("last_seen", 0) < cutoff
              or SKIP_TITLE.search(v.get("title", ""))
              or is_transient(v)
              or (k.endswith("\x00") and is_owned(k[:-1]))
              or ("\x00" in k and not k.endswith("\x00")
                  and k.split("\x00", 1)[0] in appid_keyed)]:
        del kb[k]


def upsert(kb, windows, when):
    """One-shot knowledge update (no view-id grouping): record each window's
    CURRENT identity. Unique-app_id windows key by app_id alone; the rest by
    title. Used by `usher capture` and the seed-from-snapshot path;
    the watch daemon uses learn() instead, which groups a window's tabs by
    view id."""
    counts = Counter(w["app_id"] for w in windows)
    for w in windows:
        app = w["app_id"]
        key = _single_id(w)   # plugin single identity (chrome/mux/kitty)
        if is_unique(app, counts):
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
        key = _single_id(w)
        if is_unique(app, counts):
            kb[kkey(app, "")] = kb_entry(w, w["title"], True, when)
        elif key:
            kb[kkey(app, key)] = kb_entry(w, key, False, when)
        elif unidentified(w):
            # AN OWNED WINDOW ITS PLUGIN COULD NOT IDENTIFY IS NOT LEARNED.
            # Falling through to the title path stored a key known to be wrong.
            # Chrome hits this whenever its session file has not caught up with
            # a window, which is often, and every title change then minted
            # another entry: measured on manifold 2026-09-29, 286 of a
            # 333-entry store were chrome keyed by raw TITLE: 86% of
            # everything usher knew, none of it matchable, and exactly the
            # tab-in-titlebar spam three schema bumps have now tried to kill.
            #
            # The window is simply not remembered until its id resolves, which
            # is normally seconds. The cost is a window whose session file
            # never catches up never being remembered, and that is the right
            # trade: an entry nothing can ever match is not memory, it is
            # litter, and it crowds out the entries that work.
            continue
        elif vid is not None and vid in groups:
            for t in groups[vid]["titles"]:
                kb[kkey(app, t)] = kb_entry(w, t, False, when)


def _learn_purge_terminals(kb, windows, seen):
    """Drop the terminal entries whose window we WATCHED GO.

    ABSENCE FROM ONE SNAPSHOT IS NOT EVIDENCE OF A CLOSED WINDOW, and reading
    it as such cost every terminal its slot at every login. The daemon captures
    as soon as it is watching, which is BEFORE the terminals it just launched
    have mapped: manifestor's 22:30:35 snapshot held zero windows, six seconds
    ahead of the two kitty windows arriving. This purge then concluded both were
    gone and deleted the slots, so the placer had nothing to aim at, the windows
    stayed where kitty dropped them, and once the hold expired the capture loop
    learned the cascade position AS the slot. Chrome was untouched and placed
    perfectly, because chrome entries age out on the TTL instead of being purged
    on absence, which is once again why this read as "restore works, mostly".

    So the question is not "is it here?" but "did we see it go?", which needs a
    memory of what was ever here: `seen` is this daemon generation's set of
    terminal identities actually observed alive. An entry we have never seen
    cannot be distinguished from one whose window has not mapped yet, so it is
    left alone and `prune_kb`'s TTL remains the backstop for a genuinely stale
    one. A reload starts a fresh generation with an empty memory, so the purge
    goes briefly quiet until each terminal is observed once; that is the
    conservative direction and it costs nothing.

    The real job is unchanged: a window that is closed during a session is seen
    and then missing, so it is dropped. Switching what a window DISPLAYS never
    needed this, since schema 5 keys a terminal by its COMMAND.

    BOTH sides must be IDENTITIES. A kb entry's "title" field is the KEY-title
    (kb_entry stamps identity(), not the window title), so comparing it to raw
    window titles never matched and this block deleted every terminal entry it
    had just written, on every pass, so terminals were never placed at all. And
    the entry is selected by its KEY SHAPE, not by is_mux_term on that key:
    is_mux_term only asks "kitty, with a colon?", which a kitty:<cwd> key also
    satisfies, so the mux purge was sweeping plain kitty windows out too."""
    live_terms = {identity(w) for w in windows
                  if is_mux_term(w["app_id"], w["title"])}
    seen.update(live_terms)
    for k in [k for k, v in kb.items()
              if TERM_KEY_RE.match(v.get("title", ""))
              and v.get("title") in seen
              and v.get("title") not in live_terms]:
        del kb[k]


def learn(kb, groups, windows, when, hold=(), seen=None):
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
    counts = Counter(w["app_id"] for w in windows)
    tcount = Counter((w["app_id"], w["title"]) for w in windows if w["title"])
    ambiguous = {k for k, c in tcount.items() if c >= 2}
    live = {w["id"] for w in windows if w.get("id") is not None}
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


def save_knowledge(kb):
    write_json(kb_path(), json.dumps(kb, indent=2))


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
    kb = load_knowledge()
    upsert(kb, snap["windows"], snap["time"])
    save_knowledge(kb)
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
MUX_BIN = os.path.expanduser("~/.local/bin/mux")
MUX_RESUME = f"{shlex.quote(MUX_BIN)} resume"


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
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    subprocess.Popen(["kitty"] + _size_opts(size)
                     + ["ksh", "-c", f"{cmd}; exec ksh -i"],
                     env=env, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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

    This is mux's durable session SET (recorded per socket under $MUX_CACHE,
    additive as sessions are built or attached, subtractive on `mux kill`), NOT
    the live tmux server, which is the whole point, because the case that
    matters is a COLD BOOT, where no session is live but `mux go` rebuilds from
    exactly this set. Reading the live server instead meant there was never
    anything to relaunch after a reboot.

    Deliberately not scraped out of `mux ls`, which is a HUMAN listing: it leads
    each line with an agent-state glyph, so the scrape that used to read it
    matched nothing and left this entire path dead with no symptom. selftest
    asserts the bare-name shape against the real binary, so a future change to
    mux's output fails LOUD here instead of silently going inert again.

    Empty when mux is absent or errors: the soft-dep no-op."""
    try:
        out = subprocess.run(
            [os.path.expanduser("~/.local/bin/mux"), "resume", "--list"],
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
        spawn_term(cmd, size)
        n += 1
        _announce(f"launch  {cmd}")
    return n


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
    return n


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
            n += p.relaunch_missing(saved, live)
        except Exception as e:
            logline(f"relaunch ({getattr(p, 'name', '?')}) error: {e}")
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
    counts = Counter(w.get("app_id", "") for w in windows)
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
        idx = next((i for i, e in enumerate(rem)
                    if e["app_id"] == app
                    and (e.get("appid_only") or e["title"] == key)), None)
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
        print(f"  UNMATCHED-LIVE   {app_of(lv)[:20]:20} | "
              f"{lv.get('title','')[:42]}")
    for e in unlayout:
        print(f"  UNMATCHED-LAYOUT {e['app_id'][:20]:20} | {e['title'][:42]}")
    have = ", ".join(sorted(outs)) or "none"
    for lv, e in unplaceable:
        print(f"  UNPLACEABLE      {app_of(lv)[:20]:20} | saved on "
              f"{e['output']}, not attached (have: {have})")


PROFILE_MARK = "usher.profile"   # last profile we acted on, per boot


def do_display_changed():
    """The display-change entry point, for hwdp's `changed` hook.

    That edge fires on EVERY output burst: a monitor blanking and waking, a
    kanshi reapply, a re-detect, not only when the set of monitors actually
    differs. Re-arming aggressive placement on each of those was a mistake:
    aggressive means every mapped window is put back where it is remembered, so
    a window deliberately moved during the session would be yanked home every
    time a screen blinked, which is exactly the teleporting the steady state
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
    if was == now:
        return 0                     # same monitors; nothing to do, silently
    try:
        with open(mark, "w") as f:
            f.write(now + "\n")
    except OSError as e:
        logline(f"display-changed: cannot record the profile: {e}")
    logline(f"display changed: profile {was or '(none)'} -> {now}; "
            "re-arming placement")
    try:
        os.makedirs(os.path.dirname(ARM_FILE), exist_ok=True)
        with open(ARM_FILE, "w") as f:
            f.write(f"{time.time()}\n")
    except OSError as e:
        logline(f"display-changed: cannot re-arm: {e}")
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
    rebooting, so it must never be the reason that does not happen."""
    if not pids:
        print("usher: nothing asked to quit; session captured")
        return 0
    print(f"usher: asked {len(pids)} process(es) to quit")
    end = time.time() + WIND_DOWN_TIMEOUT
    while time.time() < end:
        alive = []
        for p in pids:
            try:
                os.kill(p, 0)
                alive.append(p)
            except OSError:
                pass
        if not alive:
            print("usher: all exited cleanly")
            return 0
        pids = alive
        time.sleep(0.2)
    print(f"usher: {len(pids)} still running after "
          f"{WIND_DOWN_TIMEOUT:g}s; going ahead anyway")
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
    except Exception as e:
        print(f"usher: capture failed, winding down anyway: {e}",
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
    rows = []
    for w in snapshot(ipc())["windows"]:
        app = w.get("app_id") or ""
        # An app_id-ONLY key ends in NUL (see kkey / appid_only), which is how
        # a uniquely-identified app like Signal is stored, so both shapes have
        # to be tried or those windows read as having no slot.
        e = kb.get(kkey(app, w.get("key") or "")) or kb.get(kkey(app, ""))
        rows.append({
            "key": w.get("key"),
            "app_id": w.get("app_id"),
            "label": w.get("title"),
            "cmd": w.get("cmd"),
            "expect_workspace": e.get("workspace") if e else None,
            "expect_pos": e.get("pos") if e else None,
            "expect_size": e.get("size") if e else None,
            "expect_output": e.get("output") if e else None,
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
        return 2
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

    pairs, unlive, unlayout = match(live, entries)
    acted = 0
    unplaceable = []
    for lv, e in pairs:
        if only and (only not in (lv.get("title") or "")) \
                and (only not in app_of(lv)):
            continue
        o = outs.get(e["output"])
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
                lv.get("output-name") == e["output"])
        label = f"{app_of(lv)[:18]:18} -> {e['output']} " \
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


# --- aggressive vs steady placement (the anti-whack-a-mole state machine) ----
# Placement is AGGRESSIVE (place any known, non-excluded window) for a window
# after session start (or a `usher aggressive` kick), then goes STEADY
# (place ONLY usher/include anchors). A GLOBAL phase, orthogonal to the per-
# view PLACE_GRACE. Steady when the FLOOR has passed AND it has been quiet (no
# new window mapped) for IDLE_SETTLE, but never past the CAP:
#   aggressive := not( (now-armed >= FLOOR and now-last_map >= SETTLE)
#                      or now-armed >= CAP )
# FLOOR is a floor, not a race, so "log in, wander off, come back in 4 min and
# launch Chrome" still lands. All three are env-overridable.
START_FLOOR = float(os.environ.get("USHER_START_FLOOR", 300))  # 5 min
IDLE_SETTLE = float(os.environ.get("USHER_IDLE_SETTLE", 25))   # 25 s quiet
AGGR_CAP = float(os.environ.get("USHER_AGGR_CAP", 900))        # 15 min cap

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

    WHY IT MATTERS AWAY FROM THE DAEMON: the compositor exports WAYFIRE_SOCKET
    to what IT starts, and a shell often does not have it, which is exactly
    where a person types `usher cleanly logoff` and was told the compositor
    could not be reached. Measured: with the variable unset the verb failed
    from a tmux pane and worked the moment it was named.

    DO NOT GUESS AT THE CAUSE IN THE MESSAGE, which the first version did: it
    blamed a stale shell and advised restarting one. On this fleet nothing
    propagates the variable at all (mux's environment feature manages four
    others), so that advice sent a reader after a restart that could not have
    helped. State the fact and the remedies; the cause is not ours to assert.

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
    match the wrong process: including the shell running the pkill."""
    _signal_watcher(signal.SIGTERM, "stop", "stopped")


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
    real = session_history
    globals()["session_history"] = lambda: {"P": [cur, prev]}
    try:
        yield
    finally:
        globals()["session_history"] = real


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
    ps = {getattr(p, "name", "?"): p for p in plugins()}
    # the registry loads the three built-ins; each claims the right windows
    ps = {getattr(p, "name", "?"): p for p in plugins()}
    ck("plugins-builtin", all(n in ps for n in ("chrome", "mux", "kitty")))
    ck("owns-chrome", ps["chrome"].owns(_tv("google-chrome")))

    # A PLAIN TERMINAL AT $HOME IS A NORMAL WINDOW, not an exception. It used
    # to be excluded end to end (never captured, never placed, never brought
    # back), which is the same shape as chrome's retired ^New Tab$ rule and is
    # retired for the same reasons: steady state leaves a terminal opened
    # mid-session where it opens, and when usher spawns one at session start it
    # can place it. The cwd IS the key, so drive these by stubbing the one
    # thing that reads it.
    _kp, _home = ps["kitty"], os.path.expanduser("~")
    _kv = {"app": "kitty", "title": "terminal", "pid": 4242, "id": None}
    _real_cwd = _term_cwd
    try:
        globals()["_term_cwd"] = lambda _pid: _home
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
        globals()["_term_cwd"] = lambda _pid: None
        # PENDING, not NEVER: a kitty has no shell in /proc for its first
        # ~0.25s, so this is "ask again", and reading it as "never remember"
        # is what dropped every non-mux terminal once already.
        ck("kitty-unreadable-cwd-is-pending",
           _kp.resolve(_kv).state == Resolution.PENDING)
        ck("kitty-unreadable-cwd-is-unidentified", unidentified(_kv))
        ck("kitty-unreadable-cwd-says-why", bool(_kp.resolve(_kv).why))
    finally:
        globals()["_term_cwd"] = _real_cwd
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
    _real_pending = _term_mux_pending
    try:
        globals()["_term_cwd"] = lambda _pid: "/w/proj"
        globals()["_term_mux_pending"] = lambda _pid: False
        ck("kitty-keys-normally-when-no-mux-pending",
           _kp.resolve(_kv).key == "kitty:/w/proj")
        globals()["_term_mux_pending"] = lambda _pid: True
        ck("kitty-defers-while-mux-pending",
           _kp.resolve(_kv).state == Resolution.PENDING)
        ck("kitty-mux-pending-is-unidentified", unidentified(_kv))
        ck("kitty-mux-pending-says-why",
           "mux" in (_kp.resolve(_kv).why or ""))
    finally:
        globals()["_term_cwd"] = _real_cwd
        globals()["_term_mux_pending"] = _real_pending

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
    ck("owner-mux", _owner(_tv("kitty", "wf:code[manifold]")) is ps["mux"])
    ck("owner-kitty", _owner(_tv("kitty", "✳ Claude Code")) is ps["kitty"])
    ck("owns-nobody", _owner(_tv("slack", "Slack")) is None)
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

    # 2. EVERY PLUGIN, including the base and anything a user registered.
    #    A plugin that answers at all must answer with a Resolution, must
    #    carry a key when ready, and must carry a reason when it does not.
    _vs = [_tv("kitty", "terminal"), _tv("kitty", "s:w\u2800[host]"),
           _tv("google-chrome", "Inbox"), _tv("nosuchapp", "x")]
    for _p in list(plugins()) + [WindowPlugin()]:
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

    # 3. THE GATE. A window that is not ready must be refused by BOTH call
    #    sites, which is the invariant every silent failure in this repo's
    #    history broke: a store written under a key the matcher never looks up.
    _real = globals()["_owner"]
    try:
        class _Pend(WindowPlugin):
            name = "pendtest"

            def owns(self, v):
                return True

            def resolve(self, v):
                return Resolution.pending("by construction")

        globals()["_owner"] = lambda _v: _Pend()
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

        globals()["_owner"] = lambda _v: _Never()
        ck("gate-never-is-unidentified", unidentified(_v))
        ck("gate-never-has-no-single-id", _single_id(_v) is None)

        # A PLUGIN THAT RAISES, OR RETURNS RUBBISH, MUST NOT GET A WINDOW
        # REMEMBERED. Both degrade to Pending, never to Ready: the fail-safe
        # direction is to forget a window, not to key it on a guess.
        class _Boom(_Pend):
            name = "boomtest"

            def resolve(self, v):
                raise RuntimeError("boom")

        globals()["_owner"] = lambda _v: _Boom()
        ck("gate-raising-plugin-is-pending", _st(_v) == Resolution.PENDING)
        ck("gate-raising-plugin-says-so", "boom" in (_wh(_v) or ""))

        class _Junk(_Pend):
            name = "junktest"

            def resolve(self, v):
                return "kitty:/tmp"        # the OLD contract's return type

        globals()["_owner"] = lambda _v: _Junk()
        ck("gate-old-contract-return-is-pending",
           _st(_v) == Resolution.PENDING)
        ck("gate-old-contract-is-not-silently-keyed", _single_id(_v) is None)
    finally:
        globals()["_owner"] = _real


def _t_terminals(ck):
    """a terminal's SLOT, and which windows need respawning."""
    ps = {getattr(p, "name", "?"): p for p in plugins()}
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
    real = (load_snapshot, plugins)
    seen = []

    class _P:
        def relaunch_missing(self, saved, live):
            seen.append([w.get("cmd") for w in saved])
            return 0

    try:
        globals()["load_snapshot"] = lambda *a: {
            "windows": [{"app_id": "kitty", "cmd": "FROM THE FILE"}]}
        globals()["plugins"] = lambda: [_P()]
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
    finally:
        globals()["load_snapshot"], globals()["plugins"] = real


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
    _real_env, _real_hunted = dict(os.environ), SOCKET_HUNTED
    _real_warned = _HUNT_WARNED
    try:
        globals()["_HUNT_WARNED"] = False
        globals()["SOCKET_HUNTED"] = None
        os.environ.pop("WAYFIRE_SOCKET", None)
        _err = io.StringIO()
        with contextlib.redirect_stderr(_err):
            wayfire_socket()
        _said = _err.getvalue()
        # It only warns when it actually HUNTED, which on a box with no
        # compositor socket it will not have done.
        if SOCKET_HUNTED:
            ck("a-hunted-socket-warns-on-stderr",
               "WAYFIRE_SOCKET is unset" in _said and SOCKET_HUNTED in _said)
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
        globals()["_HUNT_WARNED"] = False
        globals()["SOCKET_HUNTED"] = None
        os.environ["WAYFIRE_SOCKET"] = "/run/nowhere.sock"
        _err3 = io.StringIO()
        with contextlib.redirect_stderr(_err3):
            _got = wayfire_socket()
        ck("a-clean-environment-is-silent",
           _err3.getvalue() == "" and _got == "/run/nowhere.sock"
           and SOCKET_HUNTED is None)
    finally:
        os.environ.clear()
        os.environ.update(_real_env)
        globals()["SOCKET_HUNTED"] = _real_hunted
        # Left ARMED rather than restored: this process genuinely has warned
        # now, and a later check that connects would otherwise print the five
        # lines into the suite's output. Honest and quiet.
        globals()["_HUNT_WARNED"] = True
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
       _c.seated_session("jello", _AT_GREETER) is None)
    ck("the-greeters-own-seated-session-is-not-ours",
       _c.seated_session("_greetd", _AT_GREETER) is None)
    # AND THE LEADER COMES BACK WITH IT, because that is what gets signalled.
    ck("a-seated-login-yields-its-id-and-leader",
       _c.seated_session("jello", _LOGGED_IN) == ("13537", "846241"))
    ck("another-users-login-is-not-ours",
       _c.seated_session("root", _LOGGED_IN) is None)
    # THIS IS WHAT DECIDES WHETHER `cleanly reboot` REFUSES, so it is pinned
    # from both sides. "Cannot reach the compositor" is TWO facts: a session
    # running that we cannot see (refuse, a layout would be lost) and NO
    # session at all (nothing to lose, so refusing only blocks the reboot).
    # Met live 2026-10-02 on a box whose greeter had failed, where usher made
    # itself the reason the machine would not go down.
    ck("no-session-means-nothing-to-lose",
       _c.seated_session("jello", _AT_GREETER) is None)
    ck("a-live-session-is-what-makes-a-refusal-right",
       _c.seated_session("jello", _LOGGED_IN) is not None)
    # AND THE SEATLESS ssh CONNECTION ASKING THE QUESTION IS NOT A SESSION,
    # which is the one that would invert the whole decision: read it as a
    # login and usher refuses to reboot a box that has no session at all.
    ck("the-asking-ssh-connection-is-not-a-session",
       _c.seated_session("jello", "   12 1000 jello  -  7041  user  -  no -")
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
    _real_exec, _real_seam = os.execv, SESSION_START
    _seen = []
    try:
        with _tf.TemporaryDirectory() as _d:
            _prov = os.path.join(_d, "session-start")
            with open(_prov, "w") as _f:
                _f.write("#!/bin/sh\nexit 0\n")
            os.chmod(_prov, 0o755)
            globals()["SESSION_START"] = _prov
            os.execv = lambda path, argv: _seen.append((path, list(argv)))
            from . import cli as _cli
            _cli.session_start("login")
        ck("the-seam-execs-the-provider-with-the-action",
           _seen == [(_prov, [_prov, "login"])])
    finally:
        os.execv = _real_exec
        globals()["SESSION_START"] = _real_seam
    # A PROVIDER THAT IS NOT EXECUTABLE IS A SILENT NO-OP, the same class as a
    # 0644 hook, so it must be refused rather than run.
    with _tf.TemporaryDirectory() as _d:
        _dud = os.path.join(_d, "session-start")
        open(_dud, "w").close()
        os.chmod(_dud, 0o644)
        _real_seam = SESSION_START
        try:
            globals()["SESSION_START"] = _dud
            from . import cli as _cli
            try:
                _cli.session_start("login")
                ck("a-non-executable-provider-is-refused", False)
            except SystemExit as _e:
                ck("a-non-executable-provider-is-refused",
                   "not executable" in str(_e))
        finally:
            globals()["SESSION_START"] = _real_seam

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
    for _m in (sys.modules[__name__], _doc, _w, _ch):
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
       os.path.basename(STATE) == "usher")
    # AND NOTHING READS THE OLD LOCATIONS ANY MORE, which is the assertion that
    # keeps a fallback from creeping back in under a different name.
    ck("no-path-points-at-the-pre-rename-dirs",
       not any(p.endswith("/session") or "/session/" in p
               or p.endswith("session-layout")
               for p in (CONFIG_DIR, STATE, EXCLUDE_FILE, INCLUDE_FILE,
                         PLUGIN_DIR)))


def _t_relaunch(ck):
    """the relaunch paths, RUN with the spawn stubbed."""
    # RUN the relaunch paths end to end with the spawn stubbed. Checking
    # mux_candidates alone is not enough: a NameError in the announce after the
    # spawn shipped undetected precisely because nothing executed these
    # functions, only the pure helper inside them.
    import io
    import contextlib
    _real = (spawn_term, _spawn_kitty, logline)
    _spawned, _logged = [], []
    try:
        globals()["spawn_term"] = lambda *a, **k: _spawned.append(("mux", a))
        globals()["_spawn_kitty"] = lambda *a, **k: _spawned.append(("kitty",
                                                                     a))
        # CAPTURE THE LOG instead of writing it. _announce appends to the REAL
        # $STATE/watch.log, so every `./test/run` used to add three fixture
        # rows to the one file that records what usher did to a LIVE session,
        # indistinguishable from real relaunches to anyone reading it later.
        # Capturing loses no coverage (_announce is still CALLED, which is
        # the whole point of running these paths) and lets us assert what it
        # said, which the old version did not.
        globals()["logline"] = _logged.append
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
        (globals()["spawn_term"], globals()["_spawn_kitty"],
         globals()["logline"]) = _real


def _t_chrome(ck):
    """chrome identity, profiles, and the restore flags."""
    ps = {getattr(p, "name", "?"): p for p in plugins()}
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
    _st = STATE            # STATE is what this sandboxes; XDG_STATE_HOME is
    _tmp = tempfile.mkdtemp()   # read at import and cannot matter here
    try:
        globals()["STATE"] = _tmp
        load_knowledge()                     # first touch of a fresh profile
        ck("new-profile-stamped", os.path.exists(schema_path())
           and open(schema_path()).read().strip() == KB_SCHEMA)
        _kb = {kkey("google-chrome", "example.com"): {
            "app_id": "google-chrome", "title": "example.com",
            "appid_only": False, "last_seen": 1_800_000_000}}
        save_knowledge(_kb)
        ck("new-profile-survives-reload", len(load_knowledge()) == 1)

        # A legacy store must be MERGED even when a profile store already
        # exists. Skipping it there orphaned 1019 placements on manifold and
        # left placement silently doing almost nothing.
        _e = lambda t: {"app_id": "google-chrome", "title": t,
                        "appid_only": False, "last_seen": 1_800_000_000}
        with open(os.path.join(STATE, "knowledge.json"), "w") as f:
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
           not os.path.exists(os.path.join(STATE, "knowledge.json"))
           and os.path.exists(os.path.join(STATE,
                                           "knowledge.json.pre-profile")))
        ck("legacy-merge-is-once", len(load_knowledge()) == 2)
    finally:
        globals()["STATE"] = _st
        shutil.rmtree(_tmp, ignore_errors=True)



def _t_contracts(ck):
    """the cross-tool contracts and the SNSS reader."""
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
    import tempfile
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

    # THE AGGRESSIVE/STEADY CLOCK. steady when the FLOOR has passed and it has
    # been quiet for IDLE_SETTLE, but never past the CAP.
    w.st["armed_at"] = now
    w.st["last_map"] = now
    ck("clock-aggressive-after-arming", w._aggressive_now())
    w.st["armed_at"] = now - START_FLOOR - IDLE_SETTLE - 10
    w.st["last_map"] = now - IDLE_SETTLE - 10
    ck("clock-settles-when-quiet", not w._aggressive_now())
    # a NEW window pushes last_map, which extends aggressive past the floor
    w.st["last_map"] = now
    ck("clock-extends-on-a-new-map", w._aggressive_now())
    # ...but never past the CAP, which is what bounds a login storm
    w.st["armed_at"] = now - AGGR_CAP - 1
    ck("clock-capped", not w._aggressive_now())

    # THE HOLD: while aggressive, a window the placer has not reached is
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
    w.st["armed_at"] = now - AGGR_CAP - 1          # steady
    ck("hold-holds-nothing-in-steady-state", w._held(_wins) == frozenset())

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
    for area in (_t_registry, _t_resolution, _t_terminals, _t_cli_split,
                 _t_launch_source,
                 _t_relaunch, _t_chrome, _t_learn,
                 _t_geometry, _t_placement, _t_snapshots, _t_profiles,
                 _t_migration, _t_watcher, _t_contracts):
        try:
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
