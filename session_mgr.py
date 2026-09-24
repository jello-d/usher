"""session-mgr -- record the Wayland window layout and place windows back.

The successor to wayfire-rule-enforcer. Instead of hand-written placement
rules, it records where windows actually are and puts them back. `watch` is
BOTH the daemon (started at login) and the CLI controller for it -- like
kanshi-mgr, one command runs the thing and drives it.

  session-mgr watch        the daemon: record continuously, place on map
  session-mgr capture      snapshot the current layout into the store now
  session-mgr restore      place the stored layout onto the live session
  session-mgr aggressive   KICK: re-arm aggressive placement (see below)
  session-mgr toggle       flip aggressive<->steady (the tray left-click)
  session-mgr settle       force steady now (end the aggressive window early)
  session-mgr status       the daemon's mode + seconds until it settles
  session-mgr exclude      show the never-place rules (session/exclude)
  session-mgr include      show the anchor rules (session/include)

Placement is AGGRESSIVE then STEADY. For START_FLOOR seconds after login (or
an `aggressive` kick) every mapped window is placed back -- what lets Chrome
launch and its windows land. Once IDLE_SETTLE seconds pass with no new window
(capped at AGGR_CAP) it goes STEADY: a reopened window just appears where you
are and stays. session/include lists the few windows to keep snapping back
even then (opt-in; empty = follow-me). session/exclude always wins.

Store ($XDG_STATE_HOME/session-layout, default ~/.local/state/...):
  current.json             the latest snapshot
  history/<epoch>.json     rolling recent snapshots (match hints)
  milestones/<date>.json   first snapshot of each day (a stable "yesterday")

Identity for matching is (app_id, key), where key = identity(view). Unique-
app_id windows (slack, --app Gmail) key by app_id alone, title-independent. App-
SPECIFIC identity + respawn live in PLUGINS (see WindowPlugin): chrome, mux, and
kitty ship built in, users add more in ~/.config/session/plugins/. The volatile
title is never the key: chrome keys by the active-tab URL (SNSS session file),
mux by the tmux SESSION **and the host it lives on** (`mux@<host>:<session>`,
respawned via `mux go`, over ssh when the host is not this box), kitty by the
shell's CWD from /proc (`kitty:<cwd>`, respawned as a shell there). See
WindowPlugin, plugins(), identity(), and learn().
"""
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time
import urllib.parse
from collections import Counter
from datetime import date

# pywayfire is needed only to talk to the live compositor -- guarded so the
# module still imports (and `session-mgr selftest` runs) without it.
try:
    from wayfire import WayfireSocket
    from wayfire.extra.wpe import WPE
except ImportError:
    WayfireSocket = WPE = None

# The work/personal boundary: this daemon runs as the personal account, so it
# must not record or move work-enclave windows. mux stamps work terminals with
# a "[WORK: <label>]" title banner; anything matching this is ignored end to
# end (never captured, never placed). Override with SESSION_SKIP_TITLE.
SKIP_TITLE = re.compile(os.environ.get("SESSION_SKIP_TITLE", r"^\[WORK"))


DEFAULT_TERM_TITLE = "terminal"

# This box's short hostname, matching tmux's #{host_short} (and `hostname -s`).
# It is what tells a LOCAL mux session from one reached over ssh: mux stamps the
# tmux SERVER's host into the terminal title, so the tag naming another box is
# the durable "this session lives on a different machine" signal. See
# mux_host_of.
LOCAL_HOST = os.uname().nodename.split(".")[0]


def is_scratch_term(app, title):
    """A plain (unnamed) terminal: kitty wearing the constant default title that
    kshrc stamps ("terminal") for a non-tmux shell. It has no cross-session
    identity, so never capture or place it -- it opens where you are and is
    never resized. Give a terminal a real name with ~/bin/settitle, or let mux
    stamp its session name, and it becomes a normal placed window. Also skips
    the legacy per-boot "ksh"/"ksh: N" titles from the old unique-title scheme,
    so stale store entries self-heal during the transition."""
    if app != "kitty":
        return False
    return (title == DEFAULT_TERM_TITLE
            or title == "ksh" or title.startswith("ksh:"))


# --- never-place rules: transient windows session must ignore ---------------
# session/exclude is the user-grown repository of windows that must open
# wherever you are, never be captured or placed: a blank New Tab, the Chrome
# profile picker, and so on. The old hardcoded Chrome list now ships as the
# file's default content. See the file's header for the format.
EXCLUDE_FILE = os.environ.get(
    "SESSION_EXCLUDE_FILE",
    os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
        "session", "exclude"))


def load_exclude_rules(path=EXCLUDE_FILE):
    """Parse session/exclude into compiled (app_re, title_re) pairs. Every rule
    is one line, '<app-regex> :: <title-regex>' -- both fields required, use
    '.*' for "any". A line starting with # is a comment, blanks ignored.
    Patterns are Python regexes matched with re.search, so they are UNANCHORED
    (a substring test): add ^...$ to pin, exactly as the work boundary's own
    ^\\[WORK does. Returns (rules, errors): a line missing '::' or with a bad
    regex is collected into errors -- surfaced by `session-mgr exclude`,
    logged by the watcher -- and skipped, never crashing the headless
    daemon. A missing
    or unreadable file yields ([], []); the built-in work-boundary and
    scratch-terminal skips still apply. Read once per process, so an edit is
    picked up by the next worker respawn or a re-run of session-mgr watch."""
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
    """True if the window must open wherever the user is -- never captured (a
    stored "New Tab" would drag every future new tab to one spot), never placed.
    Takes a view/window/entry dict. Two sources: a session/exclude config rule
    (blank New Tab, profile picker, a pre-load "Google Chrome" title -- config-
    driven, grows without a code change) OR a plugin's transient() (a scratch
    terminal). plugin_transient is only reached if no exclude rule matched."""
    v = _pview(v)
    app, t = v["app"], v["title"].strip()
    if any(ar.search(app) and tr.search(t) for ar, tr in EXCLUDE_RULES):
        return True
    return plugin_transient(v)


def reload_exclude():
    """Re-read session/exclude into the module globals, live -- the watch loop
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
# session/include mirrors session/exclude's '<app-regex> :: <title-regex>'
# format. It is the steady-state whitelist: once the aggressive start window
# ages out, ONLY windows matching an anchor rule are (re)placed; everything else
# opens where you are and stays (default follow-me -- an empty/absent file
# anchors nothing). Exclude still wins: a window matching both is never placed.
INCLUDE_FILE = os.environ.get(
    "SESSION_INCLUDE_FILE",
    os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
        "session", "include"))

ANCHOR_RULES, ANCHOR_ERRORS = load_exclude_rules(INCLUDE_FILE)


def is_anchored(app, title):
    """True if the window matches a session/include rule -- the opt-in set that
    is STILL placed in the conservative steady state."""
    t = title.strip()
    return any(ar.search(app) and tr.search(t) for ar, tr in ANCHOR_RULES)


def reload_anchor():
    """Re-read session/include live, exactly as reload_exclude does its file."""
    global ANCHOR_RULES, ANCHOR_ERRORS
    ANCHOR_RULES, ANCHOR_ERRORS = load_exclude_rules(INCLUDE_FILE)
    logline(f"anchor reloaded: {len(ANCHOR_RULES)} rule(s),"
            f" {len(ANCHOR_ERRORS)} error(s)")
    for _n, _text, _msg in ANCHOR_ERRORS:
        logline(f"anchor rule error (line {_n}): {_msg}: {_text!r}")


def is_mux_term(app, title):
    """A named mux terminal: kitty whose title is 'session:window' (a mux
    session attached). NOT a plain 'terminal', a scratch 'ksh:', or a work
    window. These are the only terminals session tracks, places, and relaunches
    -- and the ones a single window cycles through as it switches sessions."""
    return (app == "kitty" and ":" in title
            and not is_scratch_term(app, title)
            and not SKIP_TITLE.search(title))


def term_wid(pid):
    """The window's TERM_WINDOW_ID, read from its process env -- the stable
    per-window id term/spawn_term mint, unchanged as the window cycles mux
    sessions. It is what clusters a window's session-titles into one identity
    (its 'tabs'). Empty string if unset or unreadable."""
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            for kv in f.read().split(b"\x00"):
                if kv.startswith(b"TERM_WINDOW_ID="):
                    return kv[15:].decode("utf-8", "replace")
    except OSError:
        pass
    return ""


STATE = os.path.join(
    os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
    "session-layout")
# Marker a worker drops once it has actually RUN launch_missing, so the launch
# survives the first worker dying to the compositor-startup race: the supervisor
# keeps launch on until this exists, not just for the first-spawned worker.
LAUNCHED = os.path.join(STATE, ".launched")
HISTORY_KEEP = 20      # recent snapshots retained under history/
MILESTONE_DAYS = 14    # daily milestones retained under milestones/


# --- display PROFILE: one remembered layout per monitor set -----------------
# A placement only means anything on the monitors it was learned on. With ONE
# flat store, docking and undocking overwrite each other's layout, and a window
# whose output is absent is simply unplaceable -- which reads as "usher does
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


def _hwdp_id():
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
    env = os.environ.get("SESSION_PROFILE")
    if env:
        return _safe_profile(env)
    now = time.time()
    if not fresh and _PROFILE["id"] and now - _PROFILE["at"] < PROFILE_TTL:
        return _PROFILE["id"]
    pid = _hwdp_id() or _derived_id(_load_snapshot()) or "default"
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
    the profile store did not exist yet, so if anything created one first -- a
    seed from a snapshot, a run before the displays came up -- adoption was
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
        # and kitty entries dropped as stale -- which would undo the merge.
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
# identity, then re-applies the shader when it restores the window -- and writes
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
    wayfire session while this file persists, so it accumulates stale ids -- see
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
    enough -- it is keyed by view id, and ids reset each session while the file
    persists, so a stale id reused by a fresh window would read as inverted (the
    "negates some that never were" bug). Gating on the compositor's live
    view-has-shader kills that: a reused id whose window carries no shader is
    excluded. (view-has-shader is not shader-specific -- one "filters"
    transformer name covers invert/monochrome/... -- but the store gate keeps
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


def snapshot(sock):
    outputs = {o["name"]: o for o in sock.list_outputs()}
    inverts = load_inverts()
    windows = []
    for v in sock.list_views(filter_mapped_toplevel=True):
        title = v.get("title", "")
        app = v.get("app-id") or v.get("app_id") or ""
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
            "pid": pid,
            "wid": window_id_for(v),
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
        "version": 1,
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


# --- Chrome tab identity: the active-tab URL from the SNSS session file -----
# Chrome gives every browser window the one app-id "google-chrome" and one pid
# (the browser process), so neither app-id nor /proc can tell its windows
# apart -- the only per-window discriminator wayfire exposes is the TITLE, the
# active tab's page title, which is volatile (unread counts "Inbox (7)",
# tab switches, navigation). Keying placement on that title never matched, so
# Chrome was never restored. The durable identity of a Chrome window is its tab
# set; the stable signal is the ACTIVE-TAB URL, which Chrome records in its
# SNSS session file. We read that file (read-only; no --remote-debugging-port,
# no new attack surface), join a live window to its session window by the
# momentary page title (wayland and SNSS reflect the same Chrome state at any
# instant), and key on the NORMALIZED URL -- which carries none of the title's
# churn. A window not yet in the session file falls back to its raw title, so
# behavior never regresses below the old title scheme.
CHROME_APPS = {"google-chrome", "chromium"}
# Seconds between starting one Chrome profile and the next. Long enough for the
# first invocation to become the browser process and open its singleton socket,
# which is what the second one needs to talk to.
CHROME_STAGGER = float(os.environ.get("SESSION_CHROME_STAGGER", 4))

# Flags usher adds when IT starts the browser. Starting the right profile is
# not enough on its own: Chrome only reopens the previous windows when the
# profile's "On startup" preference says to, and unset (the state of both
# profiles here) means the New Tab page. So usher got the profile right and
# Chrome opened a blank window.
#
#   --restore-last-session      reopen the last session regardless of that
#                               preference. This is the whole intent of the
#                               launch, and it applies ONLY to usher's own
#                               invocation, never to one started by hand.
#   --hide-crash-restore-bubble suppress "Chrome didn't shut down correctly.
#                               Restore?". A session that ends with the machine
#                               going down is recorded as exit_type=Crashed, so
#                               that bubble appears at every login, and having
#                               just ASKED for the restore we would be offering
#                               it a second time.
#
# Override with SESSION_CHROME_FLAGS (space separated), empty to pass none.
_CHROME_FLAGS_DEFAULT = "--restore-last-session --hide-crash-restore-bubble"
CHROME_FLAGS = shlex.split(
    os.environ.get("SESSION_CHROME_FLAGS", _CHROME_FLAGS_DEFAULT))
# Wayland titles Chrome sets are "<page title> - Google Chrome"; strip that
# browser suffix to recover the page title the session file stores.
CHROME_SUFFIXES = (" - Google Chrome", " - Chromium")

# ~/.config/session/identity: optional URL-normalization rules for domains
# whose PATH is also volatile (e.g. mail.google.com carries message ids). Same
# '<regex> :: <value>' line shape as session/exclude, but the left side matches
# the normalized "host/path" and the right side is the LITERAL canonical id to
# collapse it to (not a regex). Live-reloaded by the capture loop.
IDENTITY_FILE = os.environ.get(
    "SESSION_IDENTITY_FILE",
    os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
        "session", "identity"))


def load_identity_rules(path=IDENTITY_FILE):
    """Parse session/identity into (url_regex, canonical) pairs. A line missing
    '::' or with a bad regex is collected into errors and skipped, never
    crashing the headless daemon; a missing file yields ([], [])."""
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
            errors.append((n, line, "missing '::' (use '<url> :: <id>')"))
            continue
        pat, canon = (s.strip() for s in line.split("::", 1))
        try:
            rules.append((re.compile(pat or ".*"), canon))
        except re.error as e:
            errors.append((n, line, f"bad regex: {e}"))
    return rules, errors


IDENTITY_RULES, IDENTITY_ERRORS = load_identity_rules()


def reload_identity():
    """Re-read session/identity live, as reload_exclude does for its file."""
    global IDENTITY_RULES, IDENTITY_ERRORS
    IDENTITY_RULES, IDENTITY_ERRORS = load_identity_rules()
    logline(f"identity reloaded: {len(IDENTITY_RULES)} rule(s),"
            f" {len(IDENTITY_ERRORS)} error(s)")
    for _n, _text, _msg in IDENTITY_ERRORS:
        logline(f"identity rule error (line {_n}): {_msg}: {_text!r}")


# SNSS command ids (Chromium components/sessions/core/session_service_commands
# .cc). Framing is fixed: int16 size, then a 1-byte id + payload of size-1; we
# always advance by size, so a payload we cannot decode never desyncs the
# stream. SetTabWindow/SetTabIndexInWindow/SetSelectedTabInWindow are raw int32
# structs; UpdateTabNavigation is a Pickle; SetSelectedNavigationIndex picks
# which of a tab's navigations is current; TabClosed/WindowClosed retire ids.
_SNSS_SET_TAB_WINDOW = 0
_SNSS_SET_TAB_INDEX = 2
_SNSS_UPDATE_TAB_NAV = 6
_SNSS_SET_SEL_NAV_INDEX = 7
_SNSS_SET_SEL_TAB_IN_WIN = 8
_SNSS_TAB_CLOSED = 16
_SNSS_WINDOW_CLOSED = 17


def _snss_i32(b, o):
    return struct.unpack_from("<i", b, o)[0], o + 4


def _snss_str(b, o):          # Pickle WriteString: int32 len, bytes, pad to 4
    n, o = _snss_i32(b, o)
    if n < 0 or o + n > len(b):
        raise ValueError("bad str")
    s = b[o:o + n]
    return s.decode("utf-8", "replace"), (o + n + 3) & ~3


def _snss_str16(b, o):        # WriteString16: int32 nchars, 2*nchars, pad to 4
    n, o = _snss_i32(b, o)
    if n < 0 or o + 2 * n > len(b):
        raise ValueError("bad str16")
    s = b[o:o + 2 * n]
    return s.decode("utf-16-le", "replace"), (o + 2 * n + 3) & ~3


def parse_snss(path):
    """Parse one SNSS session file into {active_page_title: raw_url} for its
    open windows -- each window's selected tab, at that tab's current
    navigation. Never raises: a malformed record is skipped, a bad file yields
    {}."""
    d = open(path, "rb").read()
    if d[:4] != b"SNSS":
        return {}
    off = 8                                     # skip magic + int32 version
    tab_win, tab_idx, win_sel, tab_nav = {}, {}, {}, {}
    nav, closed_tabs, closed_wins = {}, set(), set()
    while off + 2 <= len(d):
        (size,) = struct.unpack_from("<H", d, off)
        off += 2
        if size == 0 or off + size > len(d):
            break
        cid = d[off]
        p = d[off + 1:off + size]
        off += size
        try:
            if cid == _SNSS_SET_TAB_WINDOW:
                w, o = _snss_i32(p, 0)
                t, o = _snss_i32(p, o)
                tab_win[t] = w
            elif cid == _SNSS_SET_TAB_INDEX:
                t, o = _snss_i32(p, 0)
                i, o = _snss_i32(p, o)
                tab_idx[t] = i
            elif cid == _SNSS_SET_SEL_TAB_IN_WIN:
                w, o = _snss_i32(p, 0)
                i, o = _snss_i32(p, o)
                win_sel[w] = i
            elif cid == _SNSS_SET_SEL_NAV_INDEX:
                t, o = _snss_i32(p, 0)
                i, o = _snss_i32(p, o)
                tab_nav[t] = i
            elif cid == _SNSS_UPDATE_TAB_NAV:
                _sz, o = _snss_i32(p, 0)         # pickle payload-size header
                t, o = _snss_i32(p, o)
                idx, o = _snss_i32(p, o)
                url, o = _snss_str(p, o)
                title, o = _snss_str16(p, o)
                nav[(t, idx)] = (url, title)
            elif cid == _SNSS_TAB_CLOSED:
                t, o = _snss_i32(p, 0)
                closed_tabs.add(t)
            elif cid == _SNSS_WINDOW_CLOSED:
                w, o = _snss_i32(p, 0)
                closed_wins.add(w)
        except Exception:
            pass
    wins = {}
    for t, w in tab_win.items():
        if t in closed_tabs or w in closed_wins:
            continue
        wins.setdefault(w, []).append(t)
    out = {}
    for w, tabs in wins.items():
        sel = win_sel.get(w)
        active = next((t for t in tabs if tab_idx.get(t) == sel), None)
        if active is None:
            continue
        entry = nav.get((active, tab_nav.get(active)))
        if not entry:
            continue
        url, title = entry
        if title and url:
            out[title] = url
    return out


_snss_cache = {"sig": None, "map": {}}


def _session_files():
    """Newest Session_* file per Chrome profile (browser windows only -- PWAs
    live in a separate Apps session and already carry stable app-ids)."""
    newest = {}
    for f in glob.glob(os.path.expanduser(
            "~/.config/google-chrome/*/Sessions/Session_*")):
        prof = os.path.dirname(os.path.dirname(f))
        try:
            mt = os.path.getmtime(f)
        except OSError:
            continue
        if prof not in newest or mt > newest[prof][1]:
            newest[prof] = (f, mt)
    return [v[0] for v in newest.values()]


def chrome_session_titles():
    """Merged {page_title: raw_url} across profiles' current sessions, cached
    and re-read only when a session file's mtime changes."""
    files = _session_files()
    try:
        sig = tuple(sorted((f, os.path.getmtime(f)) for f in files))
    except OSError:
        sig = None
    if sig != _snss_cache["sig"]:
        merged = {}
        for f in files:
            try:
                merged.update(parse_snss(f))
            except Exception:
                pass
        _snss_cache["sig"] = sig
        _snss_cache["map"] = merged
    return _snss_cache["map"]


def normalize_url(url):
    """A URL's stable identity: host + path (query and fragment dropped -- they
    carry the volatile per-visit state), then any session/identity rule that
    matches collapses it to that rule's canonical id."""
    try:
        pr = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    base = (pr.netloc + pr.path).rstrip("/") or pr.netloc or url
    for rx, canon in IDENTITY_RULES:
        if rx.search(base):
            return canon
    return base


def chrome_url_for(title):
    """The normalized active-tab URL for a live Chrome window titled `title`,
    or None if it is not in the current session file (fall back to the title).
    Joins on the page title after stripping the browser-name suffix."""
    t = title
    for suf in CHROME_SUFFIXES:
        if t.endswith(suf):
            t = t[:-len(suf)]
            break
    url = chrome_session_titles().get(t)
    return normalize_url(url) if url else None


# --- plugin framework: app-specific window identity + restore --------------
# The engine is app-AGNOSTIC; how to IDENTIFY and RESPAWN a given app's windows
# lives in a plugin. chrome, mux, and kitty ship built in; a user drops more
# into ~/.config/session/plugins/*.py (each a module defining a top-level PLUGIN
# with the WindowPlugin surface -- duck-typed, no import of this script needed).
# The engine consults the registry (order matters: FIRST owner wins) at each
# app-specific site: identity, transient, per-window id, force-title keying, and
# relaunch. Every window hook takes a normalized VIEW (see _pview: app/title,
# so a plugin can read /proc) and is optional but owns.
HOME = os.path.expanduser("~")


def chrome_profile_map():
    """normalized-URL -> the Chrome PROFILE DIRECTORY that has it open.

    Built from the same SNSS session files the chrome identity is read from, so
    it needs no new state: the profile is simply where each file LIVES
    (.../<Profile>/Sessions/Session_*). The files survive a restart, which is
    how Chrome restores itself, so this is answerable at login before Chrome
    has started."""
    out = {}
    for p in _session_files():
        prof = os.path.basename(os.path.dirname(os.path.dirname(p)))
        try:
            found = parse_snss(p)
        except Exception:
            continue
        for url in found.values():
            k = normalize_url(url)
            if k:
                out.setdefault(k, prof)
    return out


def chrome_profiles_for(saved):
    """The profile directories to start, one per profile that actually had a
    window last session, in first-seen order. Falls back to a single unnamed
    launch (Chrome's own choice, possibly the picker) when nothing can be
    matched -- no worse than before, and only when there is nothing to go on."""
    pm = chrome_profile_map()
    out = []
    for w in saved:
        if w.get("app_id") not in CHROME_APPS:
            continue
        prof = pm.get(saved_key(w))
        if prof and prof not in out:
            out.append(prof)
    return out or [None]


def _pview(v):
    """Normalize a wayfire view, a snapshot window, or a kb entry to the fields
    plugins read: app, title, pid (-1 when absent, e.g. a stored entry)."""
    if "app" in v and "app_id" not in v and "app-id" not in v:
        return v                                # already normalized
    return {"app": v.get("app-id") or v.get("app_id") or "",
            "title": v.get("title", ""),
            "pid": v.get("pid", -1)}


class WindowPlugin:
    """Base + interface. A plugin CLAIMS an app's windows (owns) and can add
    stable identity, a transient test, a per-window id, and a way to respawn a
    missing window. Every window hook takes a normalized view (v["app"],
    v["title"], v["pid"]); the defaults make each opt-in."""
    name = "base"

    def owns(self, v):
        return False

    def identity(self, v):
        return None       # a stable kb key, or None to defer to the raw title

    def transient(self, v):
        return False      # never capture/place (a New Tab, a scratch terminal)

    def window_id(self, v):
        return None       # a stable per-window id (mux/kitty's TERM_WINDOW_ID)

    def relaunch_missing(self, saved, live):
        return 0          # respawn this app's saved-but-absent windows; count


PLUGIN_DIR = os.path.join(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
    "session", "plugins")

_PLUGINS = None


def plugins():
    """The loaded plugin list -- built-ins first, then user plugins -- lazily
    built and cached. reload_plugins() drops the cache. mux is BEFORE kitty so a
    mux-attached kitty window is claimed by mux, the rest by kitty."""
    global _PLUGINS
    if _PLUGINS is None:
        _PLUGINS = [ChromePlugin(), MuxPlugin(), KittyPlugin()] \
            + _load_user_plugins()
    return _PLUGINS


def reload_plugins():
    global _PLUGINS
    _PLUGINS = None
    ps = plugins()
    logline("plugins reloaded: "
            + ", ".join(getattr(p, "name", "?") for p in ps))


def _load_user_plugins():
    """Import every ~/.config/session/plugins/*.py and collect its top-level
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
    v = _pview(v)
    for p in plugins():
        try:
            if p.owns(v):
                return p
        except Exception:
            pass
    return None


def identity(v):
    """The kb KEY-title for a window -- the single chokepoint every keying site
    routes through (upsert, learn, match, place). An owning plugin's identity()
    wins (Chrome's URL, mux's session, kitty's cwd); otherwise the raw title."""
    v = _pview(v)
    p = _owner(v)
    if p is not None:
        try:
            k = p.identity(v)
            if k:
                return k
        except Exception:
            pass
    return v["title"]


def _single_id(v):
    """An owning plugin's stable single-key identity for this window, or None to
    fall through to the title-grouping path (non-owned apps). Drives the
    keying branch in upsert()/learn()."""
    v = _pview(v)
    p = _owner(v)
    if p is not None:
        try:
            return p.identity(v)
        except Exception:
            pass
    return None


def plugin_transient(v):
    """True if this window's OWNING plugin marks it transient (a scratch
    terminal). Only the owner is consulted -- a plugin's hooks apply to the
    windows it claims, never another plugin's (e.g. kitty's cwd==$HOME scratch
    test must not fire on a mux window whose shell sits at $HOME)."""
    v = _pview(v)
    p = _owner(v)
    if p is not None:
        try:
            return bool(p.transient(v))
        except Exception:
            pass
    return False


def is_owned(app):
    """True if some plugin claims this app-id -- so its windows never drop to an
    app_id-only key (the old FORCE_TITLE_APPS rule, now plugin-driven). By app
    alone (chrome/kitty own by app-id; mux is a title-keyed subset of the kitty
    app, already covered)."""
    return _owner({"app": app, "title": "", "pid": -1}) is not None


def window_id_for(v):
    """The OWNING plugin's stable per-window id for a view, else ''."""
    v = _pview(v)
    p = _owner(v)
    if p is not None:
        try:
            return p.window_id(v) or ""
        except Exception:
            pass
    return ""


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
    """The working dir of a kitty window's SHELL -- its first non-helper child's
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


def mux_session_of(title):
    """The mux SESSION from a `session:window` banner -- the durable unit that
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

    mux added the tag for exactly this consumer -- its own comment says a local
    session and an ssh'd one sharing a name "would otherwise snap the two
    windows onto each other" -- so reading it is the whole local/remote story;
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


def mux_identity(title):
    """The mux plugin's kb key: `mux@<host>:<session>`, or None if the title is
    not a session banner. FULLY QUALIFIED, always -- a bare `mux:<session>` key
    could not say which box it meant, and two boxes running a same-named session
    (the norm here: a `tackup` session on both) would share one saved slot and
    fight over it. An untagged title falls back to this host.

    The TITLE is the authority here, deliberately. The host tag names the tmux
    SERVER's host, which is the question identity asks; sniffing the ssh in
    /proc would answer a different one (the ROUTE taken), and the two diverge
    through a jump host. A window is also free to move between sessions while
    that ssh stays put, so the process tree goes stale where the title does
    not. Tried and reverted 2026-09-20.
    """
    s = mux_session_of(title)
    if not s:
        return None
    return f"mux@{mux_host_of(title) or LOCAL_HOST}:{s}"


# The parsed form of a stored mux key. Neither field can contain ':' (tmux
# forbids it in a session name, and a hostname cannot hold one), so the split
# is unambiguous.
MUX_KEY_RE = re.compile(r"^mux@([^:]+):(.+)$")


class ChromePlugin(WindowPlugin):
    """Chrome / Chromium: identity is the active-tab URL read from the SNSS
    session file (chrome_url_for). Transient states (a blank New Tab, the
    profile picker) are handled by the session/exclude config, not here."""
    name = "chrome"

    def owns(self, v):
        return v["app"] in CHROME_APPS

    def identity(self, v):
        return chrome_url_for(v["title"])

    def relaunch_missing(self, saved, live):
        """Start the browser if the last session had Chrome windows and none
        is running now. Chrome restores its OWN windows, but only once
        something starts it -- so on a login where nothing did, usher was
        leaving the largest part of the desk shut. It starts the browser and
        nothing more: which windows come back stays Chrome's business.

        Started PER PROFILE, naming each one. A bare `google-chrome` on a box
        with several profiles and no `Default` opens the profile PICKER and
        waits for a human, restoring nothing at all -- so the one thing usher
        had to get right about starting it was which profile to start."""
        if not any(w.get("app_id") in CHROME_APPS for w in saved):
            return 0
        if any(_pview(v)["app"] in CHROME_APPS for v in live):
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
    """mux-attached kitty terminals -- a kitty window wearing a mux
    `session:window` banner (is_mux_term). Identity is the mux SESSION plus the
    HOST it lives on (`mux@<host>:<session>`), both parsed from the title: the
    session is the durable unit `mux go` names, and the host is the trailing tag
    mux stamps (see mux_host_of). NOT the full title, which churns as you switch
    windows within a session and carries padding.

    Claims a REMOTE session (one whose host is not this box) as readily as a
    local one: it is the same kind of window doing the same job, wants the same
    slot back, and differs only in how it respawns -- `mux go` here, the same
    through `ssh` there. Respawn is the sole mux-BINARY touchpoint, best-effort
    so it no-ops without mux (the soft dep)."""
    name = "mux"

    def owns(self, v):
        return is_mux_term(v["app"], v["title"])

    def identity(self, v):
        return mux_identity(v["title"])

    def window_id(self, v):
        return term_wid(v["pid"])

    def relaunch_missing(self, saved, live):
        return mux_relaunch_missing(saved, live)


class KittyPlugin(WindowPlugin):
    """Non-mux kitty terminals -- a shell or a program (e.g. Claude Code) in a
    working dir. Claims any kitty window mux did not (registry order). Identity
    is the shell's CWD from /proc (`kitty:<cwd>`), so the window keeps its place
    across restarts regardless of the volatile title. A bare shell sitting at
    $HOME is a scratch terminal (transient). Respawns a missing one as a plain
    shell in that cwd (`kitty --directory` -- deliberately NOT re-running the
    captured command)."""
    name = "kitty"

    def owns(self, v):
        return v["app"] == "kitty"

    def transient(self, v):
        # a live window: a shell at $HOME (or an unreadable proc) is scratch. A
        # stored entry (pid<0) is never re-judged transient -- it was kept at
        # capture; fall back to the title scratch test so prune_kb stays safe.
        if v["pid"] and v["pid"] > 0:
            cwd = _term_cwd(v["pid"])
            return (not cwd) or cwd == HOME
        return is_scratch_term(v["app"], v["title"])

    def identity(self, v):
        cwd = _term_cwd(v["pid"])
        return f"kitty:{cwd}" if cwd and cwd != HOME else None

    def window_id(self, v):
        return term_wid(v["pid"])

    def relaunch_missing(self, saved, live):
        return kitty_relaunch_missing(saved, live)


# --- knowledge base: identity -> latest placement -------------------------
# The daemon matches against this, not raw snapshots. Each capture upserts
# every window's (app_id, title) with its newest placement, so it is a
# superset across time (remembers closed windows) but deduplicated with
# recency (the latest observation wins). Entries unseen for TTL age out; no
# LRU is needed, the TTL bounds the store (see learn() for the grouping).
KNOWLEDGE_TTL = 30 * 86400

# Apps a plugin claims (is_owned) legitimately SHARE one app_id -- a momentary
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
# sharing one slot. The old keys can never match again, so migrate_kb drops them
# once (the store is a rebuildable cache).
KB_SCHEMA = "4"
_MIGRATE_APPS = CHROME_APPS | {"kitty"}


def migrate_kb(kb):
    """One-time store migration, idempotent via a schema stamp beside the kb.
    On a stale/absent schema, drop every Chrome + kitty title-keyed entry so
    relearn under the new identities, then stamp -- so a boot after the upgrade
    collapses the accumulated per-title pile instead of carrying it."""
    sp = schema_path()
    try:
        cur = open(sp).read().strip()
    except OSError:
        cur = ""
    if cur == KB_SCHEMA:
        return
    for k in [k for k in kb if k.split("\x00", 1)[0] in _MIGRATE_APPS]:
        del kb[k]
    try:
        os.makedirs(STATE, exist_ok=True)
        save_knowledge(kb)
        write_json(sp, KB_SCHEMA)
    except OSError:
        pass


def load_knowledge():
    """The knowledge base for the CURRENT display profile. A monitor set with
    nothing learned yet starts empty (and seeds from the last snapshot), which
    is right: the placements from another desk would not fit here anyway."""
    adopt_legacy_store()
    try:
        kb = json.load(open(kb_path()))
    except (FileNotFoundError, ValueError):
        # A store that does not exist yet is CURRENT by construction, so stamp
        # it NOW. Without this, the first monitor set to be seen writes an
        # unstamped store, and the very next load judges it stale and drops
        # exactly the chrome + kitty entries it has just learned -- every new
        # desk silently losing its browser and terminal placements once.
        try:
            os.makedirs(STATE, exist_ok=True)
            write_json(schema_path(), KB_SCHEMA)
        except OSError:
            pass
        snap = _load_snapshot()    # seed from the latest snapshot if present
        if snap is None:
            return {}
        kb = {}
        upsert(kb, snap["windows"], snap["time"])
        return kb
    migrate_kb(kb)
    return kb


def is_unique(app, counts):
    """True if this app_id identifies exactly one window (so it can key by
    app_id alone, title-independent). A plugin-owned app is never unique, even
    when momentarily alone -- its windows share an app_id (see is_owned)."""
    return counts[app] == 1 and not is_owned(app)


def kb_entry(w, title, appid_only, when):
    """A knowledge record for one identity at window w's current placement.
    `title` is the KEY-title (identity() -- a URL for Chrome); `label` keeps the
    human window title for logs, since the key may no longer read as one."""
    return {
        "app_id": w["app_id"], "title": title, "appid_only": appid_only,
        "label": w.get("title", ""),
        "output": w["output"], "workspace": w["workspace"],
        "pos": w["pos"], "size": w["size"],
        "sticky": bool(w.get("sticky", False)),
        "inverted": bool(w.get("inverted", False)), "last_seen": when,
    }


def prune_kb(kb, when):
    """Drop aged-out entries, work-tagged entries, and stale per-title entries
    for an app now keyed by app_id (an app_id-only key ends in NUL).

    A plugin-owned app must never carry an app_id-only key. If a stale one
    lingers -- e.g. written before the app got a plugin -- it is doubly
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
    title. Used by `session-mgr capture` and the seed-from-snapshot path;
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


def learn(kb, groups, windows, when):
    """Watch-time knowledge update with view-id tab-grouping.

    Each live view -- keyed by its wayfire id, stable for the window's whole
    life -- owns the set of titles it has shown. Every title in the set is
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

    # Degroup: purge now-ambiguous titles from every group and the store.
    for app, title in ambiguous:
        kb.pop(kkey(app, title), None)
    for g in groups.values():
        g["titles"] -= {t for a, t in ambiguous if a == g["app"]}

    # Retire groups whose window closed (their kb entries linger under the TTL).
    for vid in [v for v in groups if v not in live]:
        del groups[vid]

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

    # Stamp: unique-app_id -> app_id key; a plugin single-identity (Chrome ->
    # its ONE active-tab URL, no title accumulation, restored whatever tab was
    # active) -> that key; other shared apps (mux terminals) -> every title in
    # the view's group, all at the view's current placement.
    for w in windows:
        app, vid = w["app_id"], w.get("id")
        key = _single_id(w)
        if is_unique(app, counts):
            kb[kkey(app, "")] = kb_entry(w, w["title"], True, when)
        elif key:
            kb[kkey(app, key)] = kb_entry(w, key, False, when)
        elif vid is not None and vid in groups:
            for t in groups[vid]["titles"]:
                kb[kkey(app, t)] = kb_entry(w, t, False, when)

    # Mux terminals: keep only the session each window CURRENTLY shows. A window
    # that cycled sessions leaves the old titles in the store, where they would
    # relaunch as phantom windows or yank a different window that later shows
    # that session. Drop any mux-terminal entry no live window shows.
    #
    # BOTH sides must be IDENTITIES. A kb entry's "title" field is the KEY-title
    # (kb_entry stamps identity(), not the window title), so comparing it to raw
    # window titles never matched and this block deleted every terminal entry it
    # had just written, on every pass -- terminals were therefore never placed
    # at all. And the entry is selected by its KEY SHAPE, not by is_mux_term on
    # that key: is_mux_term only asks "kitty, with a colon?", which a
    # kitty:<cwd> key also satisfies, so the mux purge was sweeping plain kitty
    # windows out too.
    live_terms = {identity(w) for w in windows
                  if is_mux_term(w["app_id"], w["title"])}
    for k in [k for k, v in kb.items()
              if MUX_KEY_RE.match(v.get("title", ""))
              and v.get("title") not in live_terms]:
        del kb[k]
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
    snap = snapshot(WayfireSocket())
    os.makedirs(STATE, exist_ok=True)
    persist(snap)
    kb = load_knowledge()
    upsert(kb, snap["windows"], snap["time"])
    save_knowledge(kb)
    print(f"session-mgr: captured {len(snap['windows'])} window(s); "
          f"{len(kb)} known -> {STATE}")


def app_of(v):
    return v.get("app-id") or v.get("app_id") or ""


# --- init-launch: bring terminals back (Chrome self-restores on its own) ----

def mux_go_command(session, host=None):
    """The shell command a terminal runs to land in `session`: `mux go` when it
    lives on this box, `mux latch HOST:SESSION` when it does not.

    The remote half used to be a hand-rolled `ssh -t <host> 'sh -lc "mux go
    X"'`, and that was the wrong layer. It attempts ONCE, at login, and a
    login is exactly when the credential is least likely to be live: the
    daemon is started by the compositor autostart, whose environment has no
    SSH_AUTH_SOCK at all (verified on manifold). The attempt failed, the `exec
    ksh -i` fallback left a bare shell, and the session never came back.

    `mux latch` is mux's own answer to this and treats it as a STATE MACHINE
    rather than a single attempt. Its `blocked` state is written for precisely
    this case -- no credential live YET -- and it polls the credential instead
    of retrying the connection, so the attachment lands by itself the moment
    an agent appears. It also distinguishes `denied` (terminal, say what to
    fix) from `probing` (retry on a backoff), which a one-shot ssh cannot.

    So remote attach semantics belong to mux, the same way the session SET
    does. usher names the host and the session and stays out of it."""
    mux = os.path.expanduser("~/.local/bin/mux")
    if not host or host == LOCAL_HOST:
        return f"{shlex.quote(mux)} go {shlex.quote(session)}"
    return f"{shlex.quote(mux)} latch {shlex.quote(host + ':' + session)}"


def _announce(msg):
    """Say it on stdout AND in the daemon's log. Both matter: stdout is what a
    person running `session-mgr launch` by hand reads, and the log is the only
    copy that survives, since the compositor autostart discards the worker's
    stdout entirely."""
    print(msg, flush=True)
    logline(msg)


def saved_sizes(saved):
    """identity -> [w, h] from the last snapshot, so a respawned window can be
    ASKED FOR at the size it had instead of mapping at kitty's configured
    default and waiting to be corrected. Measured here: a relaunched terminal
    mapped at 1085x672 (the 80c x 24c in kitty.conf) against a remembered
    2132x1690, and sat that way until placement caught up."""
    out = {}
    for w in saved:
        k, s = saved_key(w), w.get("size")
        if k and s and len(s) == 2 and s[0] and s[1]:
            out.setdefault(k, [int(s[0]), int(s[1])])
    return out


def _size_opts(size):
    """kitty's initial-size flags. Plain numbers are PIXELS (kitty.conf here
    uses the `c` suffix for cells). kitty rounds to whole cells and adds its
    padding, so this lands CLOSE rather than exact -- 2176x1761 for a 2132x1690
    request when measured -- and the normal placement pass makes it exact. The
    point is that the window never appears at the wrong size."""
    if not size:
        return []
    return ["-o", f"initial_window_width={int(size[0])}",
            "-o", f"initial_window_height={int(size[1])}"]


def spawn_term(session, host=None, size=None):
    """Open a terminal attached to a mux session, launched through a shell so
    that DETACHING drops back to that shell instead of closing the window.
    kitty running `mux go` as its direct child would exit on detach (mux exits
    -> kitty exits -> window vanishes). Running it inside `ksh -c '... ; exec
    ksh -i'` leaves an interactive shell after detach: the window survives and,
    re-sourcing kshrc, becomes a plain 'terminal' -- untracked, exactly what a
    detached scratch terminal should be. TMUX is cleared so mux does a fresh
    attach, not a switch-client that hijacks another window.

    A REMOTE session (host not this box) differs only in the command; the same
    detach-survives-as-a-shell wrapper holds, so dropping an ssh'd session
    leaves a local shell exactly as a local one does."""
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    env["TERM_WINDOW_ID"] = os.urandom(6).hex()   # stable per-window id
    cmd = f"{mux_go_command(session, host)}; exec ksh -i"
    subprocess.Popen(["kitty"] + _size_opts(size) + ["ksh", "-c", cmd],
                     env=env, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _load_snapshot():
    """The last snapshot, or None if there is not a readable one. The single
    reader of current.json, so relaunch and doctor always look at the same
    thing."""
    try:
        with open(os.path.join(STATE, "current.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


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
    the live tmux server -- which is the whole point, because the case that
    matters is a COLD BOOT, where no session is live but `mux go` rebuilds from
    exactly this set. Reading the live server instead meant there was never
    anything to relaunch after a reboot.

    Deliberately not scraped out of `mux ls`, which is a HUMAN listing: it leads
    each line with an agent-state glyph, so the scrape that used to read it
    matched nothing and left this entire path dead with no symptom. selftest
    asserts the bare-name shape against the real binary, so a future change to
    mux's output fails LOUD here instead of silently going inert again.

    Empty when mux is absent or errors -- the soft-dep no-op."""
    try:
        out = subprocess.run(
            [os.path.expanduser("~/.local/bin/mux"), "resume", "--list"],
            capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return set()
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def live_keys(live):
    """The resolved identities of the windows currently on screen -- the ONE
    definition of "already showing" that every relaunch path tests against, so
    the question is answered the same way for each. Comparing identities rather
    than raw state is what keeps the plugins from tripping over each other: a
    mux-attached window keys mux@... (its owner is the mux plugin), so it can
    never be mistaken for a kitty:<cwd> window whose shell happens to sit in the
    same place."""
    out = set()
    for v in live:
        k = identity(_pview(v))
        if k:
            out.add(k)
    return out


def mux_candidates(saved, livekeys, known, local_host=None):
    """The (host, session) pairs to respawn: every mux window in the last
    snapshot that is not already on screen (`livekeys`, from live_keys). Pure
    and side-effect free so selftest can drive it with fixtures -- this logic
    used to be reachable only through two subprocesses and a compositor, which
    is exactly why it could rot unnoticed.

    A LOCAL session must still be one mux knows (`known`): the set is
    subtractive on `mux kill`, so a session you deliberately killed stays
    killed rather than rising again at every login. A REMOTE one is taken on
    trust from our own store, with no network call in the login path -- if it
    has gone, `mux go` on the far box rebuilds it from that box's own set, which
    is the same answer an ssh probe would have cost a round trip to get."""
    local_host = local_host or LOCAL_HOST
    out, seen = [], set()
    for w in saved:
        if w.get("app_id") != "kitty":
            continue
        m = MUX_KEY_RE.match(saved_key(w))
        if not m:
            continue
        host, sess = m.group(1), m.group(2)
        key = f"mux@{host}:{sess}"
        if key in seen or key in livekeys:
            continue
        if host == local_host and sess not in known:
            continue
        seen.add(key)
        out.append((host, sess))
    return out


def mux_relaunch_missing(saved, live):
    """The mux plugin's relaunch: reopen each mux session that was on screen at
    the last snapshot and is not now, reattached with `mux go` -- locally, or
    over ssh for a session that lived on another box."""
    n = 0
    sizes = saved_sizes(saved)
    for host, sess in mux_candidates(saved, live_keys(live), mux_session_set()):
        spawn_term(sess, host, sizes.get(f"mux@{host}:{sess}"))
        n += 1
        where = "" if host == LOCAL_HOST else f"  [on {host}]"
        _announce(f"launch  mux go {sess}{where}")
    return n


def _spawn_kitty(cwd, size=None):
    """Open a plain kitty shell in cwd (a fresh per-window id). Deliberately NOT
    re-running the window's captured program -- restoring the place + directory,
    not the command."""
    env = {k: v for k, v in os.environ.items() if k != "TMUX"}
    env["TERM_WINDOW_ID"] = os.urandom(6).hex()
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


def launch_missing(*_):
    """Ask every plugin to respawn any of its saved-but-absent windows. Loads
    the last snapshot + the live views ONCE and hands both to each plugin's
    relaunch_missing; sums the counts. Chrome self-restores (its plugin returns
    0); mux reopens terminals. (The unused arg keeps the old call sites.)"""
    saved = (_load_snapshot() or {}).get("windows", [])
    try:
        live = WayfireSocket().list_views(filter_mapped_toplevel=True)
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
    match anything -- honest, and better than matching the wrong window."""
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
    snapshot (undo a shuffle you just made); a date -- or today/yesterday --
    is that day's FIRST snapshot, the stable 'how it looked that morning'."""
    miles, hist = _available()
    if spec in ("list", ""):
        print("milestones: " + (", ".join(miles) or "(none)"))
        print(f"history:    {len(hist)} rolled snapshot(s); `--from latest`"
              " is the newest")
        sys.exit(0)
    if spec == "latest":
        if not hist:
            sys.exit("session-mgr: no history snapshots yet")
        path, label = hist[-1], "latest (history)"
    else:
        d = _spec_to_date(spec)
        if d is None:
            sys.exit(f"session-mgr: unknown --from '{spec}' (want: latest, "
                     f"today, yesterday, or YYYY-MM-DD). Have: "
                     f"{', '.join(miles) or 'no milestones yet'}")
        path, label = os.path.join(STATE, "milestones", f"{d}.json"), d
        if not os.path.exists(path):
            sys.exit(f"session-mgr: no milestone for {d}. Have: "
                     f"{', '.join(miles) or 'none'}")
    try:
        with open(path) as f:
            return label, json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"session-mgr: cannot read {path}: {e}")


def match(live, entries):
    """Greedily match each live window to a knowledge entry, consume-once. An
    app_id-keyed entry matches on app_id alone (unique-app_id apps whose title
    drifts); the rest need an exact identity too (raw title, or -- for Chrome --
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


def do_restore(dry, only=None, source=None):
    sock = WayfireSocket()
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
        # still get its inversion back -- the "forgets some" bug was applying
        # invert only inside the move branch.
        if e.get("inverted"):
            apply_invert(sock, lv["id"])
            if same:
                print("  inverted " + label)

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


# --- doctor: say out loud what this thing is and is not doing ---------------
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
           else "hwdp" if _hwdp_id() else "derived from outputs")
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
    snap = _load_snapshot()
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
    known = mux_session_set()
    chrome_up = any(_pview(v)["app"] in CHROME_APPS for v in live)
    chrome_note = ("Chrome restores its own" if chrome_up
                   else "browser NOT running: usher starts it, Chrome"
                        " restores its own")
    for w in saved:
        app, key = w.get("app_id", ""), saved_key(w)
        if app in CHROME_APPS:
            out(f"  {'self' if chrome_up else 'START':10} {app:14}"
                f" {key[:36]:36}  ({chrome_note})")
            continue
        m = MUX_KEY_RE.match(key)
        if m:
            host, sess = m.group(1), m.group(2)
            if key in lk:
                out(f"  live       {key[:56]}")
            elif host == LOCAL_HOST and sess not in known:
                out(f"  skip       {key[:44]}  (mux no longer knows"
                    f" '{sess}')")
            else:
                how = (f"mux go {sess}" if host == LOCAL_HOST
                       else f"ssh {host} -> mux go {sess}")
                out(f"  RELAUNCH   {key[:44]:44}  {how}")
            continue
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
        if e["output"] in outs:
            out(f"  placeable  {app_of(lv)[:14]:14} {e['title'][:34]:34}"
                f" -> {where}")
        else:
            out(f"  UNPLACEABLE {app_of(lv)[:13]:13} {e['title'][:34]:34}"
                f" -> {where} NOT ATTACHED")
    for lv in unlive:
        out(f"  unmatched  {app_of(lv)[:14]:14} {lv.get('title','')[:34]}")


PROFILE_MARK = "session-mgr.profile"   # last profile we acted on, per boot


def do_display_changed():
    """The display-change entry point, for hwdp's `changed` hook.

    That edge fires on EVERY output burst -- a monitor blanking and waking, a
    kanshi reapply, a re-detect -- not only when the set of monitors actually
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


def do_doctor():
    """The whole report. Returns an exit code: non-zero only for a CONTRACT
    breach, which is the class of fault that otherwise shows no symptom."""
    lines = []

    def out(s):
        lines.append(s)

    kb, snap = _doctor_store(out)
    out("== plugins ==")
    for p in plugins():
        hooks = [h for h in ("owns", "identity", "transient", "window_id",
                             "relaunch_missing")
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


# Layout-significant events: re-snapshot AND roll the history/milestone ring.
LAYOUT_TRIGGERS = {
    "view-geometry-changed", "view-workspace-changed", "view-tiled",
    "view-set-output", "view-wset-changed", "view-mapped", "view-unmapped",
    "view-fullscreen", "view-sticky", "output-added", "output-removed",
    "wset-workspace-changed",
}
# A title/app-id change (a tab switch) also feeds the knowledge base -- it adds
# a title to the window's group -- but must NOT roll history, or the ring
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
#                       content loads -- under CPU/network spikes that whole
#                       storm can take a minute or two.
PLACE_SETTLE = 1.5    # BROWSER windows: seconds the title must be QUIET before
#                       we place. A browser churns its title through a session-
#                       restore as tabs load, and reconfiguring it mid-restore
#                       can make it DROP the window -- a heavy tab-group window
#                       was lost exactly this way. A PLACE_EVENT only re-arms
#                       the timer; the move waits for the churn to stop. Well
#                       under PLACE_GRACE.
PLACE_SETTLE_FAST = 0.15  # everything else: the title is already stable at map
#                           and nothing restores tabs, so place almost at once
#                           (one placer tick). No reason to make normal apps sit
#                           out the browser settle -- this is the common case.

# --- aggressive vs steady placement (the anti-whack-a-mole state machine) ----
# Placement is AGGRESSIVE (place any known, non-excluded window) for a window
# after session start (or a `session-mgr aggressive` kick), then goes STEADY
# (place ONLY session/include anchors). A GLOBAL phase, orthogonal to the per-
# view PLACE_GRACE. Steady when the FLOOR has passed AND it has been quiet (no
# new window mapped) for IDLE_SETTLE, but never past the CAP:
#   aggressive := not( (now-armed >= FLOOR and now-last_map >= SETTLE)
#                      or now-armed >= CAP )
# FLOOR is a floor, not a race, so "log in, wander off, come back in 4 min and
# launch Chrome" still lands. All three are env-overridable.
START_FLOOR = float(os.environ.get("SESSION_START_FLOOR", 300))  # 5 min
IDLE_SETTLE = float(os.environ.get("SESSION_IDLE_SETTLE", 25))   # 25 s quiet
AGGR_CAP = float(os.environ.get("SESSION_AGGR_CAP", 900))        # 15 min cap

# Runtime seams (ephemeral, like the singleton lock): the kick writes ARM_FILE,
# the worker reads it and publishes STATUS_FILE for `session-mgr status` + the
# (Phase-2) tray gadget.
RUNTIME_DIR = os.environ.get("XDG_RUNTIME_DIR") or STATE
ARM_FILE = os.path.join(RUNTIME_DIR, "session-mgr.arm")
STATUS_FILE = os.path.join(RUNTIME_DIR, "session-mgr.status")


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


LOG_CAP = 256 * 1024   # rotate watch.log past this; bounds it to ~2x LOG_CAP


def logline(msg):
    """Append a timestamped line to the daemon's own log. Autostart discards a
    child's stdout/stderr, so without this a death (or a skipped event) is
    invisible -- which is exactly how a slow-login crash went unnoticed. Best
    effort: logging must never itself take the daemon down. Rotated at LOG_CAP
    (one generation kept) so a respawn loop cannot fill the disk -- the tree
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


def connect(retries=25, delay=0.2):
    """Open an IPC socket, retrying while the compositor's socket comes up. At
    autostart the ipc plugin may not have exported WAYFIRE_SOCKET yet, and
    WayfireSocket() raises at once with no retry of its own -- so a daemon that
    connects eagerly can die before it ever watches (kanshi-mgr retries the
    same way, ~5s). Only the initial connect retries; a mid-session drop is a
    real teardown and is handled by the caller."""
    last = None
    for _ in range(retries):
        try:
            return WayfireSocket()
        except Exception as e:      # socket absent/unready: wait and retry
            last = e
            time.sleep(delay)
    raise last


def is_desync_error(e):
    """True if e means the IPC socket is POISONED (off-by-one) and only a
    reconnect can cure it -- as opposed to a benign server error-response (e.g.
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
    knowledge writes -- a hand-launched stopgap outliving the next autostart is
    the concrete case. flock auto-releases when the holder exits (even a
    crash), so the slot frees itself with no stale-pidfile cleanup. Returns the
    held fd (keep it for the process lifetime), None if another watcher holds
    it, or "unlocked" if the lock infra itself is unavailable (never let a lock
    failure disable restore -- degrade to unlocked and say so)."""
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
    """XDG_RUNTIME_DIR (session-private tmpfs) or STATE as fallback -- the one
    place the lock file and the adopt flag live."""
    return os.environ.get("XDG_RUNTIME_DIR") or STATE


ADOPT_FLAG = "session-adopt"   # marker: armed by resume, consumed at init


def arm_adopt(on):
    """Arm (session-mgr resume) or clear (session-mgr watch) the one-shot
    adopt flag. watch clears it so a start/reload is unambiguously restore
    mode."""
    p = os.path.join(runtime_dir(), ADOPT_FLAG)
    try:
        os.makedirs(runtime_dir(), exist_ok=True)
        if on:
            open(p, "w").close()
        elif os.path.exists(p):
            os.remove(p)
    except OSError:
        pass


def take_adopt():
    """One-shot: True (and clear) if a `session-mgr resume` armed the flag, else
    False. Consumed by the worker at init, so only the first worker after a
    resume adopts; respawns and plain watch restore."""
    try:
        os.remove(os.path.join(runtime_dir(), ADOPT_FLAG))
        return True
    except OSError:
        return False


def do_watch(launch=True):
    """Supervisor: hold the single-instance lock, then spawn a worker and
    respawn it with backoff if it dies. The worker is this same script
    RE-EXEC'd (the _worker verb), not a fork -- so it reloads its code from
    disk on every respawn (kill the worker to pick up an edit), and only the
    supervisor holds the lock (the worker no longer inherits the fd, so an
    orphan can never block a restart). If a watcher is ALREADY running, this
    re-invocation reloads it in place (SIGHUP re-exec, picking up a code edit
    and the armed mode) instead of exiting -- so re-running watch/resume IS the
    reload, and there is no separate reload verb. Two paths in one script, self-
    contained (contrast kanshi/kanshi-mgr); session teardown reaps both via the
    cgroup kill, so the supervisor need not detect session end itself."""
    script = os.path.abspath(sys.argv[0])
    _lock = acquire_singleton()
    if _lock is None:
        # already running -> reload it (picks up code + the flag-armed mode).
        _signal_watcher(signal.SIGHUP, "reload", "reloaded")
        return
    if _lock == "unlocked":
        logline("singleton lock unavailable; supervising unlocked")
    elif isinstance(_lock, int):
        try:                    # record our pid so a re-run/stop can signal us
            os.ftruncate(_lock, 0)
            os.write(_lock, f"{os.getpid()}\n".encode())
        except OSError:
            pass

    holder = {"proc": None}

    def stop(signum, _frame):
        p = holder["proc"]
        if p and p.poll() is None:
            p.terminate()
        logline(f"supervisor stopping (signal {signum})")
        os._exit(0)

    def reload_self(signum, _frame):
        # Signal-handler context: the main loop is blocked in proc.wait(), so
        # do NOT call Popen.wait() here -- it re-enters the same lock and
        # deadlocks. Just SIGTERM the worker (it holds no lock and dies on its
        # own; execv abandons the wait anyway) and release the lock fd so the
        # re-exec'd self can re-acquire it.
        p = holder["proc"]
        if p:
            try:
                os.kill(p.pid, signal.SIGTERM)
            except OSError:
                pass
        if isinstance(_lock, int):
            try:
                os.close(_lock)
            except OSError:
                pass
        logline("reload (SIGHUP): re-exec supervisor")
        # Re-exec via the internal _super verb, NOT the original watch/resume
        # argv: a re-exec must supervise WITHOUT re-arming/clearing the adopt
        # flag, so a `session-mgr resume` that triggered this reload is
        # honoured by the next worker instead of clobbered by a re-run of
        # arm_adopt.
        keep = ["--no-launch"] if "--no-launch" in sys.argv[1:] else []
        os.execv(sys.executable, [sys.executable, script, "_super"] + keep)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, reload_self)

    # A fresh supervisor (login or a re-run) starts un-launched: drop a
    # stale marker so this generation relaunches. (A reload is safe -- the open
    # terminals are live, so launch_missing skips them.)
    try:
        os.makedirs(STATE, exist_ok=True)
        os.remove(LAUNCHED)
    except OSError:
        pass

    base = [sys.executable, script, "_worker"]
    backoff = 2
    while True:
        # Relaunch missing mux terminals on the first worker that actually
        # REACHES launch_missing (which drops LAUNCHED), NOT merely the first
        # spawned. The first worker often dies to the compositor-startup race
        # before it can launch; welding launch to it lost the relaunch entirely.
        # While the marker is absent, every spawn keeps launch on, so a crashed-
        # early worker just hands the launch to its successor. launch_missing is
        # idempotent (skips sessions a live window already shows), so at worst a
        # rare double-pass is harmless.
        argv = base if (launch and not os.path.exists(LAUNCHED)) \
            else base + ["--no-launch"]
        try:
            proc = subprocess.Popen(argv)
        except OSError as e:
            logline(f"spawn failed: {e}; retry in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue
        holder["proc"] = proc
        started = time.time()
        try:
            rc = proc.wait()
        except Exception as e:
            logline(f"wait: {e}")
            rc = -1
        holder["proc"] = None
        ran = int(time.time() - started)
        if ran >= 60:
            backoff = 2                # a healthy run resets the backoff
        logline(f"worker exited (rc {rc}, ran {ran}s); respawn in {backoff}s")
        time.sleep(backoff)
        backoff = min(backoff * 2, 30)


def watch_worker(launch=True):
    """The daemon proper: place windows to their known spot as they appear
    (react), and continuously record the layout into the knowledge base
    (capture). Runs as a child of do_watch's supervisor; an uncaught crash
    here is caught there and the worker respawned. On startup, unless launch
    is False, it also relaunches personal mux terminals that have no window.
    Placement and capture each get their own IPC socket so neither blocks the
    events.

    If a `session-mgr resume` armed the adopt flag, the FIRST worker to
    reach init consumes it and LEARNS the current hand-arranged layout as
    the baseline
    instead of restoring the remembered one -- for use after killing session and
    fixing windows by hand, so it does not undo the good state. Then it watches
    normally; respawns (flag gone) restore as usual."""
    import threading
    os.makedirs(STATE, exist_ok=True)
    kb = load_knowledge()
    lock = threading.Lock()
    # dirty: knowledge needs a capture. layout: roll history too (not tab-flip).
    st = {"dirty": True, "layout": True, "last": time.time(),
          "armed_at": time.time(),   # aggressive-mode clock (reset by the kick)
          "last_map": time.time()}   # last new toplevel map (feeds IDLE_SETTLE)
    placed = set()
    pending = {}           # vid -> {"v": latest view, "due": place-after time}:
    #                        the settle-debounce queue, drained by placer_loop
    deadline = {}          # vid -> time after which we no longer place it
    groups = {}            # vid -> {"app", "titles": set}: in-session tab-group
    place_sock = connect()
    logline("session-mgr watch: starting")
    for _n, _text, _msg in EXCLUDE_ERRORS:
        logline(f"exclude rule error (line {_n}): {_msg}: {_text!r}")

    def try_place(v):
        # A desync-class IPC error (timeout/off-by-one) poisons place_sock the
        # same way it poisons the capture socket, and would then silently fail
        # EVERY placement for the rest of the session -- so rebuild it on one.
        # A benign server error-response (e.g. "view is not toplevel" for a
        # popup) leaves the socket in sync: log it and move on, never reconnect.
        nonlocal place_sock
        try:
            return _place_view(v)
        except Exception as e:
            if is_desync_error(e):
                logline(f"place desync: {e}; reconnecting place socket")
                try:
                    place_sock.close()
                except Exception:
                    pass
                try:
                    place_sock = connect()
                except Exception as e2:
                    logline(f"place reconnect failed: {e2}")
            else:
                logline(f"place error: {e}")
            return None

    def _steady_at():
        # steady when (FLOOR passed AND quiet for SETTLE) OR past CAP; the kick
        # resets armed_at and a new map pushes last_map -- both extend
        # aggressive.
        with lock:
            armed = st["armed_at"]
            last_map = st["last_map"]
        return min(armed + AGGR_CAP,
                   max(armed + START_FLOOR, last_map + IDLE_SETTLE))

    def aggressive_now():
        return time.time() < _steady_at()

    def write_status():
        # Publish {mode, seconds_left} for `session-mgr status` + the tray. The
        # steady-at estimate assumes no more windows arrive; a map or a kick
        # moves it out. Atomic replace so a reader never sees a half file.
        now = time.time()
        steady_at = _steady_at()
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

    def _place_view(v):
        vid = v.get("id")
        if vid is None or vid in placed:
            return
        if v.get("parent", -1) != -1:
            return   # a dialog / child view (a file picker, a "Save As" sheet):
                     # it MUST stay on its parent's output. Issuing an output
                     # move for it aborts the whole compositor -- wayfire's
                     # move_view_to_output dassert("Cannot move a dialog to a
                     # different output than its parent"). The event path is not
                     # toplevel-filtered like the init path, so dialogs reach
                     # here; the parent field (-1 == none) is the reliable tell,
                     # where is_transient's title match is not (a portal file
                     # chooser has a null/foreign title).
        if time.time() > deadline.get(vid, 0):
            return   # past the grace window: the window is settled, hands off
        app = v.get("app-id") or v.get("app_id") or ""
        title = v.get("title", "")
        if SKIP_TITLE.search(title) or is_transient(v):
            return   # work / scratch / transient-chrome: leave where it opened
        if not aggressive_now() and not is_anchored(app, title):
            return   # steady state: only session/include anchors are (re)placed
        with lock:
            e = (kb.get(kkey(app, ""))
                 or kb.get(kkey(app, identity(v))))
        if not e:
            return   # never seen this identity -> we don't know where it goes
        outs = {o["name"]: o for o in place_sock.list_outputs()}
        o = outs.get(e["output"])
        if not o:
            return
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
                placed.add(vid)
                # Invert follows the window even when it needs no move. placed
                # dedups, so this fires once per map and never fights a later
                # Super+N un-invert.
                if e.get("inverted"):
                    apply_invert(place_sock, vid)
                return
        place(place_sock, vid, e, o)
        placed.add(vid)
        if e.get("inverted"):
            apply_invert(place_sock, vid)
        msg = (f"placed  {app[:18]:18} {e['output']} "
               f"ws{tuple(e['workspace'])} | {title[:32]}"
               f"{' [inv]' if e.get('inverted') else ''}")
        print(msg, flush=True)
        # ALSO to the log. The autostart discards the worker's stdout, so a
        # per-window placement left no trace anywhere, and the only record of
        # placement was the init-placed COUNT. Reconstructing why one window
        # was not placed then depends entirely on the history ring, which
        # samples on capture and cannot say whether usher acted or the human
        # did. This is the line that answers that next time.
        logline(msg)
        return True

    def capture_loop():
        cap = connect()
        inv_seen = store_mtime(INVERT_STORE)
        exc_seen = store_mtime(EXCLUDE_FILE)
        inc_seen = store_mtime(INCLUDE_FILE)
        idn_seen = store_mtime(IDENTITY_FILE)
        arm_seen = store_mtime(ARM_FILE)
        errstreak = 0
        while True:
            time.sleep(1)
            # Auto-incorporate session/exclude + session/include edits: reload
            # when either file changes, so a new never-place or anchor rule
            # applies on save.
            e = store_mtime(EXCLUDE_FILE)
            if e != exc_seen:
                exc_seen = e
                reload_exclude()
            i = store_mtime(INCLUDE_FILE)
            if i != inc_seen:
                inc_seen = i
                reload_anchor()
            d2 = store_mtime(IDENTITY_FILE)
            if d2 != idn_seen:
                idn_seen = d2
                reload_identity()
            # aggressive/settle/toggle all write a timestamp to ARM_FILE; adopt
            # it as the new armed_at (now = kick, a past ts = settle to steady).
            # Then publish status each tick for `session-mgr status` + tray.
            a = store_mtime(ARM_FILE)
            if a != arm_seen:
                arm_seen = a
                try:
                    with lock:
                        st["armed_at"] = float(open(ARM_FILE).read().strip())
                    logline("aggressive re-armed (kick)"
                            if aggressive_now() else "settled to steady")
                except (OSError, ValueError):
                    pass
            write_status()
            # Inversion has no view event: a Super+N toggle only writes the
            # invert store. Treat a change to that file as a capture trigger, so
            # invert/un-invert persists on its own without waiting for a move.
            # (apply_invert also writes it during restore -- harmless, just a
            # redundant capture of state we set ourselves.)
            m = store_mtime(INVERT_STORE)
            if m != inv_seen:
                inv_seen = m
                with lock:
                    st["dirty"] = True
                    st["last"] = time.time()
            with lock:
                due = st["dirty"] and time.time() - st["last"] >= DEBOUNCE
            if not due:
                continue
            # A transient IPC timeout (the compositor stalls under a slow
            # login) must not kill this thread: leave st["dirty"] set and the
            # next tick retries. Without the guard the capture thread died
            # silently and snapshots simply stopped.
            try:
                snap = snapshot(cap)
                with lock:
                    roll = st["layout"]
                    learn(kb, groups, snap["windows"], snap["time"])
                    st["dirty"] = False
                    st["layout"] = False
                    save_knowledge(kb)
                persist(snap, roll=roll)
                errstreak = 0
            except Exception as e:
                errstreak += 1
                logline(f"capture error: {e} (streak {errstreak})")
                # A request timeout leaves its response unread in cap's buffer,
                # desyncing it off-by-one: every later call then reads the
                # PREVIOUS call's response (the name/mapped KeyError storm).
                # Reusing it never resyncs, so on a desync-class error drop the
                # socket and reconnect; st["dirty"] stays set, so the next tick
                # retries on the fresh socket. A benign error would not desync,
                # so it is left alone -- the streak backstop below still covers
                # a persistent one.
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
                # (compositor wedged, or a class reconnect cannot fix). Exit so
                # the supervisor does a clean full respawn instead of limping on
                # a broken capture thread.
                if errstreak >= CAPTURE_FAIL_LIMIT:
                    logline(f"capture failing {errstreak}x; exit for respawn")
                    os._exit(1)

    threading.Thread(target=capture_loop, daemon=True).start()

    # Consume the one-shot adopt flag (armed by `session-mgr resume`): the first
    # worker to reach here adopts; a respawn sees it gone and restores.
    adopt = take_adopt()
    if adopt:
        # Capture-and-resume: adopt the CURRENT layout as the baseline and do
        # NOT restore. No init-place and no grace deadlines for open windows, so
        # they stay exactly where they are; the refreshed knowledge means new
        # windows FROM HERE are maintained against the good state, not the stale
        # pre-kill one. capture_loop keeps it current after this.
        try:
            do_capture()
            kb = load_knowledge()   # closure: try_place sees the refreshed KB
            logline("adopt: captured current layout as baseline; not restoring")
        except Exception as e:
            logline(f"adopt capture error: {e}")
    else:
        # Place anything already open when we start (react handles the rest);
        # they get a grace window from now, so init-place lands but later stray
        # title changes on them do not.
        now = time.time()
        n_placed = 0
        for v in place_sock.list_views(filter_mapped_toplevel=True):
            if v.get("id") is not None:
                deadline[v["id"]] = now + PLACE_GRACE
            try:
                if try_place(v):
                    n_placed += 1
            except Exception as e:
                logline(f"init place error: {e}")
        logline(f"init-placed {n_placed} window(s)")

    watch = connect()
    watch.watch(list(KNOWLEDGE_TRIGGERS | PLACE_EVENTS))
    print(f"session-mgr watch: {len(kb)} known windows; watching", flush=True)
    logline(f"watching, {len(kb)} known windows")

    # Relaunch missing terminals now that we are watching, so their map events
    # are caught and placed by the loop below. Chrome restores itself. Drop the
    # LAUNCHED marker only after launch_missing returns, so the supervisor keeps
    # launch on for a successor if this worker dies before reaching here.
    if launch:
        try:
            launch_missing()
            open(LAUNCHED, "w").close()
        except Exception as e:
            logline(f"launch_missing error: {e}")

    # Settle-debounce placer. Moves a window only once its title has been QUIET
    # for PLACE_SETTLE: a restoring client churns its title as tabs load, and
    # reconfiguring it mid-restore can make it drop the window. The event loop
    # only records the latest view + a due time in `pending`; this thread does
    # the actual place when the churn stops, reusing place_sock (nothing else
    # touches it once init is done, so the socket has one writer).
    def placer_loop():
        while True:
            time.sleep(0.1)
            now = time.time()
            ready = []
            with lock:
                for vid in list(pending):
                    if vid in placed:
                        pending.pop(vid, None)
                    elif now >= pending[vid]["due"]:
                        ready.append(pending.pop(vid)["v"])
            for v in ready:
                try_place(v)

    threading.Thread(target=placer_loop, daemon=True).start()

    while True:
        try:
            msg = watch.read_next_event()
        except Exception as e:
            logline(f"watch loop exit: {e}")   # compositor gone: real teardown
            break
        # Guard the WHOLE event body: a stalled-compositor IPC timeout -- or any
        # unforeseen error -- on one event must skip that event, never fall out
        # of the loop and end the daemon. The login-storm crash that piled
        # Chrome up came in through exactly this path (a placement call).
        try:
            ev = msg.get("event", "")
            v = msg.get("view", {}) or {}
            if ev == "view-mapped" and v.get("id") is not None:
                deadline[v["id"]] = time.time() + PLACE_GRACE   # start grace
                with lock:
                    st["last_map"] = time.time()   # feed the IDLE_SETTLE clock
            if ev in PLACE_EVENTS:
                vid = v.get("id")
                if vid is not None and vid not in placed:
                    # Defer to placer_loop. Browsers wait PLACE_SETTLE (re-
                    # armed on every title change) so we never move one mid-
                    # restore; other apps are stable at map -> a tiny settle,
                    # placed on the next tick.
                    app = v.get("app-id") or v.get("app_id") or ""
                    wait = (PLACE_SETTLE if is_browser(app)
                            else PLACE_SETTLE_FAST)
                    with lock:
                        pending[vid] = {"v": v, "due": time.time() + wait}
            elif ev == "view-unmapped" and v.get("id") is not None:
                placed.discard(v["id"])
                deadline.pop(v["id"], None)
                with lock:
                    pending.pop(v["id"], None)
            if ev in KNOWLEDGE_TRIGGERS:
                with lock:
                    st["dirty"] = True
                    st["last"] = time.time()
                    if ev in LAYOUT_TRIGGERS:
                        st["layout"] = True
        except Exception as e:
            logline(f"event error ({msg.get('event', '?')}): {e}")


def _signal_watcher(sig, action, done):
    """Signal the running supervisor, whose pid is in the lock file (the single
    place that path lives). Exit if none is running or the signal fails."""
    d = os.environ.get("XDG_RUNTIME_DIR") or STATE
    path = os.path.join(d, "session-watch.lock")
    try:
        pid = int(open(path).read().strip())
    except (OSError, ValueError):
        sys.exit(f"session-mgr: no running watcher to {action}")
    try:
        os.kill(pid, sig)
    except OSError as e:
        sys.exit(f"session-mgr: cannot signal watcher pid {pid}: {e}")
    print(f"session-mgr: {done} watcher (pid {pid})")


def do_stop():
    """Stop the watcher cleanly: SIGTERM the supervisor, whose stop handler
    terminates the worker and exits (releasing the lock). Replaces the
    `pkill -f 'session-mgr watch'` dance, which races the respawn and can
    match the wrong process -- including the shell running the pkill."""
    _signal_watcher(signal.SIGTERM, "stop", "stopped")


def _snss_build(window, tab, url, title, ver=3):
    """Build a minimal one-window/one-tab SNSS blob, for selftest's parser
    check -- the inverse of parse_snss (Pickle 4-byte alignment and all)."""
    def wi(x):
        return struct.pack("<i", x)

    def ws(s):
        b = s.encode("utf-8")
        return wi(len(b)) + b + b"\x00" * ((-len(b)) % 4)

    def ws16(s):
        b = s.encode("utf-16-le")
        return wi(len(s)) + b + b"\x00" * ((-len(b)) % 4)

    def cmd(cid, payload):
        body = bytes([cid]) + payload
        return struct.pack("<H", len(body)) + body

    pk = wi(tab) + wi(0) + ws(url) + ws16(title)
    return (b"SNSS" + wi(ver)
            + cmd(_SNSS_SET_TAB_WINDOW, wi(window) + wi(tab))
            + cmd(_SNSS_SET_TAB_INDEX, wi(tab) + wi(0))
            + cmd(_SNSS_SET_SEL_TAB_IN_WIN, wi(window) + wi(0))
            + cmd(_SNSS_SET_SEL_NAV_INDEX, wi(tab) + wi(0))
            + cmd(_SNSS_UPDATE_TAB_NAV, wi(len(pk)) + pk))


def selftest():
    """Offline unit checks for the plugin framework + Chrome-identity machinery
    -- no compositor, deterministic. Run with `session-mgr selftest`."""
    global IDENTITY_RULES
    fails = []

    def ck(name, cond):
        if not cond:
            fails.append(name)

    def V(app, title="", pid=-1):
        return {"app": app, "title": title, "pid": pid}

    # the registry loads the three built-ins; each claims the right windows
    ps = {getattr(p, "name", "?"): p for p in plugins()}
    ck("plugins-builtin", all(n in ps for n in ("chrome", "mux", "kitty")))
    ck("owns-chrome", ps["chrome"].owns(V("google-chrome")))
    ck("owns-mux", ps["mux"].owns(V("kitty", "wf:code")))
    ck("owns-kitty-notmux", not ps["mux"].owns(V("kitty", "✳ Claude Code"))
       and ps["kitty"].owns(V("kitty", "✳ Claude Code")))
    ck("owner-mux", _owner(V("kitty", "wf:code[manifold]")) is ps["mux"])
    ck("owner-kitty", _owner(V("kitty", "✳ Claude Code")) is ps["kitty"])
    ck("owns-nobody", _owner(V("slack", "Slack")) is None)
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
    ck("mux-id", ps["mux"].identity(V("kitty", "wf:code⠀⠀⠀⠀[manifold]"))
       == "mux@manifold:wf")
    ck("mux-id-untagged",
       ps["mux"].identity(V("kitty", "wf:code")) == f"mux@{LOCAL_HOST}:wf")
    # THE case this exists for: one session name, two boxes, two slots.
    ck("mux-id-splits-hosts",
       ps["mux"].identity(V("kitty", "tackup:main⠀⠀⠀⠀[manifestor]"))
       != ps["mux"].identity(V("kitty", "tackup:main⠀⠀⠀⠀[manifold]")))

    # live_keys resolves a real on-screen title through to its identity
    ck("live-keys", live_keys([V("kitty", "live:1⠀⠀⠀⠀[manifestor]")])
       == {"mux@manifestor:live"})

    # relaunch candidate selection, driven with fixtures (no mux, no compositor)
    def S(key, app="kitty"):
        return {"app_id": app, "key": key, "title": ""}

    snap = [S("mux@manifestor:usher"),      # local, still known -> relaunch
            S("mux@manifestor:gone"),       # local, killed since -> skip
            S("mux@manifold:tackup"),       # remote -> relaunch on trust
            S("mux@manifestor:live"),       # already on screen -> skip
            S("mux@manifestor:usher"),      # duplicate -> deduped
            S("kitty:/tmp"),                # not a mux key -> not ours
            S("mux@manifestor:x", "signal")]    # not a terminal -> ignored
    got = mux_candidates(snap, {"mux@manifestor:live"},
                         {"usher", "live"}, local_host="manifestor")
    ck("mux-candidates", got == [("manifestor", "usher"),
                                 ("manifold", "tackup")])
    ck("mux-candidates-both-hosts",
       mux_candidates([S("mux@manifestor:tackup"), S("mux@manifold:tackup")],
                      set(), {"tackup"}, local_host="manifestor")
       == [("manifestor", "tackup"), ("manifold", "tackup")])
    # a remote session is never gated on the LOCAL set
    ck("mux-candidates-remote-unknown",
       mux_candidates([S("mux@manifold:elsewhere")], set(), set(),
                      local_host="manifestor")
       == [("manifold", "elsewhere")])

    ck("kitty-candidates",
       kitty_candidates([S("kitty:/tmp"), S("kitty:/tmp"),
                         S("kitty:/nonexistent-" + "z" * 12),
                         S("mux@manifestor:wf")], set()) == ["/tmp"])
    ck("kitty-candidates-live",
       kitty_candidates([S("kitty:/tmp")], {"kitty:/tmp"}) == [])

    # the spawn command: `mux go` here, `mux latch HOST:SESSION` there. usher
    # must NOT hand-roll ssh -- a one-shot attempt at login is exactly when no
    # credential is live yet, and mux latch polls for one instead of failing.
    ck("go-local", mux_go_command("wf").endswith("mux go wf"))
    ck("go-local-selfhost",
       mux_go_command("wf", LOCAL_HOST) == mux_go_command("wf"))
    _r = mux_go_command("wf", "manifold")
    ck("go-remote", _r.endswith("latch manifold:wf"))
    ck("go-remote-delegates", "ssh" not in _r and " go " not in _r)

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
                            [V("google-chrome", "x")]) == 0)

    # learn() must KEEP the entry it just wrote for a live terminal. Its mux
    # purge once compared kb keys (identities) against raw window titles, so it
    # deleted every terminal entry on the same pass that created it, and
    # terminals were never placed at all. Nothing else here would catch that.
    def LW(vid, title, app="kitty"):
        return {"id": vid, "app_id": app, "title": title, "pid": -1,
                "output": "DP-1", "workspace": [1.0, 1.0],
                "pos": [0.0, 0.0], "size": [800.0, 600.0]}

    _kb, _groups = {}, {}
    learn(_kb, _groups, [LW(1, "usher:main⠀⠀⠀⠀[manifestor]"),
                         LW(2, "tackup:main⠀⠀⠀⠀[manifold]")], 1_800_000_000)
    ck("learn-keeps-live-mux",
       sorted(v["title"] for v in _kb.values())
       == ["mux@manifestor:usher", "mux@manifold:tackup"])
    # a terminal whose window is gone IS dropped (the point of the purge)
    learn(_kb, _groups, [LW(1, "usher:main⠀⠀⠀⠀[manifestor]")],
          1_800_000_001)
    ck("learn-drops-absent-mux",
       [v["title"] for v in _kb.values()] == ["mux@manifestor:usher"])
    # ...but a kitty:<cwd> entry is NOT swept by the mux purge (it merely has a
    # colon in it, which is all is_mux_term ever tested for)
    _kb["kitty\x00kitty:/tmp"] = {"app_id": "kitty", "title": "kitty:/tmp",
                                  "last_seen": 1_800_000_001,
                                  "appid_only": False}
    learn(_kb, _groups, [LW(1, "usher:main⠀⠀⠀⠀[manifestor]")],
          1_800_000_002)
    ck("learn-keeps-kitty-cwd", "kitty\x00kitty:/tmp" in _kb)

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
    _saved_env = os.environ.get("SESSION_PROFILE")
    os.environ["SESSION_PROFILE"] = "testset"
    ck("profile-env", profile_id() == "testset")
    ck("profile-paths", kb_path().endswith("knowledge-testset.json")
       and schema_path().endswith("knowledge-testset.schema"))

    # A NEW profile must be stamped CURRENT the moment it is created. It was
    # not, and the next load then judged the unstamped store stale and dropped
    # every chrome + kitty entry it had just learned -- each new monitor set
    # silently losing its browser and terminal placements exactly once.
    import tempfile
    _st, _prev = STATE, os.environ.get("XDG_STATE_HOME")
    _tmp = tempfile.mkdtemp()
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

    if _saved_env is None:
        del os.environ["SESSION_PROFILE"]
    else:
        os.environ["SESSION_PROFILE"] = _saved_env

    # CONTRACT with mux: `mux resume --list` must stay BARE NAMES, one per line.
    # This is the guard the old `mux ls` scrape lacked -- a cosmetic change over
    # in mux (the agent-state glyph) silently killed relaunch with no symptom.
    # Skipped when mux is absent (the soft dep); an empty set is legitimate.
    ck("mux-list-contract",
       all(re.fullmatch(r"[^\s:]+", s) for s in mux_session_set()))

    # identity() is a STRICT no-op for a non-plugin app
    ck("noop-slack", identity(V("slack", "Slack")) == "Slack")

    saved = IDENTITY_RULES
    IDENTITY_RULES = []
    ck("norm-query",
       normalize_url("https://github.com/jello-d/vigilance?tab=x")
       == "github.com/jello-d/vigilance")
    ck("norm-frag",
       normalize_url("https://mail.google.com/mail/u/0/#inbox")
       == "mail.google.com/mail/u/0")
    IDENTITY_RULES = [(re.compile(r"^mail\.google\.com"), "gmail")]
    ck("norm-rule",
       normalize_url("https://mail.google.com/mail/u/0/#inbox") == "gmail")
    IDENTITY_RULES = saved

    # parse_snss recovers the active-tab url from a synthetic session file
    import tempfile
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, _snss_build(11, 22, "https://example.com/x", "Example"))
        os.close(fd)
        m = parse_snss(path)
        ck("snss-parse", m.get("Example") == "https://example.com/x")
    finally:
        os.remove(path)

    # any real session file present must parse without raising
    try:
        for p in _session_files():
            parse_snss(p)
        ck("snss-live", True)
    except Exception:
        ck("snss-live", False)

    if fails:
        print("selftest FAIL: " + ", ".join(fails), file=sys.stderr)
        return 1
    print("selftest OK")
    return 0


def main():
    args = sys.argv[1:]
    verb = args[0] if args else ""
    if verb == "capture":
        do_capture()
    elif verb == "restore":
        only = None
        if "--only" in args:
            k = args.index("--only")
            only = args[k + 1] if k + 1 < len(args) else None
        source = None
        if "--from" in args:      # a stored milestone instead of the live kb
            k = args.index("--from")
            source = resolve_snapshot(args[k + 1] if k + 1 < len(args)
                                      else "list")
        do_restore(dry="--dry-run" in args, only=only, source=source)
    elif verb == "watch":         # start, or reload if running -- RESTORE mode
        arm_adopt(False)
        do_watch(launch="--no-launch" not in args)
    elif verb == "resume":        # start/reload in ADOPT (no restore)
        arm_adopt(True)
        do_watch(launch="--no-launch" not in args)
    elif verb == "_super":        # internal: re-exec'd supervisor (no re-arm)
        do_watch(launch="--no-launch" not in args)
    elif verb == "_worker":       # internal: the supervised worker
        watch_worker(launch="--no-launch" not in args)
    elif verb == "stop":          # SIGTERM the supervisor cleanly (no pkill)
        do_stop()
    elif verb == "launch":
        n = launch_missing()
        print(f"session-mgr: launched {n} terminal(s)")
    elif verb == "exclude":       # show the never-place rules as loaded
        for ar, tr in EXCLUDE_RULES:
            print(f"{ar.pattern} :: {tr.pattern}")
        for n, text, msg in EXCLUDE_ERRORS:
            print(f"error: line {n}: {msg}: {text!r}", file=sys.stderr)
        print(f"# {len(EXCLUDE_RULES)} rule(s), {len(EXCLUDE_ERRORS)} error(s)"
              f" from {EXCLUDE_FILE}", file=sys.stderr)
        sys.exit(1 if EXCLUDE_ERRORS else 0)
    elif verb == "include":       # show the anchor (steady-state) rules loaded
        for ar, tr in ANCHOR_RULES:
            print(f"{ar.pattern} :: {tr.pattern}")
        for n, text, msg in ANCHOR_ERRORS:
            print(f"error: line {n}: {msg}: {text!r}", file=sys.stderr)
        print(f"# {len(ANCHOR_RULES)} rule(s), {len(ANCHOR_ERRORS)} error(s)"
              f" from {INCLUDE_FILE}", file=sys.stderr)
        sys.exit(1 if ANCHOR_ERRORS else 0)
    elif verb == "identity":      # show URL rules + resolve live Chrome windows
        for rx, canon in IDENTITY_RULES:
            print(f"{rx.pattern} :: {canon}")
        for n, text, msg in IDENTITY_ERRORS:
            print(f"error: line {n}: {msg}: {text!r}", file=sys.stderr)
        print(f"# {len(IDENTITY_RULES)} rule(s), "
              f"{len(IDENTITY_ERRORS)} error(s) from {IDENTITY_FILE}",
              file=sys.stderr)
        try:
            for v in WayfireSocket().list_views(filter_mapped_toplevel=True):
                t = v.get("title", "")
                p = _owner(v)
                if p is not None:
                    print(f"# [{p.name}] {t[:38]!r} -> {identity(v)}",
                          file=sys.stderr)
        except Exception as e:
            print(f"# (no live join: {e})", file=sys.stderr)
        sys.exit(1 if IDENTITY_ERRORS else 0)
    elif verb == "plugins":       # list loaded plugins (built-in + user)
        for p in plugins():
            hooks = [h for h in ("owns", "identity", "transient", "window_id",
                                 "relaunch_missing")
                     if h in getattr(type(p), "__dict__", {})]
            print(f"{getattr(p, 'name', '?'):10} {', '.join(hooks)}")
        print(f"# {len(plugins())} plugin(s); user dir {PLUGIN_DIR}",
              file=sys.stderr)
    elif verb == "display-changed":   # hwdp's changed hook; no-op if same set
        sys.exit(do_display_changed())
    elif verb == "doctor":        # what is it doing, and what is it NOT doing
        sys.exit(do_doctor())
    elif verb == "selftest":      # offline unit checks (no compositor needed)
        sys.exit(selftest())
    elif verb in ("aggressive", "settle", "toggle"):
        # Placement-mode controls (tray + CLI). All three drive the ONE armed_at
        # seam the watcher adopts from ARM_FILE: aggressive arms NOW (aggressive
        # for START_FLOOR); settle arms in the PAST (steady at once, past the
        # CAP); toggle flips from live STATUS_FILE mode (the tray left-click).
        act = verb
        if act == "toggle":
            try:
                act = ("settle" if json.load(open(STATUS_FILE)).get("mode")
                       == "aggressive" else "aggressive")
            except (OSError, ValueError):
                act = "aggressive"
        ts = time.time() if act == "aggressive" else time.time() - AGGR_CAP - 1
        msg = ("re-armed aggressive placement" if act == "aggressive"
               else "settled to steady")
        try:
            os.makedirs(os.path.dirname(ARM_FILE), exist_ok=True)
            with open(ARM_FILE, "w") as f:
                f.write(f"{ts}\n")
            print(f"session-mgr: {msg}")
        except OSError as e:
            sys.exit(f"session-mgr: cannot {act}: {e}")
    elif verb == "status":        # current placement mode + seconds to steady
        try:
            s = json.load(open(STATUS_FILE))
            print(f"mode: {s.get('mode', '?')}  "
                  f"seconds_left: {s.get('seconds_left', '?')}")
        except (OSError, ValueError):
            sys.exit("session-mgr: no status (watcher not running?)")
    else:
        print("usage: session-mgr capture | "
              "restore [--dry-run] [--only S] [--from SPEC] | "
              "watch [--no-launch] | resume | stop | launch | aggressive | "
              "settle | toggle | status | exclude | include | identity | "
              "plugins | display-changed | doctor | selftest",
              file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
