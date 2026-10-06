# usher

Record the Wayland window layout and place windows back: a plugin-based
session manager for wlroots/[Wayfire](https://github.com/WayfireWM/wayfire).

Instead of hand-written placement rules, `usher` records where your windows
actually are and puts them back where you left them. Two commands split the
job: `usher-mgr` is the service your session starts, and `usher` is how you ask
anything of it.

- **Aggressive then steady.** For a window's first moments after login (or a
  re-arm) every mapped window is placed back, which lets a browser open all its
  windows and have them land. Then it goes steady: a reopened window just
  appears where you are and stays. `~/.config/usher/include` lists the few
  windows to keep snapping back even then; `~/.config/usher/exclude` lists
  windows never to place.
- **Stable identity, never the title.** A window is matched to its saved slot by
  an app-specific identity, because window titles are too volatile to key on.
- **One layout per monitor set.** A placement only means anything on the
  monitors it was learned on, so the store is keyed by the connected display
  set: docked and undocked remember separately instead of overwriting each
  other. [hwdp](https://github.com/jello-d/hwdp) supplies the id when present
  (a *soft* dependency; without it the set is derived from the outputs, and
  failing that everything shares one `default` profile).
- **It will tell you what it is doing.** `usher doctor` reports the store,
  the cross-tool contracts, and per window what would happen and why. When it
  *cannot* see the live session it says so loudly and exits non-zero, rather
  than answering the window questions from nothing.
- **Go back to a past layout.** A daily milestone and a rolling history are
  kept, so `usher restore --from yesterday` (or `latest`, or a date) puts
  the desk back the way it was; `--from list` shows what is available.

## What usher needs from an app

Nothing, for the part most people want. Three tiers, and each is only worth
reaching for when the one below it falls short.

- **The window back where and how big it was** needs **nothing**. Any window
  with a title is captured, keyed and placed.
- **The app started for you** at login needs a **desktop entry**, because the
  only command usher ever runs is an `Exec=` out of a desktop file it read.
- **Windows told apart from each other**, a per-window relaunch, or a clean
  shutdown needs a **plugin**. Nothing else can answer *which* window this is.

### Tier 1: nothing

Open the app yourself and it lands where you left it, at the size you left it.
This needs no configuration and no entry: a single-window app is keyed by its
**app-id alone**, so the slot does not move when the document does.

What you give up is only the starting. If the app is already running when you
log in, there is nothing to give up at all.

### Tier 2: a desktop entry

Write one when you want the app started for you and the registry cannot
already answer. That is the case when the app ships no entry, when its entry
is `Terminal=true` (Debian's `vim.desktop` is `Exec=vim %F, Terminal=true`, so
it describes terminal vim and usher correctly refuses it for a gvim window), or
when its app-id differs from the entry's filename.

```ini
# ~/.local/share/applications/gvim.desktop
[Desktop Entry]
Type=Application
Name=GVim
Exec=gvim
StartupWMClass=gvim
NoDisplay=true
```

`StartupWMClass` is the load-bearing line: the join is on the window's app-id,
so it has to name that when the filename does not. Check with
`usher doctor`, which prints the command it would run for every saved window.

`NoDisplay=true` keeps the entry out of your application menu and usher still
honours it. The spec says NoDisplay means "do not show this in menus" and says
nothing about launching, so usher reads it as a refusal only for an entry you
did **not** author. `Hidden=true` is a deletion in the spec's own words, so
that is honoured everywhere, including your own entries.

### Tier 3: a plugin

Reach for one when identity is the problem, not launching. Any single answer
of yes means the tiers above cannot serve you:

- **Several windows of one app must be told apart.** Without a plugin, two or
  more windows of the same app fall back to per-**title** keys, so the slot
  follows the document rather than the window. One window is fine; several is
  what needs a plugin. This is the whole reason the chrome plugin exists.
- **The identity is not in the title.** chrome reads a SessionID out of the
  browser's session file; kitty reads the shell's cwd out of `/proc`; mux reads
  the command the window is running. A title that has to be right at the
  instant you look is a bootstrap, not an identity.
- **The relaunch differs per window.** The registry describes an *app*, so the
  default starts one invocation per app. A terminal holding a specific remote
  session needs its own command, which is what `relaunch_command` is for.
- **Identity is not ready the moment the window maps.** A plugin can answer
  `("pending", why)` and usher will neither place nor remember the window
  until it is sure. Nothing else can express that, and guessing corrupts the
  slot it was about to aim at.
- **The app needs letting go cleanly.** `wind_down` is how chrome gets
  `SessionEnded` instead of `Crashed` on reboot.

If none of those is true, a desktop entry is the simpler and more portable
answer: it needs no Python, benefits your launcher and menus too, and cannot
break when usher's internals move.

## Plugins

How to identify and respawn a given app's windows lives in a **plugin**. Three
ship built in, and none keys on what the window is currently *showing*,
because a window that can display many things would otherwise lose its place
every time you switched:

- **chrome**: keys a Chrome/Chromium window by its **SessionID**, read from the
  browser's own session file. Keying on the active tab instead meant a thousand
  entries describing six windows, and revisiting an old page could drag the
  window to another desktop. The id is fresh every time Chrome restarts, so a
  window is followed across that boundary by the **tabs** it came back with,
  joining the previous session file to the new one. A window the session file
  cannot identify is not remembered at all, rather than being keyed on the
  title it happens to be wearing. Starts the browser per profile, with
  `--restore-last-session`, when the last session had Chrome windows and none
  is running.
- **mux**: keys a [mux](https://github.com/jello-d/mux) terminal by the
  **command it runs** (`term:resume`, or `term:latch <host>:<session>`), so
  switching sessions inside a window does not forfeit its place. Relaunch
  replays that command: a `mux latch` is reproduced exactly, and anything else
  was a local mux, for which `mux resume` rebuilds the whole recorded set
  rather than the single session a titlebar happened to name. `mux` is a
  *soft* dependency: absent, the plugin degrades to a no-op.
- **kitty**: keys any other kitty terminal by its shell's **working directory**
  (from `/proc`) and respawns it as a shell there.

Add your own: drop a `*.py` file into `~/.config/usher/plugins/` defining a
top-level `PLUGIN` object. See [`share/plugins/example.py`](
share/plugins/example.py). Each plugin claims an app's windows (`owns`) and may
implement `resolve` / `relaunch_command` /
`relaunch_missing` / `wind_down`, each taking a normalized view (`v["app"]`,
`v["title"]`, `v["pid"]`, `v["id"]`). `v["id"]` is the compositor's view id,
stable for exactly one window's lifetime and `None` for a window replayed from
the store, so it is what to cache a hard-won identity against.

**Any app comes back, plugin or not.** A window whose app no plugin claims is
still relaunched at session start, from the freedesktop registry: usher joins
the app-id to a `.desktop` entry (by filename, then `StartupWMClass`), takes
its `Exec=`, and strips the field codes so the app opens with no document.
That is the same invariant the session-start seam holds, and it is why this is
safe: **the only command usher ever runs is an `Exec=` out of a desktop file
it read**, never a string it stored or a `/proc` cmdline it sniffed. It
refuses rather than guesses when several entries match, when none does, and
when the registry marks the entry `NoDisplay`, `Hidden`, `Terminal=true` or
not an `Application`, which is what keeps tray applets and D-Bus portal
services from being started as if they were apps. A plugin that claims the app
overrides it; `USHER_NO_DEFAULT_RELAUNCH=1` turns it off entirely.
`usher doctor` prints the command it would run for each saved window, so you
can see the set before a reboot trusts it.

**To make usher relaunch something it cannot work out, write a desktop entry.**
An app launched from a shell with no entry of its own (or whose entry is
`Terminal=true`, like Debian's `vim.desktop`) is still remembered and still
placed when you open it; it just is not started for you. Drop a file in
`~/.local/share/applications/` to close that:

```ini
[Desktop Entry]
Type=Application
Name=GVim
Exec=gvim
StartupWMClass=gvim
NoDisplay=true
```

`StartupWMClass` is the part that matters: usher joins on the app-id, so it
must be the window's app-id when the filename is not. `NoDisplay=true` keeps
the entry out of your application menu and usher still honours it, because
NoDisplay means "do not show this in menus" and says nothing about launching:
it is read as a refusal only for an entry you did not author. `Hidden=true` is
a deletion in the spec's own words, so that is honoured everywhere.

`resolve` answers one question in three ways, and the third is the point:
`("ready", key)` when the window is definitively that key, `("pending", why)`
when it will be knowable shortly, `("never", why)` when it never will. usher
neither places nor remembers a window that is not `ready`, so a plugin that
does not yet know must say so rather than guess: a guessed key is written into
the store and then placed against, which is worse than waiting. The `why` is
printed by `usher doctor`, so the plugin that knows supplies the explanation.
A 2-tuple keeps plugins import-free; `Resolution.ready(key)` works too.

## Install

`usher` is Python (the daemon talks to the compositor over the Wayfire IPC
socket via `pywayfire`), so `setup.sh` builds a venv:

```sh
./setup.sh install      # core: build the venv, link the commands + man
./setup.sh indicator    # optional: the tray indicator (--user service)
./setup.sh all          # both
./setup.sh hooks        # link the hwdp display-change hook
./setup.sh check        # audit the install
./setup.sh test         # run the in-repo suite
```

`install` links the hwdp hook by itself when hwdp's hook directory already
exists, so a box with hwdp needs no extra step and one without is untouched.

Everything is userspace (no sudo), into `~/.local` (override with `PREFIX` /
`XDG_*`). Under a provisioning layer (e.g. tackup) the same `setup.sh` is the
door.

Then wire the daemon into your compositor's autostart, e.g. in `wayfire.ini`:

```ini
[autostart]
session_restore = usher-mgr watch
```

## Commands

Two, split by who does the typing. `usher-mgr` is the service: your session
autostarts it and a hook calls it. `usher` is everything you ask of a running
usher. Each refuses the other's verbs and names the one that wants it.

```sh
usher-mgr watch              # the daemon (the autostart entry)
usher-mgr resume             # start in ADOPT mode: take the layout as truth
usher-mgr display-changed    # the hwdp hook; a no-op if the monitor set matches

usher save                   # record the current layout
usher restore [--dry-run]    # put windows back  [--only S] [--from SPEC]
usher lock                   # lock the seated session, and verify it took
usher predict                # record what the next restore SHOULD produce
usher verify                 # diff the live layout against that prediction
usher doctor                 # what it is doing, and what it is NOT
usher status                 # placement mode and seconds until steady
usher toggle                 # flip aggressive/steady (the tray click)
usher cleanly reboot         # wind down, keeping the layout, then reboot
usher cleanly login          # start the console session from a remote shell
```

A login you summoned is one you are **not sitting at**, so `usher cleanly
login` refuses unless this box can actually lock its console, and the daemon
locks it on arrival (before placing anything: placement works fine under a
lock). usher does not lock anything itself; it asks logind and whatever the
session registered as its locker does the work. `--force` accepts an unlocked
console deliberately. The lock is verified by reading `LockedHint` back,
because `loginctl lock-session` exits 0 whether or not anything is listening.

`usher cleanly login` needs a provider: usher knows that one executable can
start a console session here and deliberately not how, so it execs whatever
`~/.config/usher/session-start` points at, passing the action as an argument.
The provider obtains its own privilege if it needs any. Without one, the verb
says so and tells you where to link it.

### Providers

One ships, in [`share/providers/`](share/providers/):

- `usher-greetd`: starts the console session through
  [greetd](https://git.sr.ht/~kennylevinsen/greetd), by authenticating you
  against PAM exactly as the login screen would. Not autologin: nothing starts
  without your password, and it only works while a greeter is waiting. It
  finds the running greeter, reads the session that greeter recorded as your
  last choice, and resolves it through the freedesktop session registry
  (`$XDG_DATA_DIRS/{wayland,x}sessions`), so there is nothing to configure.
  All seven greeters packaged for greetd are recognised, including the three
  that record no choice at all; with no recorded default it offers the list.
  `--list-sessions` shows what it would do and needs no password.

**usher ships providers and does not install them**, which is a privilege
boundary rather than an omission. A provider is re-exec'd under sudo, so root
executes it, so it has to be root-owned in a root-visible tree; this package
installs as you, into `~/.local`. Copy it yourself, or let a provisioner do
it:

```sh
sudo install -o root -g root -m 0755 \
  share/providers/usher-greetd /usr/local/libexec/usher-greetd
ln -sfn /usr/local/libexec/usher-greetd ~/.config/usher/session-start
```

Each provider carries `--selftest`, which needs no root, no display manager
and no live greeter, so the installed copy can be checked in place:

```sh
/usr/local/libexec/usher-greetd --selftest
```

## Config

- `~/.config/usher/exclude`: `<app-regex> :: <title-regex>` never-place list.
- `~/.config/usher/include`: the same shape; the steady-state anchor list.
- `~/.config/usher/plugins/*.py`: user window plugins.

Example defaults ship in [`share/config/`](share/config/). The
daemon soft-degrades when any are absent.

### Environment

Every knob usher reads, with its default. All are read **once at import**, so
a running daemon keeps the values it started with: change one and restart it
with `usher reload`.

- **`USHER_SKIP_TITLE`** (`^\[WORK`): titles matching this regex are ignored
  end to end, never captured, placed or relaunched. This is the work/personal
  boundary rather than a convenience, so widen it with care.
- **`USHER_START_FLOOR`** (`300`): seconds after login, or an `aggressive`
  kick, during which every mapped window is placed back. A floor, not a race.
- **`USHER_IDLE_SETTLE`** (`25`): seconds with no new window before aggressive
  placement gives way to steady, where only `include` anchors are moved.
- **`USHER_AGGR_CAP`** (`900`): hard cap on the aggressive window, whatever
  the other two say.
- **`USHER_CHROME_FLAGS`**
  (`--restore-last-session --hide-crash-restore-bubble`): flags added to each
  Chrome launch, space separated. Empty passes none.
- **`USHER_CHROME_STAGGER`** (`4`): seconds between per-profile Chrome
  launches. Chrome is one process per user-data-dir, so launching two
  profiles in the same second loses one of them.
- **`USHER_WIND_DOWN_TIMEOUT`** (`8`): seconds `wind-down` waits for every app
  it asked to quit, as one bounded deadline for all of them.
- **`USHER_EXCLUDE_FILE`** (`~/.config/usher/exclude`) and
  **`USHER_INCLUDE_FILE`** (`~/.config/usher/include`): override the rule
  files. Losing them is silent, since no rules parses fine and means "place
  everything".
- **`USHER_PROFILE`** (derived): force the display-profile id instead of
  deriving it from the connected monitors.
- **`USHER_NO_DEFAULT_RELAUNCH`** (unset): set to `1` to stop usher starting
  saved windows from the freedesktop registry. Plugins and `exclude` still
  apply.
- **`USHER_SUMMONED`** (unset): internal, and never set explicitly. `usher
  cleanly login` exports it into the session it starts, which is how the
  daemon can tell a session begun remotely from one begun at the keyboard. On
  that signal it locks the console once, before placing anything, because a
  summoned session would otherwise come up logged in and unlocked in front of
  nobody.

### Exit status

- **`0`**: did what you asked, and it was fine.
- **`1`**: did what you asked; the answer is bad (a contract breach, a failed
  `verify`).
- **`2`**: could not do it at all: no such verb, no prediction to check
  against, or no visible session. Nothing was assessed, which is a different
  statement from `1`.

## License

Apache-2.0.

## Development

An 80-column limit is enforced by a tracked pre-commit hook. Enable it once
per clone:

    git config core.hooksPath .githooks
