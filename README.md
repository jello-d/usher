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
implement `identity` / `transient` / `relaunch_command` /
`relaunch_missing` / `wind_down`, each taking a normalized view (`v["app"]`,
`v["title"]`, `v["pid"]`, `v["id"]`). `v["id"]` is the compositor's view id,
stable for exactly one window's lifetime and `None` for a window replayed from
the store, so it is what to cache a hard-won identity against.

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
usher doctor                 # what it is doing, and what it is NOT
usher status                 # placement mode and seconds until steady
usher toggle                 # flip aggressive/steady (the tray click)
usher cleanly reboot         # wind down, keeping the layout, then reboot
usher cleanly login          # start the console session from a remote shell
```

`usher cleanly login` needs a provider: usher knows that one executable can
start a console session here and deliberately not how, so it execs whatever
`~/.config/usher/session-start` points at, passing the action as an argument.
The provider obtains its own privilege if it needs any. Without one, the verb
says so and tells you where to link it.

## Config

- `~/.config/usher/exclude`: `<app-regex> :: <title-regex>` never-place list.
- `~/.config/usher/include`: the same shape; the steady-state anchor list.
- `~/.config/usher/plugins/*.py`: user window plugins.

Example defaults ship in [`share/config/`](share/config/). The
daemon soft-degrades when any are absent.

## License

Apache-2.0.

## Development

An 80-column limit is enforced by a tracked pre-commit hook. Enable it once
per clone:

    git config core.hooksPath .githooks
