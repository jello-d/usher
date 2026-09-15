# usher

Record the Wayland window layout and place windows back — a plugin-based session
manager for wlroots/[Wayfire](https://github.com/WayfireWM/wayfire).

Instead of hand-written placement rules, `usher` records where your windows
actually are and puts them back where you left them. The one command
`session-mgr` is both the login daemon and its controller.

- **Aggressive then steady.** For a window's first moments after login (or a
  re-arm) every mapped window is placed back — what lets a browser open all its
  windows and have them land. Then it goes steady: a reopened window just
  appears where you are and stays. `~/.config/session/include` lists the few
  windows to keep snapping back even then; `~/.config/session/exclude` lists
  windows never to place.
- **Stable identity, never the title.** A window is matched to its saved slot by
  an app-specific identity, because window titles are too volatile to key on.
- **One layout per monitor set.** A placement only means anything on the
  monitors it was learned on, so the store is keyed by the connected display
  set: docked and undocked remember separately instead of overwriting each
  other. [hwdp](https://github.com/jello-d/hwdp) supplies the id when present
  (a *soft* dependency; without it the set is derived from the outputs, and
  failing that everything shares one `default` profile).
- **It will tell you what it is doing.** `session-mgr doctor` reports the store,
  the cross-tool contracts, and per window what would happen and why.
- **Go back to a past layout.** A daily milestone and a rolling history are
  kept, so `session-mgr restore --from yesterday` (or `latest`, or a date) puts
  the desk back the way it was; `--from list` shows what is available.

## Plugins

How to identify and respawn a given app's windows lives in a **plugin**. Three
ship built in — none uses the volatile title:

- **chrome** — keys a Chrome/Chromium window by its **active-tab URL** (read
  from the browser's own SNSS session file), normalized to host/path.
- **mux** — keys a [mux](https://github.com/jello-d/mux) terminal by its tmux
  **session** name *and the host it runs on* (`mux@<host>:<session>`), both read
  from the title mux stamps, and respawns it with `mux go`. A session reached
  over **ssh** is respawned with `ssh -t <host> …` instead, so a remote session
  comes back on its own box and never collides with a same-named local one.
  Candidates come from mux's durable session **set** (`mux resume --list`), not
  the live server, so they survive a reboot. `mux` is a *soft* dependency: if it
  is absent the plugin degrades to a no-op.
- **kitty** — keys any other kitty terminal by its shell's **working directory**
  (from `/proc`) and respawns it as a shell there.

Add your own: drop a `*.py` file into `~/.config/session/plugins/` defining a
top-level `PLUGIN` object. See [`share/plugins/example.py`](
share/plugins/example.py). Each plugin claims an app's windows (`owns`) and
may implement `identity` / `transient` / `window_id` / `relaunch_missing`, each
taking a normalized view (`v["app"]`, `v["title"]`, `v["pid"]`).

## Install

`usher` is Python (the daemon talks to the compositor over the Wayfire IPC
socket via `pywayfire`), so `setup.sh` builds a venv:

```sh
./setup.sh install      # core: build the venv, link session-mgr + man
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
session_restore = session-mgr watch
```

## Config

- `~/.config/session/exclude` — `<app-regex> :: <title-regex>` never-place list.
- `~/.config/session/include` — the same shape; the steady-state anchor list.
- `~/.config/session/identity` — `<url-regex> :: <canonical>` URL-normalization
  rules for the chrome plugin (e.g. collapse a Gmail path to a stable id).
- `~/.config/session/plugins/*.py` — user window plugins.

Example defaults ship in [`share/session/`](share/session/). The
daemon soft-degrades when any are absent.

## License

Apache-2.0.

## Development

An 80-column limit is enforced by a tracked pre-commit hook. Enable it once
per clone:

    git config core.hooksPath .githooks
