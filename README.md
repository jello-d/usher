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

## Plugins

How to identify and respawn a given app's windows lives in a **plugin**. Three
ship built in — none uses the volatile title:

- **chrome** — keys a Chrome/Chromium window by its **active-tab URL** (read
  from the browser's own SNSS session file), normalized to host/path.
- **mux** — keys a [mux](https://github.com/jello-d/mux) terminal by its tmux
  **session** name and respawns it with `mux go`. `mux` is a *soft* dependency:
  if it is absent the plugin degrades to a no-op.
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
./setup.sh check        # audit the install
./setup.sh test         # run the in-repo suite
```

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
