# usher

Record the Wayland window layout and place windows back: a plugin-based
session manager for wlroots/[Wayfire](https://github.com/WayfireWM/wayfire).

Instead of hand-written placement rules, `usher` records where your windows
actually are and puts them back where you left them. Two commands split the
job: `usher-mgr` is the service your session starts, and `usher` is how you ask
anything of it.

- **Place then settled.** For a window's first moments after login (or a
  re-arm) every mapped window is placed back, which lets a browser open all its
  windows and have them land. Then it goes settled: a reopened window just
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
  the compositor gives an app-id is captured, keyed and placed, and if you
  have several of one app they each get their own remembered slot.
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

- **A particular window must get a particular slot.** Without a plugin,
  several windows of one app all get placed, but their slots are
  *interchangeable*: the app-id is the key and a slot index assigns one per
  window, so which of your three windows lands in which remembered rect is
  not something usher can promise. If that matters, something has to say
  WHICH window each one is, and only a plugin can. This is the whole reason
  the chrome plugin exists.
- **The identity is not in the title.** chrome reads a SessionID out of the
  browser's session file and finds which window it is by the SIZE Chrome
  records for it, asking the title only to break a tie between windows of
  one size; kitty reads the shell's cwd out of `/proc`; mux reads the command
  the window is running. A title belongs to a page, not a window.
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
implement `resolve` / `owns_key` / `relaunch_command` /
`relaunch_missing` / `wind_down`, each taking a normalized view (`v["app"]`,

`v["title"]`, `v["pid"]`, `v["id"]`). `v["id"]` is the compositor's view id,
stable for exactly one window's lifetime and `None` for a window replayed from
the store, so it is what to cache a hard-won identity against.
`owns_key` answers whether `resolve` could EVER have produced a stored
identity, so usher can report an entry no window can match: a plugin is the
authority on its own key shapes, and `None` ("I cannot say") is the default
and reads as matchable, since calling a working slot litter invites deleting
real memory.

`relaunch_missing` returns the **app-ids it started**, which is how usher knows
whether to let the registry default start an app a plugin claims but did not
actually launch; a count still works and is read as "I may have started
anything I own".

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
./setup.sh paths        # every root this package owns, KIND<tab>PATH
./setup.sh test         # run the in-repo suite
```

`install` links the hwdp hook by itself when hwdp's hook directory already
exists, so a box with hwdp needs no extra step and one without is untouched.

Everything is userspace (no sudo), into `~/.local` (override with `PREFIX` /
`XDG_*`). Under a provisioning layer (e.g. tackup) the same `setup.sh` is the
door.

### Machine-wide (`--system`)

```sh
sudo sh setup.sh install --system     # /opt/usher + /usr/local/bin
sh setup.sh check --system            # audit it (needs no root)
sudo sh setup.sh uninstall --system
```

One root-owned payload at `/opt/usher`, nothing writable by group or other,
with the commands at `/usr/local/bin` and the man page under
`/usr/local/share/man`. Every user then gets `usher` from one copy, which is
what makes it reachable **from another account**: if some windows on your
display belong to a different user, that user has to be able to invoke `usher`
without a copy inside a home nobody else can read.

Each user's config, state and runtime stay per-user, because none of it was
ever inside the payload. So does the tray indicator, which is a
`systemd --user` service with its own venv.

Two things worth knowing before switching:

- **It removes the sudo caller's `~/.local` copy in the same install**, because
  `/usr/local/bin` precedes `~/.local/bin` and the shadowed copy would rot. It
  keeps the tray's venv, and it repoints the hwdp hook.
- **Anything naming `~/.local/bin/usher-mgr` by absolute path must be updated**,
  the compositor autostart above especially. The install names each such file
  it finds rather than editing it: those are yours. A dangling autostart means
  no placement daemon at the next login, with nothing on screen saying why.

`DESTDIR` stages the tree and the links for packagers, but **not** the venv:
`python3 -m venv` bakes an absolute interpreter path into every console script,
so the venv is always built at its final path. `check --system` asserts that
baked path rather than trusting it.

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
usher forget 'chrome:win:*'  # drop remembered slots (previews; --apply acts)
usher undo [N] [--apply]     # list snapshots of the store, or merge one back
usher status                 # every fact the daemon publishes
usher place             # place every window that maps, for a while
usher settle                 # go settled now: leave new windows where they open
usher transpose              # sweep OPEN windows onto where they now belong
usher toggle                 # flip between those two (what the tray click does)
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

### Windows that belong to another account

If some windows on your display are run by a *different user* (a work account
with its own browser, say), usher must not treat them as yours: it cannot read
that account's application state, so it cannot identify those windows, and a
guess corrupts one of your own slots. So it declines them. They open where
they open, usher leaves them alone, and `doctor` says why.

Telling them apart needs nothing from you: usher compares the owner of the
window's process against the session user. **Whose** window it is is a
separate question usher cannot answer for itself, so there is a seam:

```
~/.config/usher/window-source <PID>
  exit 0, one word on stdout    that window's SOURCE name
  exit 1, no output             no source: the session user's own window
  anything else                 could not tell
```

Optional, and usher works identically with none: without a provider it falls
back to the uid comparison it can always make, so the only thing missing is
the *name*. A provider is asked only about windows that are already not ours,
and its answer is cached for the life of the process, so this is not on the
hot path. It gets two seconds.

No provider is named here, and usher knows nothing about what a source *is*:
wire whatever on your box can answer. A one-line shim is the normal shape:

```sh
#!/bin/sh
# ~/.config/usher/window-source
exec some-tool which-account-is pid "$1"
```

Once a source is named, those windows are *remembered and placed* like any
other: their slots key on the source name, so they survive a reboot and a
reinstall of that account. Several windows of one of its apps share one key,
because the state that would tell them apart is in a home usher may not read,
so the first gets the remembered place and the rest stay where they open.

A window of another account **waits**, unplaced and unlearned, until that
account has said which of its windows it is. The account answers for every
window it owns: a digest where it can tell windows of an app apart, or `-`
where it has nothing to add (a single-window app keeps the plain source key).
Waiting matters because the plain source key is a slot every window of the app
shares, so placing from it and then learning the result into the window's own
key is how a window ended up on the wrong workspace. A source that never
answers costs placement quality and never a window's memory: after two minutes
the window falls back to the plain key.

**Starting them is the other account's job**, since usher has no privilege to
spawn as another user and should not acquire any. So there is a second seam,
and what crosses it is a *trigger*:

```
~/.config/usher/source-trigger <SOURCE> capture|resume
  exit 0          accepted; that account is doing it
  anything else   could not, and usher says so
```

**No content crosses.** Both words come from a closed set usher itself
defines, so there is nothing for the far side to validate and nothing for
this side to inject. An earlier design handed over the app-ids to start, and
that is an escalation rather than a convenience: a recognised terminal app-id
resolves to a terminal on the far side, so the session user could have
arbitrary code run as the other account, which is the one thing the account
boundary exists to prevent.

**The argv is exactly three words, and the hook must pass stdin through.**
One line per window of that source goes on the child's standard input:

```
pid <toplevel-identifier> <pid>
```

That is the one fact the other account cannot get for itself:
`ext_foreign_toplevel_list_v1` is the only window protocol a sandboxed client
is given and it carries no pid, so the account cannot map one of its own
windows to one of its own processes, and a terminal's identity (its directory,
its session) lives nowhere else. The compositor reports a view's pid from the
client socket's peer credentials, so the session user has it already.

It travels on stdin rather than in the argument list **because the fixed arity
is what lets a sudoers grant name one command with no wildcard**, and a
wildcard there is execution as the account. A hook that `exec`s preserves
stdin and needs no change; one that drops it costs the account the windows it
needed a pid to describe and nothing else.

No mechanism is named here: reach that account however suits you, and which
system account a source name means is yours to decide too.

The account then runs, as itself, one of two **internal** verbs that never
take an argument:

- **`usher-mgr _source-capture`** records which apps *this* account has open,
  into `~/.local/state/usher/roster.json`. It reads them from the compositor
  over `ext_foreign_toplevel_list_v1`, which the compositor filters to this
  account's own windows, so the filtering *is* the scoping and no caller can
  widen it. A roster and not a layout, for Wayland's reasons rather than any
  policy: no Wayland protocol exposes a window's position, not even to the
  window's own client, so the apps this account launched do not know where
  they are either. The compositor does know and is reachable only over an IPC
  socket in the session user's `0700` runtime directory, so this side can
  neither read a position nor act on one. Placement stays the session user's
  not as a restriction but as the only split there is.
  It also records, per window, *how to bring that one back*: the identity
  and the command, read from this account's own `/proc` with the relayed pid.
  An app-id alone is enough for most apps and not for a terminal, which would
  otherwise come back as a bare shell in your home directory having forgotten
  both its directory and the session it was showing.

- **`usher-mgr _source-resume`** starts the remembered apps that are not
  running, resolving each app-id against *this* account's own desktop
  registry, and brings each remembered window back by its own command. Pass
  it the same `pid` lines and it can count what is already up per *command*
  rather than per app, which is the difference between restoring one of two
  terminals and restoring both.

The authority sits on the side that cannot be forged: the record of what an
account had open is written *by* that account, in a home the session user can
neither read nor write. So a caller supplies a trigger and never content, and
cannot introduce an app the human did not run there. A relayed pid is not
content either, and the account **checks that each one is its own process**
before reading anything from it: the pid comes from the Wayland connection's
peer, so a proxy or a pid namespace between an app and the compositor would
make it somebody else's, and checking turns either change into a loud refusal
rather than a confidently wrong answer.

Two rules that are easy to get backwards, both of them refusals:

- An observation with **no windows at all** does not overwrite a remembered
  roster. Capture while the session is intact, before anything is torn down;
  an account captured after its apps are killed would otherwise record an
  empty desk, and the next login would restore nothing from a record that
  looks perfectly valid. `usher cleanly logoff` does this in the right order.
- A resume **refuses rather than starting blind** when it cannot see what is
  already up, since starting a second copy of everything is worse than
  starting nothing.

Both verbs are hidden from the usage text and refused by the `usher` entry
point, which is what lets a sudoers grant name a fixed command with no
wildcard: a verb a human types is one that may later grow a flag, and a grant
must not be able to mean something nobody reviewed.

Nothing is logged when there is nothing to ask. When there *is* and no hook is
wired, usher says which apps of whose it could not start, so the reason
nothing came back is never silent.

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
- `~/.config/usher/include`: the same shape; the settled-state anchor list.
- `~/.config/usher/plugins/*.py`: user window plugins.
- `~/.config/usher/replay`: commands a terminal may be restarted running,
  one per line as typed (`top`, `htop -d 5`, a script's name). A terminal
  running a listed command is remembered apart from an idle shell in the
  same directory and comes back running it; anything else comes back as a
  plain shell. Opt-in, because re-running what you typed is not the same
  act as starting an app from its desktop entry.

Example defaults ship in [`share/config/`](share/config/). The
daemon soft-degrades when any are absent.

### Surfaces, for a laptop that docks

A window's place is remembered per monitor set, so the first time you dock at
a new desk usher has nothing to go on and leaves everything where it opens.
A **surface map** gives it a starting point: a name for a part of a panel at
that desk, so the name can carry a window's home from one desk to another
where a pixel rect cannot.

The map is not usher's to own: [hwdp](https://github.com/jello-d/hwdp) holds
it, via `hwdp surfaces`, because resolving "the bottom half of that monitor"
to a rect needs the logical size after rotation and scale. usher reads that
and seeds a window into the surface it occupies at another desk.

    hwdp surfaces --map     the surfaces, the region as a fraction of its
                            panel, and the desk's DEFAULT
    usher doctor            the map, and which surfaces this desk has

Where a window goes, in order: the surface of the same name; else the surface
this desk puts in the window's own workspace cell (under wsync a cell is the
whole desk, so it is the same place); else the desk's DEFAULT, which is what
makes the map total. The window keeps its position and size as a FRACTION of
the region it was learned in, so it fills the same part of the target region
at that desk's resolution. Undocking uses the same path, so a window whose
monitor has gone lands in its region on the laptop instead of staying parked
out of sight.

**The surface decides; a desk's learned slot only tunes it.** When you
arrive at a desk, a window goes to the surface it held on the desk you came
from. This desk's learned slot for it is used only when that slot sits in the
same surface, where it is a finer answer than the surface's fraction; a slot
anywhere else (including outside every surface) is stale, so the surface wins
and the next capture relearns it. Once you have arrived, what you arrange by
hand is learned and kept: a slot learned since you arrived is never overruled.
Two windows sharing one identity (two shells in one directory) each go to
the surface its own slot held on the desk you came from. To keep a spot no
surface covers, name it in the desk's map.

**Seeded windows are laid out beside each other.** A window placed from a
surface rather than from a learned slot is a guess, so two of them seeded into
one surface at a desk change are not stacked on top of each other: the second
goes beside the first along the surface's long axis (one under the other on a
portrait panel), shrinking into the gap if it must keep at least half its
length, and staying where the surface put it otherwise. Learned slots are
never moved by this; they are your arrangement.

**No window is left where it cannot be seen.** Whatever put it there (a
parked window that lost a shared slot, a slot learned mostly off its panel, a
grid that shrank), the daemon checks every few seconds that each window is on
an attached output, in a cell the grid has, and mostly on its panel, and puts
any that is not on this desk by the same order a seed takes. Every placement
is also fitted to the panel's WORK AREA, which the compositor computes net of
the bars, so their heights at each panel's DPI need no configuration.
`usher doctor` lists any window that cannot be seen.

**No map means no seeding**, which is the opt-out: with no hwdp, no surfaces
file for this desk, or an unreadable one, usher behaves exactly as it did
before, learning only.

### Environment

Every knob usher reads, with its default. All are read **once at import**, so
a running daemon keeps the values it started with: change one and restart it
with `usher reload`.

- **`USHER_SKIP_TITLE`** (`^\[WORK`): titles matching this regex are ignored
  end to end, never captured, placed or relaunched. This is the work/personal
  boundary rather than a convenience, so widen it with care.
- **`USHER_START_FLOOR`** (`30`): seconds after login, or a `usher place`
  kick, during which every mapped window is placed back. A floor, not a race:
  activity extends it, and you can re-arm it by hand. Restoring a session
  takes seconds, so this is sized from measurement rather than caution.
- **`USHER_IDLE_SETTLE`** (`15`): seconds with no new window before placing
  gives way to settled, where only `include` anchors are moved. This is how
  big a gap in arrivals means the restore is over, so it tracks how apps
  spawn rather than how long you want placing: the widest gap measured during
  a real restore is 4-5s.
- **`USHER_PLACE_CAP`** (`180`): hard cap on the place window, whatever
  the other two say. A window that mapped while placing is still owed one
  placement when it first becomes identifiable, past the cap or not.
- **`USHER_DOCK_HOLD`** (`20`): seconds that a monitor arriving or leaving
  suppresses capture for, so an undock's collapse is not learned as the new
  truth. Ended early by hwdp's display-change hook.
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
  daemon can tell a session begun remotely from one begun at the keyboard. It
  is one of two routes: the variable travels by exec inheritance, which stops
  working if the compositor is started as a systemd unit, so `cleanly login`
  also leaves a one-shot marker at `$XDG_RUNTIME_DIR/usher.summoned` that the
  daemon consumes as it reads. On
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
