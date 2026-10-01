"""usher: record the Wayland window layout and place windows back.

The successor to wayfire-rule-enforcer. Instead of hand-written placement
rules, it records where windows actually are and puts them back. `watch` is
BOTH the daemon (started at login) and the CLI controller for it: like
kanshi-mgr, one command runs the thing and drives it.

  usher-mgr watch        the daemon: record continuously, place on map
  usher capture      snapshot the current layout into the store now
  usher restore      place the stored layout onto the live session
  usher aggressive   KICK: re-arm aggressive placement (see below)
  usher toggle       flip aggressive<->steady (the tray left-click)
  usher settle       force steady now (end the aggressive window early)
  usher status       the daemon's mode + seconds until it settles
  usher exclude      show the never-place rules (usher/exclude)
  usher include      show the anchor rules (usher/include)

Placement is AGGRESSIVE then STEADY. For START_FLOOR seconds after login (or
an `aggressive` kick) every mapped window is placed back: what lets Chrome
launch and its windows land. Once IDLE_SETTLE seconds pass with no new window
(capped at AGGR_CAP) it goes STEADY: a reopened window just appears where you
are and stays. usher/include lists the few windows to keep snapping back
even then (opt-in; empty = follow-me). usher/exclude always wins.

THREE LAYERS, and the dependency runs ONE WAY:

    engine   the store, window identity, the plugins, capture/restore/doctor
    watch    the daemon: Supervisor (the lock + the respawn loop) and
             Watcher (place on map, record continuously)
    cli      main(), the verb dispatch, and the only entry to either

watch imports engine. engine imports NEITHER of the others, which is what
keeps `usher capture` (or selftest) from dragging in the daemon, and
what makes the daemon's dependencies visible as one import list instead of
being spread through a 3700-line module.
"""
