"""usher: record the Wayland window layout and place windows back.

The successor to wayfire-rule-enforcer. Instead of hand-written placement
rules, it records where windows actually are and puts them back. `watch` is
BOTH the daemon (started at login) and the CLI controller for it: like
kanshi-mgr, one command runs the thing and drives it.

THE VERBS ARE `cli.VERBS`, and are deliberately NOT restated here. This
paragraph used to list nine of them and had drifted to naming eight that
exist out of twenty-five, missing `save`, `lock`, `predict`, `verify`,
`cleanly` and `doctor` entirely. One table, read by `usher help`, by the
usage text and by the checks that assert each verb is reachable.

Placement is AGGRESSIVE then STEADY. For START_FLOOR seconds after login (or
an `aggressive` kick) every mapped window is placed back: what lets Chrome
launch and its windows land. Once IDLE_SETTLE seconds pass with no new window
(capped at AGGR_CAP) it goes STEADY: a reopened window just appears where you
are and stays. usher/include lists the few windows to keep snapping back
even then (opt-in; empty = follow-me). usher/exclude always wins.

SIX MODULES, and the dependency runs ONE WAY:

    chrome    the SNSS format and chrome identity. Imports nothing of ours.
    engine    the store, window identity, the plugins, capture and restore
    watch     the daemon: Supervisor (the lock + the respawn loop) and
              Watcher (place on map, record continuously)
    doctor    the report
    selftest  every offline check, grouped by area
    cli       main(), the verb dispatch, and the only entry to any of them

    cli -> engine, watch, doctor, selftest      doctor -> engine, chrome
    watch -> engine                             engine -> chrome

engine imports NO module that imports it, which is what keeps `usher save`
from dragging in the daemon and makes each consumer's dependencies visible as
one import list. cli defers the daemon and the suite to their branches, so a
verb nobody called costs nothing to parse.
"""
