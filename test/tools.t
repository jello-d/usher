#!/bin/sh
# test/tools.t - every shipped script parses: the Python modules under
# py_compile (the engine + the indicator), the shell scripts under sh -n.
# Catches a syntax regression before it ships.
. "$(dirname "$0")/harness_lib"
harness_init tools

_bad=0
# EVERYTHING IS GLOBBED, NEVER LISTED: a listed selector silently shrinks to
# cover less the moment a module is added or renamed, which is the same quiet
# no-op this suite exists to catch.
#
# The comment above used to say exactly that, and the very next line then LISTED
# the indicator's old __main__.py by name. Renaming that package left the
# path dangling and THIS TEST STILL PASSED, because
# the `[ -e ] || continue` below reads a missing listed file as nothing to do.
# So the indicator went uncompiled and the suite reported "engine + indicator
# parse". The skip is right for a glob that matches nothing and wrong for a name
# someone typed; globbing removes the difference.
# COUNTED PER SELECTOR, not in total. A single tally only catches a TOTAL
# collapse: measured here, breaking the indicator glob took 10 files to 8 and
# a floor of 6 still passed, the same false green in a new disguise. One
# package going dark is the realistic failure, so each selector must produce at
# least one file of its own.
_py=0
_compile_group() {   # <name> <min> <file>...
  _name=$1; _min=$2; shift 2
  _n=0
  for _f in "$@"; do
    # -f, NOT -e: the providers glob is BARE (they have bare names, being
    # executed rather than imported), so it also matches the `__pycache__`
    # DIRECTORY that running py_compile here leaves behind, and -e let a
    # directory through to be compiled. The *.py groups never saw this.
    [ -f "$_f" ] || continue
    _n=$((_n + 1)); _py=$((_py + 1))
    python3 -m py_compile "$_f" 2>/dev/null \
      || { echo "  py: $_f" >&2; _bad=1; }
  done
  [ "$_n" -ge "$_min" ] || { echo "  $_name: $_n file(s), expected >= $_min" >&2
    _bad=1; }
}
_compile_group engine    5 "$HERE/usher"/*.py
_compile_group indicator 2 "$HERE/indicator"/*/*.py
_compile_group plugins   1 "$HERE/share/plugins"/*.py
# The providers are python with BARE names, because they are EXECUTED rather
# than imported (the naming rule: a shebang script takes a bare name, whatever
# directory it sits in). py_compile does not care about the suffix, so they are
# syntax-checked here like everything else; test/providers.t runs them.
_compile_group providers 1 "$HERE/share/providers"/*
_sh=0
for _f in "$HERE/setup.sh" "$HERE/indicator/setup.sh" "$HERE/test/run" \
          "$HERE/test/harness_lib" "$HERE/.githooks/pre-commit" \
          "$HERE/share/hooks"/*; do
  [ -f "$_f" ] || continue
  _sh=$((_sh + 1))
  { dash -n "$_f" 2>/dev/null || sh -n "$_f" 2>/dev/null; } \
    || { echo "  sh: $_f" >&2; _bad=1; }
done
# A hook that is not EXECUTABLE is silently ignored by the runner that invokes
# it, which is the same shape as every other fault this suite now guards. A
# PROVIDER with no exec bit fails differently and just as quietly: usher's seam
# execs it, so the mode is the difference between a login and an EACCES.
for _f in "$HERE/share/hooks"/* "$HERE/share/providers"/*; do
  [ -f "$_f" ] && [ ! -x "$_f" ] && { echo "  not executable: $_f" >&2
    _bad=1; }
done
[ "$_bad" = 0 ] || fail "a shipped script failed its syntax check"

# THE SHIPPED EXAMPLE PLUGIN MUST SATISFY THE CONTRACT IT TEACHES. It is the
# file users copy, so if it drifts from the hooks usher actually calls, every
# plugin written from it starts broken, and nothing else would notice: it
# imports nothing (deliberately, so a dropped-in plugin cannot break on an
# internal move) and is never loaded by the suite. Compiling it proves only
# that it parses. This LOADS it and calls the hooks for real.
PYTHONPATH="$HERE" python3 - "$HERE" <<'PYEOF' || fail "share/plugins/example.py
 does not satisfy the plugin contract"
import importlib.util, sys
from usher.engine import _as_resolution
root = sys.argv[1]
path = root + "/share/plugins/example.py"
spec = importlib.util.spec_from_file_location("ex", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
p = getattr(m, "PLUGIN", None)
assert p is not None, "no top-level PLUGIN object"
v = {"app": "spotify", "title": "Some Track", "pid": 1, "id": 3}
assert p.owns(v), "owns() does not claim its own app"
r = _as_resolution(p.resolve(v), "example")
assert r.is_ready, f"resolve() is not ready: {r!r}"
assert r.key, "resolve() is ready with no key"
PYEOF
# EVERY TUNABLE IS DOCUMENTED, IN BOTH PLACES, and the list is DERIVED from
# the code rather than written out here. A second hand-written inventory is
# what goes stale: nine of the twelve knobs were documented nowhere at all
# until this check was written, including USHER_SKIP_TITLE, which is the
# work/personal boundary. BOTH DIRECTIONS are checked, because a knob that is
# removed from the code leaves its documentation behind, and prose describing
# a variable nothing reads is worse than no prose.
#
# A HUMAN-ONLY knob is still a knob: USHER_SUMMONED is set by usher itself and
# is documented saying exactly that, which is the honest answer rather than an
# exemption.
_knobs=$(grep -rho 'USHER_[A-Z_]*' "$HERE"/usher/*.py | sort -u)
_nk=$(printf '%s\n' "$_knobs" | grep -c .)
# VACUITY GUARD ON THE SCRAPE: if the grep stops matching, every assertion
# below passes over the empty set and this reports success while checking
# nothing.
[ "$_nk" -ge 10 ] || fail "only $_nk tunables found: the scrape is broken"
for _k in $_knobs; do
  grep -q "$_k" "$HERE/man/man1/usher.1" \
    || fail "$_k is read by the code and absent from the man page"
  grep -q "$_k" "$HERE/README.md" \
    || fail "$_k is read by the code and absent from README.md"
done
# ...and nothing documented that the code does not read.
for _d in $(grep -rho 'USHER_[A-Z_]*' "$HERE/man/man1/usher.1" \
            "$HERE/README.md" | sort -u); do
  printf '%s\n' "$_knobs" | grep -qx "$_d" \
    || fail "$_d is documented but no code reads it"
done

# ...AND THE STATED DEFAULTS ARE HELD AGAINST THE CODE. Naming a knob is the
# cheap half; the number beside it is what a reader acts on, and changing
# START_FLOOR from 300 to 240 would otherwise leave two files quietly lying.
# Read from the IMPORTED module, so the check cannot be satisfied by a second
# copy of the number.
PYTHONPATH="$HERE" python3 - "$HERE" <<'PYEOF' || fail "a documented default
 disagrees with the code"
import sys
root = sys.argv[1]
sys.path.insert(0, root)
from usher import chrome, engine
man = open(root + "/man/man1/usher.1").read()
rdm = open(root + "/README.md").read()
KNOBS = (("USHER_START_FLOOR", engine.START_FLOOR),
         ("USHER_IDLE_SETTLE", engine.IDLE_SETTLE),
         ("USHER_AGGR_CAP", engine.AGGR_CAP),
         ("USHER_CHROME_STAGGER", chrome.CHROME_STAGGER),
         ("USHER_WIND_DOWN_TIMEOUT", engine.WIND_DOWN_TIMEOUT))
bad = []
for name, val in KNOBS:
    want = str(int(val))
    for label, doc, span in (("man", man, 60), ("README", rdm, 80)):
        after = doc.split(name, 1)[1][:span]
        if want not in after:
            bad.append(f"{name}: code says {want}, {label} does not")
assert not bad, "; ".join(bad)
PYEOF

# A FLOOR, so an empty set cannot pass. Every selector above is a glob, and a
# glob that matches nothing checks nothing while still reporting success, which
# is how a renamed package went uncompiled behind a green test. The numbers only
# have to be low enough never to need touching and high enough to catch a
# collapse; they are not an inventory.
[ "$_sh" -ge 5 ] || fail "only $_sh shell file(s): a selector is gone"
pass "$_py python, $_sh shell, $_nk tunables documented both ways"
