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
# indicator/session_mgr_indicator/__main__.py. Renaming the package to
# usher_indicator left that path dangling and THIS TEST STILL PASSED, because
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
    [ -e "$_f" ] || continue
    _n=$((_n + 1)); _py=$((_py + 1))
    python3 -m py_compile "$_f" 2>/dev/null \
      || { echo "  py: $_f" >&2; _bad=1; }
  done
  [ "$_n" -ge "$_min" ] || { echo "  $_name: $_n file(s), expected >= $_min" >&2
    _bad=1; }
}
_compile_group engine    5 "$HERE/session_mgr"/*.py
_compile_group indicator 2 "$HERE/indicator"/*/*.py
_compile_group plugins   1 "$HERE/share/plugins"/*.py
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
# it, which is the same shape as every other fault this suite now guards.
for _f in "$HERE/share/hooks"/*; do
  [ -f "$_f" ] && [ ! -x "$_f" ] && { echo "  not executable: $_f" >&2
    _bad=1; }
done
[ "$_bad" = 0 ] || fail "a shipped script failed its syntax check"
# A FLOOR, so an empty set cannot pass. Every selector above is a glob, and a
# glob that matches nothing checks nothing while still reporting success, which
# is how a renamed package went uncompiled behind a green test. The numbers only
# have to be low enough never to need touching and high enough to catch a
# collapse; they are not an inventory.
[ "$_sh" -ge 5 ] || fail "only $_sh shell file(s): a selector is gone"
pass "$_py python, $_sh shell"
