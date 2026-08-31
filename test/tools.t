#!/bin/sh
# test/tools.t - every shipped script parses: the Python modules under py_compile
# (the engine + the indicator), the shell scripts under sh -n. Catches a syntax
# regression before it ships.
. "$(dirname "$0")/lib.sh"
harness_init tools

_bad=0
for _f in "$HERE/session_mgr.py" \
          "$HERE/indicator/session_mgr_indicator/__main__.py" \
          "$HERE/share/plugins"/*.py; do
  [ -e "$_f" ] || continue
  python3 -m py_compile "$_f" 2>/dev/null \
    || { echo "  py: $_f" >&2; _bad=1; }
done
for _f in "$HERE/setup.sh" "$HERE/indicator/setup.sh" "$HERE/test/run"; do
  { dash -n "$_f" 2>/dev/null || sh -n "$_f" 2>/dev/null; } \
    || { echo "  sh: $_f" >&2; _bad=1; }
done
[ "$_bad" = 0 ] || fail "a shipped script failed its syntax check"
pass "engine + indicator + setup.sh parse"
