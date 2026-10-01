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
# A FLOOR, so an empty set cannot pass. Every selector above is a glob, and a
# glob that matches nothing checks nothing while still reporting success, which
# is how a renamed package went uncompiled behind a green test. The numbers only
# have to be low enough never to need touching and high enough to catch a
# collapse; they are not an inventory.
[ "$_sh" -ge 5 ] || fail "only $_sh shell file(s): a selector is gone"
pass "$_py python, $_sh shell"
