#!/bin/sh
# indicator.t - the tray indicator's installer: the venv lands INSIDE usher's
# payload and the pre-payload venv is retired safely.
#
# WHY THIS FILE EXISTS: indicator/setup.sh had no install test at all, only
# py_compile coverage of its python, and the payload conversion changed where
# its venv lives. A change with no check is the shape this suite exists to
# catch, and the core's canary only pins that a `venv-indicator` is CARRIED
# across the payload swap, not that anything puts one there.
#
# A STUB VENV (UI_SKIP_BUILD) and a FAKE HOME, so there is no network and
# nothing outside the sandbox is reachable. HOME is faked for every
# invocation, not just the ones about HOME: the installer derives its
# pre-payload venv path from $HOME absolutely, so a build with a broken guard
# would otherwise delete the developer's live venv from inside what looks like
# a sandboxed test. That happened twice while converting the core.
. "$(dirname "$0")/harness_lib"
harness_init indicator

command -v python3 >/dev/null 2>&1 || { pass "skipped (no python3)"; exit 0; }

H=$T/home; BIN=$T/bin; SHR=$T/share; CFG=$T/config
mkdir -p "$H" "$BIN"
APP=usher-indicator

# ROOT, NOT JUST THE BIN DIR. The retirement gates on where the NEW VENV is,
# as a literal `$HOME/.local/share/usher/venv-indicator`, so "the default
# location" means the DATA home and not the bin dir. Driving only UI_BIN left
# the data home in the sandbox, so the gate correctly refused and the test
# read that as a missing retirement.
run() {   # app-install with everything sandboxed under the root given as $1
  env HOME="$H" UI_BIN="$1/bin" XDG_DATA_HOME="$1/share" \
    XDG_CONFIG_HOME="$CFG" UI_SKIP_BUILD=1 NO_COLOR=1 \
    sh "$HERE/indicator/setup.sh" app
}
_stub_venv() {   # a venv the retirement will accept as working
  mkdir -p "$1/bin"; printf '#!/bin/sh\n' > "$1/bin/$APP"
  chmod +x "$1/bin/$APP"; }
_plant_old() { rm -rf "$H/.venvs"; mkdir -p "$H/.venvs/$APP/bin"
  printf '#!/bin/sh\n' > "$H/.venvs/$APP/bin/$APP"
  chmod +x "$H/.venvs/$APP/bin/$APP"; }

# THE VENV BELONGS INSIDE usher's PAYLOAD, and under a name the core's
# `venv*` carry glob matches, or the next core install destroys it.
_stub_venv "$T/sand/share/usher/venv-indicator"
run "$T/sand" >/dev/null 2>&1 || fail "indicator app install errored"
BIN=$T/sand/bin; SHR=$T/sand/share
[ "$(readlink "$BIN/$APP")" = "$SHR/usher/venv-indicator/bin/$APP" ] \
  || fail "$APP does not link into usher's payload venv-indicator"
case $(basename "$(dirname "$(dirname "$(readlink "$BIN/$APP")")")") in
  venv-indicator) ;;
  *) fail "the venv name is outside the core's venv* carry glob" ;;
esac

# A NON-DEFAULT BIN DIR MUST NOT REACH THE REAL ~/.venvs. Same bug the core
# shipped and had to be caught live: the old path is absolute, so without the
# guard a sandboxed install deletes it.
_plant_old
run "$T/sand" >/dev/null 2>&1 || fail "second install errored"
[ -d "$H/.venvs/$APP" ] \
  || fail "a sandboxed install deleted the pre-payload venv"

# ...and the default one MUST retire it, or the guard has turned the feature
# off and nothing would say so.
_plant_old
_stub_venv "$H/.local/share/usher/venv-indicator"
run "$H/.local" >/dev/null 2>&1 || fail "default-location install errored"
[ -d "$H/.venvs/$APP" ] \
  && fail "a default-location install did not retire the pre-payload venv"

# A FAILED REBUILD LEAVES THE OLD ONE ALONE: deleting first would leave the
# tray with no venv at all and a unit restarting a command that is not there.
_plant_old
rm -rf "$H/.local/share/usher/venv-indicator"
mkdir -p "$H/.local/share/usher/venv-indicator/bin"   # present but EMPTY
run "$H/.local" >/dev/null 2>&1 || fail "install with a dud venv errored"
[ -d "$H/.venvs/$APP" ] \
  || fail "retired the pre-payload venv while the new one was unusable"

pass "payload venv-indicator, the carry name, and the retirement guard"
