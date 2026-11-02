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

# THE SOURCE IS NORMALLY NOT WRITABLE BY THIS USER, and THIS is the install
# that broke on it. The tray is per-user and its source is the package's
# DEPLOYED CLONE, which became root-owned the day usher gained a machine-wide
# mode. pip BUILDS IN TREE (the default since 21.3), so it wanted to write
# `usher_indicator.egg-info` into a directory it could not write:
#
#     error: could not create 'usher_indicator.egg-info': Permission denied
#     ERROR: Failed to build ... when getting requirements to build wheel
#
# A STUB pip, so no network, and so the ARGUMENT pip was handed can be
# asserted: it must be a COPY and never the source. `app` skips
# `python3 -m venv` when the dir exists, so a planted venv with a stub
# `bin/pip` reaches the build.
RO=$T/ro; mkdir -p "$RO"
cp -R "$HERE/indicator"/. "$RO/" 2>/dev/null || :
rm -rf "$RO"/*.egg-info "$RO/build"
PV=$T/pipvenv/bin; mkdir -p "$PV"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >> %s/pip.log\nexit 0\n' "$T" \
  >"$PV/pip"
chmod +x "$PV/pip"
printf '#!/bin/sh\nexit 0\n' > "$PV/$APP"; chmod +x "$PV/$APP"
# ONLY THE DIRECTORY, which is what a root-owned 0755 clone looks like to a
# non-root caller: a copy made BY this user is this user's and removable.
chmod a-w "$RO" "$RO/usher_indicator"
_rc=0
env HOME="$H" UI_BIN="$T/ro-bin" XDG_DATA_HOME="$T/ro-share" \
  XDG_CONFIG_HOME="$T/ro-cfg" UI_VENV="$T/pipvenv" NO_COLOR=1 \
  sh "$RO/setup.sh" app >"$T/ro.out" 2>&1 || _rc=$?
chmod u+w "$RO" "$RO/usher_indicator"
[ "$_rc" = 0 ] || fail "app install from a READ-ONLY source errored: $(cat \
  "$T/ro.out")"
grep -q . "$T/pip.log" 2>/dev/null \
  || fail "the stub pip was never called, so nothing was proven"
grep -qx -- "$RO" "$T/pip.log" \
  && fail "pip was pointed AT THE SOURCE: $(cat "$T/pip.log")"
[ -z "$(ls -a "$RO" | grep -E 'egg-info|^build$')" ] \
  || fail "the install wrote build detritus into the source"

pass "payload venv-indicator, the carry name, the retirement guard, \
read-only source"
