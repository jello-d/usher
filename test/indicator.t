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

# --- THE UNIT'S LIFETIME, AND THE ENABLE LINK IT REPLACED ------------------
# THE TRAY IS A SESSION HELPER, so it belongs to graphical-session.target and
# not to default.target. Under default.target it ran from BOOT, because this
# user lingers: a tray process on a box nobody has logged into. Measured on
# manifestor, where it read `active` while graphical-session.target read
# `inactive`.
grep -q '^WantedBy=graphical-session.target$' \
  "$HERE/indicator/$APP.service" \
  || fail "the unit is not wanted by graphical-session.target"
# ANCHORED ON A DIRECTIVE, not on the word: the unit's own comments explain
# why it MOVED OFF default.target, so a bare substring test fails over
# correct prose. A blanket substring sees too much as easily as a word
# boundary sees too little, which this tree records in both directions.
grep -qE '^(WantedBy|After|PartOf|Requires|BindsTo)=.*default\.target' \
  "$HERE/indicator/$APP.service" \
  && fail "a unit directive still names default.target"
grep -q '^Restart=on-failure$' "$HERE/indicator/$APP.service" \
  || fail "the unit does not use Restart=on-failure"
# AND IT STOPS WITH THE SESSION. WantedBy alone only STARTS it; PartOf is
# what propagates the stop, so without it the tray outlives the logout and
# the move buys half of what it is for. Right for a PRESENTER and wrong for
# the daemon, whose capture is the FIRST step of a clean logoff.
grep -q '^PartOf=graphical-session.target$' \
  "$HERE/indicator/$APP.service" \
  || fail "the unit does not stop with graphical-session.target"

# AND THE MOVE IS A SILENT NO-OP WITHOUT RETIRING THE OLD ENABLE LINK, which
# is the half that would have shipped: `systemctl enable` only ADDS the links
# a unit declares and removes none, so the stale `default.target.wants` symlink
# goes on pulling the tray up at boot while `is-enabled` reads `enabled` and
# everything looks done. A rename must remove what it replaced, and here the
# thing replaced is an enable link rather than a file.
grep -q 'disable "\$UNIT"' "$HERE/indicator/setup.sh" \
  || fail "service() does not retire the old enable link before enabling"

# ...AND A STEP AN INSTALL CAN MAKE MUST BE A STEP check CAN SEE. Driven with
# a PLANTED stale link in a sandboxed unit dir, plus the control: this must
# not fire when there is no such link, or it is a check nobody can satisfy.
_uc=$T/unitcfg; mkdir -p "$_uc/systemd/user/default.target.wants"
_chk() {  # indicator check, with the unit dir sandboxed under $_uc
  env HOME="$H" UI_BIN="$T/sand/bin" XDG_DATA_HOME="$T/sand/share" \
    XDG_CONFIG_HOME="$_uc" NO_COLOR=1 \
    sh "$HERE/indicator/setup.sh" check 2>&1
}
# THE TARGET HAS TO EXIST FOR THIS CASE TO BE THE RESOLVING ONE. The first
# version linked to a unit file the sandbox did not have, so this case was
# ITSELF dangling and the `-e`-only plant was caught here rather than by the
# dangling case below: three cases, two of them the same. The plant is what
# said so.
: > "$_uc/systemd/user/$APP.service"
ln -sfn "$_uc/systemd/user/$APP.service" \
  "$_uc/systemd/user/default.target.wants/$APP.service"
case $(_chk) in
  *"still wanted by default.target"*) : ;;
  *) fail "check passed over a stale default.target enable link" ;;
esac
rm -f "$_uc/systemd/user/default.target.wants/$APP.service"
case $(_chk) in
  *"still wanted by default.target"*)
    fail "check reports a stale enable link that is not there" ;;
  *) : ;;
esac
# A DANGLING LINK COUNTS TOO: `-e` follows the symlink, so a wants link whose
# target does not exist yet is INVISIBLE to `-e` alone and that is exactly
# the shape an uninstalled-then-reinstalled box leaves. `-e` AND `-L`, the
# pair `_user_copies` already tests for the same reason.
ln -sfn /nonexistent/usher-indicator.service \
  "$_uc/systemd/user/default.target.wants/$APP.service"
case $(_chk) in
  *"still wanted by default.target"*) : ;;
  *) fail "check passed over a DANGLING stale enable link" ;;
esac
rm -f "$_uc/systemd/user/default.target.wants/$APP.service"

# --- THE READER'S OWN TABLE ------------------------------------------------
# `read_status` is this package's ONE contract with the daemon and it decides
# whether the tray draws at all: everything it cannot understand reads as
# `down`, which is deliberately forgiving and therefore deliberately QUIET.
# Everything above tests the INSTALL; usher's own suite holds the FIELD NAMES
# from both sides; this is the reader's logic.
#
# IT NEEDS A PYTHON WITH PILLOW, which the module imports at top, so the
# INSTALLED indicator venv is the only interpreter that can import it. The
# skip is ANNOUNCED, because a test reporting the same thing whether or not
# half of it ran is the false green this tree exists to refuse.
_iv=$HOME/.local/share/usher/venv-indicator/bin/python3
if [ -x "$_iv" ]; then
  _so=$(cd / && env PYTHONPATH="$HERE/indicator" "$_iv" \
        -m usher_indicator status-test 2>&1) || {
    fail "the status reader's own table: $_so"
  }
  case $_so in
    *"status-test OK"*) : ;;
    *) fail "status-test said nothing recognisable: $_so" ;;
  esac
  # THE COUNT IS READ, because a table that silently shrank would still say
  # OK: the lesson this fleet paid for at 149-to-129 files.
  _sn=$(printf '%s' "$_so" | sed -n 's/.*OK (\([0-9]*\) checks).*/\1/p')
  [ -n "$_sn" ] && [ "$_sn" -ge 26 ] \
    || fail "the status table shrank to ${_sn:-?} checks"
  _smsg="the status reader ($_sn cells)"
else
  _smsg="status reader SKIPPED (no indicator venv)"
fi

pass "payload venv-indicator, the carry name, the retirement guard, \
read-only source, $_smsg"
