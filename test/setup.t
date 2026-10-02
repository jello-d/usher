#!/bin/sh
# setup.t - setup.sh install -> assert the console-script + man links land (NOT
# the indicator, which is the separate `indicator` verb) -> uninstall -> assert
# gone. A scratch PREFIX + a STUB venv (USHER_SKIP_BUILD), so no network and
# nothing outside the sandbox is touched. `check` is not run here (it needs a
# real venv with pywayfire); tools.t + selftest.t cover the code.
. "$(dirname "$0")/harness_lib"
harness_init setup

BIN=$T/bin; SHR=$T/share; VENV=$T/venv; CFG=$T/config
# HOME IS SANDBOXED FOR EVERY INVOCATION, not just the ones that are about
# HOME. setup.sh derives the pre-payload venv path (OLD_VENV) from $HOME
# absolutely, because the directory it names never sat under a PREFIX, so a
# BUILD WITH A BROKEN GUARD can delete the developer's live venv from inside
# what looks like a fully sandboxed test. That is not hypothetical: it
# happened twice on the box this was written on, the second time from the
# regression harness that was proving the guard works.
#
# So the sandbox does not rely on setup.sh being correct. A test whose safety
# depends on the code under test being right is not a sandbox.
H=$T/home; mkdir -p "$H"
mkdir -p "$VENV/bin"
for _a in usher usher-mgr; do
  printf '#!/bin/sh\n' > "$VENV/bin/$_a"; chmod +x "$VENV/bin/$_a"
done
# XDG_CONFIG_HOME is sandboxed too: the hwdp display-change hook lands under it,
# and a test must never reach into the real ~/.config to place one.
HOOK=$CFG/hwdp/hooks/changed.d/40-usher
run() {
  env HOME="$H" PREFIX="$T" XDG_BIN_HOME="$BIN" XDG_DATA_HOME="$SHR" \
    XDG_CONFIG_HOME="$CFG" USHER_VENV="$VENV" USHER_SKIP_BUILD=1 NO_COLOR=1 \
    sh "$HERE/setup.sh" "$@"
}

# install: the console script + the man page are linked; the indicator is NOT
# (that is the `indicator` verb, kept out so a host wiring it gets no dupe).
run install >/dev/null 2>&1 || fail "install errored"
# BOTH, because the install linked only one while the package provided more,
# and the check reported success anyway.
for _a in usher usher-mgr; do
  [ "$(readlink "$BIN/$_a")" = "$VENV/bin/$_a" ] \
    || fail "$_a not symlinked to the venv console script"
done
[ -e "$SHR/man/man1/usher.1" ] || fail "man page not linked"
# THE PAYLOAD, and the man link resolving INTO it rather than into the source.
[ -d "$SHR/usher" ] && [ ! -L "$SHR/usher" ] \
  || fail "no payload directory at $SHR/usher"
[ "$(readlink "$SHR/man/man1/usher.1")" = "$SHR/usher/man/man1/usher.1" ] \
  || fail "man page does not resolve into the payload"
# The providers ship in the payload too, since a provisioner installs one from
# the package rather than from the repo it was built in.
[ -x "$SHR/usher/share/providers/usher-greetd" ] \
  || fail "the payload has no executable provider"
[ -e "$BIN/usher-indicator" ] \
  && fail "install linked the indicator (should be indicator-only)"

# the hwdp hook is opt-in by PRESENCE: with no hwdp hook root, install must
# NOT invent one (a box without hwdp stays untouched).
[ -e "$HOOK" ] && fail "install created an hwdp hook with no hook root present"

# `hooks` places it, and is idempotent (re-running must not error or double up)
run hooks >/dev/null 2>&1 || fail "hooks errored"
run hooks >/dev/null 2>&1 || fail "hooks is not idempotent"
# INTO THE PAYLOAD, NOT THE SOURCE. This assertion is the conversion: the hook
# used to point at $HERE/share/hooks/hwdp-changed, i.e. straight into the
# clone, and a dangling hook is silently skipped by its runner.
[ "$(readlink "$HOOK")" = "$SHR/usher/share/hooks/hwdp-changed" ] \
  || fail "hwdp hook does not resolve into the payload"

# with the hook root now present, install adopts it without being asked
rm -f "$HOOK"
run install >/dev/null 2>&1 || fail "second install errored"
[ -e "$HOOK" ] || fail "install did not adopt an existing hwdp hook root"

# uninstall: the console-script + man symlinks and the hook are removed
run uninstall >/dev/null 2>&1 || fail "uninstall errored"
for _a in usher usher-mgr; do
  [ -e "$BIN/$_a" ] || [ -L "$BIN/$_a" ] && fail "$_a symlink not removed"
done
[ -e "$SHR/man/man1/usher.1" ] && fail "man page not removed"
[ -e "$HOOK" ] && fail "hwdp hook not removed"
[ -e "$SHR/usher" ] && fail "uninstall left the payload behind"

# ---- the venv canary ------------------------------------------------------
# A RE-INSTALL MUST NOT DESTROY A VENV INSIDE THE PAYLOAD, and nothing else
# here would notice: the swap replaces the whole payload directory, so without
# the carry-across step every provision sweep would delete the core's venv AND
# the tray's, leaving ~/.local/bin/* dangling until something rebuilt them.
#
# BOTH NAMES, because usher ships two and the carry is a `venv*` glob. A
# template that moved only `venv` would take `venv-indicator` with it, which
# is the deviation from the reference implementation worth pinning.
P=$SHR/usher
run install >/dev/null 2>&1 || fail "re-install for the canary errored"
for _v in venv venv-indicator; do
  mkdir -p "$P/$_v/bin"; echo canary > "$P/$_v/bin/CANARY"
done
run install >/dev/null 2>&1 || fail "install over a populated payload errored"
for _v in venv venv-indicator; do
  [ -f "$P/$_v/bin/CANARY" ] \
    || fail "install destroyed the $_v inside the payload"
done
# And the staging scratch dirs must not be left lying about.
for _d in "$P.new" "$P.old"; do
  [ -e "$_d" ] && fail "install left staging detritus at $_d"
done

# ---- the pre-payload venv retirement, and its sandbox guard ---------------
# THIS IS THE CHECK THAT WAS MISSING, and its absence cost the live install on
# the box this was written on. `OLD_VENV` is an ABSOLUTE ~/.venvs path (the
# directory it names never sat under a PREFIX), so an unguarded retirement
# reaches out of any sandbox into the real $HOME: the first scratch-PREFIX
# run, the step whose whole promise is "no touch to the real tree", deleted
# ~/.venvs/usher and left ~/.local/bin/usher-mgr dangling with the daemon
# alive only on open file descriptors.
#
# A FAKE HOME DRIVES BOTH SIDES, so the test can prove the retirement happens
# when it should AND cannot happen when it should not, without either answer
# depending on the real home directory.
_plant_old() { rm -rf "$H/.venvs"; mkdir -p "$H/.venvs/usher/bin"
  printf '#!/bin/sh\n' > "$H/.venvs/usher/bin/usher"
  chmod +x "$H/.venvs/usher/bin/usher"; }
runh() {   # install with HOME faked, at the PREFIX given as $1
  env HOME="$H" PREFIX="$1" XDG_BIN_HOME="$1/bin" XDG_DATA_HOME="$1/share" \
    XDG_CONFIG_HOME="$CFG" USHER_SKIP_BUILD=1 NO_COLOR=1 \
    sh "$HERE/setup.sh" install; }

# A SANDBOXED INSTALL MUST LEAVE IT ALONE. The venv it would build is a stub
# (USHER_SKIP_BUILD), so plant one at the scratch VENV path too, or the
# "is the new venv working" precondition short-circuits and the test passes
# for the wrong reason.
_plant_old
mkdir -p "$T/sand/share/usher/venv/bin"
printf '#!/bin/sh\n' > "$T/sand/share/usher/venv/bin/usher"
chmod +x "$T/sand/share/usher/venv/bin/usher"
runh "$T/sand" >/dev/null 2>&1 || fail "sandboxed install errored"
[ -d "$H/.venvs/usher" ] \
  || fail "a sandboxed install deleted the pre-payload venv"

# AND THE DEFAULT PREFIX MUST RETIRE IT, or the guard above has simply turned
# the feature off and nothing would notice.
_plant_old
mkdir -p "$H/.local/share/usher/venv/bin"
printf '#!/bin/sh\n' > "$H/.local/share/usher/venv/bin/usher"
chmod +x "$H/.local/share/usher/venv/bin/usher"
runh "$H/.local" >/dev/null 2>&1 || fail "default-prefix install errored"
[ -d "$H/.venvs/usher" ] \
  && fail "a default-prefix install did not retire the pre-payload venv"

# AND A FAILED REBUILD MUST LEAVE THE OLD ONE ALONE, which is the other half
# of "a rebuild, not a move": deleting first and building second would, on a
# bad build, leave the box with NO venv and no placement at the next login.
# Driven by making the new venv unusable (no console script) while the old one
# is present, so the only correct outcome is that nothing is removed.
#
# THIS ONE DID NOT BITE AT FIRST. The earlier version asserted only the happy
# path, so removing the "is the new venv working" precondition entirely failed
# no check: both cases planted a working venv, so the precondition was
# satisfied either way and the test could not tell it was gone.
_plant_old
rm -rf "$H/.local/share/usher/venv"
mkdir -p "$H/.local/share/usher/venv/bin"      # present but EMPTY: no `usher`
runh "$H/.local" >/dev/null 2>&1 || fail "install with a dud new venv errored"
[ -d "$H/.venvs/usher" ] \
  || fail "retired the pre-payload venv while the new one was unusable"

pass "payload + links + hooks + uninstall + venv canary + retirement guard"
