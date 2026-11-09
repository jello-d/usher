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

# THE SOURCE MAY BE READ-ONLY, and on this fleet it normally IS: the deployed
# clone is root-owned since usher gained a machine-wide mode, and a per-user
# verb resolves to the SYSTEM clone's setup.sh whenever one exists. pip BUILDS
# IN TREE (the default since 21.3), so installing straight from the source
# wants to write `*.egg-info` beside the code and cannot. Measured 2026-11-02:
# it broke a whole provision at the indicator step.
#
# DRIVEN WITH A STUB pip SO NO NETWORK IS NEEDED and the argument pip was
# actually given can be asserted, which is the thing under test: it must be a
# COPY and never the source. build_venv skips `python3 -m venv` when the dir
# already exists, so planting one with a stub `bin/pip` is enough to reach it.
RO=$T/ro; mkdir -p "$RO"
cp -R "$HERE"/. "$RO/" 2>/dev/null || :
rm -rf "$RO/.git" "$RO"/*.egg-info "$RO/build"
PV=$T/pipvenv/bin; mkdir -p "$PV"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >> %s/pip.log\nexit 0\n' "$T" \
  >"$PV/pip"
chmod +x "$PV/pip"
printf '#!/bin/sh\nexit 0\n' > "$PV/usher"; chmod +x "$PV/usher"
# THE SOURCE *DIRECTORY* IS WHAT IS NOT WRITABLE, which is what a root-owned
# clone actually looks like to a non-root caller: its dirs are 0755 root-owned,
# so a copy MADE by this user is this user's and removable. `chmod -R a-w`
# models something harsher and wrong, and it failed the payload swap rather
# than the pip build: the real bug is pip writing egg-info INTO the source
# dir, so that is the one bit to take away.
chmod a-w "$RO" "$RO/usher"
_rc=0
env HOME="$H" PREFIX="$T/ro-prefix" XDG_BIN_HOME="$T/ro-prefix/bin" \
  XDG_DATA_HOME="$T/ro-prefix/share" XDG_CONFIG_HOME="$T/ro-cfg" \
  USHER_VENV="$T/pipvenv" NO_COLOR=1 \
  sh "$RO/setup.sh" install >"$T/ro.out" 2>&1 || _rc=$?
chmod u+w "$RO" "$RO/usher"
[ "$_rc" = 0 ] || fail "install from a READ-ONLY source errored: $(cat \
  "$T/ro.out")"
# pip WAS CALLED, or this check proves nothing at all.
grep -q . "$T/pip.log" 2>/dev/null \
  || fail "the stub pip was never called, so nothing was proven"
# AND NOT ON THE SOURCE. That is the whole assertion.
grep -qx -- "$RO" "$T/pip.log" \
  && fail "pip was pointed AT THE SOURCE: $(cat "$T/pip.log")"
# A GLOB RATHER THAN `ls | grep`, which is SC2143 plus SC2010: an unmatched
# glob stays literal and `-e` is false for it, so this needs no pipeline and
# names the offending path. Found because mux borrowed this check and MUX'S
# LINT SHELLCHECKS ITS `.t` FILES where usher's only syntax-checks them, so
# the same line was clean here and rejected there. A borrowed check is only
# as good as the borrower's linter.
for _det in "$RO"/*.egg-info "$RO/build"; do
  [ -e "$_det" ] \
    && fail "the install wrote build detritus into the source: $_det"
done

# --- THE RULE FILES ARE A CHECK, and its three outcomes are the point ------
# A rule can now be REFUSED for being able to freeze the daemon (see
# engine.regex_probe), and a refused rule is a fault the box is carrying, so
# `check` fails and a provision fails with it: an escalation nobody has to go
# looking for, where a line in watch.log is somewhere nobody looks.
#
# ONE IS "ASSESSED AND BAD"; ANYTHING ELSE IS "COULD NOT ASK". Conflating the
# two is how a check comes to fail on a clean box and then gets switched off,
# and the first cut did exactly that: run on a system-mode box the lookup
# found no command, the shell answered 127, and two perfect rule files were
# reported as broken. Driven with a STUB `usher` whose exit code is chosen,
# which is the only way to reach all three arms with no rule file at all.
RB=$T/rulebin; mkdir -p "$RB"
_rule_out() {   # $1 = the code the stub exits with
  printf '#!/bin/sh\nexit %s\n' "$1" > "$RB/usher"
  chmod +x "$RB/usher"
  env HOME="$H" PREFIX="$T/rp" XDG_BIN_HOME="$T/rp/bin" \
    XDG_DATA_HOME="$T/rp/share" XDG_CONFIG_HOME="$T/rcfg" NO_COLOR=1 \
    PATH="$RB:$PATH" sh "$HERE/setup.sh" check 2>&1 || :
}
_o=$(_rule_out 0)
printf '%s\n' "$_o" | grep -q "the exclude rules load with no errors" \
  || fail "a clean rule file did not report clean: $_o"
_o=$(_rule_out 1)
printf '%s\n' "$_o" | grep -q "exclude rule file has errors" \
  || fail "rc 1 from the verb was not reported as a rule FAILURE: $_o"
_o=$(_rule_out 127)
printf '%s\n' "$_o" | grep -q "UNCHECKED rather than clean" \
  || fail "a verb that could not RUN was read as a rule failure: $_o"
# AND THE THREE READ DIFFERENTLY, since collapsing two is how the wrong one
# gets acted on.
[ "$(_rule_out 0)" != "$(_rule_out 1)" ] \
  && [ "$(_rule_out 1)" != "$(_rule_out 127)" ] \
  || fail "two of the three rule verdicts are indistinguishable"

pass "payload + links + hooks + uninstall + venv canary + retirement guard\
 + the rule-file check"
