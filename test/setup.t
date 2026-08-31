#!/bin/sh
# setup.t - setup.sh install -> assert the console-script + man links land (NOT
# the indicator, which is the separate `indicator` verb) -> uninstall -> assert
# gone. A scratch PREFIX + a STUB venv (USHER_SKIP_BUILD), so no network and
# nothing outside the sandbox is touched. `check` is not run here (it needs a
# real venv with pywayfire); tools.t + selftest.t cover the code.
. "$(dirname "$0")/lib.sh"
harness_init setup

BIN=$T/bin; SHR=$T/share; VENV=$T/venv
mkdir -p "$VENV/bin"
printf '#!/bin/sh\n' > "$VENV/bin/session-mgr"; chmod +x "$VENV/bin/session-mgr"
run() {
  env PREFIX="$T" XDG_BIN_HOME="$BIN" XDG_DATA_HOME="$SHR" \
    USHER_VENV="$VENV" USHER_SKIP_BUILD=1 NO_COLOR=1 \
    sh "$HERE/setup.sh" "$@"
}

# install: the console script + the man page are linked; the indicator is NOT
# (that is the `indicator` verb, kept out so a host wiring it gets no duplicate).
run install >/dev/null 2>&1 || fail "install errored"
[ "$(readlink "$BIN/session-mgr")" = "$VENV/bin/session-mgr" ] \
  || fail "session-mgr not symlinked to the venv console script"
[ -e "$SHR/man/man1/usher.1" ] || fail "man page not linked"
[ -e "$BIN/session-mgr-indicator" ] \
  && fail "install linked the indicator (should be indicator-only)"

# uninstall: the console-script + man symlinks are removed
run uninstall >/dev/null 2>&1 || fail "uninstall errored"
[ -e "$BIN/session-mgr" ] && fail "session-mgr symlink not removed"
[ -e "$SHR/man/man1/usher.1" ] && fail "man page not removed"

pass "install + uninstall"
