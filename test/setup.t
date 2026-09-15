#!/bin/sh
# setup.t - setup.sh install -> assert the console-script + man links land (NOT
# the indicator, which is the separate `indicator` verb) -> uninstall -> assert
# gone. A scratch PREFIX + a STUB venv (USHER_SKIP_BUILD), so no network and
# nothing outside the sandbox is touched. `check` is not run here (it needs a
# real venv with pywayfire); tools.t + selftest.t cover the code.
. "$(dirname "$0")/lib.sh"
harness_init setup

BIN=$T/bin; SHR=$T/share; VENV=$T/venv; CFG=$T/config
mkdir -p "$VENV/bin"
printf '#!/bin/sh\n' > "$VENV/bin/session-mgr"; chmod +x "$VENV/bin/session-mgr"
# XDG_CONFIG_HOME is sandboxed too: the hwdp display-change hook lands under it,
# and a test must never reach into the real ~/.config to place one.
HOOK=$CFG/hwdp/hooks/changed.d/40-usher
run() {
  env PREFIX="$T" XDG_BIN_HOME="$BIN" XDG_DATA_HOME="$SHR" \
    XDG_CONFIG_HOME="$CFG" USHER_VENV="$VENV" USHER_SKIP_BUILD=1 NO_COLOR=1 \
    sh "$HERE/setup.sh" "$@"
}

# install: the console script + the man page are linked; the indicator is NOT
# (that is the `indicator` verb, kept out so a host wiring it gets no dupe).
run install >/dev/null 2>&1 || fail "install errored"
[ "$(readlink "$BIN/session-mgr")" = "$VENV/bin/session-mgr" ] \
  || fail "session-mgr not symlinked to the venv console script"
[ -e "$SHR/man/man1/usher.1" ] || fail "man page not linked"
[ -e "$BIN/session-mgr-indicator" ] \
  && fail "install linked the indicator (should be indicator-only)"

# the hwdp hook is opt-in by PRESENCE: with no hwdp hook root, install must
# NOT invent one (a box without hwdp stays untouched).
[ -e "$HOOK" ] && fail "install created an hwdp hook with no hook root present"

# `hooks` places it, and is idempotent (re-running must not error or double up)
run hooks >/dev/null 2>&1 || fail "hooks errored"
run hooks >/dev/null 2>&1 || fail "hooks is not idempotent"
[ "$(readlink "$HOOK")" = "$HERE/share/hooks/hwdp-changed" ] \
  || fail "hwdp hook not linked to the shipped script"

# with the hook root now present, install adopts it without being asked
rm -f "$HOOK"
run install >/dev/null 2>&1 || fail "second install errored"
[ -e "$HOOK" ] || fail "install did not adopt an existing hwdp hook root"

# uninstall: the console-script + man symlinks and the hook are removed
run uninstall >/dev/null 2>&1 || fail "uninstall errored"
[ -e "$BIN/session-mgr" ] && fail "session-mgr symlink not removed"
[ -e "$SHR/man/man1/usher.1" ] && fail "man page not removed"
[ -e "$HOOK" ] && fail "hwdp hook not removed"

pass "install + hooks + uninstall"
