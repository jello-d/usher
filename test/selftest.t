#!/bin/sh
# test/selftest.t - the engine's own offline unit checks (the plugin registry,
# the chrome/mux/kitty identity parsing, the SNSS reader). `usher selftest`
# imports no compositor (pywayfire is guarded), so it runs under plain
# python3.
#
# AND UNDER THE DEPLOYED VENV TOO, WHEN THERE IS ONE, because running it only
# under the system python hid three failing checks on every provisioned box
# for two days. `_tblind` blinded doctor by unsetting WAYFIRE_SOCKET, which
# stopped being sufficient the moment usher gained its own socket DISCOVERY:
# with pywayfire importable it simply FOUND the live socket and was not blind.
# The system python cannot import pywayfire, so the checks passed here and
# failed there, which is the worst possible split and exactly the one a suite
# is supposed to close.
#
# THE VENV RUN IS ANNOUNCED, NEVER SILENTLY SKIPPED. A suite that reports the
# same thing whether or not half of it ran is the false green this tree keeps
# finding.
. "$(dirname "$0")/harness_lib"
harness_init selftest

command -v python3 >/dev/null 2>&1 || { pass "skipped (no python3)"; exit 0; }
PYTHONPATH="$HERE" python3 -m usher selftest >/dev/null 2>&1 \
  || fail "usher selftest failed under the system python3"

# The deployed interpreter, which differs in the one way that matters: it can
# import pywayfire, so any check whose answer depends on that is exercised.
_venv=
for _c in "$HOME/.local/share/usher/venv/bin/python" \
          "$HOME/.venvs/usher/bin/python"; do
  [ -x "$_c" ] && { _venv=$_c; break; }
done

if [ -n "$_venv" ]; then
  PYTHONPATH="$HERE" "$_venv" -m usher selftest >/dev/null 2>&1 \
    || fail "usher selftest failed under the deployed venv ($_venv)"
  # And with a REAL socket in the environment, which is how a human runs it.
  for _s in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"/wayfire-*.socket; do
    [ -S "$_s" ] || continue
    WAYFIRE_SOCKET="$_s" PYTHONPATH="$HERE" "$_venv" -m usher selftest \
      >/dev/null 2>&1 || fail "usher selftest failed with WAYFIRE_SOCKET set"
    _withsock=" + live socket"
    break
  done
  pass "usher selftest (system python3 + deployed venv${_withsock:-})"
else
  pass "usher selftest (system python3; NO VENV FOUND, so the pywayfire-
dependent checks were NOT exercised)"
fi
