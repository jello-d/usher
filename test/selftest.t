#!/bin/sh
# test/selftest.t - the engine's own offline unit checks (the plugin registry,
# the chrome/mux/kitty identity parsing, the SNSS reader). `session-mgr selftest`
# imports no compositor (pywayfire is guarded), so it runs under plain python3.
. "$(dirname "$0")/lib.sh"
harness_init selftest

command -v python3 >/dev/null 2>&1 || { pass "skipped (no python3)"; exit 0; }
python3 "$HERE/session_mgr.py" selftest >/dev/null 2>&1 \
  || fail "session_mgr selftest failed"
pass "session_mgr selftest"
