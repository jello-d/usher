#!/bin/sh
# setup.sh - install / uninstall / check / test the usher window-placement
# gadget: the session-mgr daemon (a Python venv console script) plus its
# optional tray indicator (the `indicator` sub-package). The SINGLE entry point
# a consumer or a provisioning layer uses.
#
#   ./setup.sh install       build the core venv + link session-mgr + man
#   ./setup.sh indicator [V] drive the optional tray indicator (passthrough)
#   ./setup.sh all           install + indicator install
#   ./setup.sh uninstall     remove the core links (the venv is left in place)
#   ./setup.sh check         core + deps present; [OK]/[FAIL] markers; drift rc
#   ./setup.sh test          run the in-repo suite (test/run)
#   ./setup.sh version       the packaged version
#
# POSIX sh, non-privileged. The core is Python (session-mgr needs pywayfire), so
# `install` builds a venv (like the indicator), NOT a bare symlink. PREFIX
# (default ~/.local), the XDG_* vars, and USHER_VENV override the destinations,
# so a test drives it against a scratch dir; USHER_SKIP_BUILD adopts an existing
# venv (the test's stub) instead of running pip.
set -eu

PKG=usher
VERSION=0.1.0
_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

PREFIX=${PREFIX:-$HOME/.local}
_bin=${XDG_BIN_HOME:-$PREFIX/bin}
_shr=${XDG_DATA_HOME:-$PREFIX/share}
_man=$_shr/man
VENV=${USHER_VENV:-$HOME/.venvs/usher}
RC=0

# marker contract: plain [OK]/[FAIL]/[WARN] an integrator's report can restyle;
# self-coloured at a terminal, plain when piped or under NO_COLOR.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _G=$(printf '\033[32m'); _R=$(printf '\033[31m')
  _Y=$(printf '\033[33m'); _O=$(printf '\033[0m')
else _G=; _R=; _Y=; _O=; fi
ok()   { printf '  %s[OK]%s   %s\n' "$_G" "$_O" "$1"; }
bad()  { printf '  %s[FAIL]%s %s\n' "$_R" "$_O" "$1"; RC=1; }
warn() { printf '  %s[WARN]%s %s\n' "$_Y" "$_O" "$1"; }

_rmln() { [ "$(readlink "$2" 2>/dev/null)" = "$1" ] && rm -f "$2" || :; }
_man_pages() { for _m in "$_root"/man/man*/*.[0-9]; do
  [ -e "$_m" ] && printf '%s\n' "$_m"; done; }

build_venv() {
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  # deps come from pyproject.toml; the forced --no-deps reinstall guarantees a
  # code change is picked up on a re-run (same version would else no-op).
  "$VENV/bin/pip" install -q "$_root"
  "$VENV/bin/pip" install -q --force-reinstall --no-deps "$_root"
  rm -rf "$_root/build" "$_root"/*.egg-info    # in-place build detritus
}

do_install() {
  [ -n "${USHER_SKIP_BUILD:-}" ] || build_venv
  mkdir -p "$_bin"
  ln -sfn "$VENV/bin/session-mgr" "$_bin/session-mgr"
  _man_pages | while IFS= read -r _m; do
    _d=$_man/$(basename "$(dirname "$_m")")
    mkdir -p "$_d"; ln -sfn "$_m" "$_d/$(basename "$_m")"; done
  echo "$PKG: session-mgr -> $_bin/session-mgr (venv $VENV)"
}

do_uninstall() {
  _rmln "$VENV/bin/session-mgr" "$_bin/session-mgr"
  _man_pages | while IFS= read -r _m; do
    _rmln "$_m" "$_man/$(basename "$(dirname "$_m")")/$(basename "$_m")"; done
  echo "$PKG: removed the core links (venv $VENV left in place)"
}

do_check() {
  echo "== $PKG (window placement) =="
  if [ -x "$VENV/bin/session-mgr" ]; then ok "venv app ($VENV)"
  else bad "venv app missing ($VENV) -- run: install"; fi
  if "$VENV/bin/python" -c 'import wayfire' 2>/dev/null; then ok "dep wayfire"
  else bad "wayfire not importable in the venv"; fi
  if [ -x "$_bin/session-mgr" ]; then ok "$_bin/session-mgr"
  else bad "$_bin/session-mgr missing"; fi
  if command -v mux >/dev/null 2>&1; then ok "mux present (terminal restore)"
  else warn "mux absent -- the mux plugin's terminal restore degrades"; fi
}

_U="usage: setup.sh [install|indicator [V]|all|uninstall|check|test|version]"
case "${1:-install}" in
  install)   do_install ;;
  indicator) shift; exec sh "$_root/indicator/setup.sh" "${@:-install}" ;;
  all)       do_install; sh "$_root/indicator/setup.sh" install ;;
  uninstall) do_uninstall ;;
  check)     do_check; exit "$RC" ;;
  test)      exec sh "$_root/test/run" ;;
  version)   echo "$PKG $VERSION" ;;
  -h|--help|help) echo "$_U" ;;
  *) echo "setup.sh: unknown command '${1:-}'" >&2; echo "$_U" >&2; exit 2 ;;
esac
