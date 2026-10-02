#!/bin/sh
# setup.sh - set up usher-indicator (the SNI tray icon for usher's
# window-placement mode) for the CURRENT user. Standalone: run `./setup.sh`.
# An integrator (a provisioning system) delegates to it via `setup.sh install` /
# `setup.sh check`, so the steps are identical whether or not one drives it.
#
#   setup.sh install     build the app env + install & enable the service
#   setup.sh app         just the app: an isolated venv + a ~/.local/bin script
#   setup.sh service     just the systemd --user unit (install + enable + start)
#   setup.sh check       verify the install ([OK]/[FAIL]/[WARN] markers)
#   setup.sh uninstall   remove the unit + the ~/.local/bin script
#
# All userspace: NO sudo. Idempotent (safe to re-run; adopts what exists). Needs
# python3 and, for the service, a systemd --user manager. A tray HOST (waybar's
# tray, or any desktop's) and `usher` on PATH are runtime needs.
# Overrides:
#   UI_VENV   venv dir   (default ~/.local/share/usher/venv-indicator)
#   UI_BIN    bin dir    (default ~/.local/bin)
#   UI_SKIP_BUILD  adopt an existing venv (the test's stub) instead of pip
set -eu

self=$0
case $self in */*) ;; *) self=$(command -v -- "$self" || echo "$self") ;; esac
PKG_DIR=$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)

# THE VENV LIVES INSIDE usher'S PAYLOAD, per the fleet place-not-link rule.
# It was ~/.venvs/usher-indicator, and ~/.venvs is nobody's payload: a tree
# outside ~/.local/share/<pkg> is not removed by an uninstall, not carried by
# a re-install, and not audited by anything.
#
# NAMED `venv-indicator` BESIDE THE CORE'S `venv`, because usher ships two and
# the core's _payload_stage carries `venv*` across its swap. A name outside
# that glob would be destroyed on the next core install.
_usher_pay=${XDG_DATA_HOME:-$HOME/.local/share}/usher
VENV=${UI_VENV:-$_usher_pay/venv-indicator}
BIN_DIR=${UI_BIN:-$HOME/.local/bin}
# Retired by `app`, once the new venv is PROVEN: a venv bakes absolute paths
# into its console scripts, so this is a REBUILD and never a move, and
# deleting before the rebuild works would leave the tray with neither.
OLD_VENV=$HOME/.venvs/usher-indicator
APP=usher-indicator
UNIT=$APP.service
UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user

app() {
  if [ -z "${UI_SKIP_BUILD:-}" ]; then
    [ -d "$VENV" ] || python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip
    # deps from pyproject.toml; the forced --no-deps reinstall guarantees a
    # code change is picked up on a re-run (same version would else no-op).
    "$VENV/bin/pip" install -q "$PKG_DIR"
    "$VENV/bin/pip" install -q --force-reinstall --no-deps "$PKG_DIR"
    rm -rf "$PKG_DIR/build" "$PKG_DIR"/*.egg-info
  fi
  mkdir -p "$BIN_DIR"
  ln -sfn "$VENV/bin/$APP" "$BIN_DIR/$APP"
  echo "$APP: app -> $BIN_DIR/$APP (venv $VENV)"
  _retire_old_venv
}

# A REBUILD, NOT A MOVE, and only once the new venv answers: see OLD_VENV.
_retire_old_venv() {
  [ -d "$OLD_VENV" ] || return 0
  [ -x "$VENV/bin/$APP" ] || return 0
  # THE NEW VENV MUST BE THE REAL ONE, AS A LITERAL: the fleet's agreed form.
  # OLD_VENV ignores BIN_DIR and XDG_DATA_HOME because the old path never had
  # either, so a sandboxed install would otherwise satisfy the check above and
  # delete the LIVE venv. A variable here is no gate, since the verification
  # recipe overrides those very variables; the core's conversion lost this
  # box's venv twice before the literal went in.
  case $VENV in
  "$HOME"/.local/share/usher/venv-indicator) ;;
  *) return 0 ;;
  esac
  rm -rf -- "$OLD_VENV"
  rmdir "$HOME/.venvs" 2>/dev/null || :     # gone once the core's goes too
  echo "$APP: retired the pre-payload venv ($OLD_VENV)"
}


service() {
  mkdir -p "$UNIT_DIR"
  install -m 0644 "$PKG_DIR/$UNIT" "$UNIT_DIR/$UNIT"
  systemctl --user daemon-reload 2>/dev/null || true
  systemctl --user enable "$UNIT" 2>/dev/null || true
  # restart (not just enable --now) so a re-run picks up a unit/code change; a
  # headless install (no user bus yet) falls through to the next login.
  systemctl --user restart "$UNIT" 2>/dev/null || true
  echo "$APP: service $UNIT installed + enabled"
}

uninstall() {
  systemctl --user disable --now "$UNIT" 2>/dev/null || true
  rm -f "$UNIT_DIR/$UNIT" "$BIN_DIR/$APP"
  systemctl --user daemon-reload 2>/dev/null || true
  echo "$APP: uninstalled (venv $VENV left in place)"
}

check() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    _e=$(printf '\033')
    _G="$_e[1;32m"; _R="$_e[1;31m"; _O="$_e[0m"
  else _G=; _R=; _O=; fi
  RC=0
  ok()  { printf '  %s[OK]%s   %s\n' "$_G" "$_O" "$*"; }
  bad() { printf '  %s[FAIL]%s %s\n' "$_R" "$_O" "$*"; RC=1; }

  if [ -x "$VENV/bin/$APP" ]; then ok "venv app ($VENV)"
  else bad "venv app missing ($VENV); run: install app"; fi
  if "$VENV/bin/python" -c 'import dbus_next, PIL' 2>/dev/null
  then ok "deps import (dbus-next, Pillow)"
  else bad "deps not importable in the venv"; fi
  if [ -x "$BIN_DIR/$APP" ]; then ok "$BIN_DIR link"
  else bad "$BIN_DIR/$APP missing"; fi
  if cmp -s "$PKG_DIR/$UNIT" "$UNIT_DIR/$UNIT" 2>/dev/null
  then ok "$UNIT current"; else bad "$UNIT missing or stale"; fi
  _st=$(systemctl --user is-enabled "$UNIT" 2>/dev/null || true)
  if [ "$_st" = enabled ]; then ok "$UNIT enabled"
  else bad "$UNIT not enabled (${_st:-unknown})"; fi
  return "$RC"
}

case "${1:-install}" in
  install)   app; service ;;
  app)       app ;;
  service)   service ;;
  check)     check ;;
  uninstall) uninstall ;;
  *) echo "usage: setup.sh [install|app|service|check|uninstall]" >&2
     exit 2 ;;
esac
