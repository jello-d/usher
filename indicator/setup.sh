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
#   UI_VENV   venv dir   (default ~/.venvs/usher-indicator)
#   UI_BIN    bin dir    (default ~/.local/bin)
#   UI_SKIP_BUILD  adopt an existing venv (the test's stub) instead of pip
#
# The SMI_* names are still read, since a provisioning system may pass them.
set -eu

self=$0
case $self in */*) ;; *) self=$(command -v -- "$self" || echo "$self") ;; esac
PKG_DIR=$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)

VENV=${UI_VENV:-${SMI_VENV:-$HOME/.venvs/usher-indicator}}
BIN_DIR=${UI_BIN:-${SMI_BIN:-$HOME/.local/bin}}
APP=usher-indicator
UNIT=$APP.service
# WHAT THE RENAME MUST REMOVE. This was session-mgr-indicator, and a --user unit
# that is merely no longer installed KEEPS RUNNING and comes back at the next
# login, so a box that skipped this step would show TWO tray icons and the old
# one would sit on a status file nothing writes any more. Naming the dead
# artifacts is the only thing that can retire them.
OLD_APP=session-mgr-indicator
OLD_UNIT=$OLD_APP.service
UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user

app() {
  if [ -z "${UI_SKIP_BUILD:-${SMI_SKIP_BUILD:-}}" ]; then
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
  echo "$APP: app -> $BIN_DIR/$APP"
}

# Retire the pre-rename install. Deliberately BEFORE the new unit starts, so the
# two never draw at once, and idempotent: on a box that never had the old name
# every line is a no-op.
retire_old() {
  _had=
  systemctl --user list-unit-files "$OLD_UNIT" >/dev/null 2>&1 \
    && [ -f "$UNIT_DIR/$OLD_UNIT" ] && _had=yes
  systemctl --user disable --now "$OLD_UNIT" 2>/dev/null || true
  rm -f "$UNIT_DIR/$OLD_UNIT" "$BIN_DIR/$OLD_APP"
  [ -n "$_had" ] && echo "$APP: retired $OLD_UNIT (renamed)"
  systemctl --user daemon-reload 2>/dev/null || true
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
  # A leftover from the rename is a FAILURE, not cosmetic: the old unit would
  # still be drawing a second icon against a status file nothing updates.
  if [ -f "$UNIT_DIR/$OLD_UNIT" ] || [ -e "$BIN_DIR/$OLD_APP" ]
  then bad "pre-rename $OLD_APP still installed; run: install"
  else ok "no pre-rename leftovers"; fi
  if cmp -s "$PKG_DIR/$UNIT" "$UNIT_DIR/$UNIT" 2>/dev/null
  then ok "$UNIT current"; else bad "$UNIT missing or stale"; fi
  _st=$(systemctl --user is-enabled "$UNIT" 2>/dev/null || true)
  if [ "$_st" = enabled ]; then ok "$UNIT enabled"
  else bad "$UNIT not enabled (${_st:-unknown})"; fi
  return "$RC"
}

case "${1:-install}" in
  install)   retire_old; app; service ;;
  app)       app ;;
  service)   service ;;
  check)     check ;;
  uninstall) uninstall ;;
  *) echo "usage: setup.sh [install|app|service|check|uninstall]" >&2
     exit 2 ;;
esac
