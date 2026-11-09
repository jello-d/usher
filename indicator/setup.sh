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

# _pip_from_copy <venv> <source>: install WITHOUT writing into the source.
#
# THIS IS THE ONE THAT BROKE, and it broke a whole provision. pip BUILDS IN
# TREE (the default since 21.3), so `pip install <dir>` writes `*.egg-info`
# and `build/` BESIDE the code. The tray is PER-USER and its source is now the
# package's DEPLOYED CLONE, which became root-owned the day usher gained a
# machine-wide mode, so the build had nowhere to put them:
#
#     creating usher_indicator.egg-info
#     error: could not create 'usher_indicator.egg-info': Permission denied
#     ERROR: Failed to build ... when getting requirements to build wheel
#
# A per-user install from a root-owned source is the NORMAL state now, not an
# edge case, so this no longer depends on writing where it reads. The same
# shape is in the core setup.sh, deliberately duplicated: the two installers
# share no library, and the shape is the fact rather than a list, so a copy
# cannot drift into a wrong answer.
_pip_from_copy() {
  _pc_v=$1 _pc_s=$2
  _pc_t=$(mktemp -d) || return 1
  # EXPANDED AND CHECKED BEFORE ANY `rm -rf`, per the standing rule.
  case $_pc_t in
  /*/*) ;;
  *) echo "$APP: refusing a scratch dir at '$_pc_t'" >&2; return 1 ;;
  esac
  _pc_rc=0
  # deps from pyproject.toml; the forced --no-deps reinstall guarantees a
  # code change is picked up on a re-run (same version would else no-op).
  # THE COPY MUST BE WRITABLE WHATEVER THE SOURCE'S MODES WERE. `cp -R`
  # carries them, so a read-only source yielded a read-only copy: pip could
  # not build in it and the cleanup below could not remove it, which turned a
  # fixed bug into a different failure with the same exit code.
  cp -R "$_pc_s/." "$_pc_t/" \
    && chmod -R u+w "$_pc_t" \
    && "$_pc_v/bin/pip" install -q "$_pc_t" \
    && "$_pc_v/bin/pip" install -q --force-reinstall --no-deps "$_pc_t" \
    || _pc_rc=$?
  rm -rf -- "$_pc_t"
  return "$_pc_rc"
}

app() {
  if [ -z "${UI_SKIP_BUILD:-}" ]; then
    [ -d "$VENV" ] || python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip
    _pip_from_copy "$VENV" "$PKG_DIR"
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
  # DISABLE BEFORE ENABLE, because `enable` only ADDS the links the unit
  # declares and removes none. When this unit moved from default.target to
  # graphical-session.target the old `default.target.wants` symlink stayed,
  # so the tray went on being pulled up at BOOT and the move was a silent
  # no-op on every already-installed box. A rename must remove what it
  # replaced, and here the thing replaced is an enable link rather than a
  # file. Not `--now`: that would stop the tray mid-provision.
  systemctl --user disable "$UNIT" 2>/dev/null || true
  systemctl --user enable "$UNIT" 2>/dev/null || true
  # restart (not just enable --now) so a re-run picks up a unit/code change,
  # AND so a box whose session predates the graphical-session.target wiring
  # keeps its tray until the next login rather than losing it to this move; a
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
  # AND A STEP AN INSTALL CAN MAKE MUST BE A STEP A CHECK CAN SEE. The move
  # off default.target is invisible otherwise: `enable` leaves the old wants
  # link, so a box that has never re-run this would read fully enabled while
  # still being pulled up at boot by the target this unit no longer names.
  if [ -e "$UNIT_DIR/default.target.wants/$UNIT" ] \
  || [ -L "$UNIT_DIR/default.target.wants/$UNIT" ]
  then bad "$UNIT is still wanted by default.target:" \
           "re-run \`setup.sh indicator install\` to retire that link"
  else ok "no stale default.target enable link"; fi
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
