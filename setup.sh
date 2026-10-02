#!/bin/sh
# setup.sh - install / uninstall / check / test the usher window-placement
# gadget: the usher daemon (a Python venv console script) plus its
# optional tray indicator (the `indicator` sub-package). The SINGLE entry point
# a consumer or a provisioning layer uses.
#
#   ./setup.sh install       build the core venv + link the commands + man
#   ./setup.sh indicator [V] drive the optional tray indicator (passthrough)
#   ./setup.sh all           install + indicator install
#   ./setup.sh hooks         link the hwdp display-change hook (install does
#                            this too when hwdp's hook dir already exists)
#   ./setup.sh uninstall     remove the core links (the venv is left in place)
#   ./setup.sh check         core + deps present; [OK]/[FAIL] markers; drift rc
#   ./setup.sh test          run the in-repo suite (test/run)
#   ./setup.sh version       the packaged version
#
# POSIX sh, non-privileged. The core is Python (usher needs pywayfire), so
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

# THE PAYLOAD: one self-contained tree, COPIES of what the repo ships, with
# links into it. The fleet's place-not-link rule
# (shared-notes/_install-placement.md): an installed package must never link
# back into its SOURCE, because a departed package's source is a cache clone
# (~/.cache/tackup/pkgs/usher) that is re-cloned on every sweep and wiped on
# demand, so every such link dangles.
#
# WHAT USHER WAS DOING WRONG was narrower than the rule's general case, and
# worth naming because the commands were already fine: `~/.local/bin/{usher,
# usher-mgr}` link into the VENV, and `pip install` COPIES the package into
# site-packages, so no command ever resolved into the clone. The violations
# were the MAN PAGE and the HWDP HOOK, both linked straight at $_root, plus
# two venvs sitting in ~/.venvs outside any payload.
_pay=$_shr/$PKG
# The venv lives INSIDE the payload now (was ~/.venvs/usher). A venv is not
# reachable by self-location anyway, since its console scripts bake an
# absolute interpreter path, so there is no reason for it to sit apart from
# the tree it belongs to.
VENV=${USHER_VENV:-$_pay/venv}
# Retired by `install`, once the new venv is PROVEN to work: see
# _retire_old_venv for why that order is the whole safety of it.
OLD_VENV=$HOME/.venvs/usher
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

# hwdp integration: usher remembers a layout PER MONITOR SET, and hwdp is what
# knows the set changed. Its hook dir is a documented contract, so dropping a
# link in is the whole wiring. Opt-in by PRESENCE: `install` does it only if
# hwdp's hook root already exists, so a box without hwdp is untouched and one
# with it needs no extra step.
# FROM THE PAYLOAD, NOT $_root. This link was one of usher's two place-not-link
# violations, and the more dangerous of the two: a dangling hook is SILENTLY
# SKIPPED by the runner that invokes it, so a wiped cache would have cost every
# monitor-set re-placement with nothing anywhere saying why.
_hook_src() { echo "$_pay/share/hooks/hwdp-changed"; }
_hook_dir() { echo "${XDG_CONFIG_HOME:-$HOME/.config}/hwdp/hooks/changed.d"; }
# Numeric prefix because hwdp runs the dir as a sorted glob and placement must
# come LAST: restoring windows before the outputs are configured and the
# compositor runtime is applied would place them against the old geometry.
_hook_dst() { echo "$(_hook_dir)/40-usher"; }

do_hooks() {
  mkdir -p "$(_hook_dir)"
  ln -sfn "$(_hook_src)" "$(_hook_dst)"
  echo "$PKG: display-change hook -> $(_hook_dst)"
}
# RELATIVE paths (manN/name.N), listed from the SOURCE because that is the one
# tree guaranteed to be there: install reads it before the payload exists, and
# uninstall reads it after the payload is gone. The caller joins it to $_pay
# for the link target and to $_man for the link itself, so neither side has to
# know whether the other tree is present.
_man_rel() { for _m in "$_root"/man/man*/*.[0-9]; do
  [ -e "$_m" ] && printf '%s/%s\n' \
    "$(basename "$(dirname "$_m")")" "$(basename "$_m")"; done; }

# _payload_stage: build the new payload beside the live one and swap it in.
#
# STAGED AND SWAPPED, never emptied in place, because the daemon this installs
# is what places every window at login and the tray reads its status every
# second. Emptying the tree first would make both fail for the length of a
# copy; two renames is as close to atomic as a directory gets.
_payload_stage() {
  _ps_new=$_pay.new
  _ps_old=$_pay.old
  # EXPANDED AND CHECKED BEFORE ANYTHING IS REMOVED, per the standing rule
  # that `rm -rf` never runs on an unexamined variable. A sibling repo's own
  # harness deleted its working tree because an empty value reached `rm -rf`
  # at trap-fire time.
  case $_pay in
  /*/*) ;;
  *) bad "refusing to stage a payload at '$_pay'"; return 1 ;;
  esac
  rm -rf -- "$_ps_new" "$_ps_old"
  mkdir -p "$_ps_new" || { bad "could not create $_ps_new"; return 1; }
  # Only what usher actually ships. There is no bin/ or libexec/: the commands
  # are venv console scripts, which is why the payload carries a venv.
  for _d in share man; do
    [ -d "$_root/$_d" ] || continue
    cp -R "$_root/$_d" "$_ps_new/" || { bad "could not copy $_d"; return 1; }
  done
  [ -d "$_ps_new/share/providers" ] || { bad "staged payload has no providers"
    rm -rf -- "$_ps_new"; return 1; }
  # CARRY EVERY VENV ACROSS, and the plural is usher's deviation from the
  # reference implementation. The swap replaces the whole payload and the
  # venvs live INSIDE it, so without this an install destroys them. usher has
  # TWO (the core's `venv` and the tray's `venv-indicator`, 14M and 35M), so a
  # template that moved only `venv` would silently take the indicator's with
  # it on every provision sweep and leave ~/.local/bin/usher-indicator
  # dangling until something rebuilt it.
  #
  # MOVED RATHER THAN COPIED, which keeps the swap quick and keeps the venv's
  # baked absolute paths valid: it starts at $_pay/venv* and ends there, with
  # only the two renames in between.
  for _v in "$_pay"/venv*; do
    [ -d "$_v" ] || continue
    _vb=$(basename "$_v")
    [ -e "$_ps_new/$_vb" ] && continue
    mv -- "$_v" "$_ps_new/$_vb" || { bad "could not carry $_vb across"
      rm -rf -- "$_ps_new"; return 1; }
  done
  if [ -e "$_pay" ] || [ -L "$_pay" ]; then
    mv -- "$_pay" "$_ps_old" || { bad "could not move the old payload"
      return 1; }
  fi
  mv -- "$_ps_new" "$_pay" || {
    bad "could not swap in the new payload"
    # ROLL BACK THE VENVS TOO. The old tree's venvs have already moved into
    # .new, so restoring .old alone would hand back a payload with none, which
    # is the state this whole function exists to avoid.
    if [ -e "$_ps_old" ]; then
      mv -- "$_ps_old" "$_pay"
      for _v in "$_ps_new"/venv*; do
        [ -d "$_v" ] || continue
        [ -e "$_pay/$(basename "$_v")" ] || mv -- "$_v" "$_pay/"
      done
    fi
    return 1; }
  rm -rf -- "$_ps_old"
}

# _retire_old_venv: A REBUILD, NOT A MOVE, and that distinction is the whole
# safety of it. A venv bakes an ABSOLUTE interpreter path into every console
# script and into pyvenv.cfg, so moving the directory leaves every entry point
# pointing at a python that is no longer there.
#
# AND ONLY ONCE THE NEW ONE WORKS. Deleting first and rebuilding second would,
# on a failed rebuild, leave the box with neither: no placement daemon at the
# next login, from a provisioning step that was meant to be routine.
_retire_old_venv() {
  [ -d "$OLD_VENV" ] || return 0
  [ -x "$VENV/bin/usher" ] || return 0
  # ONLY FOR A DEFAULT-PREFIX INSTALL, and this guard is the whole reason the
  # function is safe. OLD_VENV is an ABSOLUTE ~/.venvs path: it is not derived
  # from PREFIX, because the directory it names was never under one. So
  # without this a scratch-prefix install reaches straight into the real $HOME
  # and deletes the live venv.
  #
  # MEASURED, NOT IMAGINED. The first cut of this had no such guard, and the
  # very first scratch-PREFIX verification run (the step whose entire promise
  # is "no touch to the real tree") removed ~/.venvs/usher on this box, leaving
  # ~/.local/bin/{usher,usher-mgr} dangling and the running daemon alive only
  # on open file descriptors. ~/.venvs/usher can only ever belong to an install
  # whose PREFIX was the default, so that is exactly what is tested.
  # THE NEW VENV MUST BE THE REAL ONE, AS A LITERAL. This is the fleet's
  # agreed form (mux, hush, bt-sane), and the literal is the whole point: the
  # first version here gated on PREFIX, which worked, but mux's first version
  # gated on `${XDG_DATA_HOME:-...}` and that is NO GATE AT ALL, because the
  # recipe's own verification step overrides XDG_DATA_HOME too, so the
  # comparison holds against a throwaway prefix and the live venv goes anyway.
  # Written the way the gotcha prescribes it so all the venv packages agree
  # and an audit of "do they all have the literal gate" has one shape to look
  # for.
  #
  # THE COST IS THE SAFE ONE: a box whose data home genuinely points elsewhere
  # never gets the retire and keeps a directory nothing reads. Deleting a live
  # venv is the other kind of wrong, and it is what this cost twice.
  case $VENV in
  "$HOME"/.local/share/usher/venv) ;;
  *) return 0 ;;
  esac
  rm -rf -- "$OLD_VENV"
  rmdir "$HOME/.venvs" 2>/dev/null || :     # gone once the tray's goes too
  echo "$PKG: retired the pre-payload venv ($OLD_VENV)"
}

build_venv() {
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  # deps come from pyproject.toml; the forced --no-deps reinstall guarantees a
  # code change is picked up on a re-run (same version would else no-op).
  "$VENV/bin/pip" install -q "$_root"
  "$VENV/bin/pip" install -q --force-reinstall --no-deps "$_root"
  rm -rf "$_root/build" "$_root"/*.egg-info    # in-place build detritus
}

# EVERY CONSOLE SCRIPT THE PACKAGE PROVIDES, named once so install, uninstall
# and check cannot disagree. This once linked ONE name while pyproject had grown
# to three entry points, which put `usher` in the venv and NOT on PATH: the
# package was correct and the command did not exist, and the install still
# reported success for the one name it knew.
#
APPS="usher usher-mgr"

do_install() {
  # THE PAYLOAD FIRST, because the venv is built INSIDE it and the links all
  # point into it. Staging also carries an existing venv across the swap, so
  # the usual case (a provision sweep re-running this) costs a directory
  # rename rather than a 14M pip rebuild.
  _payload_stage || return 1
  [ -n "${USHER_SKIP_BUILD:-}" ] || build_venv
  mkdir -p "$_bin"
  for _a in $APPS; do ln -sfn "$VENV/bin/$_a" "$_bin/$_a"; done
  _man_rel | while IFS= read -r _r; do
    mkdir -p "$_man/$(dirname "$_r")"
    ln -sfn "$_pay/man/$_r" "$_man/$_r"; done
  echo "$PKG: payload $_pay; $APPS -> $_bin (venv $VENV)"
  [ -d "$(_hook_dir)" ] && do_hooks || :
  _retire_old_venv
}

do_uninstall() {
  _rmln "$(_hook_src)" "$(_hook_dst)"
  for _a in $APPS; do _rmln "$VENV/bin/$_a" "$_bin/$_a"; done
  _man_rel | while IFS= read -r _r; do
    _rmln "$_pay/man/$_r" "$_man/$_r"; done
  # THE PAYLOAD GOES, AND IT TAKES THE VENVS WITH IT, which is worth SAYING
  # rather than leaving a reader to discover: the tray's unit will keep
  # restarting a command whose venv is gone until it is re-installed.
  _had_venv=
  for _v in "$_pay"/venv*; do [ -d "$_v" ] && _had_venv=1; done
  if [ -d "$_pay" ] && [ ! -L "$_pay" ]; then
    case $_pay in
    /*/*) rm -rf -- "$_pay" ;;
    *) bad "refusing to remove a payload at '$_pay'" ;;
    esac
  fi
  echo "$PKG: removed $_pay and its links from $PREFIX"
  [ -z "$_had_venv" ] || echo "$PKG: that INCLUDED the venv(s); re-run" \
    "'setup.sh all' to restore the daemon and the tray"
}

do_check() {
  echo "== $PKG (window placement) =="
  # THE PAYLOAD IS A REAL DIRECTORY, not a symlink, which is the shape the
  # place-not-link rule is actually about: a payload that is a link into the
  # source clone looks identical from every other check here.
  if [ -d "$_pay" ] && [ ! -L "$_pay" ]; then ok "payload ($_pay)"
  else bad "payload missing or a symlink ($_pay); run: install"; fi
  if [ -x "$VENV/bin/usher" ]; then ok "venv app ($VENV)"
  else bad "venv app missing ($VENV); run: install"; fi
  # EVERY LINK MUST RESOLVE INTO THE PAYLOAD. Checked by PREFIX rather than by
  # naming the clone, because this package does not know what installed it;
  # anything resolving elsewhere is the violation whatever the elsewhere is.
  _out=
  for _l in "$_bin/usher" "$_bin/usher-mgr" "$(_hook_dst)"; do
    [ -L "$_l" ] || continue
    case $(readlink -f "$_l" 2>/dev/null) in
    "$_pay"/*) ;;
    *) _out="$_out $_l" ;;
    esac
  done
  if [ -z "$_out" ]; then ok "links resolve inside the payload"
  else bad "resolves outside $_pay:$_out"; fi
  if [ -d "$OLD_VENV" ]; then
    bad "the pre-payload venv is still there ($OLD_VENV); run: install"
  fi
  if "$VENV/bin/python" -c 'import wayfire' 2>/dev/null; then ok "dep wayfire"
  else bad "wayfire not importable in the venv"; fi
  for _a in $APPS; do
    if [ -x "$_bin/$_a" ]; then ok "$_bin/$_a"
    else bad "$_bin/$_a missing"; fi
  done
  if command -v mux >/dev/null 2>&1; then ok "mux present (terminal restore)"
  else warn "mux absent: the mux plugin's terminal restore degrades"; fi
  if ! command -v hwdp >/dev/null 2>&1; then
    warn "hwdp absent: one layout for all monitor sets (profile 'default')"
  elif [ "$(readlink "$(_hook_dst)" 2>/dev/null)" = "$(_hook_src)" ]; then
    ok "hwdp display-change hook linked"
  else
    warn "hwdp present but no display-change hook; run: setup.sh hooks"
  fi
}

_U="usage: setup.sh [install|indicator [V]|all|hooks|uninstall|check|test\
|version]"
case "${1:-install}" in
  install)   do_install ;;
  hooks)     do_hooks ;;
  indicator) shift; exec sh "$_root/indicator/setup.sh" "${@:-install}" ;;
  all)       do_install; sh "$_root/indicator/setup.sh" install ;;
  uninstall) do_uninstall ;;
  check)     do_check; exit "$RC" ;;
  test)      exec sh "$_root/test/run" ;;
  version)   echo "$PKG $VERSION" ;;
  -h|--help|help) echo "$_U" ;;
  *) echo "setup.sh: unknown command '${1:-}'" >&2; echo "$_U" >&2; exit 2 ;;
esac
