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
#   ./setup.sh paths         every root this package owns, KIND<tab>PATH
#   ./setup.sh test          run the in-repo suite (test/run)
#   ./setup.sh version       the packaged version
#   ./setup.sh <install|uninstall|check|paths> --system
#                            the MACHINE-WIDE mode, as root (below)
#
# POSIX sh, non-privileged. The core is Python (usher needs pywayfire), so
# `install` builds a venv (like the indicator), NOT a bare symlink. PREFIX
# (default ~/.local), the XDG_* vars, and USHER_VENV override the destinations,
# so a test drives it against a scratch dir; USHER_SKIP_BUILD adopts an existing
# venv (the test's stub) instead of running pip.
#
# SYSTEM MODE (`--system`, as root) is the same payload, root-owned and closed
# (nothing writable by group or other), at /opt/usher, with the commands at
# /usr/local/bin and the man page under /usr/local/share/man: one tree plus its
# links, per the fleet's install-placement rule, and the same `--system`
# spelling drydock's root mode already calls for a root-scope pin. Every user
# then gets usher from one copy, which is what makes it reachable from ANOTHER
# ACCOUNT: a window-source enclave runs its own apps as its own user, and that
# user has to be able to invoke usher without a copy in a home root cannot
# read. Each user's config, state and runtime stay per-user, because none of
# it was ever inside the payload.
#
# THE TRAY INDICATOR STAYS PER-USER and is not offered here: it is a systemd
# --user unit with its own venv inside the payload, so the mode switch keeps
# `venv-indicator` and removes only the core's code.
#
# THE VENV IS NOT RELOCATABLE, which is this package's one deviation from the
# reference implementation and is measured rather than assumed: `python3 -m
# venv` bakes an ABSOLUTE interpreter path into every console script, so a venv
# built under a DESTDIR stage and then installed leaves `usher` and `usher-mgr`
# with a dead shebang. The venv is therefore always built AT its final path,
# DESTDIR stages the tree and the links alone, and `check --system` asserts the
# baked path against the payload rather than trusting it.
set -eu

PKG=usher
VERSION=0.1.0
_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# THE MODE IS THE SECOND ARGUMENT, and only on the four verbs that have one
# (the dispatch guard at the bottom refuses it anywhere else). drydock's root
# mode calls `setup.sh <verb> --system` in exactly this position.
#
# UNTIL THIS EXISTED THE FLAG WAS IGNORED, which is the accident worth naming
# because it was live: `case "${1:-install}"` read only $1, so a root-scope pin
# under drydock root mode ran `setup.sh install --system` as root, installed
# into /root/.local, and reported success. A verb that ignores a flag does the
# user-mode thing while the caller believes otherwise.
_MODE=user
[ "${2:-}" = --system ] && _MODE=system
_dest=${DESTDIR:-}
if [ "$_MODE" = system ]; then
  case ${1:-} in
  install|uninstall)
    # A DESTDIR STAGE GRANTS NOTHING, so it needs no root: a non-root caller
    # can only write where it already could. That is also what lets the suite
    # drive a root-only mode.
    if [ -z "$_dest" ] && [ "$(id -u)" != 0 ]; then
      echo "setup.sh: --system installs as root" \
        "(sudo sh setup.sh $1 --system)" >&2
      exit 1
    fi ;;
  esac
  PREFIX=$_dest/usr/local
  _bin=$PREFIX/bin
  _shr=$_dest/opt
  _man=$PREFIX/share/man
else
  PREFIX=${PREFIX:-$HOME/.local}
  _bin=${XDG_BIN_HOME:-$PREFIX/bin}
  _shr=${XDG_DATA_HOME:-$PREFIX/share}
  _man=$_shr/man
fi
# Where the OTHER mode's command would be, so each mode can name a leftover.
# /usr/local/bin precedes ~/.local/bin, so the system copy shadows the user one
# and the shadowed copy then rots: the fleet's one-command-on-PATH rule.
_sysbin=$_dest/usr/local/bin/$PKG
# The command and man directories as a READER must see them: every message
# naming a path a human will type, and every line `paths` prints, strips the
# stage, for the same reason the links do. DESTDIR is a build detail; the
# contract is about where the installed system has things.
_bint=${_bin#"$_dest"}
_mant=${_man#"$_dest"}

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
# WHERE THE PAYLOAD WILL BE WHEN IT RUNS, which differs from where it is
# WRITTEN only under DESTDIR: links carry the final path, as a staged package's
# must, or a stage ships links that dangle the moment it is installed.
_payt=${_pay#"$_dest"}
# The venv lives INSIDE the payload now (was ~/.venvs/usher). A venv is not
# reachable by self-location anyway, since its console scripts bake an
# absolute interpreter path, so there is no reason for it to sit apart from
# the tree it belongs to.
VENV=${USHER_VENV:-$_pay/venv}
# The venv as the COMMAND LINKS must name it: same reason as _payt, and it is
# a separate name because USHER_VENV may put the venv outside the payload, in
# which case stripping the stage is a no-op.
_venvt=${VENV#"$_dest"}
# Retired by `install`, once the new venv is PROVEN to work: see
# _retire_old_venv for why that order is the whole safety of it.
OLD_VENV=$HOME/.venvs/usher
# NO PRE-PAYLOAD VENV EVER LIVED UNDER /opt, and in system mode $HOME is
# root's, so the name is cleared rather than left pointing at /root/.venvs for
# the retire and the check to reason about. Belt and braces beside the
# per-user early return in do_install.
[ "$_MODE" = user ] || OLD_VENV=
RC=0

# marker contract: plain [OK]/[FAIL]/[WARN] an integrator's report can restyle;
# self-coloured at a terminal, plain when piped or under NO_COLOR.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _G=$(printf '\033[32m'); _R=$(printf '\033[31m')
  _Y=$(printf '\033[33m'); _O=$(printf '\033[0m')
else _G=; _R=; _Y=; _O=; fi
# `$*`, NOT `$1`, so a message wrapped across continuation lines arrives whole.
# These read $1 alone until 2026-11-01, which SILENTLY TRUNCATED every call
# written in the usual multi-argument style, and it survived a test: the checks
# grepped for words that happened to be in the first argument, so a message
# missing its second half passed. Found by reading the output of a real run.
ok()   { printf '  %s[OK]%s   %s\n' "$_G" "$_O" "$*"; }
bad()  { printf '  %s[FAIL]%s %s\n' "$_R" "$_O" "$*"; RC=1; }
warn() { printf '  %s[WARN]%s %s\n' "$_Y" "$_O" "$*"; }

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
_hook_src() { echo "$_payt/share/hooks/hwdp-changed"; }
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

# _close_payload <dir>: root-owned and closed, and a no-op in user mode.
#
# `go+rX` MATTERS AS MUCH AS `go-w`, because root's umask decides what `cp -R`
# and `python3 -m venv` leave behind, and under a 077 umask the tree comes out
# unreadable by every user it exists to serve. Both directions, explicitly.
#
# `-h` ON THE CHOWN so a symlink inside the tree becomes root's own rather than
# its target being chased. A venv is full of them.
#
# THE RISK IS CHMODDING SOMETHING OUTSIDE THE TREE, so it was measured rather
# than assumed: GNU `chmod -R` does not follow a symlink, to a file or to a
# directory, so the venv's `bin/python3 -> /usr/bin/python3` leaves the system
# interpreter's mode untouched. Both shapes checked before trusting it.
_close_payload() {
  [ "$_MODE" = system ] || return 0
  [ "$(id -u)" != 0 ] || chown -R -h root:root "$1"
  chmod -R u+rwX,go+rX,go-w "$1"
}

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
  # CLOSED BEFORE THE SWAP in system mode, so the live tree is never open for
  # an instant. do_install closes it AGAIN after build_venv, because the venv
  # is created at its final path AFTER this swap and inherits root's umask.
  _close_payload "$_ps_new"
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

# _login_home: the sudo caller's home, or nothing. ONLY SUDO_USER is read: a
# provisioner's own name for the login user is its business, and a package may
# not read a framework's variable (the layering rule). With no sudo caller the
# switch NAMES the leftover rather than guessing whose home to edit, and that
# user's own `check` is then the detector.
_login_home() {
  _lu=${SUDO_USER:-}
  [ -n "$_lu" ] && [ "$_lu" != root ] || return 0
  getent passwd "$_lu" | cut -d: -f6
}

# _user_copies HOME: the user-mode pieces that may not coexist with a system
# install, one per line. THE CORE'S CODE ONLY.
#
# `venv-indicator` IS DELIBERATELY ABSENT, and so is the `usher-indicator`
# command: the tray is a systemd --user unit, per-user by nature, and it
# invokes `usher toggle` BY NAME, so it keeps working against the system copy.
# Removing its 35M venv would break a running tray to no purpose. The payload
# DIRECTORY is not named either, so it survives as that venv's home.
#
# The bin names come from APPS, so a fourth entry point cannot be linked by
# install and then left behind by the switch.
_user_copies() {
  for _a in $APPS; do
    if [ -e "$1/.local/bin/$_a" ] || [ -L "$1/.local/bin/$_a" ]; then
      echo "$1/.local/bin/$_a"
    fi
  done
  for _uc in "$1/.local/share/man/man1/$PKG.1" \
             "$1/.local/share/$PKG/share" "$1/.local/share/$PKG/man" \
             "$1/.local/share/$PKG/venv"; do
    if [ -e "$_uc" ] || [ -L "$_uc" ]; then echo "$_uc"; fi
  done
  return 0
}

# _mode_switch: user to system, in the same install, because two `usher` on
# PATH is banned and /usr/local/bin shadows ~/.local/bin. Each removal is
# pinned to its exact shape FIRST, per the standing rm rule: this runs as root
# inside a user's home, so nothing outside those literal shapes is ever
# touched.
_mode_switch() {
  _lh=$(_login_home)
  case $_lh in
  /?*) ;;
  *) echo "$PKG: no sudo caller, so no user-mode copy was looked for;" \
       "that user's 'setup.sh check' names one if it exists" >&2
     return 0 ;;
  esac
  for _uc in $(_user_copies "$_lh"); do
    case $_uc in
    "$_lh/.local/bin/usher"|"$_lh/.local/bin/usher-mgr"|\
    "$_lh/.local/share/man/man1/$PKG.1") rm -f -- "$_uc" ;;
    "$_lh/.local/share/$PKG"/share|"$_lh/.local/share/$PKG"/man|\
    "$_lh/.local/share/$PKG"/venv) rm -rf -- "$_uc" ;;
    *) continue ;;
    esac
    echo "$PKG: removed the user-mode $_uc (mode switch to system)"
  done
  rmdir "$_lh/.local/share/$PKG" 2>/dev/null || :
  # THE hwdp HOOK IS USHER'S OWN LINK, so it is REPOINTED rather than said: it
  # was created by do_hooks, not written by the user, and the removal above
  # just made it dangle. That matters more than it looks, because hwdp's runner
  # SILENTLY SKIPS a dangling hook, so the cost would be every monitor-set
  # re-placement with nothing anywhere saying why. Only a link into the payload
  # this install removed is touched; one a user pointed elsewhere is theirs.
  _uh=$_lh/.config/hwdp/hooks/changed.d/40-usher
  case $(readlink "$_uh" 2>/dev/null) in
  "$_lh/.local/share/$PKG"/share/hooks/hwdp-changed)
    ln -sfn "$_payt/share/hooks/hwdp-changed" "$_uh"
    echo "$PKG: repointed $_uh at the system payload" ;;
  esac
  # A FILE THAT NAMES THE OLD PATH IS SAID, NEVER EDITED: it is the user's (or
  # their integrator's), and an installer that rewrites somebody's compositor
  # config is worse than a stale line.
  #
  # AND THIS IS THE DANGEROUS ONE, worth the four lines it costs. usher's
  # daemon is started from an ABSOLUTE path in the compositor autostart, so a
  # switch leaves that line naming a command that no longer exists and THE
  # NEXT LOGIN HAS NO PLACEMENT DAEMON AT ALL, silently: a dangling command
  # fails at the CALL rather than at the lookup. The running daemon survives on
  # open file descriptors, so nothing looks wrong until the next session.
  for _c in "$_lh/.config/wayfire/wayfire.ini" "$_lh/.config/wlogout/layout" \
            "$_lh/.local/bin/session-logoff"; do
    grep -q -- "\.local/bin/$PKG" "$_c" 2>/dev/null || continue
    echo "$PKG: NOTE $_c names the removed user copy; point it at" >&2
    echo "$PKG:      $_bint/usher   (and $_bint/usher-mgr)" >&2
  done
  # AND A DAEMON STARTED FROM THE REMOVED COPY IS STILL RUNNING IT, which the
  # fleet recipe asks of any package with one and which this switch could not
  # otherwise say. It survives on open file descriptors and keeps working, so
  # nothing looks wrong, and then:
  #   - a WORKER respawn re-runs the removed command and cannot, so placement
  #     stops at the first worker death rather than at the install
  #   - `usher reload` makes the supervisor re-exec its OWN original argv,
  #     which is now a path that does not exist
  # Measured on a box whose session predated the switch: the supervisor was
  # alive on `~/.local/share/usher/venv/bin/python3` after that venv was gone.
  #
  # SAID AND NOT FIXED, because as root this has no business restarting a
  # user's session daemon, and a restart from the wrong environment is worse
  # than a stale one (a daemon with no WAYLAND_DISPLAY spawns terminals that
  # die instantly). The remedy is the user's, in their own session.
  for _d in /proc/[0-9]*; do
    [ -r "$_d/cmdline" ] || continue
    tr '\0' ' ' < "$_d/cmdline" 2>/dev/null \
      | grep -q -- "$_lh/.local/\(bin/$PKG-mgr\|share/$PKG/venv\)" || continue
    echo "$PKG: NOTE a daemon (pid ${_d#/proc/}) is still RUNNING the copy" \
      "just removed; it works until its next respawn. Restart it from the" \
      "session that owns it: 'usher stop', then log out and in, or re-run" \
      "the compositor autostart." >&2
    break
  done
}

# _system_leftover: is there a system-mode command beside a user install?
_system_leftover() { [ -e "$_sysbin" ] || [ -L "$_sysbin" ]; }

do_install() {
  # THE PAYLOAD FIRST, because the venv is built INSIDE it and the links all
  # point into it. Staging also carries an existing venv across the swap, so
  # the usual case (a provision sweep re-running this) costs a directory
  # rename rather than a 14M pip rebuild.
  # ROOT'S UMASK DECIDES WHAT THE VENV LOOKS LIKE, and under 077 it would be a
  # 35M tree no other user can read, which is the single thing this mode exists
  # to provide. Pinned here so the files are born open; _close_payload is then
  # the backstop rather than the mechanism.
  [ "$_MODE" = user ] || umask 022
  _payload_stage || return 1
  [ -n "${USHER_SKIP_BUILD:-}" ] || build_venv
  # CLOSED AGAIN, because the venv does not exist until build_venv has run: it
  # is built at its FINAL path (a venv bakes absolute paths, so it cannot be
  # staged) and is the largest part of the tree.
  _close_payload "$_pay"
  mkdir -p "$_bin"
  for _a in $APPS; do ln -sfn "$_venvt/bin/$_a" "$_bin/$_a"; done
  _man_rel | while IFS= read -r _r; do
    mkdir -p "$_man/$(dirname "$_r")"
    ln -sfn "$_payt/man/$_r" "$_man/$_r"; done
  echo "$PKG: payload $_payt; $APPS -> $_bin (venv $_venvt)"
  # EVERY STEP BELOW IS ONE USER'S, and as root each would act on /root: the
  # hwdp hook in their config, the pre-payload venv under their home, and a
  # reload of THEIR daemon. The mode switch is the one thing a root install
  # legitimately does inside a user's home, and only for the sudo caller.
  if [ "$_MODE" = system ]; then
    _mode_switch
    echo "$PKG: per-user steps are each user's: 'usher' is on PATH for" \
      "everyone, and the hwdp display-change hook is a link per user" >&2
    # The tilde is LITERAL on purpose: this line is advice every user copies,
    # not a path to resolve, and expanding it here would print root's home.
    # shellcheck disable=SC2088
    echo "$PKG:   ln -sfn $_payt/share/hooks/hwdp-changed" \
      "~/.config/hwdp/hooks/changed.d/40-usher" >&2
    return 0
  fi
  _system_leftover && warn "a system install ($_sysbin) shadows this one:" \
    "remove it with 'sudo sh setup.sh uninstall --system'"
  [ -d "$(_hook_dir)" ] && do_hooks || :
  _retire_old_venv
  _reload_daemon
}

# INSTALLED IS NOT RUNNING, and nothing used to close that gap: a pkg install
# replaces the venv while the LIVE daemon keeps the code it started with until
# the next login. Measured 2026-10-07 on both boxes at once, one of them 41
# hours stale, which quietly invalidated two verifications that day.
#
# SAFE TO DO UNCONDITIONALLY ONLY BECAUSE A QUIET START IS NOW SETTLED. reload
# places nothing, re-baselines nothing, suppresses the relaunch and leaves the
# place clock expired, so a deploy cannot move a window or change
# placement behaviour. Before that it re-armed place for five minutes.
_reload_daemon() {
  # NO PID PROBE: `usher reload` REFUSES when there is nothing running and
  # exits EXIT_CANNOT (2), so the exit code answers the question and this does
  # not need to know where the lock file lives. It used to ask through the
  # venv's python, which was one of three places cwd-shadowing had to be
  # fixed; one fewer now.
  #
  # NEVER FATAL. A failed reload leaves the OLD daemon running, which is the
  # state we were already in, so it must not fail an install that otherwise
  # succeeded.
  # `|| _rc=$?` RATHER THAN A BARE ASSIGNMENT, because under `set -e` a
  # command substitution that FAILS aborts the script: an install with a
  # broken venv died here instead of reporting it, which the setup test's dud
  # venv caught. It is also the rc-after-the-wrong-thing family this tree
  # keeps recording.
  _rc=0
  _out=$("$_bin/usher" reload 2>&1) || _rc=$?
  case $_rc in
  0) echo "$PKG: reloaded the running daemon onto this payload" ;;
  2) echo "$PKG: no daemon running; the session will start the new code" ;;
  *) echo "$PKG: WARNING could not reload the daemon, so it is still" \
       "running the OLD code. Run 'usher reload' by hand." >&2
     echo "$_out" | sed 's/^/  /' >&2 ;;
  esac
}

do_uninstall() {
  # THE HOOK IS PER-USER CONFIG, so as root it would look under /root and find
  # nothing: every user's own link is theirs to drop.
  [ "$_MODE" = user ] && _rmln "$(_hook_src)" "$(_hook_dst)" || :
  for _a in $APPS; do _rmln "$_venvt/bin/$_a" "$_bin/$_a"; done
  _man_rel | while IFS= read -r _r; do
    _rmln "$_payt/man/$_r" "$_man/$_r"; done
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
  echo "$PKG: removed $_payt and its links from $PREFIX"
  [ -z "$_had_venv" ] || echo "$PKG: that INCLUDED the venv(s); re-run" \
    "'setup.sh all' to restore the daemon and the tray"
  if [ "$_MODE" = system ]; then
    echo "$PKG: every user's own config, state, runtime and tray venv are" \
      "theirs and were not touched. Anything naming $_bint/usher (a" \
      "compositor autostart, a power menu) now dangles: re-install per user" \
      "or point it back at ~/.local/bin."
  fi
}

# _check_system: what only the machine-wide mode owes. Ownership and modes are
# read with `find`, which needs no privilege on a world-readable tree, so a
# non-root caller gets the same verdict root does.
#
# THE PACKAGE'S OWN PER-USER AUDIT IS NOT RUN: it asks about a config dir, a
# store, a runtime status file and a live daemon, all of which are /root's when
# this runs as root, and reporting on /root describes nobody who uses this
# install.
_check_system() {
  if [ -d "$_pay" ] && [ ! -L "$_pay" ]; then ok "payload ($_payt)"
  else bad "payload missing or a symlink ($_payt); run: install --system"; fi
  # NAMED, NOT RESOLVED. `readlink -f` is the right question in user mode and
  # the wrong one here: under a DESTDIR stage the links correctly name a
  # /opt/usher that does not exist yet, so resolving them answers nothing.
  _out=
  for _a in $APPS; do
    [ "$(readlink "$_bin/$_a" 2>/dev/null)" = "$_venvt/bin/$_a" ] \
      || _out="$_out $_bin/$_a"
  done
  # WORD-SPLIT RATHER THAN PIPED INTO `while`, and that is the point: `bad`
  # sets RC, and a pipeline runs its right-hand side in a SUBSHELL, so every
  # failure it reported would be printed and then thrown away with the
  # subshell's RC. The split is safe here because _man_rel yields `manN/name.N`
  # from a glob this package controls.
  _mout=
  for _r in $(_man_rel); do
    [ "$(readlink "$_man/$_r" 2>/dev/null)" = "$_payt/man/$_r" ] \
      || _mout="$_mout $_man/$_r"
  done
  if [ -z "$_out" ]; then ok "commands link into the payload"
  else bad "does not name $_venvt:$_out"; fi
  if [ -z "$_mout" ]; then ok "man links name the payload"
  else bad "man links do not name the payload:$_mout"; fi
  if [ -d "$_pay" ]; then
    _open=$(find "$_pay/" ! -type l \( -perm -0002 -o -perm -0020 \) -print \
      2>/dev/null | head -n 1)
    # A DESTDIR STAGE IS A NON-ROOT BUILD, so ownership is asked only of a real
    # install; the modes are asked of both.
    [ -n "$_open" ] || [ -n "$_dest" ] || _open=$(find "$_pay/" ! -user root \
      -print 2>/dev/null | head -n 1)
    if [ -n "$_open" ]; then
      bad "the payload is not root-owned and closed: $_open"
    else ok "the payload is root-owned and closed"; fi
    # AND READABLE, which is the half a 077 umask breaks and `go-w` alone will
    # not catch: a closed tree nobody can read serves none of the users this
    # mode exists for.
    _unread=$(find "$_pay/" ! -type l ! -perm -0004 -print 2>/dev/null \
      | head -n 1)
    if [ -n "$_unread" ]; then
      bad "the payload is not world-readable: $_unread"
    else ok "the payload is readable by every user"; fi
  fi
  # THE VENV'S BAKED PATH, which is the one assertion this package needs and
  # mux does not. A venv is NOT relocatable: every console script carries an
  # absolute `#!` to its own interpreter, so a venv built under a stage and
  # then installed leaves both commands with a dead shebang, and the links,
  # the modes and the tree all still look perfect. Measured before it was
  # written: a moved venv's python still runs and its scripts do not.
  if [ -f "$VENV/bin/usher" ]; then
    case $(head -n 1 "$VENV/bin/usher" 2>/dev/null) in
    "#!$_venvt/bin/"*) ok "the venv's interpreter path is $_venvt" ;;
    *) bad "the venv names another path, so its commands cannot run:" \
         "$(head -n 1 "$VENV/bin/usher" 2>/dev/null) (rebuild it in place)" ;;
    esac
  fi
  _lh=$(_login_home)
  case $_lh in
  /?*)
    _left=$(_user_copies "$_lh")
    if [ -n "$_left" ]; then
      bad "user-mode copy beside the system install (two copies on PATH," \
        "and this one shadows it): $(echo "$_left" | head -n 1)"
    else ok "no user-mode copy for $SUDO_USER"; fi ;;
  esac
  if [ -x "$VENV/bin/python" ] \
     && "$VENV/bin/python" -c 'import wayfire' 2>/dev/null; then
    ok "dep wayfire"
  else bad "wayfire not importable in the venv"; fi
  echo "  [INFO] per-user setup is each user's: their hwdp hook, their" \
    "config and their daemon. Run 'setup.sh check' as them."
}

do_check() {
  echo "== $PKG (window placement) =="
  if [ "$_MODE" = system ]; then
    _check_system
    return 0
  fi
  # ONE COPY ON PATH, from whichever side. A leftover of the OTHER mode is a
  # FAIL, named, and THIS is the side a provisioner with no sudo caller relies
  # on: the mode switch could not look in a home it was never told about, so
  # the user's own check is the only detector left.
  if _system_leftover; then
    bad "a system install ($_sysbin) exists too: two copies on PATH, and" \
      "the system one shadows this"
  fi
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
  # IS THE RUNNING DAEMON ON THIS PAYLOAD? A step an install can make must be
  # a step a check can see, and "installed" was not "running": compare the
  # daemon's START TIME against the payload's mtime, which is the only reading
  # that settles it. The clone's HEAD does not, and neither does the venv.
  # NOT a hard failure: no daemon at all is a legitimate state (a box with no
  # session), and install already reloads, so this is the backstop for a
  # reload that was skipped or failed.
  # THE VERDICT COMES FROM THE ENGINE, not from a comparison written again
  # here: `engine.daemon_code_age()` knows that the WORKER's start time is the
  # one that moves (a reload re-execs the supervisor in place) and that the
  # *.py files are what to date, never the directory, whose mtime the import
  # itself bumps. Two readings of that got written wrong here before it was
  # one function with checks behind it.
  _age=$(cd / && "$VENV/bin/python3" -c \
    'from usher.engine import daemon_code_age
v, d = daemon_code_age()
print(v, d)' 2>/dev/null) || _age="unknown could not ask"
  case $_age in
  none*)    ok "no daemon running (nothing to be stale)" ;;
  current*) ok "the running daemon is on this payload" ;;
  stale*)   warn "the daemon is running OLDER code: ${_age#stale }" ;;
  *)        warn "cannot tell whether the daemon is current: ${_age#unknown }";;
  esac
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

# --- paths: the ONE declaration of every root this package owns --------------
# PART OF THE PACKAGE CONTRACT (the fleet's install-placement rule): one
# declaration feeds the things that each otherwise guess, which is the argument
# for it being a verb rather than prose: the install audit, a stale-path sweep,
# uninstall saying what it kept, and discoverability.
#
# EVERY VALUE IS DERIVED, never restated, so a root cannot be renamed in the
# code and still reported from here. `KIND<tab>PATH` per line, two fields,
# because a consumer wants to act per KIND (remove a payload, never a config),
# and tab-separated because a path may contain a space.
do_paths() {
  for _a in $APPS; do printf 'bin\t%s\n' "$_bint/$_a"; done
  printf 'payload\t%s\n' "$_payt"
  printf 'venv\t%s\n'    "$_venvt"
  for _r in $(_man_rel); do printf 'man\t%s\n' "$_mant/$_r"; done
  # SYSTEM MODE OWNS ONLY THE MACHINE'S ROOTS. Config, state and runtime are
  # each user's, and printing root's would name directories nobody who uses
  # this install ever reads.
  if [ "$_MODE" = system ]; then
    return 0
  fi
  printf 'venv-indicator\t%s\n' "$_pay/venv-indicator"
  printf 'config\t%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/$PKG"
  printf 'state\t%s\n' \
    "${XDG_STATE_HOME:-$HOME/.local/state}/$PKG"
  # A GLOB, NOT THE DIRECTORY. usher owns `usher.status`, `usher.arm` and
  # `usher.profile` as FILES in the runtime root, not a directory of its own,
  # and naming the whole root would invite a sweep to delete another tool's
  # socket.
  printf 'runtime\t%s\n' "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/$PKG.*"
  printf 'hook\t%s\n' "$(_hook_dst)"
}

_U="usage: setup.sh [install|uninstall|check|paths [--system]|indicator [V]\
|all|hooks|test|version]"
# --- ARGUMENTS PAST THE VERB ARE REFUSED, NEVER IGNORED ----------------------
# THE VERB DISPATCH HAS ALWAYS REFUSED AN UNKNOWN VERB; what it could not see
# was an unknown argument AFTER a known one, and that is the hole `--system`
# would otherwise have widened: `setup.sh install --system` ran do_install and
# ignored the flag, so drydock's root mode installed into /root/.local and this
# script said it had succeeded. A setting is the mistake a human makes
# (`setup.sh install PREFIX=/var/tmp/x` writes to the REAL prefix, because
# PREFIX is an ENVIRONMENT variable and $2 was never read), so it gets its own
# wording rather than a bare "unexpected argument".
#
# Matched on `*=*` rather than a `[A-Z]*=*` range, since a bracket range is a
# COLLATION range and admits surprises in another locale; the match only
# chooses the WORDING, so the loose, locale-proof test is the right one.
_badarg() {   # <verb> <offending argument>
  case $2 in
  *=*)
    printf 'setup.sh: %s is a SETTING, not an argument.\n' "$2" >&2
    printf '  Settings come from the environment, so:  %s sh setup.sh %s\n' \
      "$2" "$1" >&2 ;;
  *)
    printf "setup.sh: unexpected argument '%s' after '%s'\n" "$2" "$1" >&2 ;;
  esac
  printf '%s\n' "$_U" >&2
  exit 2
}
# `indicator` is the one verb that legitimately takes more: it passes a verb
# and its flags straight through to the sub-package. `--system` is the one
# FLAG, and only on the four verbs that have a system mode: accepting it
# anywhere else would install somewhere the caller did not ask for.
case "${1:-install}" in
  indicator) ;;
  install|uninstall|check|paths)
    if [ "${2:-}" = --system ]; then
      [ "$#" -le 2 ] || _badarg "$1" "$3"
    else
      [ "$#" -le 1 ] || _badarg "$1" "$2"
    fi ;;
  *) [ "$#" -le 1 ] || _badarg "${1:-install}" "$2" ;;
esac

case "${1:-install}" in
  install)   do_install ;;
  hooks)     do_hooks ;;
  indicator) shift; exec sh "$_root/indicator/setup.sh" "${@:-install}" ;;
  all)       do_install; sh "$_root/indicator/setup.sh" install ;;
  uninstall) do_uninstall ;;
  check)     do_check; exit "$RC" ;;
  paths)     do_paths ;;
  test)      exec sh "$_root/test/run" ;;
  version)   echo "$PKG $VERSION" ;;
  -h|--help|help) echo "$_U" ;;
  *) echo "setup.sh: unknown command '${1:-}'" >&2; echo "$_U" >&2; exit 2 ;;
esac
