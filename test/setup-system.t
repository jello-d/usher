#!/bin/sh
# setup-system.t - the MACHINE-WIDE mode, `setup.sh <verb> --system`: a
# root-owned, closed payload at /opt/usher with its links under /usr/local, and
# a mode switch that removes the sudo caller's user-mode copy while keeping the
# per-user tray. No test may run as root, so everything goes through DESTDIR,
# which stages the system tree under a scratch root exactly as a packager
# would.
#
# WHY THIS MODE EXISTS, so the assertions read as more than placement: a
# window-source enclave runs its apps as its OWN account, and that account
# cannot reach a copy of usher inside a home it is not allowed to read. One
# root-owned tree is what makes `usher` invokable from another user at all.
. "$(dirname "$0")/harness_lib"
harness_init setup-system

D=$T/dest
# THE UMASK IS PINNED SO THE CLOSING IS THE INSTALLER'S DOING. `cp -R` copies a
# file's mode through the caller's umask, so under 022 the tree comes out
# closed anyway and every closedness assertion below would pass with the
# installer's chmod deleted. 007 leaves group-write ON and world-read OFF,
# which is wrong in both directions the installer must fix.
umask 007

# HOME IS SANDBOXED FOR EVERY INVOCATION, not only the ones that are about
# HOME: setup.sh derives the pre-payload venv path from $HOME absolutely, so a
# build with a broken guard can delete the developer's live venv from inside
# what looks like a fully sandboxed test. It has happened twice on this
# package. A test whose safety depends on the code under test being right is
# not a sandbox.
H=$T/home
# THE CALLER'S OWN hwdp HOOK DIRECTORY EXISTS, so the per-user step that a
# system install must skip is REACHABLE. do_hooks is opt-in by presence, so
# without this the "nothing per-user was touched" block below passes for the
# wrong reason: the step declines on its own and a missing early return is
# invisible.
mkdir -p "$H/.config/hwdp/hooks/changed.d"

sysrun() { env HOME="$H" DESTDIR="$D" USHER_SKIP_BUILD=1 NO_COLOR=1 \
  sh "$HERE/setup.sh" "$@"; }

# --- THE FLAG IS REFUSED WHERE IT MEANS NOTHING ------------------------------
# A verb with no system mode that silently ignored `--system` would do the
# user-mode thing while the caller believed otherwise. That is not a
# hypothetical: before this mode existed, `setup.sh install --system` read only
# $1, so drydock's root mode installed into /root/.local and reported success.
_rc=0; env HOME="$H" sh "$HERE/setup.sh" version --system >/dev/null 2>&1 \
  || _rc=$?
[ "$_rc" = 2 ] || fail "version --system was not refused (rc $_rc)"
_rc=0; sysrun install --system extra >/dev/null 2>&1 || _rc=$?
[ "$_rc" = 2 ] || fail "install --system extra was not refused (rc $_rc)"
[ ! -e "$D/opt/usher" ] || fail "a refused install still wrote $D/opt/usher"

# A SETTING AFTER THE VERB IS REFUSED TOO, which is the mistake a human makes:
# PREFIX is an environment variable, so `setup.sh install PREFIX=/x` used to
# write to the REAL prefix and say it had succeeded.
_rc=0
_o=$(env HOME="$H" sh "$HERE/setup.sh" install PREFIX=/var/tmp/nope 2>&1) \
  || _rc=$?
[ "$_rc" = 2 ] || fail "install PREFIX=... was not refused (rc $_rc)"
case $_o in
  *"is a SETTING"*) ;;
  *) fail "the refusal does not name the setting mistake: $_o" ;;
esac

# --- NOT ROOT AND NO DESTDIR: REFUSED, WITH THE REMEDY -----------------------
if [ "$(id -u)" != 0 ]; then
  _rc=0
  # OPTIONS BEFORE ASSIGNMENTS: `env HOME=x -u DESTDIR` reads `-u` as a
  # command name, which reports as the refusal not firing.
  _o=$(env -u DESTDIR HOME="$H" sh "$HERE/setup.sh" install --system 2>&1) \
    || _rc=$?
  [ "$_rc" = 1 ] || fail "a non-root --system install was not refused: $_o"
  case $_o in
    *"sudo sh setup.sh install --system"*) ;;
    *) fail "the refusal does not name the remedy: $_o" ;;
  esac
  [ ! -e /opt/usher ] || fail "a refused install reached the real /opt/usher"
fi

# --- A USER-MODE INSTALL FOR THE SUDO CALLER, to be switched away ------------
# getent is stubbed so SUDO_USER resolves to a scratch home: the switch runs as
# root inside a REAL user's home, so that is the half worth proving.
U=$T/uhome
mkdir -p "$T/stub" "$U/.config/wayfire" "$U/.config/hwdp/hooks/changed.d"
printf '#!/bin/sh\necho "tester:x:1000:1000::%s:/bin/sh"\n' "$U" \
  >"$T/stub/getent"
chmod +x "$T/stub/getent"

# A STUB VENV, since no test may run pip. Its console scripts carry the
# shebang a REAL venv bakes, because that absolute path is the thing
# check --system asserts.
_stub_venv() {   # <venv dir> <the path it will be AT when it runs>
  mkdir -p "$1/bin"
  for _a in usher usher-mgr; do
    printf '#!%s/bin/python3\n' "$2" >"$1/bin/$_a"; chmod +x "$1/bin/$_a"
  done
  # `python` answers the dep probe, so a clean check can be asserted by its
  # EXIT CODE rather than only by its lines.
  printf '#!/bin/sh\nexit 0\n' >"$1/bin/python"; chmod +x "$1/bin/python"
}

_stub_venv "$U/.local/share/usher/venv" "$U/.local/share/usher/venv"
env HOME="$U" PREFIX="$U/.local" XDG_BIN_HOME="$U/.local/bin" \
  XDG_DATA_HOME="$U/.local/share" XDG_CONFIG_HOME="$U/.config" \
  USHER_SKIP_BUILD=1 NO_COLOR=1 \
  sh "$HERE/setup.sh" install >/dev/null 2>&1 || fail "user install errored"
[ -L "$U/.local/bin/usher" ] || fail "fixture: no user-mode link to switch"
[ -L "$U/.config/hwdp/hooks/changed.d/40-usher" ] \
  || fail "fixture: no hwdp hook to repoint"
# THE TRAY'S VENV, which must SURVIVE the switch: it is a systemd --user unit,
# per-user by nature, and it calls `usher` by name so it keeps working against
# the system copy.
mkdir -p "$U/.local/share/usher/venv-indicator/bin"
# A compositor autostart naming the user copy by ABSOLUTE path: the file the
# switch must NAME and must not EDIT.
printf 'session_restore = $HOME/.local/bin/usher-mgr watch\n' \
  >"$U/.config/wayfire/wayfire.ini"
cp "$U/.config/wayfire/wayfire.ini" "$T/ini.before"

# --- INSTALL: ONE CLOSED TREE, LINKS TO ITS FINAL PATH -----------------------
# The payload's venv is pre-planted so the staging carry picks it up; a real
# install builds it in place, which is why the shebang names /opt and not the
# stage.
mkdir -p "$D/opt/usher"
_stub_venv "$D/opt/usher/venv" /opt/usher/venv
_o=$(env HOME="$H" PATH="$T/stub:$PATH" SUDO_USER=tester DESTDIR="$D" \
  USHER_SKIP_BUILD=1 NO_COLOR=1 sh "$HERE/setup.sh" install --system 2>&1) \
  || fail "system install: $_o"
[ -d "$D/opt/usher" ] && [ ! -L "$D/opt/usher" ] \
  || fail "no payload tree at $D/opt/usher"
[ -d "$D/opt/usher/share/providers" ] && [ -d "$D/opt/usher/share/hooks" ] \
  || fail "the system payload is not the shipped tree"

# THE LINKS CARRY /opt/usher, NOT THE STAGE: a staged package whose links point
# into the staging directory ships links that dangle once it is installed.
for _a in usher usher-mgr; do
  [ "$(readlink "$D/usr/local/bin/$_a")" = "/opt/usher/venv/bin/$_a" ] \
    || fail "$_a link is not the final path: $(readlink \
      "$D/usr/local/bin/$_a")"
done
[ "$(readlink "$D/usr/local/share/man/man1/usher.1")" \
  = /opt/usher/man/man1/usher.1 ] || fail "man link is not the final path"

# CLOSED: every user runs it and nobody but root may change it.
_open=$(find "$D/opt/usher/" ! -type l \( -perm -0002 -o -perm -0020 \) \
  -print | head -1)
[ -z "$_open" ] || fail "the system payload is group/other-writable: $_open"
# AND READABLE, the half a 077 umask breaks and `go-w` alone cannot catch.
_unread=$(find "$D/opt/usher/" ! -type l ! -perm -0004 -print | head -1)
[ -z "$_unread" ] || fail "the system payload is not world-readable: $_unread"

# NOTHING PER-USER WAS TOUCHED AS ROOT: no hook under the caller's config, no
# reload of the caller's daemon, no pre-payload venv retirement in their home.
#
# THE FIXTURE ABOVE CREATES THE CALLER'S HOOK DIRECTORY ON PURPOSE, and
# without that this whole block was VACUOUS: do_hooks is opt-in BY PRESENCE,
# so with no `$H/.config/hwdp/hooks/changed.d` it declines on its own and the
# assertion passed whether or not the per-user steps were skipped. Found by
# planting the missing early return and watching nothing catch it.
# `-e` AND `-L`, because `-e` FOLLOWS the link and the hook this would write
# names a /opt/usher that does not exist on a staged install: a dangling link
# is invisible to `! -e` alone, which is how this assertion passed over a
# planted install that had just created one. The same pair is why
# _user_copies tests both.
_uhk=$H/.config/hwdp/hooks/changed.d/40-usher
{ [ ! -e "$_uhk" ] && [ ! -L "$_uhk" ]; } \
  || fail "a system install wrote a per-user hwdp hook"
[ ! -e "$H/.local" ] || fail "a system install wrote into the caller's ~/.local"
# AND IT DID NOT TRY TO RELOAD ROOT'S DAEMON, which is the other per-user step
# and the one that leaves no file behind to assert on: it is visible only in
# what install SAID.
case $_o in
  *"reloaded the running daemon"*|*"could not reload the daemon"*|\
  *"no daemon running"*)
    fail "a system install reached for the caller's daemon: $_o" ;;
esac

# --- THE MODE SWITCH ---------------------------------------------------------
for _a in usher usher-mgr; do
  { [ ! -e "$U/.local/bin/$_a" ] && [ ! -L "$U/.local/bin/$_a" ]; } \
    || fail "the user-mode $_a survived the switch (two copies on PATH)"
done
[ ! -e "$U/.local/share/usher/venv" ] \
  || fail "the user-mode venv survived the switch"
[ ! -e "$U/.local/share/usher/share" ] \
  || fail "the user-mode payload's share survived the switch"
{ [ ! -e "$U/.local/share/man/man1/usher.1" ] \
  && [ ! -L "$U/.local/share/man/man1/usher.1" ]; } \
  || fail "the user-mode man link survived the switch"
# THE TRAY IS PER-USER AND MUST SURVIVE.
[ -d "$U/.local/share/usher/venv-indicator/bin" ] \
  || fail "the switch removed the per-user tray's venv"

# THE hwdp HOOK IS REPOINTED, NOT LEFT DANGLING. usher created that link, and
# hwdp's runner SKIPS a dangling hook SILENTLY, so the cost of getting this
# wrong is every monitor-set re-placement with nothing saying why.
[ "$(readlink "$U/.config/hwdp/hooks/changed.d/40-usher")" \
  = /opt/usher/share/hooks/hwdp-changed ] \
  || fail "the hwdp hook was not repointed at the system payload: \
$(readlink "$U/.config/hwdp/hooks/changed.d/40-usher")"

# THE AUTOSTART IS NAMED AND NOT EDITED. It is the user's (or their
# integrator's) file, and it names the removed command by ABSOLUTE path, so the
# next login would have no placement daemon at all.
cmp -s "$U/.config/wayfire/wayfire.ini" "$T/ini.before" \
  || fail "the switch EDITED the user's wayfire.ini"
case $_o in
  *wayfire.ini*"names the removed user copy"*) ;;
  *) fail "the stale autostart was not named: $_o" ;;
esac

# --- CHECK -------------------------------------------------------------------
_rc=0
env HOME="$H" PATH="$T/stub:$PATH" SUDO_USER=tester DESTDIR="$D" \
  USHER_SKIP_BUILD=1 NO_COLOR=1 sh "$HERE/setup.sh" check --system \
  >"$T/out" 2>&1 || _rc=$?
[ "$_rc" = 0 ] || fail "check --system failed on a clean install: $(cat \
  "$T/out")"
for _w in 'commands link into the payload' 'man links name the payload' \
    'root-owned and closed' 'readable by every user' \
    'interpreter path is /opt/usher/venv' 'no user-mode copy for tester'; do
  grep -q "$_w" "$T/out" || fail "check --system lacks [$_w]: $(cat "$T/out")"
done

# AN OPEN FILE IS A FAIL, named.
chmod g+w "$D/opt/usher/share/hooks/hwdp-changed"
_rc=0; sysrun check --system >"$T/out" 2>&1 || _rc=$?
{ [ "$_rc" != 0 ] && grep -q 'not root-owned and closed' "$T/out"; } \
  || fail "a group-writable payload passed check: $(cat "$T/out")"
chmod g-w "$D/opt/usher/share/hooks/hwdp-changed"

# AN UNREADABLE FILE IS A FAIL TOO, which is the direction a root umask of 077
# produces and which the `go-w` audit alone reports as perfect.
chmod go-r "$D/opt/usher/man/man1/usher.1"
_rc=0; sysrun check --system >"$T/out" 2>&1 || _rc=$?
{ [ "$_rc" != 0 ] && grep -q 'not world-readable' "$T/out"; } \
  || fail "an unreadable payload passed check: $(cat "$T/out")"
chmod go+r "$D/opt/usher/man/man1/usher.1"

# A VENV THAT NAMES ANOTHER PATH IS A FAIL, which is THIS package's own
# assertion and the one mux does not need: a venv is not relocatable, so a
# staged venv installed as-is leaves both commands with a dead shebang while
# the links, the modes and the tree all still look perfect.
printf '#!%s/opt/usher/venv/bin/python3\n' "$D" >"$D/opt/usher/venv/bin/usher"
_rc=0; sysrun check --system >"$T/out" 2>&1 || _rc=$?
{ [ "$_rc" != 0 ] && grep -q 'venv names another path' "$T/out"; } \
  || fail "a venv baked with the stage path passed check: $(cat "$T/out")"
# THE WHOLE MESSAGE, not just its first clause. The marker helpers once read
# `$1` alone, so a message wrapped across continuation lines lost everything
# after the first argument, and THIS CHECK PASSED OVER IT because the words it
# grepped for were in that first argument. Assert the part that comes after.
grep -q "rebuild it in place" "$T/out" \
  || fail "the venv FAIL is truncated (no remedy): $(grep FAIL "$T/out")"
grep -q "$D/opt/usher/venv/bin/python3" "$T/out" \
  || fail "the venv FAIL does not name the offending path: $(grep FAIL \
    "$T/out")"
printf '#!/opt/usher/venv/bin/python3\n' >"$D/opt/usher/venv/bin/usher"

# A USER-MODE COPY BESIDE IT IS A FAIL, named, from the system side ...
mkdir -p "$U/.local/bin"; ln -s x "$U/.local/bin/usher"
_rc=0
env HOME="$H" PATH="$T/stub:$PATH" SUDO_USER=tester DESTDIR="$D" \
  USHER_SKIP_BUILD=1 NO_COLOR=1 sh "$HERE/setup.sh" check --system \
  >"$T/out" 2>&1 || _rc=$?
{ [ "$_rc" != 0 ] && grep -q 'two copies on PATH' "$T/out"; } \
  || fail "a user copy beside the system one passed: $(cat "$T/out")"
grep -q 'and this one shadows it' "$T/out" \
  || fail "the two-copies FAIL is truncated: $(grep FAIL "$T/out")"
rm -f "$U/.local/bin/usher"

# ... and from the USER side, which is the one a provisioner with no sudo
# caller relies on: the switch cannot look in a home it was never told about,
# so that user's own check is the only detector left.
env HOME="$U" PREFIX="$U/.local" XDG_BIN_HOME="$U/.local/bin" \
  XDG_DATA_HOME="$U/.local/share" XDG_CONFIG_HOME="$U/.config" \
  DESTDIR="$D" USHER_SKIP_BUILD=1 NO_COLOR=1 \
  sh "$HERE/setup.sh" check >"$T/out" 2>&1 || :
grep -q 'a system install .* exists too' "$T/out" \
  || fail "a user-mode check did not name the system copy: $(cat "$T/out")"
grep -q 'the system one shadows this' "$T/out" \
  || fail "the user-side FAIL is truncated: $(grep FAIL "$T/out")"

# --- PATHS: ONLY THE MACHINE'S ROOTS -----------------------------------------
_p=$(sysrun paths --system)
case $_p in
  *config*|*state*|*runtime*|*hook*|*venv-indicator*)
    fail "paths --system names a per-user root: $_p" ;;
esac
case $_p in
  *"/opt/usher"*) ;; *) fail "paths --system has no payload: $_p" ;;
esac
# AND IT NAMES THE FINAL PATH, not the stage, for the same reason the links do.
case $_p in
  *"$D"*) fail "paths --system leaks the DESTDIR stage: $_p" ;;
esac
# THE USER MODE STILL REPORTS EVERY ROOT, so the system filter cannot be
# hiding them from both.
_pu=$(env HOME="$U" PREFIX="$U/.local" XDG_BIN_HOME="$U/.local/bin" \
  XDG_DATA_HOME="$U/.local/share" XDG_CONFIG_HOME="$U/.config" \
  NO_COLOR=1 sh "$HERE/setup.sh" paths)
for _k in config state runtime hook venv-indicator payload venv bin man; do
  printf '%s\n' "$_pu" | cut -f1 | grep -qx "$_k" \
    || fail "paths (user) does not report '$_k': $_pu"
done

# --- UNINSTALL ---------------------------------------------------------------
sysrun uninstall --system >/dev/null 2>&1 || fail "system uninstall errored"
[ ! -e "$D/opt/usher" ] || fail "uninstall left $D/opt/usher"
for _a in usher usher-mgr; do
  [ ! -L "$D/usr/local/bin/$_a" ] || fail "uninstall left the $_a link"
done
[ ! -L "$D/usr/local/share/man/man1/usher.1" ] || fail "uninstall left man"
# IT DOES NOT REACH INTO A USER'S FILES, and the tray's venv is the one that
# proves it: a system uninstall that took it would break a running tray.
[ -d "$U/.local/share/usher/venv-indicator" ] \
  || fail "a system uninstall reached into a user's files"
[ -L "$U/.config/hwdp/hooks/changed.d/40-usher" ] \
  || fail "a system uninstall removed a user's hwdp hook"

pass "flag guard, closed tree, final-path links, the switch, the venv shebang"
