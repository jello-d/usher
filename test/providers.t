#!/bin/sh
# test/providers.t - the session-start PROVIDERS usher ships in
# share/providers/. A provider is the executable usher's seam
# (~/.config/usher/session-start) points at, and its job is to start a console
# session on this machine's display manager.
#
# USHER SHIPS THEM AND DOES NOT INSTALL THEM, which is the install-placement
# rule rather than an omission: a provider is re-exec'd under sudo, so root
# EXECUTES it, so it has to land root-owned in a root-visible tree. This
# package installs as the user into ~/.local and cannot make such a file.
# tackup's modules/compositor copies it to /usr/local/libexec 0755 and creates
# the seam symlink. So the split is: usher owns the CODE and these checks,
# tackup owns the PLACEMENT and the wiring, and neither keeps a copy of the
# other's half.
#
# EACH PROVIDER CARRIES ITS OWN `--selftest` and that is what runs here. It
# needs no root, no display manager and no live greeter, which is the property
# that lets the same command be run against the INSTALLED copy on a real box
# (/usr/local/libexec/usher-greetd --selftest) when a box misbehaves.
. "$(dirname "$0")/harness_lib"
harness_init providers

command -v python3 >/dev/null 2>&1 || { pass "skipped (no python3)"; exit 0; }

# A FLOOR, because every selector in this suite is a glob and a glob matching
# nothing reports success while checking nothing. One provider ships today.
_n=0
for _p in "$HERE/share/providers"/*; do
  [ -f "$_p" ] || continue
  _n=$((_n + 1))
  [ -x "$_p" ] || fail "$_p is not executable, so the install ships a dud"
  "$_p" --selftest >"$T/$(basename "$_p").out" 2>&1 || {
    sed 's/^/    /' "$T/$(basename "$_p").out" >&2
    fail "$(basename "$_p") --selftest failed"; }
  grep -q 'selftest OK' "$T/$(basename "$_p").out" \
    || fail "$(basename "$_p") --selftest did not report OK"
done
[ "$_n" -ge 1 ] || fail "share/providers/ is empty: no provider would ship"

# THE SEAM TAKES THE ACTION AS argv, and that contract broke once with both
# sides written and neither run against the other: usher execs `<provider>
# login` and the provider's parser took no positional, so the only invocation
# that matters died on "unrecognized arguments: login" while every hand-typed
# --selftest worked.
for _p in "$HERE/share/providers"/*; do
  [ -f "$_p" ] || continue
  _out=$("$_p" --help 2>&1) || fail "$(basename "$_p") --help failed"
  case "$_out" in
    *login*) ;;
    *) fail "$(basename "$_p") does not document the login action" ;;
  esac
done

pass "$_n provider(s): selftest, the exec bit, and the action contract"
