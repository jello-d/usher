#!/bin/sh
# test/tools.t - every shipped script parses: the Python modules under
# py_compile (the engine + the indicator), the shell scripts under sh -n.
# Catches a syntax regression before it ships.
. "$(dirname "$0")/harness_lib"
harness_init tools

_bad=0
# EVERYTHING IS GLOBBED, NEVER LISTED: a listed selector silently shrinks to
# cover less the moment a module is added or renamed, which is the same quiet
# no-op this suite exists to catch.
#
# The comment above used to say exactly that, and the very next line then LISTED
# the indicator's old __main__.py by name. Renaming that package left the
# path dangling and THIS TEST STILL PASSED, because
# the `[ -e ] || continue` below reads a missing listed file as nothing to do.
# So the indicator went uncompiled and the suite reported "engine + indicator
# parse". The skip is right for a glob that matches nothing and wrong for a name
# someone typed; globbing removes the difference.
# COUNTED PER SELECTOR, not in total. A single tally only catches a TOTAL
# collapse: measured here, breaking the indicator glob took 10 files to 8 and
# a floor of 6 still passed, the same false green in a new disguise. One
# package going dark is the realistic failure, so each selector must produce at
# least one file of its own.
_py=0
_compile_group() {   # <name> <min> <file>...
  _name=$1; _min=$2; shift 2
  _n=0
  for _f in "$@"; do
    # -f, NOT -e: the providers glob is BARE (they have bare names, being
    # executed rather than imported), so it also matches the `__pycache__`
    # DIRECTORY that running py_compile here leaves behind, and -e let a
    # directory through to be compiled. The *.py groups never saw this.
    [ -f "$_f" ] || continue
    _n=$((_n + 1)); _py=$((_py + 1))
    python3 -m py_compile "$_f" 2>/dev/null \
      || { echo "  py: $_f" >&2; _bad=1; }
  done
  [ "$_n" -ge "$_min" ] || { echo "  $_name: $_n file(s), expected >= $_min" >&2
    _bad=1; }
}
_compile_group engine    5 "$HERE/usher"/*.py
_compile_group indicator 2 "$HERE/indicator"/*/*.py
_compile_group plugins   1 "$HERE/share/plugins"/*.py
# The providers are python with BARE names, because they are EXECUTED rather
# than imported (the naming rule: a shebang script takes a bare name, whatever
# directory it sits in). py_compile does not care about the suffix, so they are
# syntax-checked here like everything else; test/providers.t runs them.
_compile_group providers 1 "$HERE/share/providers"/*
_sh=0
for _f in "$HERE/setup.sh" "$HERE/indicator/setup.sh" "$HERE/test/run" \
          "$HERE/test/harness_lib" "$HERE/.githooks/pre-commit" \
          "$HERE/share/hooks"/*; do
  [ -f "$_f" ] || continue
  _sh=$((_sh + 1))
  { dash -n "$_f" 2>/dev/null || sh -n "$_f" 2>/dev/null; } \
    || { echo "  sh: $_f" >&2; _bad=1; }
done
# A hook that is not EXECUTABLE is silently ignored by the runner that invokes
# it, which is the same shape as every other fault this suite now guards. A
# PROVIDER with no exec bit fails differently and just as quietly: usher's seam
# execs it, so the mode is the difference between a login and an EACCES.
for _f in "$HERE/share/hooks"/* "$HERE/share/providers"/*; do
  [ -f "$_f" ] && [ ! -x "$_f" ] && { echo "  not executable: $_f" >&2
    _bad=1; }
done
[ "$_bad" = 0 ] || fail "a shipped script failed its syntax check"

# THE SHIPPED EXAMPLE PLUGIN MUST SATISFY THE CONTRACT IT TEACHES. It is the
# file users copy, so if it drifts from the hooks usher actually calls, every
# plugin written from it starts broken, and nothing else would notice: it
# imports nothing (deliberately, so a dropped-in plugin cannot break on an
# internal move) and is never loaded by the suite. Compiling it proves only
# that it parses. This LOADS it and calls the hooks for real.
PYTHONPATH="$HERE" python3 - "$HERE" <<'PYEOF' || fail "share/plugins/example.py
 does not satisfy the plugin contract"
import importlib.util, sys
from usher.engine import _as_resolution
root = sys.argv[1]
path = root + "/share/plugins/example.py"
spec = importlib.util.spec_from_file_location("ex", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
p = getattr(m, "PLUGIN", None)
assert p is not None, "no top-level PLUGIN object"
v = {"app": "spotify", "title": "Some Track", "pid": 1, "id": 3}
assert p.owns(v), "owns() does not claim its own app"
r = _as_resolution(p.resolve(v), "example")
assert r.is_ready, f"resolve() is not ready: {r!r}"
assert r.key, "resolve() is ready with no key"
PYEOF
# EVERY TUNABLE IS DOCUMENTED, IN BOTH PLACES, and the list is DERIVED from
# the code rather than written out here. A second hand-written inventory is
# what goes stale: nine of the twelve knobs were documented nowhere at all
# until this check was written, including USHER_SKIP_TITLE, which is the
# work/personal boundary. BOTH DIRECTIONS are checked, because a knob that is
# removed from the code leaves its documentation behind, and prose describing
# a variable nothing reads is worse than no prose.
#
# A HUMAN-ONLY knob is still a knob: USHER_SUMMONED is set by usher itself and
# is documented saying exactly that, which is the honest answer rather than an
# exemption.
_knobs=$(grep -rho 'USHER_[A-Z_]*' "$HERE"/usher/*.py | sort -u)
_nk=$(printf '%s\n' "$_knobs" | grep -c .)
# VACUITY GUARD ON THE SCRAPE: if the grep stops matching, every assertion
# below passes over the empty set and this reports success while checking
# nothing.
[ "$_nk" -ge 10 ] || fail "only $_nk tunables found: the scrape is broken"
for _k in $_knobs; do
  grep -q "$_k" "$HERE/man/man1/usher.1" \
    || fail "$_k is read by the code and absent from the man page"
  grep -q "$_k" "$HERE/README.md" \
    || fail "$_k is read by the code and absent from README.md"
done
# ...and nothing documented that the code does not read.
for _d in $(grep -rho 'USHER_[A-Z_]*' "$HERE/man/man1/usher.1" \
            "$HERE/README.md" | sort -u); do
  printf '%s\n' "$_knobs" | grep -qx "$_d" \
    || fail "$_d is documented but no code reads it"
done

# THE `cleanly` EXIT CONTRACT IS PUBLISHED, in the man page and in the verb's
# own usage. Asked for by tackup (T1), whose power menu carried a wrong belief
# about this control flow for as long as the menu existed, because the
# asymmetry (reboot and shutdown exec, logoff returns) was only ever visible
# in usher's source. The BEHAVIOUR has its own checks in selftest; this asks
# only whether a caller can find it out without reading the source.
#
# ON THE IDIOM LITERAL rather than on prose about it: that string is what a
# caller copies, so a reword that drops it has dropped the thing being
# documented. Both documents must carry it, since the usage is what somebody
# typing the verb wrong actually sees.
_idiom='cleanly <verb> || '
grep -qF "$_idiom" "$HERE/man/man1/usher.1" \
  || fail "the man page does not give the caller idiom for cleanly"
# THE USAGE IS ASKED OF THE PROGRAM, not grepped out of cli.py: the literal
# sitting in the source says nothing about whether a human ever sees it, and
# this is the path somebody typing the verb wrong actually takes. BOTH streams
# combined, since usage goes to stderr.
_usage=$(cd "$HERE" && PYTHONPATH="$HERE" python3 -m usher cleanly \
         not-a-verb 2>&1 || true)
printf '%s' "$_usage" | grep -qF "$_idiom" \
  || fail "cleanly's usage does not give the caller idiom"
printf '%s' "$_usage" | grep -qi 'never return' \
  || fail "cleanly's usage does not say which verbs never return"

# EVERY PUBLIC VERB HAS A MAN ENTRY, and nothing in that section is not a
# verb. Same argument as the tunables above and found the same way: the user
# asked for "command line equivalents of the tray toggle" when `place`
# and `settle` had existed all along. They were documented, and UNFINDABLE,
# because two .SS subsections sat in the MIDDLE of the verb list and thirteen
# verbs had drifted under a heading about relaunching apps.
#
# THE MAN PAGE IS THE EXHAUSTIVE REFERENCE and is checked as one. The README
# is a CURATED tour and deliberately is not: requiring every verb there would
# bloat the one document whose job is orientation. What IS checked there is
# the reverse direction, so a verb removed from the code cannot linger in the
# showcase.
#
# ANCHORED ON `.TP` + `.B`, which is the section's own convention. A bare
# grep for `.B` picks up emphasis inside descriptions (`.B --from`,
# `.B Exec=`) and reports 29 things that are not verbs.
_nv=$(PYTHONPATH="$HERE" python3 - "$HERE" <<'PYEOF'
import re
import sys
root = sys.argv[1]
sys.path.insert(0, root)
from usher.cli import VERBS

pub = sorted(v for v, (aud, desc) in VERBS.items() if desc)
assert len(pub) >= 15, f"only {len(pub)} public verbs: the scrape is broken"

man = open(root + "/man/man1/usher.1").read()
assert ".SH VERBS" in man, "no .SH VERBS section"
sec = man.split(".SH VERBS", 1)[1].split("\n.SH ", 1)[0]
lines = sec.splitlines()
entries = []
for i, ln in enumerate(lines):
    nxt = lines[i + 1] if i + 1 < len(lines) else ""
    if ln.strip() == ".TP" and nxt.startswith(".B "):
        head = nxt[3:].split('"')[0].strip()
        entries += [t.strip() for t in head.split("|") if t.strip()]
assert len(entries) >= 15, f"only {len(entries)} man entries: the scrape broke"

missing = [v for v in pub if v not in entries]
assert not missing, f"public verb(s) with no man entry: {missing}"
alien = [e for e in entries if e not in VERBS]
assert not alien, f"documented as a verb but is not one: {alien}"
# A .SS inside VERBS is what split the list and hid thirteen verbs.
split = [l for l in lines if l.startswith(".SS")]
assert not split, f"a subsection splits the verb list: {split}"

# The README's tour may be selective, but every verb it SHOWS must be real.
rd = open(root + "/README.md").read()
shown = sorted(set(re.findall(r"^usher(?:-mgr)? ([a-z-]+)", rd, re.M)))
assert len(shown) >= 8, f"only {len(shown)} README verbs: the scrape broke"
ghost = [s for s in shown if s not in VERBS]
assert not ghost, f"README shows a verb that does not exist: {ghost}"
print(len(pub))
PYEOF
) || fail "a verb is undocumented, or documented and gone"

# ...AND THE STATED DEFAULTS ARE HELD AGAINST THE CODE. Naming a knob is the
# cheap half; the number beside it is what a reader acts on, and changing
# START_FLOOR from 300 to 240 would otherwise leave two files quietly lying.
# Read from the IMPORTED module, so the check cannot be satisfied by a second
# copy of the number.
PYTHONPATH="$HERE" python3 - "$HERE" <<'PYEOF' || fail "a documented default
 disagrees with the code"
import re
import sys
root = sys.argv[1]
sys.path.insert(0, root)
from usher import chrome, engine, watch
man = open(root + "/man/man1/usher.1").read()
rdm = open(root + "/README.md").read()
KNOBS = (("USHER_START_FLOOR", engine.START_FLOOR),
         ("USHER_IDLE_SETTLE", engine.IDLE_SETTLE),
         ("USHER_PLACE_CAP", engine.PLACE_CAP),
         ("USHER_CHROME_STAGGER", chrome.CHROME_STAGGER),
         ("USHER_WIND_DOWN_TIMEOUT", engine.WIND_DOWN_TIMEOUT),
         ("USHER_DOCK_HOLD", watch.DOCK_HOLD))
# THE DEFINITION LINE, not "the number appears somewhere near the name".
# Two holes closed, both met for real:
#   `30 in "300"` is TRUE, so a containment test passed while the docs still
#   carried the old default of a knob shortened to a prefix of it.
#   AND THE FIRST MENTION IS NOT ALWAYS THE DEFINITION: one entry gained a
#   cross-reference to another knob and the check then read the 60 characters
#   after the CROSS-REFERENCE, reporting a correct document as wrong.
# Anchoring on the shape each document states a default IN is exact, and it
# leaves prose free to mention a knob wherever it is useful.
DEFN = {"man": lambda n: r'\.BI %s " ?(\d+)"' % re.escape(n),
        "README": lambda n: r"\*\*`%s`\*\* \(`(\d+)`\)" % re.escape(n)}
bad = []
for name, val in KNOBS:
    want = str(int(val))
    for label, doc in (("man", man), ("README", rdm)):
        m = re.search(DEFN[label](name), doc)
        if not m:
            bad.append(f"{name}: {label} has no definition line for it")
        elif m.group(1) != want:
            bad.append(f"{name}: code says {want}, {label} says {m.group(1)}")
assert not bad, "; ".join(bad)
PYEOF

# A FLOOR, so an empty set cannot pass. Every selector above is a glob, and a
# glob that matches nothing checks nothing while still reporting success, which
# is how a renamed package went uncompiled behind a green test. The numbers only
# have to be low enough never to need touching and high enough to catch a
# collapse; they are not an inventory.
[ "$_sh" -ge 5 ] || fail "only $_sh shell file(s): a selector is gone"
pass "$_py python, $_sh shell, $_nk tunables, $_nv verbs"
