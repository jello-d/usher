#!/usr/bin/env python3
"""Does anything usher writes or prints carry another account's content?

RUN BY HAND against a live box, and not by test/run: it reads the real store
and runs the real reports. READ-ONLY.

WHY THIS IS NOT THE ORPHAN WATCH. That one classifies by key SHAPE, which is
exactly what it cannot see here: the one real leak found this way was keyed
as the OWNER's, which was the whole fault, and the inverse is not decidable
from shape at all. So this is a CONTENT instrument and the two are not
substitutes.

AND A SOURCE NAME IS A BAD CONTENT FILTER, which cost two false alarms
before this was written the way it is: the owner legitimately reads about the
same company, and the reports name the source by design. So every test here
is per ROW, and the store test asks the one question that settles whose a
window is rather than what a string says.

    content-sweep.py [--verbose] [--source NAME]...

`--source` ADDS A NAME TO LOOK FOR. The names are otherwise derived from the
store's own `source` fields, which is right on a box that has an enclave and
VACUOUS on one that does not: measured, a planted leak went uncaught on
manifestor and the sweep still printed CLEAN, because with no sources in the
store there was nothing for any of its three tests to match. So it says that
rather than passing, and a name can be supplied for a box that has seen one
before or for planting a regression.
"""
import os
import pathlib
import re
import subprocess
import sys

VERBOSE = "--verbose" in sys.argv
sys.path.insert(0, str(sorted(pathlib.Path("/opt/usher/venv/lib").glob(
    "python3*/site-packages"))[0]))
import usher.engine as E                                       # noqa: E402

USHER = "/usr/local/bin/usher"
_bad = 0


def run(*a):
    p = subprocess.run([USHER] + list(a), capture_output=True, text=True)
    return p.stdout + p.stderr


def _socket():
    """A one-shot verb hunts for the socket and warns; a probe need not."""
    if os.environ.get("WAYFIRE_SOCKET"):
        return
    hits = sorted(pathlib.Path(os.environ.get(
        "XDG_RUNTIME_DIR", "/run/user/%d" % os.getuid())).glob(
            "wayfire-*.socket"))
    if len(hits) == 1:
        os.environ["WAYFIRE_SOCKET"] = str(hits[0])


_socket()
kb, prof = E.kb_for_profile()
_asked = [a for i, a in enumerate(sys.argv)
          if i and sys.argv[i - 1] == "--source"]
srcs = sorted(({(e.get("source") or "") for e in kb.values()}
               | set(_asked)) - {""})
print("profile %s, %d entries; sources: %s%s"
      % (prof, len(kb), srcs or "(none)",
         " (%d asked for)" % len(_asked) if _asked else ""))

# VACUITY FIRST, because all three tests below match on these names and an
# empty set makes every one of them pass over everything. A planted leak
# measured UNCAUGHT here while the sweep printed CLEAN, which is the false
# green this tree's conventions exist to prevent.
if not srcs:
    print("")
    print("SWEEP DID NOT RUN: no source names to look for, so none of the "
          "three tests\n  could match anything. Pass --source NAME to sweep "
          "for one anyway.")
    sys.exit(2)

# 1. THE REPORTS, ROW BY ROW. Every legitimate spelling is stripped first
#    (the redaction tag, the parenthesised app qualifier, a per-window key,
#    and the source alone as a field); whatever still names the source is
#    content rather than a label.
for verb, out in (("dry-run", run("restore", "--dry-run")),
                  ("doctor", run("doctor"))):
    sus, named = [], 0
    for line in out.splitlines():
        if not any(s in line for s in srcs):
            continue
        named += 1
        for s in srcs:
            if s not in line:
                continue
            bare = line.replace("[%s]" % s, "").replace("(%s)" % s, "")
            bare = re.sub(r"\b%s:[0-9a-f]+" % re.escape(s), "", bare)
            bare = re.sub(r"\b%s\b" % re.escape(s), "", bare)
            if s.lower() in bare.lower():
                sus.append(line.strip())
    print("%-8s %d row(s) naming a source, %d suspect" % (verb, named,
                                                          len(sus)))
    _bad += len(sus)
    for line in sus[:5]:
        print("    SUSPECT: %s" % line[:100])

# 2. THE STORE: an OWNER-keyed entry whose label names a source.
#
#    AND THE DISCRIMINATOR IS NOT THE STRING, which is what makes this
#    usable. The owner reads about that company too, so a label alone flags
#    their own browsing: measured, a per-window chrome slot labelled
#    `<a window title>` which is the owner's own window.
#    The question that settles it is the one this tree already uses to decide
#    what is purgeable: DOES A LIVE WINDOW OF OURS STILL RESOLVE TO THIS KEY?
#    The one real leak found this way was `slack NUL ''`, an app-id-only key
#    for an app only the foreign account runs, so NO live owner window
#    claimed it.
live_keys = set()
why = ""
try:
    sock = E.ipc()
    for v in sock.list_views(filter_mapped_toplevel=True):
        if E.source_of(v):
            continue                 # another account's window, not ours
        # IT RETURNS THE FALLBACK TOO, i.e. the key this window WOULD take,
        # so only a key the store actually holds counts as held.
        k = E.matched_key(kb, E.app_of(v), E.identity(v), E.source_of(v))
        if k and k in kb:
            live_keys.add(k)
except Exception as e:                                         # noqa: BLE001
    why = str(e)

flag, mine = [], []
for k, e in kb.items():
    if e.get("source"):
        continue                     # a source-keyed row, already redacted
    lab = ((e.get("label") or "") + " " + (e.get("title") or "")).strip()
    if not any(s.lower() in lab.lower() for s in srcs):
        continue
    (mine if k in live_keys else flag).append(
        (k.replace("\0", " NUL "), lab[:62]))

if why:
    # NO EVIDENCE IS NOT A CLEAN BILL, which is the one cell of this that
    # must not fail quiet: with no compositor every row is unclassifiable,
    # and reading that as "the owner's own" is the direction that hides a
    # leak. So it reports them all and says why.
    print("CANNOT CLASSIFY (%s): %d owner-keyed label(s) name a source"
          % (why, len(flag) + len(mine)))
    _bad += len(flag) + len(mine)
    for k, lab in (flag + mine)[:8]:
        print("    UNCLASSIFIED %s   %s" % (k, lab))
else:
    print("owner-keyed labels naming a source: %d the owner's own (a live "
          "window of ours holds the key), %d SUSPECT" % (len(mine),
                                                         len(flag)))
    _bad += len(flag)
    for k, lab in flag[:8]:
        print("    SUSPECT %s   %s" % (k, lab))
    if VERBOSE:
        for k, lab in mine[:8]:
            print("    (ours)  %s   %s" % (k, lab))

# 3. AND EVERY SOURCE-KEYED ROW MUST CARRY NO LABEL AT ALL, which is the
#    redaction's own invariant rather than a content question.
lab = [k.replace("\0", " NUL ") for k, e in kb.items()
       if e.get("source") and (e.get("label") or "").strip()]
print("source-keyed entries carrying a label: %d" % len(lab))
_bad += len(lab)
for k in lab[:5]:
    print("    LEAK %s" % k)

print("")
print("SWEEP CLEAN" if not _bad else "SWEEP: %d thing(s) to look at" % _bad)
sys.exit(0 if not _bad else 1)
