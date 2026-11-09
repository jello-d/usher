#!/usr/bin/env python3
"""Orphan watch: every store on this box, by SHAPE not by content.

RUN BY HAND against a live box, not by test/run. READ-ONLY, and it reads
EVERY store rather than the loaded one, because a dormant store has no
writer and the TTL never reaches it (it prunes a store on its own profile's
load), so a cleanup that only touches the profile you are plugged into is
not a cleanup. `doctor` reports the same walk now; this one names the rows.

**THE UNMATCHABLE QUESTION IS THE PRODUCT'S, NOT THIS FILE'S.** It used to
carry its own `wildcard` test, `not app and not ident`, which is the FIRST
CUT of what shipped: that version reads `\\0titan` (the 5c5fdb0 wildcard,
no app-id with the SOURCE as its identity) as a BLANK-APP key, which this
file's own header called "designed, narrow". So a hand classifier beside a
shipped detector had already drifted into calling a wildcard harmless, which
is why it now asks `engine.unmatchable_entries` and only REPORTS.

WHAT IT STILL OWNS, because neither is an orphan and the product correctly
says nothing about them:

  blank-app     an empty app-id WITH a title. Matchable and narrow, by
                design, and still worth a population count: it is what
                accumulates one per Chrome dialog.
  source-alone  a source key with no per-window identity. Correct as the
                fallback, counted so the per-window SHARE is visible, which
                is how the enclave's per-window work was measured at all.
  source-label  a source-keyed entry carrying a readable label: a LEAK, and
                decidable from the row rather than from content, which is
                what keeps it here rather than in the sweep.

AND IT IS NOT A SUBSTITUTE FOR `content-sweep.py`: this classifies by key
shape and therefore cannot see the one real leak that was keyed as the
OWNER's, which was the whole fault. Neither instrument is sufficient.
"""
import glob
import json
import os
import sys

for r, d, f in os.walk("/opt/usher/venv/lib"):
    if os.path.basename(r) == "site-packages":
        sys.path.insert(0, r)
        break
from usher import engine                                       # noqa: E402

if not hasattr(engine, "unmatchable_entries"):
    # A BOX ONE DEPLOY BEHIND MUST SAY SO rather than crash or, worse, fall
    # back to the hand classifier this file just retired.
    print("this usher predates `unmatchable_entries`: provision first")
    sys.exit(2)

live = engine.profile_id()
tot = {"unmatchable": 0, "blank-app": 0, "source-label": 0,
       "source-alone": 0}
for path in sorted(glob.glob(os.path.join(engine.STATE,
                                          "knowledge*.json"))):
    try:
        kb = json.load(open(path))
    except Exception as e:                                     # noqa: BLE001
        print("%-34s UNREADABLE %s" % (os.path.basename(path), e))
        continue
    if not isinstance(kb, dict):
        print("%-34s NOT AN OBJECT" % os.path.basename(path))
        continue
    prof = os.path.basename(path)[len("knowledge-"):-len(".json")]
    un = engine.unmatchable_entries(kb)
    blank, slab, salone = [], [], []
    for k, v in kb.items():
        app, _, ident = k.partition("\0")
        e = v or {}
        src = e.get("source")
        if not app and ident and not any(k == _k for _k, _w in un):
            blank.append(ident)
        if src:
            if e.get("label"):
                slab.append(ident)
            if ":" not in ident:
                salone.append(ident)
    tot["unmatchable"] += len(un)
    for n, lst in (("blank-app", blank), ("source-label", slab),
                   ("source-alone", salone)):
        tot[n] += len(lst)
    print("%-14s %4d entries  unmatchable %d  blank-app %d  "
          "source-label %d  source-alone %d%s"
          % (prof, len(kb), len(un), len(blank), len(slab), len(salone),
             " <- live" if prof == live else ""))
    for k, why in un:
        print("                 %-12s %s" % (why, k.replace("\0", " NUL ")))
    for i in blank:
        print("                 blank-app: %r" % i[:60])
    for i in slab:
        print("                 LEAK source-label: %r" % i[:40])

print("\ntotals across every store: %s" % tot)
# BLANK-APP IS NOT IN THE VERDICT, deliberately: it is matchable and narrow,
# so counting it as something to fix made every box with one Chrome dialog
# read as dirty. The verdict is what the product can PROVE plus the one leak
# this file can see.
bad = tot["unmatchable"] + tot["source-label"]
print("orphan count to watch: %d  (%s)"
      % (bad, "CLEAN" if bad == 0 else "see above"))
sys.exit(0 if bad == 0 else 1)
