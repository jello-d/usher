#!/usr/bin/env python3
"""Orphan watch: every store on this box, by SHAPE not by content.

Four classes, each one a thing this repo has actually had:
  wildcard      empty app-id AND empty identity: matches every handle-less
                window (d9dbc9f)
  blank-app     empty app-id with a title: DESIGNED, narrow, but it is the
                population that accumulates per Chrome dialog
  source-label  a source-keyed entry carrying a readable label: a leak
  source-alone  a source key with no per-window identity: correct as the
                fallback, worth counting so the per-window share is visible

RUN BY HAND against a live box, not by test/run. READ-ONLY, and it reads
EVERY store rather than the loaded one, because a dormant store has no
writer and the TTL never reaches it, so a cleanup that only touches the
profile you are plugged into is not a cleanup.

AND IT IS NOT A SUBSTITUTE FOR `content-sweep.py`, which is the complement
rather than a duplicate: this classifies by key SHAPE and therefore cannot
see the one leak that was keyed as the OWNER's, which was the whole fault.
Neither instrument is sufficient; run both.
"""
import glob
import json
import os
import sys
import time

for r, d, f in os.walk("/opt/usher/venv/lib"):
    if os.path.basename(r) == "site-packages":
        sys.path.insert(0, r)
        break
from usher import engine

live = engine.profile_id()
tot = {"wildcard": 0, "blank-app": 0, "source-label": 0, "source-alone": 0}
for path in sorted(glob.glob(os.path.join(engine.STATE, "knowledge*.json"))):
    try:
        kb = json.load(open(path))
    except Exception as e:
        print("%-34s UNREADABLE %s" % (os.path.basename(path), e))
        continue
    prof = os.path.basename(path)[len("knowledge-"):-len(".json")]
    wild, blank, slab, salone = [], [], [], []
    for k, v in kb.items():
        app, _, ident = k.partition("\0")
        e = v or {}
        src = e.get("source")
        if not app and not ident:
            wild.append(k)
        elif not app:
            blank.append(ident)
        if src:
            if e.get("label"):
                slab.append(ident)
            if ":" not in ident:
                salone.append(ident)
    for n, lst in (("wildcard", wild), ("blank-app", blank),
                   ("source-label", slab), ("source-alone", salone)):
        tot[n] += len(lst)
    mark = " <- live" if prof == live else ""
    print("%-14s %4d entries  wildcard %d  blank-app %d  "
          "source-label %d  source-alone %d%s"
          % (prof, len(kb), len(wild), len(blank), len(slab), len(salone),
             mark))
    for i in blank:
        print("                 blank-app: %r" % i[:60])
    for i in slab:
        print("                 LEAK source-label: %r" % i[:40])

print("\ntotals across every store: %s" % tot)
bad = tot["wildcard"] + tot["blank-app"] + tot["source-label"]
print("orphan count to watch: %d  (%s)"
      % (bad, "CLEAN" if bad == 0 else "see above"))
