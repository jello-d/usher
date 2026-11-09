"""Does the OWNER see a per-window identifier for another account's window?

Run by enclave-vm's guest, as the session user, with the venv's python. It is
the one measurement that splits the two causes of an account reporting apps
but no WINDOW rows:

    the identifier is ABSENT   the compositor is not publishing
                               `security-context.toplevel-identifier`, so the
                               owner has nothing to relay and the account
                               cannot tie a toplevel to a process
    the identifier is PRESENT  the owner can relay it, so a missing window row
                               is the ACCOUNT's half

IN A FILE AND RUN AS A FILE, because nested `su -c` quoting has destroyed a
probe in this tree seven times. Read-only: it lists views and writes nothing.
"""
import os
import sys

sys.path.insert(0, os.environ.get("USHER_TREE", "/nonexistent"))
from usher import engine                                       # noqa: E402

sock = engine.ipc()
views = sock.list_views(filter_mapped_toplevel=True)
rows = []
for v in views:
    ctx = v.get("security-context")
    src, own = engine.window_origin(v.get("pid", -1))
    ident = ""
    if isinstance(ctx, dict):
        ident = ctx.get("toplevel-identifier") or ""
    rows.append((v.get("app-id") or "?", src or "", own, bool(ctx), ident))

# `own is not None` RATHER THAN TRUTHY: window_origin answers (None, None) for
# ours and (name-or-None, uid) for anything else, and uid 0 is falsy.
_foreign = [r for r in rows if r[1] or r[2] is not None]
_withid = [r for r in _foreign if r[4]]
# ONE LINE, because it becomes a serial marker: the counts are the finding and
# the per-row detail goes to stderr for a reader.
print("views=%d foreign=%d ctx=%d ident=%d"
      % (len(rows), len(_foreign),
         sum(1 for r in _foreign if r[3]), len(_withid)))
for app, src, own, ctx, ident in rows:
    sys.stderr.write("  %-20s src=%-8s owner=%-6s ctx=%s ident=%s\n"
                     % (app[:20], src or "-", own if own is not None else "-",
                        "yes" if ctx else "no", (ident or "-")[:20]))
