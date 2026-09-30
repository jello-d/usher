"""`python -m session_mgr <verb>`: the DEV entry, accepting every verb.

Running the engine file directly used to be the way to drive a dev tree; it
cannot be any more, because a module run as a script is `__main__`, so the
daemon importing `session_mgr.engine` would load a SECOND copy of it with its
own rule cache, plugin registry and profile cache. Going through the package
means there is exactly one of each, however it is started.

IT USES THE PERMISSIVE AUDIENCE ON PURPOSE. The installed commands are split
(`usher` for the human, `usher-mgr` for the service) and each refuses the
other's verbs, which is the point of the split. This entry is neither: it is how
a dev tree is driven against a live session without installing anything, so it
has to reach `watch` and `selftest` alike. Narrowing it to the CLI audience
would have broken the documented way of testing this program.
"""
from .cli import main_legacy

main_legacy()
