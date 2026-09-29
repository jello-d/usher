"""`python -m session_mgr <verb>`, the same entry as the console script.

Running the engine file directly used to be the way to drive a dev tree; it
cannot be any more, because a module run as a script is `__main__`, so the
daemon importing `session_mgr.engine` would load a SECOND copy of it with its
own rule cache, plugin registry and profile cache. Going through the package
means there is exactly one of each, however it is started.
"""
from .cli import main

main()
