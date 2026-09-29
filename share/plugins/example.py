# example.py: a user window plugin for usher.
#
# Drop a copy into ~/.config/session/plugins/ and edit. usher imports every *.py
# there and takes its top-level PLUGIN object (duck-typed: no import of usher
# needed). A plugin CLAIMS an app's windows (owns) and may give them a stable
# identity, a transient test, and a way to respawn a missing one. Every window
# hook takes a normalized view dict:
#
#   v["app"]     the app-id
#   v["title"]   the current window title, which is usually too volatile to key
#   v["pid"]     the process, or -1 for a window replayed from the store
#   v["id"]      the compositor's view id, or None when there is no live window
#
# v["id"] is the only handle stable for exactly one window's lifetime, so it is
# what to cache a hard-won identity against. The chrome plugin does: it joins a
# window to Chrome's session file by the page title ONCE, then remembers, since
# a title that has to be right at the instant you look is a bootstrap and not
# an identity.
#
# Registry order is chrome, mux, kitty, then user plugins; the FIRST plugin
# whose owns() is true handles the window.
#
# This example gives Spotify a stable identity, because its title drifts per
# track and without this it would never match its saved slot.


class SpotifyPlugin:
    name = "spotify"

    def owns(self, v):
        return v["app"] == "spotify"

    def identity(self, v):
        return "spotify"        # one window, one durable key (ignore the title)

    # Optional hooks. Every default is a no-op, so omit what you do not need.
    #
    #   def transient(self, v):
    #       return False   # never capture or place this window
    #
    #   def relaunch_command(self, v):
    #       # How to bring THIS window back, read from the live window while
    #       # it can still be asked, and recorded in the snapshot. This is
    #       # where to put "what was it doing", as against identity's "which
    #       # window is it".
    #       return None
    #
    #   def relaunch_missing(self, saved, live):
    #       return 0     # respawn this app's saved-but-absent windows; count
    #
    #   def wind_down(self, live):
    #       # Ask this app to exit CLEANLY at session end, and return the pids
    #       # you signalled; the engine waits for them all under one bounded
    #       # deadline. Return [] if the app needs nothing, the common case.
    #       return []


PLUGIN = SpotifyPlugin()
