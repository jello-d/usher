# example.py -- a user window plugin for usher.
#
# Drop a copy into ~/.config/session/plugins/ and edit. usher imports every *.py
# there and takes its top-level PLUGIN object (duck-typed -- no import of usher
# needed). A plugin CLAIMS an app's windows (owns) and may give them a stable
# identity, a transient test, a per-window id, and a way to respawn a missing
# one. Every window hook takes a normalized view dict: v["app"] (the app-id),
# v["title"], v["pid"]. Registry order is chrome, mux, kitty, then user plugins;
# the FIRST plugin whose owns() is true handles the window.
#
# This example gives Spotify a stable identity -- its title drifts per track, so
# without this it would never match its saved slot.


class SpotifyPlugin:
    name = "spotify"

    def owns(self, v):
        return v["app"] == "spotify"

    def identity(self, v):
        return "spotify"        # one window, one durable key (ignore the title)

    # Optional hooks (defaults are fine to omit):
    #   def transient(self, v):        return False   # never capture/place it
    #   def window_id(self, v):        return None    # a stable per-window id
    #   def relaunch_missing(self, saved, live): return 0   # respawn missing


PLUGIN = SpotifyPlugin()
