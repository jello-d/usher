# example.py: a user window plugin for usher.
#
# Drop a copy into ~/.config/usher/plugins/ and edit. usher imports every *.py
# there and takes its top-level PLUGIN object (duck-typed: no import of usher
# needed). A plugin CLAIMS an app's windows (owns) and may RESOLVE their
# identity, and give a way to respawn a missing one. Every window hook takes a
# normalized view dict:
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
# EDITS APPLY AUTOMATICALLY: the running watcher notices this directory change
# within a second and rebuilds the registry, exactly as it does for
# usher/exclude and usher/include. A file that does not import is logged
# and skipped, leaving the three built-ins, so a half-saved edit cannot take
# the daemon down. Watch ~/.local/state/usher/watch.log for the
# "plugins reloaded" line.
#
# This example gives Spotify a stable identity, because its title drifts per
# track and without this it would never match its saved slot.


class SpotifyPlugin:
    name = "spotify"

    def owns(self, v):
        return v["app"] == "spotify"

    def resolve(self, v):
        # THREE ANSWERS, and the third is the whole point of the hook:
        #
        #   ("ready", key)     this is definitively window <key>
        #   ("pending", why)   I will know shortly; ask again
        #   ("never", why)     I will never know; do not remember it
        #
        # usher neither PLACES nor REMEMBERS a window that is not ready, so if
        # you cannot yet say which window this is, SAY THAT. Returning a key
        # you are unsure of is the worse failure: it gets written into the
        # store and then placed against. That really happened here, to the
        # built-in kitty plugin, and it shrank a terminal to a quarter of its
        # size on every reboot until someone noticed.
        #
        # The `why` is what `usher doctor` prints beside an unmatched window,
        # so the plugin that knows the reason is the one that supplies it.
        #
        # A 2-tuple keeps this file import-free. Returning
        # Resolution.ready(key) works if you would rather import usher.
        return "ready", "spotify"   # one window, one durable key

    # Optional hooks. Every default is a no-op, so omit what you do not need.
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
