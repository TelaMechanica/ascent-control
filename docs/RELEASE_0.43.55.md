# ASCENT Control 0.43.55 test build

- Fix Diagnostics Device History and Network Adapters reads on page entry.
- Bound diagnostic reads, show errors with Retry, and ignore superseded responses.
- Restore local no-signal background image preparation under Settings: choose a
  PNG/JPEG, review the aspect-preserving crop and save the required 1920x1080 JPEG.
- Keep receiver upload/apply in AC+ because that path uses Service Mode.

The existing native camera tools and support packs are unchanged and remain pinned
to the published 0.43.54 input archives. This update preserves host settings and
device history. No receiver configuration, wallpaper application or reboot is
performed by these host-side fixes.
