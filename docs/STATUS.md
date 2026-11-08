Public 0.43.56 test build fixes Live control replacement during telemetry. See [release notes](RELEASE_0.43.56.md).

# Current status

Public 0.43.54 build 2 is released. The 0.43.55 test build fixes diagnostic page
loading and restores the host-only background image tool under Settings.
The tests cover navigation, in-flight deduplication, successful reads, HTTP errors,
timeouts, retry, reentry and late replies. Windows image conversion is checked
using the embedded interpreter, including image paths containing an apostrophe.

Receiver wallpaper upload/apply remains in AC+ through Service Mode. The public
backend exposes only image selection/preparation and local JPEG download.
Z8/Z40/Hub/HD Pro builders and their pinned support resources are unchanged.
Physical RF/camera qualification is not implied by this host update.
