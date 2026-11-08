# ASCENT Control 0.43.56 test build

Live HID telemetry and video status now refresh their readouts without replacing
the video button or unsaved input controls. A 200 ms page replacement could
interrupt a click before it reached the desktop host. Endpoint choices, transport,
buffering and Stop remain available; host dispatch errors are shown.

Diagnostics and local background JPEG preparation fixes from 0.43.55 are retained.
Native camera support, HD Pro tester builds and pinned input archives are unchanged.
Host regression checks do not establish receiver or physical controller qualification.
