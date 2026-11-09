# MAX Ethernet controls and observations

Ordinary Ethernet reads, RTSP viewing, short 5D menu keys and short pairing are shared AC features. They do not require privileged receiver access.

The selected receiver address and Windows source interface are checked for each operation. A selection nonce and a fresh receiver baseband read protect remote keys from selection changes. Pairing requires explicit confirmation and can interrupt the video link. Only short UP, DOWN, LEFT, RIGHT, CONFIRM, BACK and PAIRING requests are exposed. One UDP packet is sent per accepted request; there is no automatic retry or physical-success claim.

Read-only bench evidence on 2026-11-08: Windows route matched the selected interface; status (300 bytes), MCS (8 bytes), power (2 bytes) and active channel IDs (129 bytes) returned matching layouts. RTSP OPTIONS returned 200 OK. The RF debug read returned a nonzero result and is reported unavailable. Raw MCS, throughput and power values have no asserted physical-unit calibration. Product and firmware identity were not read over Ethernet. These observations do not establish USB identity or fleet membership.

Reference firmware analysis: the MAX HF 19.2.14 ground executable binds UDP port 9001 to all interfaces, dispatches 13-byte frames to the vendor short-key parser, and recognizes the menu/pairing key codes. The shorter status-query frames do not enter that handler. This supports implementing the short keys, but physical menu movement and pairing remain operator bench checks.

The UI keeps video playback controls available without USB correlation and uses the selected Ethernet endpoint by default. Status/key results update their own panel without replacing the video controls. Changing the selected connection discards delayed replies. RTSP response is server evidence; decoded playback is a separate check.
