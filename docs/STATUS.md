# Current status

Future installer builds include an unchecked Launch AC completion checkbox.
Only successful full-UI installs can launch it after an explicit selection;
quiet installs, repair and removal never do. Full source regression: 622 passed
and 55 subtests; runtime inventory/privacy passed. The released 0.43.62 MSI
and its existing assets are unchanged. No application or hardware was launched.

The 0.43.62 maintenance candidate includes shared MAX Ethernet functions and
withholds the defective HD Pro tester build. See RELEASE_0.43.62.md for scope.
Local full host regression: 620 passed and 55 subtests passed. Source/privacy,
runtime inventory and camera-boundary checks passed. Windows package and fresh
GitHub source checks must pass before publication. Tracking issue: #20.

Original public code remains GPL-3.0-only with the recorded firmware permission.
AC+ implementation, receiver deployment and Picker remain private. Host checks
and package validation do not establish hardware qualification.

Repeater Ethernet identity/role/QoS and guarded bind/role requests remain public.
Desktop publish inputs now include the MAX Ethernet worker and coverage document;
manifest-to-publish regression checks guard against future omissions.
