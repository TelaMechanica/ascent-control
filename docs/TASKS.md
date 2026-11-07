# Work queue

- Integrate package/dependency contracts with the application loader and operation routes.
- Implement authenticated package installation, atomic activation/rollback and stable configuration ownership.
- Preserve the private capability boundary and fail-closed operation checks.
- Complete the public desktop source migration without vendor binaries or device captures.
- Finalize project use/license terms while retaining third-party attribution and terms.
- Verify reproducible packages and clean install/upgrade behavior before distributing an installer.
- Keep Service Mode and dependent widget deployment outside this public source snapshot.

Current shared runtime: six modules, byte-pinned source inventory, offline CLI and regression tests. Run the full pytest suite, runtime inventory/hash/import check and privacy check for source changes. Hardware validation requires separate authorization; host fixtures do not establish physical behavior.
