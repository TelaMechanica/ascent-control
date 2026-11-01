# Current status

Migration is incomplete; this is not a runnable public application or a public installer.

## Shared source import — batch 1

Six existing standalone runtime modules have been imported byte for byte: firmware version parsing/comparison, MGRS coordinate conversion, tile image validation, CRSF RC encoding, MSP ring parsing and MSP DisplayPort OSD decoding. The original module names are retained to avoid introducing a second compatibility layer. Source and existing protocol-test hashes are recorded in SHARED_SOURCE_IMPORT.json.

Verification: `python -m pytest tests -q` passes 80 tests and 27 subtests. The 58 unchanged protocol tests also pass against the original source tree. Privacy checks pass. The public runtime inventory is explicitly allowlisted and hash-pinned; its static imports are limited to four standard-library modules. These modules neither acquire receiver access nor install or activate widgets. Image header validation does not establish full image decodability or physical renderer output.

Shared dependency/upgrade plans require both the verified application extension and its loaded provider for the private variant, even when a manifest omits that dependency. Upgrade plans retain the widget configuration-family identity.

## Still open

Atomic installation/rollback, publisher trust, legacy backend/UI integration, provider extraction, remaining public/private source allocation and build inventory are not completed. The running internal application remains unchanged. Public project-wide licensing remains pending. No hardware qualification is implied.

Next bounded work: import reviewed base control/transport components with synthetic fixtures; define the loaded-provider operation boundary; move private workflows into their owning repository; preserve existing receiver identity guards and runtime switching ownership. Both agents use AGENTS.md and the checked-in task ledger.
