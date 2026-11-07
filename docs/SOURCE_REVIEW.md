# Shared source inventory

Six modules are imported byte-for-byte from source commit a13ed8e42ef729b25a6306ac30d762c6fcdca369. SHA256 hashes and byte counts are in SHARED_SOURCE_IMPORT.json. Existing technical attribution and behavioral reference comments remain in the modules.

The runtime modules use only the Python standard library. The source checker verifies their inventory, hashes and import closure. Regression tests cover CRSF/MSP framing, checksums and channel mapping, coordinate conversion, version comparisons and tile validation. CLI tests run the commands with synthetic local inputs and check error paths.

This source snapshot includes no Service Mode implementation, access/provisioning assets, vendor executables, firmware images or receiver installation executors. Tests do not contact hardware. Third-party material retains its own terms; final project use/license terms remain under review.
