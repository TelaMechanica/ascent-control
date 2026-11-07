# Shared source review

2026-11-06. Six modules are imported byte-for-byte from the existing public source-review branch a13ed8e42ef729b25a6306ac30d762c6fcdca369. SHA256 and byte counts are in SHARED_SOURCE_IMPORT.json. No original internal Git history, captured traffic, vendor executable or firmware image is imported.

## Origin and approval scope

The firmware version parser, MGRS arithmetic and tile-header validator were developed in this project. Historical source introduction commits are `02e62fd`, `0cacdaa` and `6efc760` respectively; these are continuity references, not an assertion that a hash alone proves ownership. Their implementation uses numeric version comparisons, geographic projection arithmetic and image-container headers.

CRSF and MSP modules retain their comments identifying Caddx Ground Configuration as the behavioral reference, including transcribed parsing/mapping behavior. The operator explicitly reports verbal Caddx approval for publishing CRSF/MSP. This approval is recorded as operator-reported, not represented as a written public license or broader redistribution authority. Vendor attribution and reference comments remain intact.

The outstanding Caddx-guidance gate concerns Service Mode and widget releases depending on it. This import includes no private Service Mode implementation, access/provisioning assets, vendor binaries or widget installation executors. No hardware was contacted or qualified.

## Review checks and limits

Imported modules have a static standard-library dependency closure only. Existing regression tests cover protocol framing/checksum/mapping, grid conversion, version comparisons and tile validation. New CLI tests execute actual commands with synthetic local inputs, including error paths. Privacy screening checks exported trees and commit metadata; original account paths and captured device identities are not introduced.

A prior similarity screen against Caddx's current public VRX client found no identical files or exact function AST matches. That screen is not proof of original authorship. The explicit provenance comments and operator-reported approval are retained rather than replacing them with an unsupported clean-room claim. Third-party rights and the final project license remain separate.
