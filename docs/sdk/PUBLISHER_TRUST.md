# Publisher trust direction for the provisional SDK

Status: proposed implementation contract for independent review. No signing or
production execution is implemented. The operator retains the final trust-policy
decision; reviewer recommendation is not operator acceptance of an executor.

The open framework separates four independent decisions:

1. Authenticity: verify package bytes against the stated publisher's key, and
   show the fingerprint. Integrity hashes alone do not establish authenticity.
2. Publisher trust: users or their operator-managed policy explicitly accept
   fingerprints. The SDK must not require a vendor-controlled publisher allowlist.
   First-seen keys require explicit acceptance; first sight alone grants nothing.
3. Capability grants: each widget receives explicit grants for individual
   capabilities. A signature, trusted publisher or AC+ label grants none by itself.
   Updates that add capabilities require renewed consent. Key changes and package
   identity changes cannot silently inherit earlier trust or grants.
4. Confinement: execution is separately isolated and subject to resource and
   operation limits. Known-publisher packages require the same confinement.

An unknown publisher's signature establishes only a claim about its key. A future
policy could permit execution with zero grants only after confinement is proven;
this preview admits no executable packages at all. No network, location, receiver
identity, raw commands, Service Mode session or credentials are ambient widget
permissions. Runtime calls must enforce revocation and selected-target identity.

Development trust is visibly separate from production trust and cannot migrate
silently. Storage protection, revocation, key rotation, recovery, signature format,
canonical package bytes and audit-record minimization need further review before
signing code. Do not invent an ad hoc cryptographic format here.

This framework introduces no payment enforcement, licensing server, account
requirement or telemetry. Distribution/release approval remains the operator's
separate decision. Existing source licenses remain in effect.
