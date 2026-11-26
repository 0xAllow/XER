# Changelog

## 0.0.1-dev - 2026-11-25

Integrated security and reliability corrections from the XER audit. This source delivery is partially verified: Go compilation/runtime tests were blocked by a missing SDK.

- Session-bound dual-approval pairing v2, expiry, cancellation, bounded pending state and explicit pairing window.
- Client validity/revocation on new requests, atomic trust/profile updates and process locks.
- Private bound download resume, protected filesystem access, hardlink/symlink refusal and atomic no-overwrite.
- Separate outer proxy TLS validation, bounded CONNECT parsing and cancellation/deadlines.
- Receiver quotas, per-upload locks, capped digest cache, overflow-safe chunk count and bounded completion hashing.
- Correct client initialization errors and resume keys; stable automation paths, validated YAML scalars and independent job error handling.
- Windows ACL/handle code and scheduler quoting, reserved filenames, safer release-key creation/manifest checks.
- Root repository layout, native CI matrix and regression tests.

First-use pairing requires the new version on both devices. No silent downgrade to the old interactive handshake exists. Persisted certificate identities are retained when valid, but old-version interoperability is not certified. Legacy OUTPUT.xer-part files are not adopted; inspect/back them up before removal. Old relative-path automation jobs must be re-added. Existing unsafe state permissions fail closed or are tightened on Windows; rotate any identity that may previously have been exposed.
