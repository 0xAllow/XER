# Security policy

XER 0.0.1-dev is integrated experimental source, independently audited or certified release. Its Go code could not be compiled or executed in the delivery environment. Run the provided CI and native validation before publishing binaries or relying on this version. Keep the receiver off untrusted networks and use disposable data for validation.

First-use pairing must compare the full session code on both devices over a trusted independent channel. New pairing is disabled unless `serve --pair-window` is used. Receiver `trust approve SESSION CODE` and sender YES are both required. Do not approve unexpected requests. Expiry and explicit revocation apply to subsequent authorized requests.

XER requires private state and trusted destination directories. Shared writable directories, staging links and hardlinked exported files are refused. The same-account attacker and OS administrator are outside the local confidentiality boundary. Existing exposed identities should be rotated; fixing permissions does not revoke copies of a stolen key. Windows ACL/reparse handling needs native verification.

Legacy XER_TOKEN / XER_TOKEN_FILE is a deliberate compatibility alternative to paired-client authorization when the operator sets those variables. Tokens should be high-entropy secrets and must not enter logs or source. Token-file errors now fail closed. Token possession grants the receiver's full transfer permissions, as does a paired identity; there are no per-client file roles.

SFTP depends on OpenSSH and independently verified host keys. SFTP uploads may overwrite remote files. XER never silently switches transport or bypasses a selected proxy. Use supported Go security releases and run govulncheck for the exact build configuration.

