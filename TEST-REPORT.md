# XER v0.0 — Public-preview verification (2026-11-16)

Author: 0xAllow. Status: **experimental preview, NOT a certified or bug-free release**.

## Verified during this update

- `go test ./...`: PASS (including new chunk-size boundary tests and HTTPS round-trip with 16 MiB chunks).
- `go test -count=2 -race ./...`: PASS.
- `go vet ./...`: PASS.
- Cross-compilation: PASS for Windows amd64, macOS amd64/arm64, Linux amd64/arm64.
- SHA-256 manifest generated for all five new binaries.
- CLI chunk ceiling raised from 8 MiB to 64 MiB; help and README updated.
- Sender streams chunks via file section readers; receiver spools request bodies to private disk temporary files before integrity verification to bound per-request heap usage.

## Not verified in this update

- Windows and macOS runtime behavior; build success does not establish functionality there.
- External SFTP servers, real Tor networks, native schedulers, dual-stack IPv6 behavior and hostile-network conditions.
- Independent vulnerability review, penetration test, formal privacy review, production readiness.
- Authenticode / Apple Developer ID signing (publisher credentials required).

## Important limitations

- SFTP relies on OpenSSH and lacks HTTPS backend's complete chunk/resume/no-overwrite guarantees.
- Native HTTPS requires reachable TCP; no automatic NAT traversal.
- The existing optional XER_TOKEN / XER_TOKEN_FILE compatibility code remains present. Pairing is the intended interactive path; the token mode has not been removed or comprehensively audited.
- Larger chunks trade disk I/O and retries for fewer requests; 64 MiB is a configurable upper limit, not a guaranteed performance improvement.
- Do not assume every corner case is bug-free. Only the listed checks were executed in this environment.
