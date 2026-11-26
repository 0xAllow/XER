# Contributing

Use a currently supported Go security release, at least Go 1.27.4 for this development branch. Source and go.mod are at repository root. The standard library is the only application dependency; go.sum is empty intentionally.

Run `gofmt -w .`, `go build ./...`, `go test -count=1 -timeout=5m ./...`, `go test -race -count=1 -timeout=5m ./...`, `go vet ./...` and `go test -cover -timeout=5m ./...`. Run govulncheck and the cross-build matrix in CI. Do not convert unavailable checks into PASS. The delivery baseline did not execute these Go checks; record your actual results in a subsequent change.

Tests isolate config/cache through test hooks, never a real user account. Do not add t.Parallel to tests that override process globals, current directory, stdin or environment. Keep network endpoints on loopback and files disposable. The local OpenSSH pipe test is a component test, not a proof of SSH authentication/host-key interoperability. Do not install scheduler jobs in ordinary tests.

Add regression coverage for error paths, integrity, resume and concurrency when changing these areas. Preserve explicit transport selection, receiver pinning, TLS 1.3, dual approval, bounded requests and atomic no-overwrite. Never weaken validation just to make tests green. Report security issues privately using SECURITY.md.
