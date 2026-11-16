# XER

**Choose the transport. Trust the connection. Transfer securely.**

**Author:** 0xAllow  
**Version:** `v0.0` (public preview / experimental)  
**License:** MIT

XER is a compact, native command-line tool for encrypted file transfer on Windows, Linux and macOS. It implements a direct HTTPS/TLS 1.3 receiver with verified one-time device pairing, file chunking, concurrent uploads, upload/download resume, and strict no-overwrite completion. It also uses the system's OpenSSH `sftp` program to work with existing SSH servers.

**Security status:** Development build, **not independently audited**. Builds, unit tests and local integration tests do not demonstrate full interoperability with arbitrary installations, proxies or OS configurations. Avoid relying on this prerelease for irreplaceable data.

## What makes XER distinct

XER focuses on a specific operational workflow rather than a broad transfer ecosystem:

- **Explicit transport control:** every transfer requires `--via https` or `--via sftp`; failure never silently switches transports.
- **Verified first-use trust for native HTTPS:** users compare a short code on both devices; future sessions use persisted device trust without asking users to paste TLS fingerprints.
- **One executable for native HTTPS:** receiver and sender are built into a compact Go binary, without Python, curl or a hosted account.
- **Resumable HTTPS uploads with bounded parallel workers:** independent chunks are integrity-checked; already confirmed chunks can be skipped on retry.
- **Failure-conscious network paths:** explicit proxies do not fall back to direct networking; the app exposes IPv4/IPv6 selection.
- **Automation without a hosted controller:** local YAML jobs integrate with operating-system schedulers.

These are XER's *design choices*, not claims of exclusive invention or superiority. HTTPS and SFTP have different guarantees: see the limitations below.

## Quick start

Put the correct native binary on both computers. On Windows, rename `xer-windows-amd64.exe` to `xer.exe`. On Linux/macOS, rename the matching binary to `xer` and run `chmod +x xer`. No Python, curl, JVM or other runtime is needed for built-in HTTPS transfers. Windows Defender Firewall may require a narrowly scoped inbound TCP 8443 rule on the receiver.

**Receiver** (in the directory where files should arrive):

```powershell
.\xer.exe serve
```

The default listener is TCP port 8443 on local interfaces. You can limit the interface and change the receiving directory:

```powershell
.\xer.exe serve --dir C:\Received --listen 192.168.1.102:8443
```

**Sender**, on another computer:

```powershell
.\xer.exe send "C:\path\to\file.txt" 192.168.1.102 --via https
```

On **first connection**, XER displays a certificate-derived pairing verification code on each computer. **Compare both codes over a trusted channel and type `YES` on both computers only if they match.** This first check cannot safely be skipped. XER retains the verified receiver identity and authorized client certificate for subsequent transfers; no `token.txt` or pasted TLS fingerprint is required.

Retrieve a file:

```powershell
.\xer.exe get 192.168.1.102:test.txt --via https
```

Do not stop the receiver while a transfer is running. Files already present at the destination are not overwritten by HTTPS `send` or `get`.

## Command reference

```text
xer serve [--dir PATH] [--listen ADDRESS:PORT]
xer send FILE HOST[:PORT] --via https [--chunk 4M] [--parallel 4]
xer get HOST[:PORT]:FILE [OUTPUT] --via https
xer send FILE USER@HOST --via sftp [--port 2222]
xer get USER@HOST:FILE [OUTPUT] --via sftp [--port 2222]
xer dns EXAMPLE.COM
xer auto add JOB.yaml | run NAME | list | remove NAME | install | uninstall | tick
xer trust list | remove CLIENT_FINGERPRINT
xer --help
xer --version
```

Manual transfer protocol selection is required. XER **never changes `--via`** to another transport when the selected one fails.

### HTTPS chunking, resume and parallelism

HTTPS uploads use bounded-size chunks, authenticated TLS 1.3 records, per-chunk integrity checks and a final local integrity check before publication. The default chunk size is 1 MiB and the default number of upload workers is one. Larger chunks are streamed and spooled to disk on the receiver; available disk space and disk I/O matter. `--chunk` permits up to 64 MiB, `--parallel` 1–8 workers:

```sh
xer send backup.zip 192.168.1.102 --via https --chunk 4M --parallel 4
```

The sender keeps an upload resume record under the user's XER state directory. Already acknowledged chunks can be skipped on retry. An interrupted HTTPS download uses an unpublished `.xer-part` file and HTTP Range requests. The receiver does not publish partially uploaded files. Internal SHA-256 checks are automatic; users do not need to calculate or paste hashes. **Parallel download is not implemented**; download resume is sequential. Parallel uploads do not necessarily improve speed on every link or disk.

### SFTP / SSH

```sh
xer send backup.zip admin@server.example --via sftp
xer get admin@server.example:backup.zip --via sftp
xer send backup.zip admin@server.example --via sftp --port 2222
```

SFTP uses the existing `sftp` executable and SSH configuration. `BatchMode=yes` and `StrictHostKeyChecking=yes` are required. Configure and verify the SSH host key through normal OpenSSH administration before running noninteractive transfers. XER does not automatically accept new SSH host keys. The SFTP backend relies on OpenSSH and **does not provide the same chunk-level resume, concurrency or atomic no-overwrite guarantees as the built-in HTTPS backend**. In particular, an SFTP upload can replace a remote file depending on server behavior: verify destination and permissions first. SFTP `--proxy` uses the same XER executable as an internal OpenSSH `ProxyCommand` helper, connecting through an explicitly selected HTTP CONNECT, HTTPS or SOCKS5(h) proxy. The proxy must permit SSH traffic on the destination port; no fallback to direct connection is allowed. For existing SSH jump hosts, native OpenSSH `ProxyJump` remains available through `ssh_config`. This adapter has not yet been validated against real Windows OpenSSH installations or Tor.

### IPv4, IPv6 and proxies

The direct HTTPS network stack supports dual-stack TCP (Go's Happy Eyeballs fallback), plus `--ipv4` and `--ipv6` for explicit address-family selection. Address selection follows the OS resolver; IPv6 is used preferentially where the resolver and network permit, and IPv4 can be used as fallback. The receiver can bind to an IPv6 literal via `--listen '[::1]:8443'`. For an IPv6 destination with a custom port use brackets: `[2001:db8::20]:8443`.

```sh
xer send file.zip server.example --via https --ipv6
xer send file.zip server.example --via https --proxy socks5h://127.0.0.1:9050
xer send file.zip server.example --via https --proxy http://proxy.example:3128
xer send file.zip server.example --via https --proxy https://proxy.example:443
```

Proxy types: HTTP CONNECT, HTTPS proxy, SOCKS5 and SOCKS5h. When selecting SOCKS5h, XER sends destination hostname resolution through the proxy (including with a locally running Tor SOCKS port); it does not install or start Tor. Credentials embedded in proxy URLs are forbidden. Explicitly configured proxies **fail closed**: XER will not retry directly if the proxy is unavailable. HTTPS and SSH certificate/host verification remain mandatory. SOCKS5 proxy authentication other than the no-authentication method is not implemented. IPv4/IPv6 flags on an explicit proxy apply to reaching the proxy itself, not to the remote target address chosen by that proxy.

### Encrypted DNS diagnostics

```sh
xer dns example.com
```

Performs A/AAAA lookups through DNS-over-HTTPS to the configured HTTPS DNS service implemented in XER. This is **a diagnostic command**, not DNS-based file transfer. It is separate from the system's ordinary resolver, which may still be used for direct HTTPS and SFTP connections.

## Optional config.toml

Rename `config.example.toml` to `config.toml` **beside the executable**, not in the current working directory. XER runs without it. Recognized settings:

```toml
[network]
port = 8443
# proxy = "socks5h://127.0.0.1:9050"

[transfer]
chunk = "1M"
parallel = 1
```

No private keys, passwords or API tokens belong here. For portability, device identities and trust databases are stored in the per-user OS configuration directory (`os.UserConfigDir()`), not in the portable TOML file. Keep the binary directory and state directory writable only by trusted accounts.

## YAML automation (and only automation)

```yaml
name: daily-transfer
from: C:\Backups\backup.zip
to: 192.168.1.102
via: https
every: daily
at: "02:00"
```

```sh
xer auto add automation.example.yaml
xer auto list
xer auto run daily-transfer
xer auto install
```

`auto add` stores a job in a user-private directory; `auto run` executes once. `auto install` registers a once-per-minute runner with Windows Task Scheduler, Linux `systemd --user`, or macOS `launchd` in an interactive user session. `auto uninstall` removes the OS registration; `auto remove NAME` removes a stored job. `auto tick` is the scheduler entry point. Jobs support `every: manual`, `hourly`, or `daily` with `at: HH:MM` in local system time. **Pair interactively before scheduling HTTPS transfers**, because scheduled jobs cannot safely approve first-time trust. SSH keys must already work noninteractively. System services and permission/credential setup vary by operating system; test scheduling on the target machine before relying on it. Scheduler installation or running may fail if the operating system does not provide a user session or background scheduler.

The job syntax is intentionally a small **flat YAML subset**, not general-purpose YAML. No complex objects, tags, anchors or inline comments are supported. Manual transfers never require YAML.

## Security and limitations

- No HTTP/FTP/plaintext fallback, no anonymous receiver by default, and no automatic acceptance of SSH host keys.
- A new HTTPS device requires manual comparison of the same verification code displayed by both peers. Verify it over a trusted channel before approving.
- Certificate identity and pairing authorization are stored locally; the receiver's `.xer-data` directory holds protected metadata and incomplete upload parts.
- Always keep trusted-device records and private keys protected with OS permissions. On shared machines, separate OS user accounts.
- The receiver uses TLS 1.3 and verified paired client identities. Uploads are published only after completeness and internal digest checks.
- If sender files change during upload, the final digest must match the originally computed value or the commit will fail.
- Native sender/receiver pairing requires reachable TCP connectivity; XER does not include a public relay or automatic NAT traversal.
- Proxy and dual-stack interoperability have only been tested in the included local tests, not exhaustively against all networks and products.
- **SFTP server upload overwrite prevention is not equivalent to the HTTPS backend.**
- Code signing for Windows requires a real Authenticode certificate; macOS notarization requires an Apple Developer ID. The included signing workflows are not official signatures by themselves.
- SHA-256 manifests provide integrity checks; Ed25519 signatures authenticate the manifest only when the trusted public key was obtained independently. Never include a release signing private key in source or release archives.

## Build and validate

Go 1.23+ is required to build from source. The core has **no external Go dependencies**.

```sh
go test -count=2 -race ./...
go vet ./...
bash scripts/build-release.sh
```

The build script produces Windows amd64, Linux amd64/arm64, macOS amd64/arm64 unsigned binaries and `SHA256SUMS`. It does not include icons. See `scripts/sign-windows.ps1`, `scripts/sign-macos.sh`, and the `cmd/xer-artifact` tool for authenticated artifact releases.

To sign an artifact checksum manifest with an independently protected Ed25519 signing key:

```sh
go run ./cmd/xer-artifact keygen --private /secure/xer-signing-key.pem --public trusted-public.pem
go run ./cmd/xer-artifact manifest --dir dist --manifest dist/SHA256SUMS
go run ./cmd/xer-artifact sign --private /secure/xer-signing-key.pem --manifest dist/SHA256SUMS --signature dist/SHA256SUMS.sig
go run ./cmd/xer-artifact verify --public trusted-public.pem --dir dist --manifest dist/SHA256SUMS --signature dist/SHA256SUMS.sig
```

The above commands are an example only. A public signing key must be authenticated out of band, and the signing key must not be included in the distributed project. Native signing is a separate step done on authorized signing machines.

## Project scope

In scope: HTTPS/TLS 1.3 direct transfer, SFTP, secure pairing, chunked uploads, bounded parallel upload workers, resume, DoH diagnostics, proxy/Tor support for HTTPS, IPv4/IPv6 support, TOML settings, YAML automation and OS scheduler integration. Out of scope: cloud, messaging APIs, SMB, WebDAV, QUIC, WebRTC, DNS tunneling, file synchronization, bundled Tor or AI inference. An AI agent can automate XER only within explicitly granted local permissions; an MCP server is not included.

See `TEST-REPORT.md` for the precise status of validation and limitations. The project may not be called universally "bug-free" or certified secure based on these tests.
