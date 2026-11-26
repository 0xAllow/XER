# XER

Native Go CLI for explicit HTTPS/TLS 1.3 and OpenSSH SFTP file transfers.

**Author:** 0xAllow. **Version:** `0.0.1-dev`. **License:** MIT.

**Security / release status:** integrated development source, **PARTIALLY VERIFIED**, not independently audited or certified. The delivery environment did not have a Go SDK; the Go build, tests, race detector and cross-builds in this version have not been run there. The included CI is configured to run them after upload, but no CI result is implied. Do not rely on this prerelease for irreplaceable data or expose its receiver to untrusted networks. See [RELEASE-REPORT.md](RELEASE-REPORT.md) and [TEST-REPORT.md](TEST-REPORT.md).

## Build

The module, workflow, license and source are at this repository root. Use Go **1.27.4 or a newer supported security release**. The application has no external Go dependencies; `go.sum` is intentionally empty. The higher minimum enables current traversal-resistant `os.Root` APIs.

```sh
go build -o xer .
go build ./...
go test -count=1 -timeout=5m ./...
go test -race -count=1 -timeout=5m ./...
go vet ./...
go test -cover -timeout=5m ./...
```

On Windows use `go build -o xer.exe .`. Use `gofmt -w .` with the real SDK before maintaining the code. Formatting could not be executed in the delivery environment either. To record all checks, including unavailable tools:

```sh
python3 scripts/verify.py --output verification-results.json
```

Python is needed only for this optional verification script, not native HTTPS transfers. To scan known vulnerabilities separately, install the pinned scanner used by CI:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.10.0
govulncheck ./...
```

## First-use HTTPS pairing

Use this version on both devices for first-use pairing. Protocol v2 uses a fresh client nonce and receiver session ID, expires after at most two minutes and requires **both** approvals. The receiver is closed to new pairing by default.

1. Start a receiver in a trusted directory, opening a short pairing window:

   ```sh
   xer serve --dir /path/to/received --listen 127.0.0.1:8443 --pair-window 5m
   ```

   Replace the loopback listen address with the appropriate LAN interface when transferring between machines. `serve` without `--listen` binds all interfaces on port 8443. Use `--pair-window` only while expecting a device.

2. Start the sender:

   ```sh
   xer send /path/to/file.bin receiver.example:8443 --via https
   ```

3. Both terminals display an 80-bit hexadecimal verification code for this exact certificate pair and session. Compare the **entire code over an independently trusted channel**. The receiver prints a command:

   ```sh
   xer trust approve SESSION_ID CODE
   ```

   Run that exact command from the receiver directory, using a second terminal. The sender operator types `YES` only after comparing the two displays. Either order of the two approvals is supported. Receiver approval alone does not authorize transfer; sender confirmation alone waits for receiver approval. Wrong codes, cancellation and expired sessions do not commit trust.

A pairing attempt cannot block a receiver stdin prompt or create an unbounded approval queue. There is one pending session and at most ten new challenges per explicitly opened receiver window. An unexpected request can occupy that slot until cancellation/expiry; do not approve it. After pairing, restart normally without `--pair-window` if the current window has not elapsed.

```sh
xer serve --dir /path/to/received
xer send file.bin receiver.example:8443 --via https --chunk 4M --parallel 4
xer get receiver.example:8443:file.bin ./download.bin --via https
```

Windows examples:

```powershell
.\xer.exe serve --dir C:\Received --pair-window 5m
.\xer.exe send C:\Backups\backup.zip 192.168.1.102 --via https
.\xer.exe get 192.168.1.102:backup.zip C:\Downloads\backup.zip --via https
```

## Trust and identity

Receiver certificate pinning is mandatory after pairing. A trusted fingerprint is checked together with certificate validity on every new authorized request, including reused TLS connections. A certificate's public bytes alone are not enough to impersonate a client: TLS proves possession of its private key.

```sh
# Run from the receiver directory:
xer trust list
xer trust remove CLIENT_FINGERPRINT

# Sender: remove a saved receiver profile before a deliberate re-pair:
xer trust forget RECEIVER_ALIAS
```

Revocation applies to subsequent requests; it does not recall bytes already sent or cancel an already authorized streaming response. Trust updates and profile updates use kernel locks and atomic files. A second receiver process using the same state directory is refused.

Certificates currently last one year. There is no silent certificate renewal that preserves a stale pin. For a deliberate rotation: stop the affected process, back up its private state securely, replace the affected identity key/certificate pair, then explicitly forget/re-pair the receiver and revoke old client fingerprints. If state was previously exposed through broad permissions, rotate identities. Do not delete keys casually or disable pinning to bypass expiry.

## Filesystem safety, integrity and resume

HTTPS upload chunks are independently SHA-256 checked, streamed to private temporary storage, then written under a lock for that upload. Completion checks all chunk positions, size and the full digest. Final publication uses a hardlink and refuses an existing destination. Unrelated uploads have separate locks.

Uploads remember their receiver, pin, source path/content and **chunk size**. A retry with changed chunk size starts another compatible session. Expired abandoned sessions are reclaimed when a new upload is initialized. Startup under the receiver singleton lock removes orphan spools and recovers commits interrupted between hardlink publication and metadata cleanup. A retry after a lost completion response can recognize an already committed file by exact size and digest, only when a prior cached upload record exists.

Downloads resume in a private `.xer-download-<id>/` directory beside the destination. Metadata binds it to the receiver pin, remote name, size and digest. A kernel lock prevents concurrent writers to the same staging session. Symlinks, hardlinks and non-regular staging files are rejected before any write. Receiver reads use `os.Root` and verified regular file handles, rejecting hardlinks and symlink escapes.

Legacy `OUTPUT.xer-part` files are **never adopted or modified**. Remove them manually only after inspecting/backing up anything you need. A remote identity/content mismatch leaves the private staging state for inspection; remove the indicated staging directory to restart after closing active transfers. Completed staging directories retain only their reusable lock file.

The destination directory and its ancestry must be controlled by your account or trusted OS administrators. Writable shared directories are conservatively refused; POSIX owner/mode checks and Windows owner/DACL checks enforce this policy. The application does not protect against malware running as your own account or administrators. Windows ACL and reparse-point handling is implemented but has not received native runtime validation in this delivery.

Hardlink-capable filesystems are required for final publication (typically NTFS, ext4 or APFS). FAT/exFAT and some network filesystems may fail closed. No unsafe rename/overwrite fallback exists. Keep files immutable while serving/downloading them. Hash caching is bounded and checked against file identity, size and modification time; the client still verifies the full downloaded hash. Parallel download is not implemented. File and Unix directory sync are used where supported; Windows power-loss durability of directory entries is not guaranteed.

### Receiver limits

| Control | Default |
| --- | --- |
| File size | 64 GiB |
| Published + reserved pending bytes | 128 GiB |
| Pending uploads | 128 |
| Published/root entries | 10,000 |
| Chunks per upload | 65,536 |
| Authenticated requests in flight | 8 |
| TCP connections admitted | 64 |
| Request-body deadline / per-write deadline | 2 minutes |
| Abandoned upload metadata TTL | 24 hours |
| Chunk size | 1 byte to 64 MiB; subject to chunk-count limit |
| Sender parallel workers | 1 to 8 |

Receiver flags: `--max-file-size BYTES`, `--max-storage BYTES`, `--max-pending N`, `--max-concurrent N`. Published files and pending reservations count toward storage quota; transient chunk spools add at most the configured request concurrency times 64 MiB. This is an application quota, not an OS disk reservation: other programs may consume free space. I/O failures are reported; use filesystem quotas if physical disk isolation is required. Full-file completion hashing has a separate bounded 30-minute connection; disconnected callers cancel hashing and leave the session resumable.

## Explicit networking and SFTP

Every manual transfer requires `--via https` or `--via sftp`. A failure never switches backends. Explicit proxies do not retry directly. `HTTP_PROXY`/`HTTPS_PROXY` environment variables are not implicitly used. Proxy URL credentials, query/fragment/path and missing ports are refused.

```sh
xer send file.bin host.example --via https --ipv4
xer send file.bin '[::1]:8443' --via https --ipv6
xer send file.bin host.example --via https --proxy http://proxy.example:3128
xer send file.bin host.example --via https --proxy https://proxy.example:443
xer send file.bin host.example --via https --proxy socks5h://127.0.0.1:9050
xer send file.bin host.example --via https --no-proxy
```

For HTTPS proxies, outer TLS verifies the proxy hostname/PKI using system trust and does not offer the XER client identity. Inner TLS separately verifies the receiver pin and uses the paired XER client certificate. Outer proxy TLS permits TLS 1.2+ for both backends; native XER endpoint TLS is 1.3+. CONNECT status/header reads are bounded and proxy handshakes support cancellation/deadlines. SOCKS5 and SOCKS5h both forward destination hostnames to the proxy in this implementation; authentication other than no-auth is unsupported. IP-family flags select the proxy's address family when a proxy is used. Tor must already be running; XER does not install/start it.

```sh
xer send file.bin admin@server.example --via sftp --port 2222
xer get admin@server.example:file.bin ./file.bin --via sftp
```

SFTP requires system OpenSSH `sftp`, preconfigured credentials and an independently verified known host key. BatchMode and StrictHostKeyChecking are mandatory. Shell command construction is not used for the transfer itself; ProxyCommand uses a quoted XER executable as a helper. Native SSH config/ProxyJump remains available.

SFTP upload can overwrite the server's destination. It does not provide native HTTPS chunk resume or parallel workers. SFTP downloads use private staging and no-overwrite publication but do not resume; OpenSSH is asked to flush transfers with `-f`. SSH host-key/authentication behavior against real servers, Windows OpenSSH and Tor still need interoperability validation for this integrated version.

`xer dns example.com` is a separate DNS-over-HTTPS diagnostic to `dns.google`. It is not a file-transfer protocol and does not replace the OS resolver for direct transfers.

## Settings and automation

Place optional `config.toml` beside the executable. See `config.example.toml` for the supported `[network]` and `[transfer]` scalars. Do not put secrets there.

| State | Location |
| --- | --- |
| Sender identity and receiver profiles | `os.UserConfigDir()/xer` |
| Upload resume records | `os.UserCacheDir()/xer/uploads` |
| Receiver identity, device trust, pairing and upload metadata | receiver directory `/.xer-data` |
| Download staging | `.xer-download-<id>` beside the chosen destination |

Automation uses a restricted flat YAML subset, not a general YAML interpreter. Only the two implemented transports are accepted at import. Single-quoted values support literal special characters and doubled apostrophes; double-quoted values support the restricted JSON/Go escape syntax. General YAML tags, anchors, nesting and inline comments are unsupported. Relative source paths are converted to absolute paths relative to the job file; old stored relative jobs must be re-added. Pair HTTPS interactively first; scheduled jobs never approve first-use trust.

```yaml
name: backup
from: /absolute/path/backup.zip
to: receiver.example:8443
via: https
every: daily
at: "02:00"
```

```sh
xer auto add automation.example.yaml
xer auto list
xer auto run backup
xer auto install
xer auto tick
xer auto uninstall
xer auto remove backup
```

On Windows, start with `automation.windows.example.yaml` instead of the Unix example.

`auto install` uses systemd --user on Linux, launchd on macOS or Task Scheduler on Windows, running a once-per-minute tick. Scheduler installation has not been executed in this delivery. Use an interactive user session with keys/profiles available. Test on a disposable account before relying on it. Hourly jobs are due at minute 00; daily jobs at `HH:MM` in local system time. A tick outside the due minute does not catch up a missed job. DST slots include UTC offset; fallback can run the two distinct repeated local-time slots.

Automation uses SFTP port 22 and does not implement per-job port/network/chunk overrides. HTTPS never overwrites an existing destination: a recurring job with the same filename will fail after the first upload unless the operator rotates the receiver file or uses distinct input/job names.

Kernel job locks prevent overlap. Only successful slots are recorded; a failed due job can retry in that minute and does not prevent other due jobs from being checked. Transfers run sequentially within a tick; a long-running job can delay others. Scheduler environment and network availability still matter.

## Release packaging

```sh
bash scripts/build-release.sh dist
```

The output directory must be empty. The script builds/tests with a real SDK and emits unsigned Windows amd64, Linux amd64/arm64 and macOS amd64/arm64 binaries plus SHA256SUMS. No binaries are included in this source delivery because none were compiled here. Run native signing on authorized machines, regenerate the manifest **after** signing, then sign the manifest with an independently protected Ed25519 key. Key generation refuses existing paths; manifests reject common private-key material in the artifact directory.

```sh
go run ./cmd/xer-artifact keygen --private /secure/signing.pem --public /secure/public.pem
go run ./cmd/xer-artifact manifest --dir dist --manifest dist/SHA256SUMS
go run ./cmd/xer-artifact sign --private /secure/signing.pem --manifest dist/SHA256SUMS --signature dist/SHA256SUMS.sig
go run ./cmd/xer-artifact verify --public /secure/public.pem --dir dist --manifest dist/SHA256SUMS --signature dist/SHA256SUMS.sig
```

