# ReachRun

ReachRun is a local, one-click reachability checkup for your domains and servers.

> Status: Phase 0 capability development is in progress. A source-only diagnostic CLI is runnable; there is no browser UI or release binary yet.

ReachRun is designed to run locally on your current macOS, Windows, or Linux computer, open its interface in your default browser, and help answer three questions:

- Which saved domains and servers are reachable right now?
- What changed since the last comparable check?
- Is a failure most likely happening at DNS, IPv4/IPv6, TCP, TLS/SNI, HTTP, or SSH?

## V1 scope

- Manually start one check from a local browser UI.
- Save a fixed list of domain and server assets locally.
- Check public website paths over HTTP/HTTPS.
- Check server endpoints over SSH, HTTP, and HTTPS.
- Run deeper diagnostics only for failures, changes, or inconclusive results.
- Keep conclusions conservative and explain the evidence behind them.
- Ship as one executable per supported operating system and CPU architecture, without a desktop-app shell.

ReachRun does not run continuously, send alerts, or claim that a failure was definitively caused by the Great Firewall. All checks originate from the user's current network.

## Development preview

The current Phase 0 CLI can verify a loopback BrowserOpener placeholder and terminal URL fallback, observe local IPv4/IPv6 route-selection conditions without sending payload, inspect three deliberately separate kinds of name-resolution evidence, follow one bounded DNS HTTPS AliasMode path, observe one bounded public Web path, recheck local and reference Web candidates under fixed first-hop conditions, make one direct Web observation, perform one bounded SSH identification exchange, and make a hostname-free TLS observation against an explicit public IP:

```bash
git clone https://github.com/wangjc683/reachrun.git
cd reachrun
go run ./cmd/reachrun browser-placeholder
go run ./cmd/reachrun family-conditions
go run ./cmd/reachrun resolve localhost
go run ./cmd/reachrun resolver-inventory
go run ./cmd/reachrun dns-observe udp current A example.com
go run ./cmd/reachrun dns-observe doh cloudflare HTTPS example.com
go run ./cmd/reachrun dns-https-path doh cloudflare example.com
go run ./cmd/reachrun web-path example.com
go run ./cmd/reachrun web-recheck one.one.one.one 1.1.1.1 1.0.0.1
go run ./cmd/reachrun web-observe https one.one.one.one 1.1.1.1
# Replace YOUR_SERVER_IP with one of your public server addresses.
go run ./cmd/reachrun ssh-observe YOUR_SERVER_IP 22
go run ./cmd/reachrun tls-observe YOUR_SERVER_IP
go run ./cmd/reachrun tls-retry-batch YOUR_SERVER_IP
```

`browser-placeholder` binds only a random `127.0.0.1` port and verifies the default-browser adapter with a one-time placeholder page; if opening fails, it prints the still-accessible URL and waits for the page request. `family-conditions` asks the kernel to select an IPv4 and IPv6 route/source address using fixed UDP endpoints but never writes payload; explicit local unavailability is neutral evidence, not a target failure. The name-resolution commands distinguish operating-system resolution, configured resolver candidates, and a controlled query to one explicit resolver. `dns-https-path` keeps that resolver and transport fixed while following up to three HTTPS AliasMode records, then observes A and AAAA without treating address hints as authoritative. `web-path` starts with system resolution, connects only to bounded public candidates, tries HTTPS first, safely re-resolves up to three redirect targets, and uses HTTP only when every initial HTTPS candidate failed before any valid response. Its report keeps every resolution and direct Web attempt as distinct evidence. `web-recheck` alternates bounded same-family local/reference candidates while keeping HTTPS hostname identity, policy, and fresh-connection behavior fixed; the labels are caller-supplied evidence context, not a DNS diagnosis. `web-observe` bypasses name resolution for the connection while preserving the hostname for HTTP Host, TLS SNI, and certificate verification. `ssh-observe` distinguishes TCP failure, a reachable but unconfirmed endpoint, and a valid SSH identification without attempting key exchange or login. `tls-observe` fixes port 443, omits SNI and identity verification, sends no HTTP, and keeps a completed or unconfirmed handshake separate from TCP failure. `tls-retry-batch` runs a bounded set of those observations with fixed concurrency, transient-only retries, jitter, a total deadline, and cancellation while preserving every attempt. Each command prints one versioned JSON evidence document. They require Go 1.26 or newer and are developer diagnostics, not the final one-click browser experience. See [Development Setup](docs/development/SETUP.md) for the full command set, tests, and platform limitations.

## Privacy

Asset lists and results are stored locally and are not uploaded to a ReachRun-operated server. Checks still contact the configured DNS/DoH providers and the target domains or servers as required.

## Documentation

The current product requirements are documented in Chinese:

- [Product Requirements Document](docs/product/PRD.md)
- [Current Architecture](docs/architecture/OVERVIEW.md)
- [Architecture Decision Records](docs/decisions/README.md)

## Agent contributors

Start with [AGENTS.md](AGENTS.md). It is the canonical index for loading only the context required by a task.

## License

[MIT](LICENSE)
