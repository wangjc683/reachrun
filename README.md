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

The current Phase 0 CLI can inspect three deliberately separate kinds of name-resolution evidence:

```bash
git clone https://github.com/wangjc683/reachrun.git
cd reachrun
go run ./cmd/reachrun resolve localhost
go run ./cmd/reachrun resolver-inventory
go run ./cmd/reachrun dns-observe udp current A example.com
```

These commands distinguish operating-system resolution, configured resolver candidates, and a controlled query to one explicit resolver. Each command prints one versioned JSON evidence envelope. They require Go 1.26 or newer and are developer diagnostics, not the final one-click browser experience. See [Development Setup](docs/development/SETUP.md) for the full command set, tests, and platform limitations.

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
