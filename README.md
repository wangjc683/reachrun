# ReachRun

ReachRun is a local, one-click reachability checkup for your domains and servers.

> Status: early design phase. There is no runnable release yet.

ReachRun runs from your current Mac and helps answer three questions:

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

ReachRun does not run continuously, send alerts, or claim that a failure was definitively caused by the Great Firewall. All checks originate from the user's current network.

## Privacy

Asset lists and results are stored locally and are not uploaded to a ReachRun-operated server. Checks still contact the configured DNS/DoH providers and the target domains or servers as required.

## Documentation

The current product requirements are documented in Chinese:

- [Product Requirements Document](docs/ReachRun%EF%BD%9C%E6%9C%AC%E5%9C%B0%E4%BA%92%E8%81%94%E7%BD%91%E8%B5%84%E4%BA%A7%E8%BF%9E%E9%80%9A%E6%80%A7%E4%BD%93%E6%A3%80%E5%B7%A5%E5%85%B7%20PRD.md)

## License

[MIT](LICENSE)
