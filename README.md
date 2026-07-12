# certflow

A small, read-only tool for taking inventory of your TLS certificates and
seeing when they expire. As certificate lifetimes shrink, the first question
every operator needs to answer is: *which certificates do I have, and when do
they expire?* certflow answers that — safely.

> **Phase 0 scope.** This release only *reads*. It opens a TLS connection,
> inspects the certificate the server presents, and reports on it. It never
> writes to any system and never handles private keys. Automated issuance and
> distribution come in later phases (see the roadmap).

[日本語のはじめ方ガイドはこちら → START-HERE-ja.md](START-HERE-ja.md)

## Quick start

Requires [Go](https://go.dev/dl/) 1.22 or newer.

```sh
# Build
go build -o certflow .

# Check a few endpoints
./certflow example.com example.org:8443

# Check a list, warn under 21 days, machine-readable output
./certflow -file hosts.txt -warn 21 -json

# For monitoring/cron: exit code 2 if any cert expires within 14 days
./certflow -file hosts.txt -fail-under 14
```

Copy `hosts.example.txt` to `hosts.txt` and edit it for your environment.

### Options

| Flag            | Default | Description                                                |
| --------------- | ------- | ---------------------------------------------------------- |
| `-file`         | (none)  | File with one `host` or `host:port` per line (`#` = skip)  |
| `-warn`         | `30`    | Days-left threshold to mark a certificate `WARN`           |
| `-timeout`      | `10s`   | TLS dial timeout per target                                |
| `-concurrency`  | `20`    | Number of concurrent probes                                |
| `-json`         | `false` | Output JSON instead of a table                             |
| `-fail-under`   | `0`     | Exit code 2 if any cert expires within N days (0 = off)    |

## Roadmap

| Phase | Scope                                                    | Risk |
| ----- | -------------------------------------------------------- | ---- |
| **0** | Read-only expiry inventory (**this release**)           | Low  |
| 1     | ACME issuance for a single host (staging CA first)       | Med  |
| 2     | Central issuance → distribute to hosts → reload services | High |
| 3     | Policy, multiple CAs, dashboard (paid tier candidates)   | High |

Later phases build only on permissively licensed libraries (e.g. `lego`, MIT;
`certmagic`, Apache-2.0). See [AGENTS.md](AGENTS.md) for the rules that govern
how code is added to this project.

## Security

certflow does not require or store private keys. Please report vulnerabilities
privately — see [SECURITY.md](SECURITY.md). Do not paste private keys or
secrets into issues.

## Support

The project is free and MIT-licensed. Paid setup, integration, and operational
support are available separately — see the repository's discussions or contact
information for details.

## License

[MIT](LICENSE) © 2026 YOUR NAME
