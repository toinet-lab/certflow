# certflow

A small, read-only tool for taking inventory of your TLS certificates and
seeing when they expire. As certificate lifetimes shrink, the first question
every operator needs to answer is: *which certificates do I have, and when do
they expire?* certflow answers that — safely.

> **Phase 0 scope.** This release only *reads*. It opens a TLS connection,
> inspects the certificate the server presents, and reports on it. It never
> writes to any system and never handles private keys. Automated issuance and
> distribution come in later phases (see the roadmap).

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

### Output columns

The table shows two axes that are deliberately kept separate:

| Column       | Meaning                                                            |
| ------------ | ----------------------------------------------------------------- |
| `STATUS`     | Expiry status: `OK` / `WARN` / `EXPIRED` (and `ERROR` on failure) |
| `TRUST`      | `yes`/`no` — whether a verifying client would trust the cert      |
| `NEGOTIATED` | The TLS version certflow negotiated (e.g. `TLS1.3`)               |

`STATUS` (expiry) and `TRUST` (trust) are **independent**: a certificate can be
valid-for-weeks yet untrusted (e.g. self-signed), or trusted yet expiring soon.

When `TRUST` is `no`, the JSON output records machine-readable reasons in
`untrusted_reasons`. Each is checked independently, so several can appear at
once (e.g. `["self_signed","expired"]`):

| Reason              | Meaning                                                              |
| ------------------- | ------------------------------------------------------------------- |
| `self_signed`       | Issuer == Subject **and** the cert verifies its own signature       |
| `expired`           | Past its `not_after`                                                 |
| `hostname_mismatch` | The target host is not covered by the certificate                   |
| `untrusted_chain`   | Could not build a chain to a trusted root in the local trust store  |

`untrusted_chain` does not distinguish "a missing intermediate" from "an unknown
root". Use the JSON `chain_length` field to tell them apart: `chain_length: 1`
means the server sent only the leaf, which strongly suggests a missing
intermediate. certflow does **not** fetch missing intermediates (no AIA
fetching) — that would mean connecting out to arbitrary URLs, which is outside
the scope of a read-only inventory.

The connection itself is still made **without** verification (see
[Security](#security)); trust is assessed afterwards against the fetched
certificate. That is what lets certflow inventory the expired, self-signed, and
mismatched certificates you most need to find.

### JSON fields

JSON output (`-json`) includes everything in the table plus `subject`, `sans`,
`serial`, `not_before`, and:

| Field               | Notes                                                          |
| ------------------- | -------------------------------------------------------------- |
| `trusted`           | `true`/`false`; omitted when a connection error made it undeterminable |
| `untrusted_reasons` | Present only when `trusted` is `false`                         |
| `tls_version`       | Same value as the `NEGOTIATED` column                          |
| `cipher_suite`      | Negotiated cipher suite (JSON only — too long for the table)   |
| `chain_length`      | Number of certificates the server presented                    |

### Limitations

- **`NEGOTIATED` is a single agreement, not a capability report.** It is the TLS
  version this one handshake settled on, not the server's full supported range.
  Go disables TLS 1.0/1.1 by default, so those never appear here even if the
  server would accept them.
- **No AIA fetching.** Missing intermediates are reported, not fetched.

> **Note (breaking change from earlier `v0.x`):** the `SUBJECT` column has been
> removed from the table to make room for `TRUST` and `NEGOTIATED`. The
> `subject` field is still present in `-json` output.

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

[MIT](LICENSE) © 2026 Toinet
