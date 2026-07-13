# certflow

**Find the certificate on your mail server before it expires.**

Certificate monitoring looks at HTTPS. Your web certificates are probably fine —
something is watching them. Meanwhile the certificate on your SMTP relay, your
IMAP server, or your LDAP directory quietly expires, and nothing warns you.
A mail server does not show a browser warning. It just stops delivering mail,
and you spend the afternoon working out why.

certflow inventories the TLS certificates across your whole estate — **HTTPS,
SMTP+STARTTLS, SMTPS, IMAP, IMAPS, POP3, POP3S, LDAPS** — and tells you when
they expire.

```console
$ certflow smtp://smtp.example.co.jp:587 imaps://imap.example.co.jp example.co.jp
STATUS  TRUST  SERVICE  NEGOTIATED  TARGET                  DAYS_LEFT  NOT_AFTER   ISSUER
OK      yes    smtp     TLS1.3      smtp.example.co.jp:587  67         2026-09-18  CN=E5,O=Let's Encrypt,C=US
OK      yes    tls      TLS1.3      imap.example.co.jp:993  67         2026-09-18  CN=E5,O=Let's Encrypt,C=US
OK      yes    tls      TLS1.3      example.co.jp:443       48         2026-08-30  CN=E5,O=Let's Encrypt,C=US
3 targets: 3 OK, 0 WARN, 0 EXPIRED, 0 ERROR
```

**certflow only reads.** It never writes to a remote system, never generates or
handles private keys, and never modifies anything. It opens a connection, reads
the certificate the server presents, reports on it, and closes.

## Install

Download from [Releases](https://github.com/toinet-lab/certflow/releases).

```sh
# RHEL / AlmaLinux / Rocky
sudo dnf install ./certflow-0.2.0-1.x86_64.rpm

# Ubuntu / Debian
sudo dpkg -i ./certflow_0.2.0_amd64.deb

# Alpine
sudo apk add --allow-untrusted ./certflow_0.2.0_x86_64.apk
```

Or build from source (Go 1.25+):

```sh
go install github.com/toinet-lab/certflow@latest
```

Single static binary. No runtime dependencies.

## Usage

```sh
certflow example.co.jp                     # one host, port 443
certflow example.co.jp:8443                # explicit port
certflow smtp://mail.example.co.jp         # SMTP STARTTLS on 587
certflow -file hosts.txt                   # a list
certflow -file hosts.txt -warn 21          # warn at 21 days instead of 30
certflow -file hosts.txt -json             # machine-readable
certflow -file hosts.txt -fail-under 14    # exit 2 if anything expires within 14 days
```

### Targets

A target is a hostname, optionally with a port, optionally with a scheme.
**The service is inferred from the port**, so you rarely need the scheme:

| You write | certflow does |
| --- | --- |
| `example.co.jp` | HTTPS on 443 |
| `mail.example.co.jp:587` | **SMTP STARTTLS** (inferred from the port) |
| `mail.example.co.jp:143` | **IMAP STARTTLS** |
| `mail.example.co.jp:110` | **POP3 STLS** |
| `mail.example.co.jp:993` | IMAPS (implicit TLS) |
| `dir.example.co.jp:636` | LDAPS (implicit TLS) |

Schemes are there for when the port is non-standard, or you want to be explicit:
`smtp://`, `smtps://`, `imap://`, `imaps://`, `pop3://`, `pop3s://`, `ldaps://`,
`https://`.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-file` | — | File with one target per line (`#` comments ignored) |
| `-warn` | `30` | Days-left threshold for `WARN` |
| `-fail-under` | `0` | Exit 2 if any certificate expires within N days (0 = never) |
| `-json` | `false` | JSON output instead of a table |
| `-timeout` | `10s` | Per-target timeout |
| `-concurrency` | `20` | Concurrent probes |
| `-version` | — | Print version |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran successfully |
| `1` | Usage error (bad flags, unreadable file, no targets) |
| `2` | `-fail-under` threshold breached — use this in cron and CI |

## The columns

**`STATUS` and `TRUST` answer different questions.** Keeping them apart is
deliberate.

- **`STATUS`** — is it expiring? `OK` / `WARN` / `EXPIRED` / `ERROR`
- **`TRUST`** — would a normal client accept it? `yes` / `no` / `-`

A certificate can be valid for another 700 days *and* trusted by nothing:

```console
$ certflow self-signed.badssl.com expired.badssl.com
STATUS   TRUST  SERVICE  NEGOTIATED  TARGET                      DAYS_LEFT  NOT_AFTER   ISSUER
OK       no     tls      TLS1.3      self-signed.badssl.com:443  725        2028-07-06  CN=*.badssl.com,O=BadSSL…
EXPIRED  no     tls      TLS1.2      expired.badssl.com:443      -4108      2015-04-12  CN=COMODO RSA Domain Val…
2 targets: 1 OK, 0 WARN, 1 EXPIRED, 0 ERROR
```

Note that both certificates appear in the inventory at all. certflow *inspects*
certificates rather than *trusting* them, so it can report on exactly the
certificates a verifying client would refuse to talk to — which are the ones you
most need to know about.

`TRUST` is `-` when it could not be determined (the host was unreachable). That
is not the same as "untrusted", and certflow does not conflate the two: a server
that is simply down should not be reported as a TLS trust failure.

When `TRUST` is `no`, `-json` carries the reason: `self_signed`,
`hostname_mismatch`, `untrusted_chain`, `expired`.

### A limit worth knowing

**`NEGOTIATED` is the TLS version certflow and the server agreed on — not the
full range the server supports.** A server shown as `TLS1.3` may happily accept
TLS 1.0 from an older client. Go disables TLS 1.0/1.1 by default, so certflow
never negotiates them and therefore cannot tell you whether the server would.

To audit what a server actually permits, use a dedicated scanner such as
[testssl.sh](https://github.com/drwetter/testssl.sh) or `sslscan`.

## JSON output

`-json` emits an array. Beyond the table columns it carries: `fingerprint`
(SHA-256 of the DER — the same certificate on many hosts has the same
fingerprint), `sans`, `self_signed`, `wildcard`, `public_key_algorithm`,
`public_key_bits`, `signature_algorithm`, `cipher_suite`, `chain_length`,
`untrusted_reasons`.

```sh
# Everything that is not trusted
certflow -file hosts.txt -json | jq '.[] | select(.trusted == false)'

# Weak keys
certflow -file hosts.txt -json | jq '.[] | select(.public_key_bits < 2048)'

# Which hosts share a certificate?
certflow -file hosts.txt -json | jq -r '.[] | "\(.fingerprint[0:16]) \(.target)"' | sort
```

## In cron

```cron
# Every morning: mail me if anything expires within 14 days.
0 8 * * * /usr/bin/certflow -file /etc/certflow/hosts.txt -fail-under 14 || \
    mail -s "certflow: certificates expiring soon" ops@example.co.jp
```

Exit code 2 is what makes this work — no output parsing required.

## Use it as a library

The probe engine is a public package.

```go
import "github.com/toinet-lab/certflow/scan"

t, err := scan.ParseTarget("smtp://mail.example.co.jp:587")
if err != nil {
    return err
}
r := scan.Probe(ctx, t, scan.Options{Timeout: 10 * time.Second})

fmt.Println(r.Fingerprint, r.NotAfter, r.Trusted)
```

`Options.Roots` takes a custom `*x509.CertPool`, so you can evaluate trust
against a private CA instead of the system store.

## Why TLS verification is disabled

`scan.Probe` connects with `InsecureSkipVerify`. This is deliberate, and it is
the point of the tool.

If certflow verified the certificate *during the handshake*, the connection would
fail for exactly the certificates worth finding: the expired ones, the
self-signed ones, the ones with the wrong hostname. You would be unable to
inventory the problems you are looking for.

So certflow connects without verifying, then **verifies the certificate it
retrieved** — separately, against the system trust store — and reports the result
in the `TRUST` column. Nothing is sent over the connection, and no action is
taken on it.

This is correct *here* because certflow only reads. **Do not copy the pattern
into code that trusts or acts on a connection.**

## Scope

certflow stays a read-only inventory tool. It will not grow into a certificate
manager: issuance, renewal, and deployment belong to a separate tool that imports
this one as a library.

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
and [AGENTS.md](AGENTS.md) — the latter is the rule set for both human and AI
contributors, and covers licensing, security, and the design invariants above.

Security issues: see [SECURITY.md](SECURITY.md). Please report them privately.

## Commercial support

certflow is free and MIT-licensed, with no limits.

Paid support is available — not only for certflow, but for the infrastructure it
looks at: mail systems, directory services, DNS, and certificate operations on
enterprise Linux.

## License

MIT
