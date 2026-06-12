# certwatch

> A fast TLS certificate & configuration grader for your terminal and CI.

[![CI](https://github.com/GlyphSH/certwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/GlyphSH/certwatch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Point `certwatch` at any number of hosts and get a one-glance report: **when each
certificate expires, whether the chain is trusted, the negotiated TLS version and
cipher, and an A–F grade** — with exit codes designed for cron jobs and CI pipelines.

No agents, no config file, no account. One command.

```console
$ certwatch github.com cloudflare.com expired.badssl.com self-signed.badssl.com wrong.host.badssl.com

HOST                    EXPIRES     DAYS   TLS  GRADE  ISSUES
----------------------  ----------  -----  ---  -----  -----------------
github.com              2026-08-02     51  1.3  A
cloudflare.com          2026-08-08     57  1.3  A
expired.badssl.com      2015-04-12  -4079  1.2  F      EXPIRED 4079d ago
self-signed.badssl.com  2028-06-08    727  1.2  F      self-signed
wrong.host.badssl.com   2026-08-24     73  1.2  C      hostname mismatch

2 ok, 1 warning, 2 critical   (exit code 2)
```

## Why

Expired or weakly-configured certificates are one of the most common — and most
*avoidable* — outages and audit findings. `certwatch` gives MSPs, sysadmins, AWS
developers, and security teams a dead-simple way to keep an eye on a fleet of
endpoints from a script, a laptop, or a CI job.

## Install

```sh
# recommended (isolated CLI install):
pipx install git+https://github.com/GlyphSH/certwatch.git

# or with pip:
pip install git+https://github.com/GlyphSH/certwatch.git
```

Requires Python 3.9+ and [`cryptography`](https://pypi.org/project/cryptography/).

> A PyPI release (`pip install certwatch`) is planned — not yet published.

## Usage

```sh
certwatch example.com                      # a single host (port 443)
certwatch example.com mail.example.com:465 # explicit port
certwatch -f hosts.txt                     # one host per line; # for comments
cat hosts.txt | certwatch                  # or pipe them in
```

### Options

| Flag | Description |
|------|-------------|
| `--warn-days N` | Flag certs expiring within `N` days (default: 30) |
| `--timeout SECS` | Per-host connection timeout (default: 8) |
| `-j, --concurrency N` | Hosts to check in parallel (default: 10) |
| `--json` / `--csv` | Machine-readable output for pipelines |
| `--no-color` | Disable ANSI colors |

### Grading

| Signal | Effect |
|--------|--------|
| Expired certificate | **F** (critical) |
| Self-signed / untrusted chain | **F** (critical) |
| TLS < 1.2 negotiated | critical |
| Weak cipher (RC4/3DES/NULL/…) or SHA-1 signature | warning |
| Hostname mismatch | warning |
| Expires within `--warn-days` | warning (critical inside 7 days) |
| Trusted, TLS 1.2/1.3, healthy expiry | **A** |

### Exit codes (CI-friendly)

| Code | Meaning |
|------|---------|
| `0` | All hosts OK |
| `1` | At least one warning |
| `2` | At least one critical (or unreachable) host |

```yaml
# e.g. a daily GitHub Actions / cron check
- run: certwatch -f production-hosts.txt --warn-days 21
```

## JSON output

```sh
$ certwatch --json example.com
[
  {
    "host": "example.com",
    "expires": "2026-01-15",
    "days": 218,
    "tls": "1.3",
    "grade": "A",
    "status": "OK",
    "issues": ""
  }
]
```

## Development

```sh
pip install -e ".[dev]"
pytest        # unit tests (no network needed — the grader is a pure function)
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
