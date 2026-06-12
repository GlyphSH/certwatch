"""Command-line interface for certwatch."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .core import Result, check_host

_COLORS = {"OK": "\033[32m", "WARN": "\033[33m", "CRIT": "\033[31m", "ERROR": "\033[31m"}
_RESET = "\033[0m"
_EXIT = {"OK": 0, "WARN": 1, "CRIT": 2, "ERROR": 2}


def _gather_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = list(args.hosts)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh]
    if not targets and not sys.stdin.isatty():
        targets += [ln.strip() for ln in sys.stdin]
    # drop blanks and comments, de-dupe preserving order
    seen: set[str] = set()
    cleaned = []
    for t in targets:
        if not t or t.startswith("#") or t in seen:
            continue
        seen.add(t)
        cleaned.append(t)
    return cleaned


def _row(r: Result) -> dict:
    return {
        "host": f"{r.host}:{r.port}" if r.port != 443 else r.host,
        "expires": r.not_after.date().isoformat() if r.not_after else "-",
        "days": r.days_left if r.days_left is not None else "-",
        "tls": (r.protocol or "-").replace("TLSv", "").replace("SSLv", "SSL"),
        "grade": r.grade if r.ok else "-",
        "status": r.status,
        "issues": "; ".join(r.issues) if r.ok else (r.error or "error"),
    }


def _print_table(results: list[Result], color: bool) -> None:
    rows = [_row(r) for r in results]
    headers = ["HOST", "EXPIRES", "DAYS", "TLS", "GRADE", "ISSUES"]
    keys = ["host", "expires", "days", "tls", "grade", "issues"]
    widths = [
        max(len(h), *(len(str(row[k])) for row in rows)) if rows else len(h)
        for h, k in zip(headers, keys)
    ]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for r, row in zip(results, rows):
        cells = "  ".join(str(row[k]).ljust(w) for k, w in zip(keys, widths))
        if color and r.status in _COLORS:
            print(f"{_COLORS[r.status]}{cells}{_RESET}")
        else:
            print(cells)


def _summary(results: list[Result]) -> str:
    counts = {"OK": 0, "WARN": 0, "CRIT": 0, "ERROR": 0}
    for r in results:
        counts[r.status if r.ok else "ERROR"] += 1
    parts = []
    for label, key in (("ok", "OK"), ("warning", "WARN"), ("critical", "CRIT"), ("error", "ERROR")):
        if counts[key]:
            parts.append(f"{counts[key]} {label}")
    return ", ".join(parts) or "no hosts checked"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certwatch",
        description="Grade the TLS certificate and configuration of one or more hosts.",
    )
    parser.add_argument("hosts", nargs="*", help="host or host:port (default port 443)")
    parser.add_argument("-f", "--file", help="read targets from a file (one per line; # comments)")
    parser.add_argument("--warn-days", type=int, default=30, metavar="N",
                        help="flag certificates expiring within N days (default: 30)")
    parser.add_argument("--timeout", type=float, default=8.0, metavar="SECS",
                        help="per-host connection timeout (default: 8)")
    parser.add_argument("-j", "--concurrency", type=int, default=10, metavar="N",
                        help="number of hosts to check in parallel (default: 10)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--csv", action="store_true", help="emit CSV instead of a table")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"certwatch {__version__}")
    args = parser.parse_args(argv)

    targets = _gather_targets(args)
    if not targets:
        parser.error("no hosts given (pass them as arguments, via --file, or on stdin)")

    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        results = list(pool.map(
            lambda t: check_host(t, timeout=args.timeout, warn_days=args.warn_days),
            targets,
        ))

    if args.json:
        print(json.dumps([_row(r) | {"status": r.status} for r in results], indent=2))
    elif args.csv:
        writer = csv.DictWriter(
            sys.stdout, fieldnames=["host", "expires", "days", "tls", "grade", "status", "issues"]
        )
        writer.writeheader()
        for r in results:
            writer.writerow(_row(r))
    else:
        color = sys.stdout.isatty() and not args.no_color
        _print_table(results, color)
        sys.stdout.flush()  # keep the table ahead of the stderr summary when piped
        worst = max((r.status if r.ok else "ERROR" for r in results), key=lambda s: _EXIT[s])
        print(f"\n{_summary(results)}   (exit code {_EXIT[worst]})", file=sys.stderr)

    worst = max((r.status if r.ok else "ERROR" for r in results), key=lambda s: _EXIT[s])
    return _EXIT[worst]


if __name__ == "__main__":
    raise SystemExit(main())
