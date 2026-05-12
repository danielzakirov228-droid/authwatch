"""Command-line interface.

Examples:

    authwatch /var/log/auth.log
    authwatch access.log --format nginx --min-fails 10 --window 5
    authwatch auth.log --json report.json --export iptables > block.sh
    authwatch auth.log --db authwatch.db --markdown report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable

from . import __version__
from .detectors import (
    DEFAULT_BF_FAILS,
    DEFAULT_BF_WINDOW_MIN,
    DEFAULT_SPRAY_USERS,
    DEFAULT_STUFF_IPS,
    Finding,
    run_all,
)
from .enrich import NullLookup, OfflineLookup, OnlineLookup, enrich_ips
from .events import AuthEvent
from .exporters import render as render_blocklist
from .parsers import parse_nginx_log, parse_ssh_log
from .report import print_console, render_markdown
from .storage import connect, save_events, save_findings


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authwatch",
        description="Offline analyzer for SSH and web login brute-force attacks.",
    )
    p.add_argument("logfile", nargs="+",
                   help="path(s) to log file; use '-' for stdin")
    p.add_argument("-f", "--format", choices=("ssh", "nginx", "auto"),
                   default="auto", help="log format (default: auto-detect)")
    p.add_argument("--assume-year", type=int, default=None,
                   help="year for syslog timestamps without year (ssh only)")

    thresholds = p.add_argument_group("detection thresholds")
    thresholds.add_argument("--min-fails", type=int, default=DEFAULT_BF_FAILS,
                            help=f"min failed attempts to flag (default: {DEFAULT_BF_FAILS})")
    thresholds.add_argument("--window", type=int, default=DEFAULT_BF_WINDOW_MIN,
                            dest="window_minutes",
                            help=f"time window in minutes (default: {DEFAULT_BF_WINDOW_MIN})")
    thresholds.add_argument("--spray-users", type=int, default=DEFAULT_SPRAY_USERS,
                            help="min distinct users for password-spraying detection")
    thresholds.add_argument("--stuff-ips", type=int, default=DEFAULT_STUFF_IPS,
                            help="min distinct IPs for credential-stuffing detection")

    out = p.add_argument_group("output")
    out.add_argument("--json", metavar="PATH", help="write findings to JSON")
    out.add_argument("--markdown", metavar="PATH", help="write a markdown report")
    out.add_argument("--export", choices=("plain", "iptables", "nftables", "ufw", "fail2ban"),
                     help="print a blocklist for the flagged IPs to stdout")
    out.add_argument("--quiet", action="store_true",
                     help="suppress the console report (useful with --json)")

    st = p.add_argument_group("state")
    st.add_argument("--db", metavar="PATH",
                    help="SQLite database to persist events and findings")

    enr = p.add_argument_group("enrichment")
    enr.add_argument("--geoip-csv", metavar="PATH",
                     help="offline CSV (cidr,country,asn,org) for IP enrichment")
    enr.add_argument("--online", action="store_true",
                     help="use ipapi.co for enrichment (rate-limited)")

    p.add_argument("--version", action="version", version=f"authwatch {__version__}")
    return p


def _detect_format(path: str) -> str:
    # cheap heuristic based on file name; fallback to ssh which is the more common case
    name = Path(path).name.lower()
    if "access" in name or "nginx" in name or name.endswith(".access.log"):
        return "nginx"
    return "ssh"


def _open_lines(path: str) -> Iterable[str]:
    if path == "-":
        yield from sys.stdin
        return
    # errors='replace' — real-world logs sometimes contain garbage bytes
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from fh


def _load_events(paths: list[str], fmt: str, assume_year: int | None) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for path in paths:
        resolved = fmt if fmt != "auto" else _detect_format(path)
        if resolved == "ssh":
            events.extend(parse_ssh_log(_open_lines(path), assume_year=assume_year))
        elif resolved == "nginx":
            events.extend(parse_nginx_log(_open_lines(path)))
        else:
            raise SystemExit(f"unsupported format: {resolved}")
    return events


def _collect_ips(findings: Iterable[Finding]) -> list[str]:
    return [f.ip for f in findings if f.ip]


def _write_json(path: str, findings: list[Finding]) -> None:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "findings": [f.as_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    events = _load_events(args.logfile, args.format, args.assume_year)
    if not events:
        sys.stderr.write("authwatch: no recognizable login events found\n")
        # not an error — empty logs are a valid state
        if args.json:
            _write_json(args.json, [])
        return 0

    findings = run_all(
        events,
        bf_fails=args.min_fails,
        bf_window_minutes=args.window_minutes,
        spray_users=args.spray_users,
        stuff_ips=args.stuff_ips,
    )

    # enrichment
    if args.geoip_csv:
        lookup = OfflineLookup(args.geoip_csv)
    elif args.online:
        lookup = OnlineLookup()
    else:
        lookup = NullLookup()
    ip_info = enrich_ips(lookup, _collect_ips(findings))

    if not args.quiet:
        print_console(findings, ip_info)

    if args.json:
        _write_json(args.json, findings)

    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(findings, ip_info))

    if args.export:
        sys.stdout.write(render_blocklist(_collect_ips(findings), args.export))

    if args.db:
        with connect(args.db) as conn:
            save_events(conn, events)
            save_findings(conn, findings, datetime.now().isoformat(timespec="seconds"))

    # exit code: 0 if clean, 1 if any findings — handy for CI / cron alerts
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
