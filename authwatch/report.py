"""Human-friendly output.

Two sinks:
  - print_console: compact, colorized if the terminal supports it
  - render_markdown: a small MD document you can paste into a ticket / PR

Colors use plain ANSI. If stdout is not a TTY we strip them automatically
so `authwatch ... > report.txt` stays clean.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, Mapping

from .detectors import Finding
from .enrich import IPInfo

_COLOR = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLOR[color]}{text}{_COLOR['reset']}"


def _kind_label(kind: str) -> str:
    return {
        "brute_force": "brute force",
        "password_spraying": "password spraying",
        "credential_stuffing": "credential stuffing",
    }.get(kind, kind)


def print_console(
    findings: Iterable[Finding],
    ip_info: Mapping[str, IPInfo] | None = None,
    stream=sys.stdout,
) -> None:
    ip_info = ip_info or {}
    color = _supports_color(stream)
    findings = list(findings)

    if not findings:
        stream.write(_c("No suspicious activity detected.\n", "dim", color))
        return

    stream.write(
        _c(f"authwatch: {len(findings)} finding(s)\n", "bold", color)
    )
    stream.write("-" * 60 + "\n")

    for f in findings:
        label = _kind_label(f.kind).upper()
        severity_color = "red" if f.kind == "brute_force" else "yellow"
        head = _c(label, severity_color, color)

        if f.ip:
            geo = ip_info.get(f.ip)
            extra = ""
            if geo and (geo.country or geo.asn):
                extra = _c(
                    f"  [{geo.country or '?'}{(' ' + geo.asn) if geo.asn else ''}]",
                    "dim", color,
                )
            stream.write(f"{head}  ip={f.ip}{extra}\n")
        else:
            stream.write(f"{head}  user={f.user}\n")

        stream.write(
            f"  window: {f.first_seen} .. {f.last_seen}\n"
            f"  fails={f.fails} successes={f.successes} "
            f"users={f.distinct_users} ips={f.distinct_ips} "
            f"sources={','.join(f.sources) or '-'}\n"
        )
        if f.sample_lines:
            stream.write(_c("  sample:\n", "dim", color))
            for ln in f.sample_lines[:2]:
                stream.write(_c(f"    {ln}\n", "dim", color))
        stream.write("\n")


def render_markdown(
    findings: Iterable[Finding],
    ip_info: Mapping[str, IPInfo] | None = None,
) -> str:
    ip_info = ip_info or {}
    findings = list(findings)
    if not findings:
        return "# authwatch report\n\nNo suspicious activity detected.\n"

    lines = ["# authwatch report", ""]
    lines.append(f"Total findings: **{len(findings)}**")
    lines.append("")
    lines.append("| kind | ip | user | window | fails | users | ips | geo |")
    lines.append("|------|----|------|--------|-------|-------|-----|-----|")
    for f in findings:
        geo = ip_info.get(f.ip or "") if f.ip else None
        geo_str = ""
        if geo and (geo.country or geo.asn):
            geo_str = f"{geo.country} {geo.asn}".strip()
        lines.append(
            "| {kind} | {ip} | {user} | {w} | {fails} | {users} | {ips} | {geo} |".format(
                kind=_kind_label(f.kind),
                ip=f.ip or "-",
                user=f.user or "-",
                w=f"{f.first_seen} → {f.last_seen}",
                fails=f.fails,
                users=f.distinct_users,
                ips=f.distinct_ips,
                geo=geo_str,
            )
        )
    lines.append("")
    return "\n".join(lines) + "\n"
