"""Emit IP lists in formats that common firewalls / blockers understand.

The goal is "copy and paste, it works". No clever logic, no sudo calls —
that is the operator's job.
"""

from __future__ import annotations

from typing import Iterable, Literal

Format = Literal["plain", "iptables", "nftables", "ufw", "fail2ban"]


def render(ips: Iterable[str], fmt: Format = "plain") -> str:
    unique = sorted({ip for ip in ips if ip})
    if not unique:
        return ""

    if fmt == "plain":
        return "\n".join(unique) + "\n"

    if fmt == "iptables":
        return "\n".join(f"iptables -A INPUT -s {ip} -j DROP" for ip in unique) + "\n"

    if fmt == "nftables":
        # one set + one rule. Users can adapt the table/chain names.
        body = "\n".join(f"    {ip}," for ip in unique)
        return (
            "table inet filter {\n"
            "  set authwatch_block {\n"
            "    type ipv4_addr\n"
            "    elements = {\n"
            f"{body}\n"
            "    }\n"
            "  }\n"
            "  chain input {\n"
            "    type filter hook input priority 0;\n"
            "    ip saddr @authwatch_block drop\n"
            "  }\n"
            "}\n"
        )

    if fmt == "ufw":
        return "\n".join(f"ufw deny from {ip}" for ip in unique) + "\n"

    if fmt == "fail2ban":
        # one IP per line; matches the format of /etc/fail2ban/ip.blocklist
        return "\n".join(unique) + "\n"

    raise ValueError(f"unknown format: {fmt}")
