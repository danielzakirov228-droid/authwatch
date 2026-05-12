"""IP enrichment.

Two modes:

1. offline — read a tiny CSV shipped by the user (ip_cidr,country,asn).
   Fast, deterministic, no network calls. Recommended for production use.

2. online  — query ipapi.co over HTTPS with urllib (stdlib only).
   Disabled by default. Off by default in CLI too; enable with --online.
   Rate-limited, best-effort.

Both modes cache results in memory for the current process.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class IPInfo:
    country: str = ""
    asn: str = ""
    org: str = ""


class OfflineLookup:
    """CSV-backed lookup. Expected columns: cidr,country,asn,org (org optional).

    Linear search; fine for a few thousand entries. If you need more, swap
    in a proper trie — the rest of the code does not care.
    """

    def __init__(self, csv_path: str | Path):
        self._entries: list[tuple[ipaddress._BaseNetwork, IPInfo]] = []
        with open(csv_path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                cidr = row.get("cidr") or row.get("network")
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr.strip(), strict=False)
                except ValueError:
                    continue
                info = IPInfo(
                    country=(row.get("country") or "").strip(),
                    asn=(row.get("asn") or "").strip(),
                    org=(row.get("org") or "").strip(),
                )
                self._entries.append((net, info))

    def lookup(self, ip: str) -> IPInfo:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IPInfo()
        for net, info in self._entries:
            if addr in net:
                return info
        return IPInfo()


class OnlineLookup:
    """Best-effort lookup via ipapi.co. Cached per-process."""

    _URL = "https://ipapi.co/{ip}/json/"

    def __init__(self, timeout: float = 3.0):
        self._timeout = timeout
        self._cache: dict[str, IPInfo] = {}

    def lookup(self, ip: str) -> IPInfo:
        if ip in self._cache:
            return self._cache[ip]
        try:
            req = urllib.request.Request(
                self._URL.format(ip=ip),
                headers={"User-Agent": "authwatch/0.1"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            info = IPInfo()
        else:
            info = IPInfo(
                country=str(data.get("country_name") or data.get("country") or ""),
                asn=str(data.get("asn") or ""),
                org=str(data.get("org") or ""),
            )
        self._cache[ip] = info
        return info


class NullLookup:
    def lookup(self, ip: str) -> IPInfo:  # noqa: ARG002
        return IPInfo()


def enrich_ips(lookup, ips: Iterable[str]) -> dict[str, IPInfo]:
    return {ip: lookup.lookup(ip) for ip in set(ips)}
