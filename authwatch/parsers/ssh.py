"""Parser for OpenSSH log lines (typically /var/log/auth.log on Debian/Ubuntu
or /var/log/secure on RHEL).

We only care about a few message shapes:

    Failed password for <user> from <ip> port <p> ssh2
    Failed password for invalid user <user> from <ip> port <p> ssh2
    Accepted password for <user> from <ip> port <p> ssh2
    Accepted publickey for <user> from <ip> port <p> ssh2
    Invalid user <user> from <ip> port <p>

Everything else is ignored. That is good enough for 95% of brute-force
investigations — if you need more, add a pattern here.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator

from ..events import AuthEvent

# syslog prefix without year, e.g. "May 12 22:01:04 host sshd[1234]:"
_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

# rsyslog with ISO timestamp, e.g. "2026-05-12T22:01:04.123456+03:00 host sshd[1234]:"
_ISO_SYSLOG = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

_FAILED = re.compile(
    r"^Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)
_ACCEPTED = re.compile(
    r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)
_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port \d+)?"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(line: str, assume_year: int) -> tuple[datetime, str] | None:
    """Return (timestamp, message) or None if the line is not an sshd syslog entry."""
    m = _SYSLOG.match(line)
    if m:
        month = _MONTHS.get(m.group("month"))
        if month is None:
            return None
        day = int(m.group("day"))
        h, mi, s = (int(x) for x in m.group("time").split(":"))
        try:
            ts = datetime(assume_year, month, day, h, mi, s)
        except ValueError:
            return None
        return ts, m.group("msg")

    m = _ISO_SYSLOG.match(line)
    if m:
        iso = m.group("iso")
        # datetime.fromisoformat handles "+03:00" since 3.11; for 3.9/3.10 strip tz.
        try:
            ts = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        except ValueError:
            # strip fractional seconds / timezone manually
            clean = re.sub(r"\.\d+", "", iso)
            clean = re.sub(r"[+-]\d{2}:?\d{2}$", "", clean)
            clean = clean.rstrip("Z")
            try:
                ts = datetime.fromisoformat(clean)
            except ValueError:
                return None
        # drop tz info; detectors work on naive timestamps from one host
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        return ts, m.group("msg")

    return None


def parse_ssh_log(
    lines: Iterable[str],
    assume_year: int | None = None,
) -> Iterator[AuthEvent]:
    """Yield AuthEvent for every ssh login attempt we can recognize.

    `assume_year` is used for classic syslog timestamps that lack a year.
    Defaults to the current year, which is usually right for live logs.
    Pass it explicitly when analyzing older archives.
    """
    if assume_year is None:
        assume_year = datetime.now().year

    # If we see a line from month 12 followed by month 1, roll the year over.
    prev_month: int | None = None
    year = assume_year

    for line in lines:
        line = line.rstrip("\r\n")
        if not line:
            continue

        parsed = _parse_timestamp(line, year)
        if parsed is None:
            continue
        ts, msg = parsed

        # naive new-year rollover for syslog format
        if prev_month == 12 and ts.month == 1:
            year += 1
            ts = ts.replace(year=year)
        prev_month = ts.month

        m = _FAILED.match(msg)
        if m:
            yield AuthEvent(ts=ts, ip=m.group("ip"), user=m.group("user"),
                            success=False, source="ssh", raw=line)
            continue

        m = _ACCEPTED.match(msg)
        if m:
            yield AuthEvent(ts=ts, ip=m.group("ip"), user=m.group("user"),
                            success=True, source="ssh", raw=line)
            continue

        m = _INVALID_USER.match(msg)
        if m:
            # "Invalid user" is logged before "Failed password"; treat as failed.
            yield AuthEvent(ts=ts, ip=m.group("ip"), user=m.group("user"),
                            success=False, source="ssh", raw=line)
            continue
        # unknown sshd message — skip silently
