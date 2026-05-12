"""Detection rules.

All detectors take an iterable of AuthEvent and return a list of Finding.
They are intentionally simple — you are meant to read and understand them,
not fight the framework.

Rules implemented:

1. brute_force(ip)            — many failed attempts from one IP in a window
2. password_spraying(ip)      — one IP hits many different usernames, mostly failing
3. credential_stuffing(user)  — many IPs hit the same user, mostly failing

Thresholds have sane defaults (see DEFAULT_* constants) and can be tuned
from the CLI or from code.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, Literal, Sequence

from .events import AuthEvent

Kind = Literal["brute_force", "password_spraying", "credential_stuffing"]

DEFAULT_BF_FAILS = 5          # N failures
DEFAULT_BF_WINDOW_MIN = 10    # within T minutes
DEFAULT_SPRAY_USERS = 5       # distinct usernames
DEFAULT_STUFF_IPS = 5         # distinct source IPs for one user


@dataclass
class Finding:
    kind: Kind
    ip: str | None            # set for ip-centric findings
    user: str | None          # set for user-centric findings
    first_seen: str           # iso timestamps, easier to serialize
    last_seen: str
    fails: int
    successes: int
    distinct_users: int = 0
    distinct_ips: int = 0
    sources: list[str] = field(default_factory=list)
    sample_lines: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "ip": self.ip,
            "user": self.user,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "fails": self.fails,
            "successes": self.successes,
            "distinct_users": self.distinct_users,
            "distinct_ips": self.distinct_ips,
            "sources": self.sources,
        }


def _sliding_window_hit(
    timestamps: Sequence, threshold: int, window: timedelta
) -> bool:
    """Return True if any window of length `window` contains >= threshold events.

    Assumes timestamps are sorted ascending. O(n) with two pointers.
    """
    if len(timestamps) < threshold:
        return False
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        if right - left + 1 >= threshold:
            return True
    return False


def detect_brute_force(
    events: Iterable[AuthEvent],
    min_fails: int = DEFAULT_BF_FAILS,
    window_minutes: int = DEFAULT_BF_WINDOW_MIN,
) -> list[Finding]:
    """Per-IP: flag if >= min_fails failed attempts fit into any window."""
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        by_ip[ev.ip].append(ev)

    window = timedelta(minutes=window_minutes)
    findings: list[Finding] = []

    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.ts)
        fails = [e for e in evs if not e.success]
        if len(fails) < min_fails:
            continue
        times = [e.ts for e in fails]
        if not _sliding_window_hit(times, min_fails, window):
            continue

        successes = sum(1 for e in evs if e.success)
        users = {e.user for e in evs if e.user}
        sources = sorted({e.source for e in evs})
        findings.append(Finding(
            kind="brute_force",
            ip=ip,
            user=None,
            first_seen=fails[0].ts.isoformat(timespec="seconds"),
            last_seen=fails[-1].ts.isoformat(timespec="seconds"),
            fails=len(fails),
            successes=successes,
            distinct_users=len(users),
            sources=sources,
            sample_lines=[e.raw for e in fails[:3] if e.raw],
        ))

    findings.sort(key=lambda f: f.fails, reverse=True)
    return findings


def detect_password_spraying(
    events: Iterable[AuthEvent],
    min_users: int = DEFAULT_SPRAY_USERS,
    min_fails: int = DEFAULT_BF_FAILS,
) -> list[Finding]:
    """Per-IP: flag if one IP failed against many distinct usernames.

    Classic spraying = low-and-slow, one password across many accounts.
    We do not try to be clever about passwords (we do not see them),
    we only look at the fan-out in usernames.
    """
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        by_ip[ev.ip].append(ev)

    findings: list[Finding] = []
    for ip, evs in by_ip.items():
        fails = [e for e in evs if not e.success and e.user]
        if len(fails) < min_fails:
            continue
        users = {e.user for e in fails}
        if len(users) < min_users:
            continue

        evs.sort(key=lambda e: e.ts)
        findings.append(Finding(
            kind="password_spraying",
            ip=ip,
            user=None,
            first_seen=evs[0].ts.isoformat(timespec="seconds"),
            last_seen=evs[-1].ts.isoformat(timespec="seconds"),
            fails=len(fails),
            successes=sum(1 for e in evs if e.success),
            distinct_users=len(users),
            sources=sorted({e.source for e in evs}),
            sample_lines=[e.raw for e in fails[:3] if e.raw],
        ))

    findings.sort(key=lambda f: f.distinct_users, reverse=True)
    return findings


def detect_credential_stuffing(
    events: Iterable[AuthEvent],
    min_ips: int = DEFAULT_STUFF_IPS,
    min_fails: int = DEFAULT_BF_FAILS,
) -> list[Finding]:
    """Per-user: flag if one account was hit by many different IPs."""
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        if ev.user:
            by_user[ev.user].append(ev)

    findings: list[Finding] = []
    for user, evs in by_user.items():
        fails = [e for e in evs if not e.success]
        if len(fails) < min_fails:
            continue
        ips = {e.ip for e in fails}
        if len(ips) < min_ips:
            continue

        evs.sort(key=lambda e: e.ts)
        findings.append(Finding(
            kind="credential_stuffing",
            ip=None,
            user=user,
            first_seen=evs[0].ts.isoformat(timespec="seconds"),
            last_seen=evs[-1].ts.isoformat(timespec="seconds"),
            fails=len(fails),
            successes=sum(1 for e in evs if e.success),
            distinct_ips=len(ips),
            sources=sorted({e.source for e in evs}),
            sample_lines=[e.raw for e in fails[:3] if e.raw],
        ))

    findings.sort(key=lambda f: f.distinct_ips, reverse=True)
    return findings


def run_all(
    events: Sequence[AuthEvent],
    *,
    bf_fails: int = DEFAULT_BF_FAILS,
    bf_window_minutes: int = DEFAULT_BF_WINDOW_MIN,
    spray_users: int = DEFAULT_SPRAY_USERS,
    stuff_ips: int = DEFAULT_STUFF_IPS,
) -> list[Finding]:
    """Run all three detectors and return a single list of findings."""
    # materialize once so each detector can iterate independently
    evs = list(events)
    out: list[Finding] = []
    out.extend(detect_brute_force(evs, bf_fails, bf_window_minutes))
    out.extend(detect_password_spraying(evs, spray_users, bf_fails))
    out.extend(detect_credential_stuffing(evs, stuff_ips, bf_fails))
    return out
