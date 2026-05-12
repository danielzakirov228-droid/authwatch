"""Parser for Nginx/Apache access logs (combined format).

authwatch does not try to be a full log parser — it only extracts login-ish
requests. By default we look at POSTs to paths that look like auth endpoints
(/login, /signin, /wp-login.php, /admin, /user/login, ...) and treat the
HTTP status as success/failure:

    2xx / 3xx  -> success  (server accepted the credentials or redirected)
    4xx        -> failure  (401/403 wrong creds, 429 rate-limited)
    5xx        -> ignored  (server error, tells us nothing about the user)

This is heuristic. If your app returns 200 on a failed login (many do),
pass a custom list of failure paths or statuses via the CLI.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator, Sequence

from ..events import AuthEvent

# combined log format:
# ip - user [10/Oct/2000:13:55:36 -0700] "METHOD /path HTTP/1.1" status size "ref" "ua"
_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) '
    r'\[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"]*?) HTTP/[^"]+" '
    r'(?P<status>\d{3}) \S+'
    r'(?: "[^"]*" "(?P<ua>[^"]*)")?'
)

DEFAULT_LOGIN_PATHS: tuple[str, ...] = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/authenticate",
    "/user/login",
    "/users/sign_in",
    "/admin",
    "/admin/login",
    "/wp-login.php",
    "/xmlrpc.php",          # common wordpress bruteforce target
    "/api/login",
    "/api/auth",
    "/api/v1/login",
)


def _parse_ts(s: str) -> datetime | None:
    # "10/Oct/2000:13:55:36 -0700"
    try:
        # strptime with %z works for "-0700"
        ts = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        return ts.replace(tzinfo=None)
    except ValueError:
        return None


def _is_login_path(path: str, patterns: Sequence[str]) -> bool:
    # match on path prefix, ignoring query string
    p = path.split("?", 1)[0].lower()
    return any(p == pat or p.startswith(pat + "/") or p == pat.lower() for pat in patterns)


def parse_nginx_log(
    lines: Iterable[str],
    login_paths: Sequence[str] | None = None,
    include_get: bool = False,
) -> Iterator[AuthEvent]:
    """Yield AuthEvent for requests that look like login attempts.

    By default only POST requests are considered. Set `include_get=True` to
    also inspect GETs — useful for basic auth endpoints.
    """
    patterns = tuple(p.lower() for p in (login_paths or DEFAULT_LOGIN_PATHS))

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        m = _LINE.match(line)
        if not m:
            continue

        method = m.group("method")
        if method != "POST" and not (include_get and method == "GET"):
            continue

        path = m.group("path")
        if not _is_login_path(path, patterns):
            continue

        ts = _parse_ts(m.group("ts"))
        if ts is None:
            continue

        status = int(m.group("status"))
        if 500 <= status < 600:
            continue  # server error, not informative
        success = status < 400

        user_field = m.group("user")
        user = None if user_field in ("-", "") else user_field

        yield AuthEvent(
            ts=ts,
            ip=m.group("ip"),
            user=user,
            success=success,
            source="nginx",
            raw=line,
        )
