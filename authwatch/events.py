"""Shared data types.

All parsers produce AuthEvent objects. Detectors and storage consume them.
Keeping this in one place so adding a new log source stays a small task.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class AuthEvent:
    ts: datetime              # event timestamp (tz-naive, local to the log)
    ip: str                   # source IP as seen in the log
    user: Optional[str]       # username if present, else None
    success: bool             # True = login succeeded, False = failed
    source: str               # "ssh", "nginx", etc. — useful for grouping
    raw: str = ""             # original log line, handy for reports

    def as_dict(self) -> dict:
        return {
            "ts": self.ts.isoformat(timespec="seconds"),
            "ip": self.ip,
            "user": self.user,
            "success": self.success,
            "source": self.source,
        }
