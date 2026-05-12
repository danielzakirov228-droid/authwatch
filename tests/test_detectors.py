from datetime import datetime, timedelta
from pathlib import Path

from authwatch.detectors import (
    detect_brute_force,
    detect_credential_stuffing,
    detect_password_spraying,
    run_all,
)
from authwatch.events import AuthEvent
from authwatch.parsers import parse_nginx_log, parse_ssh_log

FIXTURES = Path(__file__).parent / "fixtures"


def _make(ts_offset_sec: int, ip: str, user: str | None, success: bool) -> AuthEvent:
    base = datetime(2026, 5, 12, 22, 0, 0)
    return AuthEvent(
        ts=base + timedelta(seconds=ts_offset_sec),
        ip=ip, user=user, success=success, source="ssh", raw="",
    )


def test_brute_force_fires_above_threshold():
    events = [_make(i * 10, "10.0.0.1", "root", False) for i in range(6)]
    findings = detect_brute_force(events, min_fails=5, window_minutes=10)
    assert len(findings) == 1
    assert findings[0].ip == "10.0.0.1"
    assert findings[0].fails == 6


def test_brute_force_respects_window():
    # 5 events but spread over 30 minutes → should NOT fire with window=10
    events = [_make(i * 600, "10.0.0.2", "root", False) for i in range(5)]
    findings = detect_brute_force(events, min_fails=5, window_minutes=10)
    assert findings == []


def test_brute_force_ignores_single_failure():
    events = [_make(0, "10.0.0.3", "root", False)]
    assert detect_brute_force(events, min_fails=5, window_minutes=10) == []


def test_password_spraying_detects_many_users_from_one_ip():
    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    events = [_make(i * 30, "10.0.0.4", u, False) for i, u in enumerate(users)]
    findings = detect_password_spraying(events, min_users=5, min_fails=5)
    assert len(findings) == 1
    assert findings[0].distinct_users >= 5


def test_credential_stuffing_detects_many_ips_on_one_user():
    events = [_make(i * 30, f"10.0.{i}.1", "alice", False) for i in range(6)]
    findings = detect_credential_stuffing(events, min_ips=5, min_fails=5)
    assert len(findings) == 1
    assert findings[0].user == "alice"
    assert findings[0].distinct_ips >= 5


def test_run_all_on_real_fixture_ssh():
    lines = (FIXTURES / "auth.log").read_text(encoding="utf-8").splitlines()
    events = list(parse_ssh_log(lines, assume_year=2026))
    findings = run_all(events, bf_fails=5, bf_window_minutes=10)
    # the fixture has 6 quick failures from 203.0.113.10
    assert any(f.kind == "brute_force" and f.ip == "203.0.113.10" for f in findings)


def test_run_all_on_real_fixture_nginx():
    lines = (FIXTURES / "nginx_access.log").read_text(encoding="utf-8").splitlines()
    events = list(parse_nginx_log(lines))
    findings = run_all(events, bf_fails=5, bf_window_minutes=10, stuff_ips=5)
    # six failed POSTs from 203.0.113.77 within ~10s → brute_force
    assert any(f.kind == "brute_force" and f.ip == "203.0.113.77" for f in findings)
    # alice targeted by 5+ distinct IPs → credential_stuffing
    assert any(f.kind == "credential_stuffing" and f.user == "alice" for f in findings)
