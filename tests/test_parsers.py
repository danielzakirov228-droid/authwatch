from pathlib import Path

from authwatch.parsers import parse_nginx_log, parse_ssh_log

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def test_ssh_parser_counts_failures_and_successes():
    events = list(parse_ssh_log(_read("auth.log"), assume_year=2026))

    assert len(events) >= 6
    fails = [e for e in events if not e.success]
    successes = [e for e in events if e.success]

    assert any(e.ip == "203.0.113.10" and not e.success for e in fails)
    assert any(e.user == "alice" and e.success for e in successes)

    # 'Invalid user' followed by 'Failed password for invalid user' would
    # otherwise double-count — we accept both as failures, which is fine:
    # they are separate syslog lines and both signal an attempt.
    assert all(e.source == "ssh" for e in events)


def test_ssh_parser_skips_unrelated_lines():
    events = list(parse_ssh_log(_read("auth.log"), assume_year=2026))
    assert not any("unrelated" in (e.raw or "") for e in events)


def test_nginx_parser_extracts_login_posts_only():
    events = list(parse_nginx_log(_read("nginx_access.log")))

    # the GET request on '/' must be skipped
    assert all("GET /" not in (e.raw or "") or "/login" in (e.raw or "") for e in events)
    assert all(e.source == "nginx" for e in events)
    assert all(not e.success for e in events), "all fixtures return 401"
    assert {e.ip for e in events} >= {"203.0.113.77", "198.51.100.2", "198.51.100.6"}
