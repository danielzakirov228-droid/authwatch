# authwatch

Offline analyzer for brute-force login attacks against SSH and web apps.

It reads the logs you already have (`/var/log/auth.log`, Nginx / Apache
access logs) and tells you who is trying to get in — grouped by IP, by user,
and by attack pattern. No agents, no daemons, no cloud. Just Python stdlib.

## Why

fail2ban reacts in real time but doesn't help you *understand* what happened.
ELK / Splunk / Wazuh are great if your company can afford them. For a
homelab, a VPS, a small web app, or a student working through TryHackMe and
HTB boxes, there wasn't a simple offline tool that:

- ingests plain log files,
- detects the common attack shapes (brute force, password spraying,
  credential stuffing),
- produces a report you can read and a blocklist you can paste into your
  firewall.

authwatch is that tool. It is intentionally small — you should be able to
read the whole source in an afternoon.

## Install

```
git clone https://github.com/yourname/authwatch
cd authwatch
pip install .
```

Or run it directly from the checkout without installing:

```
python -m authwatch path/to/auth.log
```

Requires Python 3.9+. No runtime dependencies.

## Quick start

```
# analyze an SSH log
authwatch /var/log/auth.log

# analyze an Nginx access log, lower thresholds
authwatch access.log -f nginx --min-fails 3 --window 5

# write a JSON report and a Markdown summary
authwatch auth.log --json findings.json --markdown report.md

# turn findings into an iptables blocklist you can pipe to a shell
authwatch auth.log --export iptables --quiet > block.sh

# keep state between runs and see repeat offenders
authwatch auth.log --db authwatch.db
```

Exit codes:

- `0` — no findings (use this in cron / CI to stay silent when all is well)
- `1` — at least one finding (trigger an alert)

## What it detects

| Pattern              | Meaning                                        | Tunable with            |
|----------------------|------------------------------------------------|-------------------------|
| brute force          | N failed attempts from one IP in a time window | `--min-fails`, `--window` |
| password spraying    | One IP failing against many distinct usernames | `--spray-users`         |
| credential stuffing  | Many IPs failing against the same username     | `--stuff-ips`           |

Defaults: 5 fails within a 10-minute window; 5 distinct users for spraying;
5 distinct IPs for stuffing. Adjust to your baseline.

## Supported log sources

- OpenSSH on Debian/Ubuntu (`/var/log/auth.log`) and RHEL/CentOS
  (`/var/log/secure`). Both classic syslog and rsyslog ISO timestamps.
- Nginx and Apache access logs in the *combined* format (default on both).
  Only POST requests to recognized login paths are considered by default;
  add `--include-get` if needed (see `nginx.py`).

Read `authwatch/parsers/` — both parsers are ~100 lines each and easy to
extend.

## IP enrichment

Two options, both optional:

```
# offline: a tiny CSV with columns cidr,country,asn,org
authwatch auth.log --geoip-csv ips.csv

# online: ipapi.co, rate-limited, no key needed
authwatch auth.log --online
```

If neither flag is set, no enrichment happens — the tool still works.

## Blocklist export formats

`--export {plain,iptables,nftables,ufw,fail2ban}` prints a ready-to-use
blocklist to stdout. Examples:

```
authwatch auth.log --export iptables --quiet
iptables -A INPUT -s 203.0.113.10 -j DROP

authwatch auth.log --export ufw --quiet
ufw deny from 203.0.113.10
```

authwatch does **not** execute these commands for you. That is the
operator's decision.

## Example output

```
authwatch: 2 finding(s)
------------------------------------------------------------
BRUTE FORCE  ip=203.0.113.10
  window: 2026-05-12T22:01:04 .. 2026-05-12T22:01:20
  fails=6 successes=0 users=4 ips=0 sources=ssh
  sample:
    May 12 22:01:04 srv sshd[1234]: Failed password for root from 203.0.113.10 ...

CREDENTIAL STUFFING  user=alice
  window: 2026-05-12T22:02:00 .. 2026-05-12T22:07:00
  fails=5 successes=0 users=0 ips=5 sources=nginx
```

## Running on a schedule

A realistic cron line on a Linux box — analyze the last rotation once per
hour and email a report if anything was found:

```
0 * * * * /usr/local/bin/authwatch /var/log/auth.log --db /var/lib/authwatch.db --markdown /tmp/aw.md && mail -s "authwatch: clean" me@example.com < /dev/null || mail -s "authwatch: findings" me@example.com < /tmp/aw.md
```

## Tests

```
pip install -e .[dev]
pytest
```

## Known limitations

- Syslog timestamps don't include a year. authwatch assumes the current
  year and rolls over on Dec → Jan boundaries. For old archives pass
  `--assume-year`.
- The Nginx parser treats HTTP 4xx as "failed login". Apps that return 200
  on bad credentials will be misclassified. Either fix your app to return a
  proper status or extend `parsers/nginx.py`.
- No IPv6-specific handling beyond what `ipaddress` gives us. It will parse
  IPv6 sources fine; firewall exports target IPv4 commands — adjust if you
  rely on `ip6tables`.
- This is an *analyzer*, not a blocker. If you need instant mitigation, run
  fail2ban alongside authwatch.

## License

MIT. See `LICENSE`.
