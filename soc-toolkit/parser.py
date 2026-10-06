"""
parser.py

Step 1: Data model for parsed auth.log entries.

Later steps (2-4) will add:
  - a line reader (generator that yields raw lines from the log file)
  - parse_line(): regex-based classifier that turns one raw line into an AuthEvent
  - parse_auth_log(): ties it together, returns a list[AuthEvent]
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional


def read_lines(path: str) -> Iterator[str]:
    """
    Step 2: Yield raw lines from an auth.log file, one at a time.

    A generator (not readlines()) so we never load the whole file into
    memory, and so a future "live tail" mode can reuse this same
    interface without changing parse_line()/parse_auth_log().

    Blank lines are skipped; each yielded line has trailing
    newline/whitespace stripped but is otherwise untouched.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip():
                yield line


@dataclass
class AuthEvent:
    """A single structured event parsed from /var/log/auth.log."""

    timestamp: datetime            # when the event occurred
    host: str                      # hostname that generated the log (e.g. "perplexed")
    process: str                   # subsystem, e.g. "sshd", "sudo", "su"
    pid: Optional[int]             # process ID, if present in the log line
    event_type: str                # our classification, e.g. "failed_password",
                                    # "accepted_password", "invalid_user", "sudo_command"
    user: Optional[str]            # username involved, if any
    source_ip: Optional[str]       # remote IP involved, if any (SSH attempts have this)
    raw_line: str                  # original, unmodified log line (keep for evidence)


# --- Step 3: line -> AuthEvent -----------------------------------------

# Splits a raw line into: timestamp | host | process(+optional pid) | message
# Handles all three shapes seen in real auth.log:
#   "sshd-session[6247]: ..."   -> process=sshd-session, pid=6247
#   "sshd[2262]: ..."           -> process=sshd, pid=2262
#   "login: ..."                -> process=login, pid=None
#   "(systemd): ..."            -> process=systemd, pid=None
_PREFIX_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"\(?(?P<process>[\w.\-]+)\)?(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Each entry: (event_type, compiled regex). First match wins.
# Regexes capture "user" and/or "ip" named groups where available.
_MESSAGE_PATTERNS = [
    ("accepted_login", re.compile(
        r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port")),
    ("failed_password", re.compile(
        r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port")),
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")),
    ("failed_login_local", re.compile(
        r"^FAILED LOGIN \d+ FROM \S+ FOR (?P<user>\S+),")),
    ("auth_failure", re.compile(
        r"^pam_unix\([\w:]+\): authentication failure;.*?"
        r"user=(?P<user>\S*).*?rhost=(?P<ip>\S*)")),
    ("session_opened", re.compile(
        r"^pam_unix\([\w:]+\): session opened for user (?P<user>[\w.\-]+)")),
    ("session_closed", re.compile(
        r"^pam_unix\([\w:]+\): session closed for user (?P<user>[\w.\-]+)")),
    ("sudo_command", re.compile(
        r"^\s*(?P<user>\S+)\s*:.*COMMAND=")),
]


def parse_line(line: str) -> Optional["AuthEvent"]:
    """
    Turn one raw auth.log line into an AuthEvent, or return None if the
    line doesn't match a known prefix shape (never raise on messy input --
    real logs have plenty of lines we don't care about).
    """
    prefix_match = _PREFIX_RE.match(line)
    if not prefix_match:
        return None

    try:
        timestamp = datetime.fromisoformat(prefix_match.group("timestamp"))
    except ValueError:
        return None

    host = prefix_match.group("host")
    process = prefix_match.group("process")
    pid_str = prefix_match.group("pid")
    pid = int(pid_str) if pid_str else None
    message = prefix_match.group("message")

    event_type = "other"
    user = None
    source_ip = None
    for label, pattern in _MESSAGE_PATTERNS:
        m = pattern.search(message)
        if m:
            event_type = label
            groups = m.groupdict()
            user = groups.get("user") or None
            source_ip = groups.get("ip") or None
            break

    return AuthEvent(
        timestamp=timestamp,
        host=host,
        process=process,
        pid=pid,
        event_type=event_type,
        user=user,
        source_ip=source_ip,
        raw_line=line,
    )


def parse_auth_log(path: str) -> list["AuthEvent"]:
    """
    Step 3: Read a full auth.log file and return a list of AuthEvents.
    Lines that don't match a known prefix shape are silently skipped
    (parse_line returns None for them) -- we don't want one weird line
    to crash a run over a multi-thousand-line log file.
    """
    events = []
    for raw in read_lines(path):
        event = parse_line(raw)
        if event is not None:
            events.append(event)
    return events


if __name__ == "__main__":
    import sys

    # Step 1 sanity check: build one AuthEvent by hand and print it.
    sample = AuthEvent(
        timestamp=datetime(2026, 9, 20, 14, 32, 7),
        host="perplexed",
        process="sshd",
        pid=1234,
        event_type="failed_password",
        user="admin",
        source_ip="203.0.113.7",
        raw_line="Sep 20 14:32:07 perplexed sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51422 ssh2",
    )
    print(sample)

    # Step 2 sanity check: read raw lines from a log file and count them.
    # Usage: python3 parser.py [path-to-log-file]
    log_path = sys.argv[1] if len(sys.argv) > 1 else "../sample_data/auth.log.sample2"
    print(f"\nReading lines from: {log_path}")
    count = 0
    for raw in read_lines(log_path):
        count += 1
        if count <= 3:
            print(f"  [{count}] {raw}")
    print(f"...\nTotal non-blank lines read: {count}")

    # Step 3 sanity check: fully parse the log and show event_type breakdown.
    print(f"\nParsing: {log_path}")
    events = parse_auth_log(log_path)
    print(f"Parsed {len(events)} events (of {count} lines)\n")

    from collections import Counter
    breakdown = Counter(e.event_type for e in events)
    print("Event type breakdown:")
    for event_type, n in breakdown.most_common():
        print(f"  {event_type:20s} {n}")

    print("\nInteresting events (not 'other'):")
    for e in events:
        if e.event_type != "other":
            print(f"  {e.timestamp} | {e.event_type:18s} | user={e.user} ip={e.source_ip}")


