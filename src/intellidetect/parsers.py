"""Log parsers: raw log lines -> normalized :class:`Event` objects.

Supported formats
-----------------
auth      OpenSSH / sudo lines in syslog format (``Mar 10 08:00:01 host sshd[12]: ...``)
sysmon    Sysmon events flattened to ``ts;EventID n;Type;Key=Value;...`` lines
firewall  iptables-style ``ts ACTION PROTO src:port -> dst:port BYTES=n``
apache    Apache/Nginx combined access log
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Event

UTC = timezone.utc
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass
class ParseStats:
    total: int = 0
    parsed: int = 0
    skipped: int = 0
    samples: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- auth
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SSH_FAIL = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port \d+)?")
_SSH_OK = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)
_SUDO = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target>\S+)\s*;"
    r"\s*COMMAND=(?P<cmd>.*)$"
)


def _syslog_ts(mon: str, day: str, clock: str, year: int | None, now: datetime | None) -> datetime:
    now = now or datetime.now(UTC)
    year = year or now.year
    ts = datetime.strptime(f"{year} {MONTHS[mon]} {day} {clock}", "%Y %m %d %H:%M:%S").replace(
        tzinfo=UTC
    )
    # Syslog has no year: a date far in the future means the log is from the previous year.
    if year == now.year and ts - now > timedelta(days=2):
        ts = ts.replace(year=year - 1)
    return ts


def parse_auth(line: str, year: int | None = None, now: datetime | None = None) -> Event | None:
    m = _SYSLOG.match(line.strip())
    if not m or m["mon"] not in MONTHS:
        return None
    ts = _syslog_ts(m["mon"], m["day"], m["time"], year, now)
    host, proc, msg = m["host"], m["proc"], m["msg"]

    if proc.startswith("sshd"):
        if f := _SSH_FAIL.search(msg):
            return Event(ts, "auth", "auth_failure", host=host, user=f["user"], src_ip=f["ip"],
                         data={"service": "ssh"}, raw=line)
        if f := _SSH_INVALID.search(msg):
            return Event(ts, "auth", "auth_failure", host=host, user=f["user"], src_ip=f["ip"],
                         data={"service": "ssh", "invalid_user": True}, raw=line)
        if f := _SSH_OK.search(msg):
            return Event(ts, "auth", "auth_success", host=host, user=f["user"], src_ip=f["ip"],
                         data={"service": "ssh", "method": f["method"]}, raw=line)
        return None
    if proc == "sudo":
        if f := _SUDO.match(msg):
            return Event(ts, "auth", "sudo", host=host, user=f["user"],
                         data={"target_user": f["target"], "command": f["cmd"].strip(),
                               "pwd": f["pwd"]}, raw=line)
    return None


# ------------------------------------------------------------------------- sysmon
_SYSMON_KINDS = {
    1: "process_create",
    3: "network_connect",
    10: "process_access",
    11: "file_create",
    22: "dns_query",
}
_KV_SPLIT = re.compile(r";(?=[A-Za-z]\w*=)")


def parse_sysmon(line: str, **_: object) -> Event | None:
    parts = line.strip().split(";", 3)
    if len(parts) < 3:
        return None
    ts_raw, eid_raw = parts[0].strip(), parts[1].strip()
    try:
        ts = datetime.strptime(ts_raw.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)
        event_id = int(eid_raw.split()[-1])
    except (ValueError, IndexError):
        return None
    kind = _SYSMON_KINDS.get(event_id)
    if kind is None:
        return None
    kv: dict[str, str] = {}
    rest = parts[3] if len(parts) > 3 else ""
    for chunk in _KV_SPLIT.split(rest):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            kv[k.strip()] = v.strip()
    data = {
        "event_id": event_id,
        "image": kv.get("Image", kv.get("SourceImage", "")),
        "parent_image": kv.get("ParentImage", ""),
        "command_line": kv.get("CommandLine", ""),
        "target_image": kv.get("TargetImage", ""),
        "granted_access": kv.get("GrantedAccess", ""),
        "target_filename": kv.get("TargetFilename", ""),
        "query": kv.get("QueryName", ""),
        "protocol": kv.get("Protocol", ""),
    }
    port = kv.get("DestinationPort", "0")
    return Event(
        ts, "sysmon", kind,
        host=kv.get("Computer", ""),
        user=kv.get("User", ""),
        src_ip=kv.get("SourceIp", ""),
        dst_ip=kv.get("DestinationIp", ""),
        dst_port=int(port) if port.isdigit() else 0,
        data={k: v for k, v in data.items() if v != ""},
        raw=line,
    )


# ------------------------------------------------------------------------ firewall
_FW = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<action>ACCEPT|ALLOW|DROP|DENY|REJECT)\s+"
    r"(?P<proto>\w+)\s+(?P<src>[\d.]+):(?P<sport>\d+)\s+->\s+(?P<dst>[\d.]+):(?P<dport>\d+)"
    r"(?:.*?BYTES=(?P<bytes>\d+))?"
)


def parse_firewall(line: str, **_: object) -> Event | None:
    m = _FW.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    allowed = m["action"] in ("ACCEPT", "ALLOW")
    return Event(
        ts, "firewall", "fw_allow" if allowed else "fw_deny",
        host="", src_ip=m["src"], dst_ip=m["dst"], dst_port=int(m["dport"]),
        data={"protocol": m["proto"].lower(), "bytes": int(m["bytes"] or 0),
              "action": m["action"].lower(), "sensor": "fw01"},
        raw=line,
    )


# -------------------------------------------------------------------------- apache
_APACHE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_apache(line: str, host: str = "web01", **_: object) -> Event | None:
    m = _APACHE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None
    path, _, query = m["url"].partition("?")
    return Event(
        ts, "apache", "http_request", host=host,
        user="" if m["user"] == "-" else m["user"], src_ip=m["ip"],
        data={
            "method": m["method"],
            "url": m["url"],
            "uri_path": path,
            "uri_query": query,
            "status": int(m["status"]),
            "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
            "user_agent": m["ua"] or "",
        },
        raw=line,
    )


PARSERS: dict[str, Callable[..., Event | None]] = {
    "auth": parse_auth,
    "sysmon": parse_sysmon,
    "firewall": parse_firewall,
    "apache": parse_apache,
}

DEFAULT_FILENAMES = {
    "auth": "auth.log",
    "sysmon": "sysmon.log",
    "firewall": "firewall.log",
    "apache": "apache_access.log",
}


def parse_lines(kind: str, lines: Iterable[str], **ctx: object) -> tuple[list[Event], ParseStats]:
    parser = PARSERS[kind]
    stats = ParseStats()
    events: list[Event] = []
    for line in lines:
        if not line.strip():
            continue
        stats.total += 1
        event = parser(line, **ctx)
        if event is None:
            stats.skipped += 1
            if len(stats.samples) < 3:
                stats.samples.append(line.strip()[:120])
        else:
            stats.parsed += 1
            events.append(event)
    return events, stats


def parse_file(kind: str, path: str | Path, **ctx: object) -> tuple[list[Event], ParseStats]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_lines(kind, fh, **ctx)


def parse_directory(directory: str | Path, **ctx: object) -> tuple[list[Event], dict[str, ParseStats]]:
    """Parse every known log file found in ``directory``; events are returned time-sorted."""
    directory = Path(directory)
    events: list[Event] = []
    stats: dict[str, ParseStats] = {}
    for kind, name in DEFAULT_FILENAMES.items():
        path = directory / name
        if path.exists():
            found, stats[kind] = parse_file(kind, path, **ctx)
            events.extend(found)
    events.sort(key=lambda e: e.ts)
    return events, stats
