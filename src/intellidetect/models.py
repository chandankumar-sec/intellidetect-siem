"""Core data model: normalized events, alerts and incidents."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Sigma / Sysmon style field names -> normalized attribute or data key (lower-case lookup).
FIELD_ALIASES = {
    "image": "image",
    "processname": "image",
    "process_name": "image",
    "commandline": "command_line",
    "command_line": "command_line",
    "parentimage": "parent_image",
    "parent_image": "parent_image",
    "user": "user",
    "username": "user",
    "computer": "host",
    "hostname": "host",
    "host": "host",
    "sourceip": "src_ip",
    "src_ip": "src_ip",
    "destinationip": "dst_ip",
    "dst_ip": "dst_ip",
    "destinationport": "dst_port",
    "dst_port": "dst_port",
    "targetimage": "target_image",
    "grantedaccess": "granted_access",
    "queryname": "query",
    "cs-uri-stem": "uri_path",
    "cs-uri-query": "uri_query",
    "c-uri": "url",
    "url": "url",
    "cs-method": "method",
    "sc-status": "status",
    "status": "status",
    "bytes": "bytes",
    "command": "command",
    "eventtype": "kind",
    "kind": "kind",
}

_TOP_LEVEL = {"host", "user", "src_ip", "dst_ip", "dst_port", "kind", "source"}


@dataclass
class Event:
    """A single normalized log event."""

    ts: datetime
    source: str  # auth | sysmon | firewall | apache
    kind: str  # auth_failure, process_create, fw_deny, http_request, ...
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    data: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def get(self, name: str, default: Any = None) -> Any:
        """Look a field up by its normalized or Sigma-style name (case-insensitive)."""
        key = FIELD_ALIASES.get(name.lower(), name.lower())
        if key in _TOP_LEVEL:
            value = getattr(self, key)
            return value if value not in ("", 0, None) else default
        return self.data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat(),
            "source": self.source,
            "kind": self.kind,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            **self.data,
        }


@dataclass
class Alert:
    """A detection hit. Repeats of the same rule/entity are folded into one alert."""

    id: str
    rule_id: str
    rule_title: str
    severity: str  # low | medium | high | critical
    tactic: str
    technique: str
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: int = 70
    tags: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)

    def entities(self) -> set[str]:
        out = set()
        for prefix, value in (
            ("host", self.host),
            ("user", self.user),
            ("ip", self.src_ip),
            ("ip", self.dst_ip),
        ):
            if value:
                out.add(f"{prefix}:{value.lower()}")
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "tactic": self.tactic,
            "technique": self.technique,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "indicators": self.indicators,
        }


@dataclass
class Incident:
    """A group of related alerts forming one investigation unit."""

    id: str
    alerts: list[Alert]
    name: str = ""
    severity: str = "low"
    score: int = 0
    priority: str = "P4"
    score_breakdown: list[tuple[str, int]] = field(default_factory=list)
    intel: list[dict[str, Any]] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime:
        return min(a.first_seen for a in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(a.last_seen for a in self.alerts)

    @property
    def tactics(self) -> list[str]:
        """Distinct tactics in kill-chain order."""
        from .mitre import KILL_CHAIN

        seen = {a.tactic for a in self.alerts}
        ordered = [t for t in KILL_CHAIN if t in seen]
        return ordered + sorted(seen - set(KILL_CHAIN))

    @property
    def techniques(self) -> list[str]:
        return sorted({a.technique for a in self.alerts if a.technique})

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "score": self.score,
            "priority": self.priority,
            "score_breakdown": [{"reason": r, "points": p} for r, p in self.score_breakdown],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "tactics": self.tactics,
            "techniques": self.techniques,
            "entities": self.entities,
            "intel": self.intel,
            "alerts": [a.to_dict() for a in sorted(self.alerts, key=lambda a: a.first_seen)],
        }


# RFC 5737 documentation ranges. Python calls them "private", but they stand in for
# internet hosts in examples and in the simulator, so they are treated as external here.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_public_ip(value: str) -> bool:
    """True for externally routable addresses (not RFC1918 / loopback / link-local)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(ip in net for net in _DOC_NETS):
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
