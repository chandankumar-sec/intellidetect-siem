"""Correlate alerts into incidents.

Alerts that share an entity (host, user or IP) within ``gap`` seconds are merged, so one
intrusion that fires ten rules becomes a single investigation instead of ten tickets.
IP addresses are mapped to inventory hostnames first, which lets a firewall alert about
``10.0.10.21`` join the Sysmon alerts raised on ``WS-ALICE``.
"""

from __future__ import annotations

from datetime import timedelta

from .enrich import Inventory
from .mitre import KILL_CHAIN
from .models import Alert, Incident, is_public_ip

GENERIC_USERS = {"", "-", "root", "system", "local service", "network service", "unknown"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _norm_user(user: str) -> str:
    return user.split("\\")[-1].lower()


def alert_entities(alert: Alert, inventory: Inventory) -> set[str]:
    entities = set()
    if alert.host:
        entities.add(f"host:{alert.host.lower()}")
        ip = inventory.ip_for_host(alert.host)
        if ip:
            entities.add(f"ip:{ip}")
    for ip in (alert.src_ip, alert.dst_ip):
        if not ip:
            continue
        entities.add(f"ip:{ip}")
        mapped = inventory.host_for_ip(ip)
        if mapped:
            entities.add(f"host:{mapped}")
    user = _norm_user(alert.user)
    if user not in GENERIC_USERS:
        entities.add(f"user:{user}")
    return entities


class _DisjointSet:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def _name(incident: Incident) -> str:
    alerts = sorted(incident.alerts, key=lambda a: a.first_seen)
    tactics = incident.tactics
    hosts = incident.entities.get("hosts", [])
    ips = incident.entities.get("external_ips", [])
    subject = ", ".join(hosts[:2]) or ", ".join(ips[:2]) or "unknown asset"
    if len(tactics) >= 3:
        return f"Multi-stage intrusion ({tactics[0]} to {tactics[-1]}) involving {subject}"
    top = max(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 0), a.count))
    if len(alerts) == 1:
        return f"{top.rule_title} on {subject}" if hosts else f"{top.rule_title} from {subject}"
    return f"{top.rule_title} and {len(alerts) - 1} related alert(s) involving {subject}"


def _entities_summary(incident: Incident, inventory: Inventory) -> dict[str, list[str]]:
    hosts: dict[str, None] = {}
    users: dict[str, None] = {}
    external: dict[str, None] = {}
    internal: dict[str, None] = {}
    for a in sorted(incident.alerts, key=lambda x: x.first_seen):
        if a.host:
            hosts[a.host] = None
        for ip in (a.src_ip, a.dst_ip):
            if not ip:
                continue
            mapped = inventory.host_for_ip(ip)
            if mapped:
                hosts[inventory.assets[mapped]["host"]] = None
            elif is_public_ip(ip):
                external[ip] = None
            else:
                internal[ip] = None
        if _norm_user(a.user) not in GENERIC_USERS:
            users[a.user] = None
    return {
        "hosts": list(hosts),
        "users": list(users),
        "external_ips": list(external),
        "internal_ips": list(internal),
    }


def correlate(alerts: list[Alert], inventory: Inventory | None = None, gap: int = 1800) -> list[Incident]:
    inventory = inventory or Inventory()
    ordered = sorted(alerts, key=lambda a: a.first_seen)
    ents = [alert_entities(a, inventory) for a in ordered]
    dsu = _DisjointSet(len(ordered))
    horizon = timedelta(seconds=gap)
    for i, a in enumerate(ordered):
        for j in range(i):
            b = ordered[j]
            if a.first_seen - b.last_seen > horizon:
                continue
            if ents[i] & ents[j]:
                dsu.union(i, j)

    groups: dict[int, list[Alert]] = {}
    for idx, alert in enumerate(ordered):
        groups.setdefault(dsu.find(idx), []).append(alert)

    incidents = []
    for members in sorted(groups.values(), key=lambda g: min(a.first_seen for a in g)):
        incident = Incident(id="", alerts=members)
        incident.severity = max((a.severity for a in members), key=lambda s: SEVERITY_ORDER.get(s, 0))
        incident.entities = _entities_summary(incident, inventory)
        incident.name = _name(incident)
        incidents.append(incident)
    for n, incident in enumerate(incidents, 1):
        incident.id = f"INC-{n:03d}"
    return incidents


def kill_chain_index(tactic: str) -> int:
    return KILL_CHAIN.index(tactic) if tactic in KILL_CHAIN else len(KILL_CHAIN)
