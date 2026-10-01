"""Explainable incident risk scoring (0-100).

Every point is attributed to a reason so an analyst can see *why* an incident ranks where it
does, instead of trusting an opaque number.
"""

from __future__ import annotations

from .enrich import CRITICALITY_RANK, IntelFeed, Inventory
from .models import Incident

SEVERITY_POINTS = {"low": 5, "medium": 15, "high": 30, "critical": 40}
ASSET_POINTS = {"critical": 12, "high": 7, "medium": 3, "low": 0}


def priority_for(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


def score_incident(incident: Incident, inventory: Inventory, intel: IntelFeed) -> Incident:
    parts: list[tuple[str, int]] = []

    parts.append((f"Highest alert severity: {incident.severity}", SEVERITY_POINTS[incident.severity]))

    stages = len(incident.tactics)
    if stages > 1:
        parts.append((f"Kill-chain progression: {stages} tactics ({' > '.join(incident.tactics)})",
                      min(6 * (stages - 1), 24)))

    hosts = incident.entities.get("hosts", [])
    if hosts:
        best = max(hosts, key=lambda h: CRITICALITY_RANK.get(inventory.criticality(h), 0))
        crit = inventory.criticality(best)
        if ASSET_POINTS[crit]:
            parts.append((f"Involves {crit} asset {best}", ASSET_POINTS[crit]))

    incident.intel = []
    seen: set[str] = set()
    for alert in incident.alerts:
        for ind in alert.indicators:
            if ind in seen:
                continue
            seen.add(ind)
            hit = intel.lookup(ind)
            if hit:
                incident.intel.append({"indicator": ind, **hit})
    if incident.intel:
        top = max(incident.intel, key=lambda h: h["confidence"])
        bonus = 15 if top["confidence"] >= 85 else 8
        parts.append((f"Threat-intel match: {top['indicator']} ({top['threat']})", bonus))

    volume = sum(a.count for a in incident.alerts)
    if volume >= 50:
        parts.append((f"Sustained activity: {volume} underlying detections", 5))

    incident.score_breakdown = parts
    incident.score = min(100, sum(p for _, p in parts))
    incident.priority = priority_for(incident.score)
    return incident
