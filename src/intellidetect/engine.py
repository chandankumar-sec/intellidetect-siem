"""Detection engine: stateless Sigma rules plus stateful (windowed) detections.

All time logic uses *event* timestamps, never the wall clock, so historical logs can be
replayed and give the same result as live ingestion.

Native rule types (``rules/native.yml``)
----------------------------------------
threshold   N matching events from one ``group_by`` key inside ``window`` seconds
distinct    N distinct values of ``distinct`` field inside ``window`` seconds
sequence    a ``match`` event preceded by N ``preceded_by`` events for the same key
beacon      regular-interval connections (low jitter) from one host to one destination
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .matching import Context, compile_selection
from .models import Alert, Event
from .sigma import SigmaRule, load_sigma_dir

RULES_DIR = Path(__file__).parent / "rules"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _evidence(events: list[Event], limit: int = 3) -> list[str]:
    return [e.raw.strip()[:220] for e in events[:limit] if e.raw]


def _indicators(events: list[Event]) -> list[str]:
    """Network indicators (external IPs, queried domains) seen in the events, for enrichment."""
    from .models import is_public_ip

    seen: list[str] = []
    for e in events:
        for value in (e.src_ip, e.dst_ip, e.data.get("query", "")):
            if value and value not in seen and (not value[0].isdigit() or is_public_ip(value)):
                seen.append(value)
    return seen[:10]


def _dominant(values: list[str]) -> str:
    values = [v for v in values if v]
    return Counter(values).most_common(1)[0][0] if values else ""


class NativeRule:
    """Base class for stateful rules defined in YAML."""

    def __init__(self, spec: dict[str, Any]):
        self.spec = spec
        self.id: str = spec["id"]
        self.title: str = spec["title"]
        self.severity: str = spec.get("severity", "medium")
        self.tactic: str = spec.get("tactic", "")
        self.technique: str = spec.get("technique", "")
        self.description: str = (spec.get("description") or "").strip()
        self.tags: list[str] = list(spec.get("tags", []))
        self.group_by: str = spec.get("group_by", "src_ip")
        self.window: float = float(spec.get("window", 300))
        self.count: int = int(spec.get("count", 1))
        self._match = compile_selection(spec.get("match", {}))
        self._exclude = compile_selection(spec["exclude"]) if spec.get("exclude") else None

    def accepts(self, event: Event, ctx: Context) -> bool:
        if not self._match(event, ctx):
            return False
        return not (self._exclude and self._exclude(event, ctx))

    def build(self, events: list[Event], first: datetime, last: datetime, key: str = "") -> Alert:
        alert = Alert(
            id="", rule_id=self.id, rule_title=self.title, severity=self.severity,
            tactic=self.tactic, technique=self.technique, description=self.description,
            first_seen=first, last_seen=last, count=len(events),
            host=_dominant([e.host for e in events]),
            user=_dominant([e.user for e in events]),
            src_ip=_dominant([e.src_ip for e in events]),
            dst_ip=_dominant([e.dst_ip for e in events]),
            evidence=_evidence(events),
            confidence=int(self.spec.get("confidence", 75)),
            tags=self.tags,
            indicators=_indicators(events),
        )
        if self.group_by in ("src_ip", "dst_ip", "host", "user") and key:
            setattr(alert, self.group_by, key)
        return alert

    def evaluate(self, events: list[Event], ctx: Context) -> list[Alert]:
        raise NotImplementedError


class WindowRule(NativeRule):
    """threshold / distinct: count (distinct) events per key in a sliding window."""

    def __init__(self, spec: dict[str, Any]):
        super().__init__(spec)
        self.distinct: str | None = spec.get("distinct")
        self.sum_field: str | None = spec.get("sum")

    def _metric(self, window: deque[Event]) -> int:
        if self.sum_field:
            return sum(int(e.get(self.sum_field) or 0) for e in window)
        if self.distinct:
            return len({e.get(self.distinct) for e in window if e.get(self.distinct) is not None})
        return len(window)

    def evaluate(self, events: list[Event], ctx: Context) -> list[Alert]:
        windows: dict[str, deque[Event]] = defaultdict(deque)
        active: dict[str, tuple[Alert, list[Event]]] = {}
        alerts: list[Alert] = []
        bursts: list[tuple[Alert, list[Event], str]] = []
        for ev in events:
            if not self.accepts(ev, ctx):
                continue
            key = ev.get(self.group_by)
            if not key:
                continue
            key = str(key)
            win = windows[key]
            win.append(ev)
            while (ev.ts - win[0].ts).total_seconds() > self.window:
                win.popleft()
            current = active.get(key)
            if current and (ev.ts - current[0].last_seen).total_seconds() <= self.window:
                current[0].last_seen = ev.ts  # same burst: fold into the open alert
                current[0].count += 1
                current[1].append(ev)
                continue
            if self._metric(win) >= self.count:
                members = list(win)
                if self.sum_field:  # report the smallest window that already crosses the threshold
                    while len(members) > 1 and self._metric(deque(members[1:])) >= self.count:
                        members.pop(0)
                alert = self.build(members, members[0].ts, ev.ts, key)
                alerts.append(alert)
                active[key] = (alert, members)
                bursts.append((alert, members, key))
        # Re-derive entities from the whole burst, not just the events seen at trigger time.
        for alert, members, key in bursts:
            full = self.build(members, alert.first_seen, alert.last_seen, key)
            alert.host, alert.user = full.host, full.user
            alert.src_ip, alert.dst_ip = full.src_ip, full.dst_ip
            alert.indicators = full.indicators
        return alerts


class SequenceRule(NativeRule):
    """A trigger event that follows ``preceded_by.count`` prior events for the same key."""

    def __init__(self, spec: dict[str, Any]):
        super().__init__(spec)
        prior = spec["preceded_by"]
        self._prior = compile_selection(prior["match"])
        self.prior_count = int(prior.get("count", 1))

    def evaluate(self, events: list[Event], ctx: Context) -> list[Alert]:
        priors: dict[str, deque[Event]] = defaultdict(deque)
        last_alert: dict[str, datetime] = {}
        alerts: list[Alert] = []
        for ev in events:
            key = ev.get(self.group_by)
            if not key:
                continue
            key = str(key)
            if self._prior(ev, ctx):
                dq = priors[key]
                dq.append(ev)
                while (ev.ts - dq[0].ts).total_seconds() > self.window:
                    dq.popleft()
            elif self.accepts(ev, ctx):
                dq = priors[key]
                while dq and (ev.ts - dq[0].ts).total_seconds() > self.window:
                    dq.popleft()
                recent = last_alert.get(key)
                if len(dq) >= self.prior_count and not (
                    recent and (ev.ts - recent).total_seconds() <= self.window
                ):
                    chain = [*dq, ev]
                    alert = self.build(chain, dq[0].ts, ev.ts, key)
                    alert.user = ev.user or alert.user
                    alert.host = ev.host or alert.host
                    alert.evidence = _evidence(list(dq)[-2:]) + _evidence([ev], 1)
                    alerts.append(alert)
                    last_alert[key] = ev.ts
        return alerts


class BeaconRule(NativeRule):
    """Detect C2-style beaconing: many connections to one destination at regular intervals."""

    def __init__(self, spec: dict[str, Any]):
        super().__init__(spec)
        self.max_cv: float = float(spec.get("max_jitter", 0.25))
        self.min_interval: float = float(spec.get("min_interval", 5))
        self.max_interval: float = float(spec.get("max_interval", 900))

    def evaluate(self, events: list[Event], ctx: Context) -> list[Alert]:
        groups: dict[tuple[str, str, int], list[Event]] = defaultdict(list)
        for ev in events:
            if self.accepts(ev, ctx) and ev.dst_ip:
                groups[(ev.host, ev.dst_ip, ev.dst_port)].append(ev)
        alerts: list[Alert] = []
        for (_host, _dst, _port), evs in groups.items():
            n = self.count
            for i in range(0, max(0, len(evs) - n + 1)):
                chunk = evs[i : i + n]
                span = (chunk[-1].ts - chunk[0].ts).total_seconds()
                if span > self.window:
                    continue
                gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(chunk, chunk[1:], strict=False)]
                mean = statistics.fmean(gaps)
                if not (self.min_interval <= mean <= self.max_interval):
                    continue
                cv = statistics.pstdev(gaps) / mean if mean else 1.0
                if cv <= self.max_cv:
                    alert = self.build(evs, evs[0].ts, evs[-1].ts)
                    alert.description = (
                        f"{self.description} {len(evs)} connections, mean interval "
                        f"{mean:.0f}s, jitter {cv:.0%}."
                    ).strip()
                    alerts.append(alert)
                    break
        return alerts


NATIVE_TYPES = {
    "threshold": WindowRule,
    "distinct": WindowRule,
    "sequence": SequenceRule,
    "beacon": BeaconRule,
}


def load_native_rules(path: str | Path | None = None) -> list[NativeRule]:
    path = Path(path) if path else RULES_DIR / "native.yml"
    docs = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    rules = []
    for spec in docs:
        rule_type = spec.get("type")
        if rule_type not in NATIVE_TYPES:
            raise ValueError(f"{spec.get('id')}: unknown rule type {rule_type!r}")
        rules.append(NATIVE_TYPES[rule_type](spec))
    return rules


class Detector:
    """Runs Sigma + native rules over an event stream and returns de-duplicated alerts."""

    def __init__(
        self,
        native: list[NativeRule] | None = None,
        sigma: list[SigmaRule] | None = None,
        ctx: Context | None = None,
        sigma_cooldown: float = 300,
    ):
        self.native = load_native_rules() if native is None else native
        self.sigma = load_sigma_dir(RULES_DIR / "sigma") if sigma is None else sigma
        self.ctx = ctx or Context()
        self.sigma_cooldown = sigma_cooldown

    def _run_sigma(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        open_alerts: dict[tuple[str, str, str, str], Alert] = {}
        for ev in events:
            for rule in self.sigma:
                if not rule.matches(ev, self.ctx):
                    continue
                key = (rule.id, ev.host, ev.user, ev.src_ip)
                current = open_alerts.get(key)
                if current and (ev.ts - current.last_seen).total_seconds() <= self.sigma_cooldown:
                    current.last_seen = ev.ts
                    current.count += 1
                    continue
                alert = Alert(
                    id="", rule_id=rule.id, rule_title=rule.title, severity=rule.severity,
                    tactic=rule.tactic, technique=rule.technique, description=rule.description,
                    first_seen=ev.ts, last_seen=ev.ts, host=ev.host, user=ev.user,
                    src_ip=ev.src_ip, dst_ip=ev.dst_ip, evidence=_evidence([ev]),
                    confidence=80, tags=rule.tags, indicators=_indicators([ev]),
                )
                open_alerts[key] = alert
                alerts.append(alert)
        return alerts

    def run(self, events: list[Event]) -> list[Alert]:
        events = sorted(events, key=lambda e: e.ts)
        alerts = self._run_sigma(events)
        for rule in self.native:
            alerts.extend(rule.evaluate(events, self.ctx))
        alerts.sort(key=lambda a: (a.first_seen, -SEVERITY_ORDER.get(a.severity, 0)))
        for i, alert in enumerate(alerts, 1):
            alert.id = f"ALR-{i:04d}"
        return alerts

    def catalog(self) -> list[dict[str, str]]:
        """Metadata for every loaded rule (used by docs and ``intellidetect rules``)."""
        rows = [
            {"id": r.id, "title": r.title, "severity": r.severity, "tactic": r.tactic,
             "technique": r.technique, "type": "sigma", "source": r.source}
            for r in self.sigma
        ]
        rows += [
            {"id": r.id, "title": r.title, "severity": r.severity, "tactic": r.tactic,
             "technique": r.technique, "type": r.spec["type"], "source": "native.yml"}
            for r in self.native
        ]
        return sorted(rows, key=lambda r: (r["tactic"], r["id"]))
