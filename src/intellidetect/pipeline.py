"""End-to-end pipeline: parse logs -> detect -> correlate -> enrich/score."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .correlate import correlate
from .engine import Detector, load_native_rules
from .enrich import IntelFeed, Inventory, load_environment, load_intel
from .matching import Context
from .models import Alert, Event, Incident
from .parsers import ParseStats, parse_directory
from .scoring import score_incident
from .sigma import load_sigma_dir


@dataclass
class Result:
    events: list[Event]
    parse_stats: dict[str, ParseStats]
    alerts: list[Alert]
    incidents: list[Incident]
    ctx: Context
    inventory: Inventory
    intel: IntelFeed
    detector: Detector
    truth: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ranked_incidents(self) -> list[Incident]:
        return sorted(self.incidents, key=lambda i: (-i.score, i.first_seen))


def load_truth(logs_dir: str | Path) -> dict[str, Any] | None:
    path = Path(logs_dir) / "ground_truth.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def run_pipeline(
    logs_dir: str | Path,
    year: int | None = None,
    env_path: str | Path | None = None,
    intel_path: str | Path | None = None,
    rules_path: str | Path | None = None,
    sigma_dir: str | Path | None = None,
) -> Result:
    truth = load_truth(logs_dir)
    if year is None and truth:
        year = truth.get("year")
    ctx, inventory = load_environment(env_path)
    intel = load_intel(intel_path)

    events, stats = parse_directory(logs_dir, year=year)
    if not events:
        raise FileNotFoundError(f"No parsable log files found in {logs_dir}")

    detector = Detector(
        native=load_native_rules(rules_path) if rules_path else None,
        sigma=load_sigma_dir(sigma_dir) if sigma_dir else None,
        ctx=ctx,
    )
    alerts = detector.run(events)
    incidents = correlate(alerts, inventory)
    for incident in incidents:
        score_incident(incident, inventory, intel)

    notes = []
    for kind, st in stats.items():
        if st.skipped:
            notes.append(f"{kind}: {st.skipped} of {st.total} lines could not be parsed")
    return Result(events, stats, alerts, incidents, ctx, inventory, intel, detector, truth, notes)
