"""Environment context (asset inventory, allow-lists) and threat-intel enrichment.

The bundled IOC feed is synthetic and only matches the simulator's addresses. Swap in a real
feed (CSV with the same columns) via ``--intel`` to enrich real data.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .matching import Context

DATA_DIR = Path(__file__).parent / "data"
CRITICALITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Inventory:
    """Asset inventory with lookups by hostname and IP."""

    assets: dict[str, dict[str, Any]] = field(default_factory=dict)  # host.lower() -> asset
    by_ip: dict[str, str] = field(default_factory=dict)  # ip -> host.lower()

    def host_for_ip(self, ip: str) -> str:
        return self.by_ip.get(ip, "")

    def ip_for_host(self, host: str) -> str:
        return self.assets.get(host.lower(), {}).get("ip", "")

    def info(self, host: str) -> dict[str, Any] | None:
        return self.assets.get(host.lower())

    def criticality(self, host: str) -> str:
        return self.assets.get(host.lower(), {}).get("criticality", "low")


def load_environment(path: str | Path | None = None) -> tuple[Context, Inventory]:
    path = Path(path) if path else DATA_DIR / "environment.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    lists = {name: {str(v).lower() for v in values} for name, values in doc.get("lists", {}).items()}
    assets = {a["host"].lower(): a for a in doc.get("assets", [])}
    inventory = Inventory(assets=assets, by_ip={a["ip"]: h for h, a in assets.items() if "ip" in a})
    return Context(lists=lists, assets=assets), inventory


@dataclass
class IntelFeed:
    indicators: dict[str, dict[str, Any]] = field(default_factory=dict)

    def lookup(self, value: str) -> dict[str, Any] | None:
        return self.indicators.get(value.lower())


def load_intel(path: str | Path | None = None) -> IntelFeed:
    path = Path(path) if path else DATA_DIR / "ioc_feed.csv"
    feed = IntelFeed()
    with open(path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            row["confidence"] = int(row.get("confidence") or 0)
            feed.indicators[row["indicator"].lower()] = row
    return feed
