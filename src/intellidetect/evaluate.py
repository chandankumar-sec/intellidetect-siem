"""Score a pipeline run against the simulator's ground truth."""

from __future__ import annotations

from typing import Any

from .correlate import alert_entities
from .pipeline import Result


def evaluate(result: Result) -> dict[str, Any]:
    truth = result.truth
    if not truth:
        raise ValueError("No ground_truth.json next to the logs; run `intellidetect simulate` first.")
    inv = result.inventory
    alert_ents = {a.id: alert_entities(a, inv) for a in result.alerts}
    incident_of = {a.id: inc for inc in result.incidents for a in inc.alerts}

    rows: list[dict[str, Any]] = []
    claimed: set[str] = set()
    for sc in truth["scenarios"]:
        wanted = set(sc["entities"])
        expected = set(sc["expected_rules"])
        related = [a for a in result.alerts if alert_ents[a.id] & wanted]
        claimed.update(a.id for a in related)
        hit_rules = {a.rule_id for a in related} & expected
        incidents = {incident_of[a.id].id for a in related if a.rule_id in expected}
        row = {
            "id": sc["id"],
            "name": sc["name"],
            "malicious": sc["malicious"],
            "expected_rules": sorted(expected),
            "detected_rules": sorted(hit_rules),
            "missing_rules": sorted(expected - hit_rules),
            "incidents": sorted(incidents),
            "alerts_on_entities": len(related),
        }
        if sc["malicious"]:
            row["pass"] = not row["missing_rules"] and len(incidents) == 1
        elif expected:  # benign true positive: should alert, and only for the expected rule
            row["pass"] = hit_rules == expected and {a.rule_id for a in related} == expected
        else:  # must stay silent
            row["pass"] = not related
        rows.append(row)

    unattributed = [a for a in result.alerts if a.id not in claimed]
    malicious = [r for r in rows if r["malicious"]]
    exp_total = sum(len(r["expected_rules"]) for r in malicious)
    hit_total = sum(len(r["detected_rules"]) for r in malicious)
    negatives = [r for r in rows if not r["malicious"]]
    n_events, n_alerts, n_inc = len(result.events), len(result.alerts), len(result.incidents)
    return {
        "scenarios": rows,
        "attack_scenarios_detected": sum(1 for r in malicious if r["pass"]),
        "attack_scenarios_total": len(malicious),
        "rule_recall": round(hit_total / exp_total, 3) if exp_total else 1.0,
        "benign_cases_handled": sum(1 for r in negatives if r["pass"]),
        "benign_cases_total": len(negatives),
        "unattributed_alerts": [
            {"id": a.id, "rule": a.rule_id, "title": a.rule_title, "host": a.host, "src_ip": a.src_ip}
            for a in unattributed
        ],
        "volume": {
            "events": n_events,
            "alerts": n_alerts,
            "incidents": n_inc,
            "events_per_incident": round(n_events / n_inc, 1) if n_inc else 0,
            "alerts_per_incident": round(n_alerts / n_inc, 1) if n_inc else 0,
        },
    }


def markdown(report: dict[str, Any]) -> str:
    v = report["volume"]
    lines = [
        "| Metric | Result |",
        "|---|---|",
        f"| Attack scenarios fully detected and correlated into one incident | "
        f"**{report['attack_scenarios_detected']} / {report['attack_scenarios_total']}** |",
        f"| Expected detections that fired (rule-level recall) | **{report['rule_recall']:.0%}** |",
        f"| Benign / tricky cases handled correctly | **{report['benign_cases_handled']} / "
        f"{report['benign_cases_total']}** |",
        f"| Alerts with no matching scenario (unexplained) | **{len(report['unattributed_alerts'])}** |",
        f"| Events ingested -> alerts -> incidents | {v['events']:,} -> {v['alerts']} -> **{v['incidents']}** |",
        "",
        "| Scenario | Type | Expected detections | Fired | Missing | Incidents | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in report["scenarios"]:
        kind = "attack" if r["malicious"] else "benign"
        exp = len(r["expected_rules"]) or "silent"
        lines.append(
            f"| {r['id']} {r['name']} | {kind} | {exp} | {len(r['detected_rules'])} | "
            f"{', '.join(r['missing_rules']) or '-'} | {', '.join(r['incidents']) or '-'} | "
            f"{'PASS' if r['pass'] else 'FAIL'} |"
        )
    return "\n".join(lines)
