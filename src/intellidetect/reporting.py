"""Output writers: incident reports (Markdown), ATT&CK Navigator layer, JSON exports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mitre import KILL_CHAIN, technique_name
from .models import Incident
from .pipeline import Result

ACTIONS: dict[str, list[str]] = {
    "T1110.001": [
        "Block the source IP at the perimeter firewall and review whether any login from it succeeded.",
        "Enforce key-only SSH (disable password auth) and deploy fail2ban or equivalent rate limiting.",
    ],
    "T1110.003": ["Check the targeted accounts for successful logins and force a password reset where needed."],
    "T1078": [
        "Disable the compromised account, revoke active sessions and SSH keys, then reset credentials.",
        "Review everything the account did from the first failed login onward (sudo, new keys, cron).",
    ],
    "T1059.001": [
        "Isolate the host from the network (EDR containment) before further triage.",
        "Decode the PowerShell payload, extract URLs, IPs and file paths, and hunt for them fleet-wide.",
    ],
    "T1059.004": ["Capture the downloaded script and review it; check the host for new users, cron jobs and SSH keys."],
    "T1566.001": ["Pull the original phishing email, delete it from all mailboxes and block the sender and URLs."],
    "T1204.002": ["Quarantine the malicious document and check who else received or opened it."],
    "T1105": ["Retrieve the downloaded payload for sandbox analysis and block the source URL or IP."],
    "T1053.005": ["Delete the rogue scheduled task after collecting its action; look for other persistence."],
    "T1003.001": [
        "Treat every credential on the host as stolen: reset the user and any admin that logged on recently.",
        "Rotate krbtgt twice if a domain controller or domain admin credential may be exposed.",
    ],
    "T1087": ["Review what the account enumerated and whether the same user ran other discovery commands."],
    "T1046": ["Identify the scanning host; if internal, treat it as a likely compromised system."],
    "T1021.002": ["Isolate the destination host, collect the dropped service binary and check for new accounts."],
    "T1569.002": ["Isolate the destination host, collect the dropped service binary and check for new accounts."],
    "T1071.001": [
        "Block the C2 address and domain at the proxy, firewall and DNS.",
        "Search other hosts for connections to the same destination (hunt for additional victims).",
    ],
    "T1048": [
        "Quantify what left the network (bytes, destination, timeframe) and involve the data owner.",
        "Check legal and regulatory notification requirements before closing the incident.",
    ],
    "T1190": ["Patch or virtual-patch the vulnerable endpoint and review the application and database logs."],
    "T1505.003": [
        "Remove the web shell, rotate any secrets stored on the web server and rebuild from a known-good image.",
        "Review file-system changes under the upload directory and outbound connections from the web server.",
    ],
    "T1595": ["Rate-limit or block the client; confirm no probed path returned sensitive content."],
}
GENERIC_ACTIONS = [
    "Preserve evidence (memory, logs, disk image) before remediation.",
    "Document the timeline, scope and containment steps in the ticket.",
]


def _fmt(ts: Any) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def recommended_actions(incident: Incident) -> list[str]:
    seen: list[str] = []
    for alert in sorted(incident.alerts, key=lambda a: a.first_seen):
        for action in ACTIONS.get(alert.technique, []):
            if action not in seen:
                seen.append(action)
    return seen + GENERIC_ACTIONS


def narrative(incident: Incident) -> str:
    n = len(incident.alerts)
    minutes = max(1, round((incident.last_seen - incident.first_seen).total_seconds() / 60))
    ents = incident.entities
    parts = [
        f"Between {_fmt(incident.first_seen)} and {_fmt(incident.last_seen)} UTC (about {minutes} min), "
        f"{n} detection(s) were correlated into one incident covering {len(incident.tactics)} ATT&CK "
        f"tactic(s): {', '.join(incident.tactics)}."
    ]
    if ents.get("hosts"):
        parts.append(f"Affected hosts: {', '.join(ents['hosts'])}.")
    if ents.get("users"):
        parts.append(f"Accounts involved: {', '.join(ents['users'])}.")
    if ents.get("external_ips"):
        parts.append(f"External addresses: {', '.join(ents['external_ips'])}.")
    if incident.intel:
        names = "; ".join(f"{i['indicator']} ({i['threat']})" for i in incident.intel)
        parts.append(f"Threat-intel matches: {names}.")
    return " ".join(parts)


def incident_markdown(incident: Incident) -> str:
    lines = [
        f"# {incident.id}: {incident.name}",
        "",
        "| Priority | Risk score | Severity | First seen (UTC) | Last seen (UTC) |",
        "|---|---|---|---|---|",
        f"| **{incident.priority}** | {incident.score}/100 | {incident.severity} | "
        f"{_fmt(incident.first_seen)} | {_fmt(incident.last_seen)} |",
        "",
        "## Summary",
        "",
        narrative(incident),
        "",
        "## Kill-chain timeline",
        "",
        "| Time (UTC) | Tactic | Technique | Detection | Entity | Events |",
        "|---|---|---|---|---|---|",
    ]
    for a in sorted(incident.alerts, key=lambda x: x.first_seen):
        entity = a.host or a.src_ip or a.user
        tech = f"{a.technique} {technique_name(a.technique)}" if a.technique else "-"
        lines.append(
            f"| {_fmt(a.first_seen)} | {a.tactic or '-'} | {tech} | {a.rule_title} (`{a.rule_id}`) | "
            f"{entity} | {a.count} |"
        )
    lines += ["", "## Why this score", "", "| Points | Reason |", "|---|---|"]
    lines += [f"| +{p} | {r} |" for r, p in incident.score_breakdown]
    lines += [f"| **{incident.score}** | **Total** |", "", "## Entities and indicators", ""]
    for label, key in (("Hosts", "hosts"), ("Users", "users"), ("External IPs", "external_ips"),
                       ("Internal IPs", "internal_ips")):
        if incident.entities.get(key):
            lines.append(f"- **{label}:** " + ", ".join(f"`{v}`" for v in incident.entities[key]))
    for hit in incident.intel:
        lines.append(f"- **Intel:** `{hit['indicator']}`: {hit['threat']} "
                     f"(confidence {hit['confidence']}, source {hit['source']})")
    lines += ["", "## Evidence", ""]
    for a in sorted(incident.alerts, key=lambda x: x.first_seen):
        if a.evidence:
            lines += [f"**{a.rule_id} {a.rule_title}**", "", "```text", *a.evidence[:2], "```", ""]
    lines += ["## Recommended response", ""]
    lines += [f"{i}. {action}" for i, action in enumerate(recommended_actions(incident), 1)]
    lines += ["", "## Analyst notes", "", "- [ ] Verdict: true positive / benign true positive / false positive",
              "- [ ] Scope confirmed (other hosts, other accounts)", "- [ ] Containment done",
              "- [ ] Detection tuned or new rule written", ""]
    return "\n".join(lines)


def navigator_layer(result: Result) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for alert in result.alerts:
        if alert.technique:
            counts[alert.technique] = counts.get(alert.technique, 0) + 1
    return {
        "name": "IntelliDetect: techniques detected in this run",
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated by IntelliDetect. Score = number of alerts per technique.",
        "gradient": {"colors": ["#ffe5b4", "#ff6666"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
        "techniques": [
            {"techniqueID": t, "score": c, "comment": technique_name(t)} for t, c in sorted(counts.items())
        ],
    }


def summary(result: Result) -> dict[str, Any]:
    n_events, n_alerts, n_inc = len(result.events), len(result.alerts), len(result.incidents)
    by_sev: dict[str, int] = {}
    for a in result.alerts:
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
    tactics = {t: 0 for t in KILL_CHAIN}
    for a in result.alerts:
        if a.tactic in tactics:
            tactics[a.tactic] += 1
    return {
        "events": n_events,
        "alerts": n_alerts,
        "incidents": n_inc,
        "reduction_events_to_incidents_pct": round(100 * (1 - n_inc / n_events), 2) if n_events else 0,
        "alerts_by_severity": by_sev,
        "alerts_by_tactic": {k: v for k, v in tactics.items() if v},
        "priorities": {p: sum(1 for i in result.incidents if i.priority == p) for p in ("P1", "P2", "P3", "P4")},
        "parse": {k: {"total": s.total, "parsed": s.parsed, "skipped": s.skipped}
                  for k, s in result.parse_stats.items()},
    }


def write_outputs(result: Result, out_dir: str | Path) -> dict[str, Path]:
    from .dashboard import build_dashboard

    out = Path(out_dir)
    (out / "reports").mkdir(parents=True, exist_ok=True)
    for stale in (out / "reports").glob("INC-*.md"):  # reports from a previous run
        stale.unlink()
    paths = {
        "alerts": out / "alerts.json",
        "incidents": out / "incidents.json",
        "summary": out / "summary.json",
        "navigator": out / "attack_navigator_layer.json",
        "dashboard": out / "dashboard.html",
    }
    paths["alerts"].write_text(json.dumps([a.to_dict() for a in result.alerts], indent=2), encoding="utf-8")
    paths["incidents"].write_text(
        json.dumps([i.to_dict() for i in result.ranked_incidents], indent=2), encoding="utf-8")
    paths["summary"].write_text(json.dumps(summary(result), indent=2), encoding="utf-8")
    paths["navigator"].write_text(json.dumps(navigator_layer(result), indent=2), encoding="utf-8")
    for incident in result.incidents:
        (out / "reports" / f"{incident.id}.md").write_text(incident_markdown(incident), encoding="utf-8")
    paths["dashboard"].write_text(build_dashboard(result), encoding="utf-8")
    return paths
