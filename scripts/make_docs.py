"""Regenerate docs/DETECTIONS.md and docs/EVALUATION.md from a real run.

Run after changing rules or the simulator so the numbers in the docs always match the code:

    python scripts/make_docs.py
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from intellidetect.engine import Detector
from intellidetect.evaluate import evaluate, markdown
from intellidetect.matching import Context
from intellidetect.mitre import technique_name
from intellidetect.pipeline import run_pipeline
from intellidetect.reporting import incident_markdown, summary
from intellidetect.simulator import Simulator

DOCS = Path(__file__).resolve().parent.parent / "docs"
START = datetime(2026, 3, 10, 8, 0, 0, tzinfo=timezone.utc)


def detections_doc(detector: Detector) -> str:
    rows = detector.catalog()
    lines = [
        "# Detection catalog",
        "",
        f"{len(rows)} detections, each mapped to a MITRE ATT&CK tactic and technique. "
        "`sigma` rules are single-event and portable (see `src/intellidetect/rules/sigma/`); "
        "the other types are stateful and defined in `src/intellidetect/rules/native.yml`.",
        "",
        "| ID | Detection | Severity | Tactic | Technique | Type |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        tech = f"{r['technique']} {technique_name(r['technique'])}" if r["technique"] else "-"
        lines.append(f"| `{r['id']}` | {r['title']} | {r['severity']} | {r['tactic']} | {tech} | {r['type']} |")
    lines += [
        "",
        "## Rule types",
        "",
        "| Type | What it detects | Example |",
        "|---|---|---|",
        "| `sigma` | One event matching field conditions (`contains`, `endswith`, `re`, `1 of`, `not`) | "
        "Office spawning PowerShell |",
        "| `threshold` | N events (or a sum of a numeric field) from one key within a time window | "
        "8 failed SSH logins in 120 s |",
        "| `distinct` | N distinct values of a field within a window | 15 ports probed in 60 s |",
        "| `sequence` | A trigger event preceded by N related events for the same key | "
        "Login success after 5 failures |",
        "| `beacon` | Regular-interval connections (low jitter) from a host to one destination | "
        "C2 check-in every 60 s |",
        "",
        "To see the Splunk version of every Sigma rule: `intellidetect sigma-to-spl`.",
        "",
    ]
    return "\n".join(lines)


def evaluation_doc() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        Simulator(seed=1337, start=START).generate().write(tmp)
        result = run_pipeline(tmp)
        report = evaluate(result)
        untuned = Detector(ctx=Context()).run(result.events)
        s = summary(result)
    extra = len(untuned) - len(result.alerts)
    lines = [
        "# Evaluation",
        "",
        "## What this measures (and what it does not)",
        "",
        "The simulator (`src/intellidetect/simulator.py`) generates about "
        f"{s['events']:,} log lines over 8 hours: normal workday traffic, five deliberately tricky "
        "benign cases, and four labeled attack scenarios. `intellidetect evaluate` runs the full "
        "pipeline and checks the result against `ground_truth.json`.",
        "",
        "**This is a regression and sanity test, not a claim of real-world accuracy.** The same person "
        "wrote the attacks and the detections, the data is synthetic, and the rules are tuned to this "
        "environment. Real logs are messier. Treat the numbers as proof that the pipeline behaves as "
        "designed (and a safety net when changing rules), not as a benchmark.",
        "",
        "## Results (seed 1337)",
        "",
        markdown(report),
        "",
        "## Why the tuning matters",
        "",
        "With the environment allow-lists disabled (authorized scanner, backup target, known-good "
        f"telemetry destination) the same data produces **{len(untuned)} alerts instead of "
        f"{len(result.alerts)}**: {extra} extra alerts that are all benign. The tricky cases:",
        "",
        "| Case | What it looks like | How it is handled |",
        "|---|---|---|",
        "| N1 Authorized vulnerability scan | Port scan plus SMB sweep | `trusted_scanners` allow-list |",
        "| N2 Scheduled backup | 400 MB sent to an external IP | `backup_destinations` allow-list |",
        "| N3 Teams telemetry | Connection every 30 s (beacon-shaped) | `known_good_destinations` allow-list |",
        "| N4 Mistyped password | 4 failures then success | Below the 5-failure sequence threshold |",
        "| N5 Help-desk `whoami /priv` | Real detection, benign cause | Fires as a low-risk P4 incident to close |",
        "",
        "## Reproduce",
        "",
        "```bash",
        "intellidetect simulate --out data --start 2026-03-10T08:00:00",
        "intellidetect evaluate --logs data",
        "```",
        "",
        "## Known limitations",
        "",
        "- Allow-lists are static YAML; a production deployment needs them fed from a CMDB.",
        "- Correlation links alerts by shared host, user or IP inside a 30-minute gap. It does not "
        "follow process trees or network flows between hosts.",
        "- The bundled threat-intel feed is synthetic. Bring your own CSV with `--intel`.",
        "- Sigma support covers the subset documented in `src/intellidetect/sigma.py` (no `near`, "
        "`count()` aggregations or field-mapping pipelines).",
        "- Log formats are fixed (OpenSSH/sudo syslog, Sysmon key=value, iptables-style, Apache combined).",
        "",
    ]
    return "\n".join(lines)


def example_report() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        Simulator(seed=1337, start=START).generate().write(tmp)
        top = run_pipeline(tmp).ranked_incidents[0]
    return incident_markdown(top)


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    (DOCS / "examples").mkdir(exist_ok=True)
    (DOCS / "examples" / "incident-report-multistage.md").write_text(
        example_report(), encoding="utf-8", newline="\n"
    )
    (DOCS / "DETECTIONS.md").write_text(detections_doc(Detector()), encoding="utf-8", newline="\n")
    (DOCS / "EVALUATION.md").write_text(evaluation_doc(), encoding="utf-8", newline="\n")
    print("wrote docs/DETECTIONS.md and docs/EVALUATION.md")


if __name__ == "__main__":
    main()
