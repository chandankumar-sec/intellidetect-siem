import json

import pytest

from intellidetect import cli
from intellidetect.engine import Detector
from intellidetect.evaluate import evaluate, markdown
from intellidetect.matching import Context
from intellidetect.pipeline import run_pipeline
from intellidetect.reporting import (
    incident_markdown,
    navigator_layer,
    recommended_actions,
    summary,
    write_outputs,
)
from intellidetect.simulator import Simulator

from .conftest import T0


def test_simulator_is_deterministic(tmp_path):
    Simulator(seed=7, start=T0).generate().write(tmp_path / "a")
    Simulator(seed=7, start=T0).generate().write(tmp_path / "b")
    for name in ("auth.log", "sysmon.log", "firewall.log", "apache_access.log", "ground_truth.json"):
        assert (tmp_path / "a" / name).read_text() == (tmp_path / "b" / name).read_text()
    Simulator(seed=8, start=T0).generate().write(tmp_path / "c")
    assert (tmp_path / "a" / "auth.log").read_text() != (tmp_path / "c" / "auth.log").read_text()


def test_simulator_writes_ground_truth(sim_dir):
    truth = json.loads((sim_dir / "ground_truth.json").read_text())
    ids = [s["id"] for s in truth["scenarios"]]
    assert {"S1", "S2", "S3", "S4", "N1", "N5"} <= set(ids)
    assert truth["year"] == 2026 and sum(truth["events"].values()) > 5000


def test_every_log_line_parses(result):
    for kind, stats in result.parse_stats.items():
        assert stats.skipped == 0, f"{kind}: {stats.samples}"
        assert stats.parsed == stats.total > 0


def test_all_attack_scenarios_detected_and_correlated(result):
    report = evaluate(result)
    failures = [r for r in report["scenarios"] if not r["pass"]]
    assert not failures, failures
    assert report["attack_scenarios_detected"] == report["attack_scenarios_total"] == 4
    assert report["rule_recall"] == 1.0
    assert report["unattributed_alerts"] == []


def test_alert_fatigue_is_actually_reduced(result):
    s = summary(result)
    assert s["events"] > 5000 and s["incidents"] <= 6
    assert s["alerts"] < s["events"] / 100
    assert s["reduction_events_to_incidents_pct"] > 99


def test_top_incident_is_the_multistage_intrusion(result):
    top = result.ranked_incidents[0]
    assert top.priority == "P1" and "WS-ALICE" in top.entities["hosts"]
    assert len(top.tactics) >= 7 and top.score >= 90


def test_benign_help_desk_case_is_low_priority(result):
    low = [i for i in result.incidents if "WS-DAVE" in i.entities["hosts"]]
    assert len(low) == 1 and low[0].priority == "P4"


def test_allowlists_matter(result):
    """Without the environment allow-lists the benign scanner/backup/telemetry cases would alert."""
    untuned = Detector(ctx=Context()).run(result.events)
    assert len(untuned) > len(result.alerts)
    assert {"IDT-004", "IDT-005", "IDT-006", "IDT-007"} <= {a.rule_id for a in untuned}


def test_run_is_deterministic(sim_dir, result):
    again = run_pipeline(sim_dir)
    assert [a.to_dict() for a in again.alerts] == [a.to_dict() for a in result.alerts]
    assert [i.to_dict() for i in again.incidents] == [i.to_dict() for i in result.incidents]


def test_missing_logs_raise(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_pipeline(tmp_path)


def test_evaluate_requires_ground_truth(sim_dir, tmp_path):
    only_auth = tmp_path / "logs"
    only_auth.mkdir()
    (only_auth / "auth.log").write_text((sim_dir / "auth.log").read_text())
    res = run_pipeline(only_auth, year=2026)
    with pytest.raises(ValueError):
        evaluate(res)


def test_markdown_report_contains_key_sections(result):
    text = incident_markdown(result.ranked_incidents[0])
    for section in ("## Summary", "## Kill-chain timeline", "## Why this score", "## Evidence",
                    "## Recommended response", "T1003.001", "192.0.2.77"):
        assert section in text
    assert text.count("\n1. ") >= 1


def test_recommended_actions_are_deduplicated(result):
    actions = recommended_actions(result.ranked_incidents[0])
    assert len(actions) == len(set(actions)) >= 6


def test_navigator_layer_is_valid(result):
    layer = navigator_layer(result)
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1110.001", "T1003.001", "T1048", "T1505.003"} <= ids


def test_write_outputs_creates_everything_and_cleans_stale_reports(result, tmp_path):
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "INC-099.md").write_text("stale")
    paths = write_outputs(result, tmp_path)
    assert all(p.exists() for p in paths.values())
    assert not (tmp_path / "reports" / "INC-099.md").exists()
    assert len(list((tmp_path / "reports").glob("INC-*.md"))) == len(result.incidents)
    incidents = json.loads(paths["incidents"].read_text())
    assert incidents[0]["score"] >= incidents[-1]["score"]


def test_dashboard_is_self_contained_and_escapes_script_end(result, tmp_path):
    result.alerts[0].evidence.append("</script><img src=x onerror=alert(1)>")
    try:
        html = write_outputs(result, tmp_path)["dashboard"].read_text(encoding="utf-8")
    finally:
        result.alerts[0].evidence.pop()
    assert "http://" not in html.split("<script id")[0] and "https://" not in html.split("<script id")[0]
    payload = html.split('<script id="data" type="application/json">')[1].split("</script>")[0]
    data = json.loads(payload)  # still valid JSON, and the injected tag could not close the script
    assert len(data["incidents"]) == len(result.incidents)
    assert "<img src=x" not in html.replace("<\\/script><img", "")


def test_evaluate_markdown_table(result):
    text = markdown(evaluate(result))
    assert "PASS" in text and "FAIL" not in text and "S2 Phishing" in text


# ----------------------------------------------------------------------------- CLI
def test_cli_end_to_end(tmp_path, capsys):
    logs, out = tmp_path / "logs", tmp_path / "out"
    assert cli.main(["simulate", "--out", str(logs), "--start", "2026-03-10T08:00:00"]) == 0
    assert cli.main(["detect", "--logs", str(logs), "--out", str(out)]) == 0
    assert (out / "dashboard.html").exists()
    assert cli.main(["evaluate", "--logs", str(logs), "--json", str(tmp_path / "e.json")]) == 0
    assert json.loads((tmp_path / "e.json").read_text())["attack_scenarios_detected"] == 4
    captured = capsys.readouterr().out
    assert "Noise reduction" in captured and "PASS" in captured


def test_cli_rules_and_spl(capsys):
    assert cli.main(["rules"]) == 0
    assert "IDT-003" in capsys.readouterr().out
    assert cli.main(["sigma-to-spl", "--index", "wineventlog"]) == 0
    assert "index=wineventlog" in capsys.readouterr().out


def test_cli_demo_and_errors(tmp_path, capsys):
    assert cli.main(["demo", "--out", str(tmp_path / "demo")]) == 0
    assert (tmp_path / "demo" / "reports" / "INC-001.md").exists()
    assert cli.main(["detect", "--logs", str(tmp_path / "missing"), "--out", str(tmp_path / "x")]) == 2
    assert "error:" in capsys.readouterr().err
