"""Command-line interface: ``intellidetect <command>``."""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import socketserver
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .evaluate import evaluate, markdown
from .pipeline import run_pipeline
from .reporting import summary, write_outputs
from .simulator import Simulator


def _print_summary(result) -> None:
    s = summary(result)
    print(f"Events ingested : {s['events']:,}")
    print(f"Alerts raised   : {s['alerts']}")
    print(f"Incidents       : {s['incidents']}  (priorities: {s['priorities']})")
    print(f"Noise reduction : {s['reduction_events_to_incidents_pct']}% (events -> incidents)\n")
    print(f"{'ID':8} {'Prio':5} {'Score':>5}  Incident")
    for inc in result.ranked_incidents:
        print(f"{inc.id:8} {inc.priority:5} {inc.score:>5}  {inc.name}")
    for note in result.notes:
        print(f"note: {note}", file=sys.stderr)


def cmd_simulate(args: argparse.Namespace) -> int:
    start = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc) if args.start else None
    truth = Simulator(seed=args.seed, start=start).generate().write(args.out)
    total = sum(truth["events"].values())
    print(f"Wrote {total:,} log lines and ground_truth.json to {args.out}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    result = run_pipeline(args.logs, year=args.year, env_path=args.env, intel_path=args.intel,
                          rules_path=args.rules, sigma_dir=args.sigma)
    paths = write_outputs(result, args.out)
    _print_summary(result)
    print(f"\nOutputs written to {args.out}  (open {paths['dashboard']})")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    result = run_pipeline(args.logs, year=args.year)
    report = evaluate(result)
    print(markdown(report))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    failed = [r["id"] for r in report["scenarios"] if not r["pass"]]
    return 1 if failed else 0


def cmd_demo(args: argparse.Namespace) -> int:
    logs = Path(args.out) / "logs"
    Simulator(seed=args.seed).generate().write(logs)
    result = run_pipeline(logs)
    paths = write_outputs(result, args.out)
    _print_summary(result)
    print(f"\nDashboard: {paths['dashboard']}")
    if args.serve:
        return cmd_serve(argparse.Namespace(dir=args.out, port=args.port, host=args.host))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .engine import Detector

    rows = Detector().catalog()
    print(f"{'ID':12} {'Sev':9} {'Tactic':22} {'Technique':10} {'Type':10} Title")
    for r in rows:
        print(f"{r['id']:12} {r['severity']:9} {r['tactic']:22} {r['technique']:10} {r['type']:10} {r['title']}")
    print(f"\n{len(rows)} rules loaded")
    return 0


def cmd_spl(args: argparse.Namespace) -> int:
    from .engine import RULES_DIR
    from .sigma import load_sigma_dir, load_sigma_file

    rules = [load_sigma_file(args.rule)] if args.rule else load_sigma_dir(RULES_DIR / "sigma")
    for rule in rules:
        print(f"# {rule.id}: {rule.title}  [{rule.technique}]\n{rule.to_spl(args.index)}\n")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(args.dir))
    with socketserver.TCPServer((args.host, args.port), handler) as httpd:
        print(f"Serving {args.dir} at http://{args.host}:{args.port}/dashboard.html  (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="intellidetect", description="SOC detection and triage pipeline")
    p.add_argument("--version", action="version", version=f"intellidetect {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("simulate", help="generate labeled sample logs")
    s.add_argument("--out", default="data")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--start", help="UTC start time, e.g. 2026-03-10T08:00:00 (default: yesterday 08:00)")
    s.set_defaults(func=cmd_simulate)

    d = sub.add_parser("detect", help="run detections on a log directory")
    d.add_argument("--logs", default="data")
    d.add_argument("--out", default="out")
    d.add_argument("--year", type=int, help="year for syslog timestamps (default: from ground truth/now)")
    d.add_argument("--env", help="custom environment.yml (allow-lists, asset inventory)")
    d.add_argument("--intel", help="custom IOC feed CSV")
    d.add_argument("--rules", help="custom native rules YAML")
    d.add_argument("--sigma", help="directory of Sigma rules")
    d.set_defaults(func=cmd_detect)

    e = sub.add_parser("evaluate", help="score detections against ground truth")
    e.add_argument("--logs", default="data")
    e.add_argument("--year", type=int)
    e.add_argument("--json", help="also write the raw report to this file")
    e.set_defaults(func=cmd_evaluate)

    m = sub.add_parser("demo", help="simulate + detect + report in one step")
    m.add_argument("--out", default="out")
    m.add_argument("--seed", type=int, default=1337)
    m.add_argument("--serve", action="store_true", help="serve the dashboard afterwards")
    m.add_argument("--port", type=int, default=8000)
    m.add_argument("--host", default="127.0.0.1")
    m.set_defaults(func=cmd_demo)

    r = sub.add_parser("rules", help="list loaded detection rules")
    r.set_defaults(func=cmd_rules)

    q = sub.add_parser("sigma-to-spl", help="print Splunk SPL for the Sigma rules")
    q.add_argument("--rule", help="a single Sigma rule file (default: all bundled rules)")
    q.add_argument("--index", default="main")
    q.set_defaults(func=cmd_spl)

    v = sub.add_parser("serve", help="serve an output directory over HTTP")
    v.add_argument("--dir", default="out")
    v.add_argument("--port", type=int, default=8000)
    v.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 inside Docker)")
    v.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
