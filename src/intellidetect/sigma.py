"""Sigma rule support: load rules, evaluate them against events, export to Splunk SPL.

Implements the subset of Sigma used by the bundled rules: selections made of field
matches with the ``contains``/``startswith``/``endswith``/``re``/``all`` modifiers (and
wildcards), lists of maps, and conditions built from ``and``/``or``/``not``, parentheses
and ``1 of`` / ``all of`` quantifiers.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from .matching import Context, compile_selection
from .mitre import tactic_from_tag, technique_from_tag
from .models import Event

# Sigma logsource -> normalized event kind
LOGSOURCE_KINDS = {
    "process_creation": "process_create",
    "process_access": "process_access",
    "network_connection": "network_connect",
    "dns_query": "dns_query",
    "file_event": "file_create",
    "webserver": "http_request",
    "sudo": "sudo",
}

SEVERITIES = {"informational": "low", "low": "low", "medium": "medium",
              "high": "high", "critical": "critical"}

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class SigmaError(ValueError):
    pass


class _Parser:
    """Recursive-descent parser for Sigma condition expressions."""

    def __init__(self, text: str, names: list[str]):
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.names = names

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> Any:
        node = self.or_expr()
        if self.peek() is not None:
            raise SigmaError(f"Unexpected token '{self.peek()}' in condition")
        return node

    def or_expr(self) -> Any:
        node = self.and_expr()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self) -> Any:
        node = self.not_expr()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self) -> Any:
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise SigmaError("Unexpected end of condition")
        if tok == "(":
            self.take()
            node = self.or_expr()
            if self.peek() != ")":
                raise SigmaError("Missing ')' in condition")
            self.take()
            return node
        if tok.lower() in ("1", "all") and self.pos + 1 < len(self.tokens) and (
            self.tokens[self.pos + 1].lower() == "of"
        ):
            quant = self.take().lower()
            self.take()  # 'of'
            pattern = self.take()
            matched = (
                list(self.names) if pattern.lower() == "them"
                else [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            )
            if not matched:
                raise SigmaError(f"No selection matches '{pattern}'")
            return ("any" if quant == "1" else "allof", matched)
        self.take()
        if tok not in self.names:
            raise SigmaError(f"Unknown selection '{tok}' in condition")
        return ("name", tok)


def _compile_condition(node: Any, selections: dict[str, Callable]) -> Callable:
    kind = node[0]
    if kind == "name":
        return selections[node[1]]
    if kind == "not":
        inner = _compile_condition(node[1], selections)
        return lambda ev, ctx: not inner(ev, ctx)
    if kind in ("and", "or"):
        left = _compile_condition(node[1], selections)
        right = _compile_condition(node[2], selections)
        if kind == "and":
            return lambda ev, ctx: left(ev, ctx) and right(ev, ctx)
        return lambda ev, ctx: left(ev, ctx) or right(ev, ctx)
    names = node[1]
    if kind == "any":
        return lambda ev, ctx: any(selections[n](ev, ctx) for n in names)
    return lambda ev, ctx: all(selections[n](ev, ctx) for n in names)


class SigmaRule:
    """A loaded Sigma rule that can be evaluated against :class:`Event` objects."""

    def __init__(self, doc: dict[str, Any], source: str = ""):
        self.doc = doc
        self.source = source
        self.uuid = str(doc.get("id", ""))
        self.id = str(doc.get("name") or self.uuid)
        self.title = doc.get("title", "Untitled")
        self.description = (doc.get("description") or "").strip()
        self.severity = SEVERITIES.get(str(doc.get("level", "medium")).lower(), "medium")
        self.tags: list[str] = list(doc.get("tags", []))
        self.tactic = next((t for t in map(tactic_from_tag, self.tags) if t), "")
        self.technique = next((t for t in map(technique_from_tag, self.tags) if t), "")
        logsource = doc.get("logsource", {})
        key = logsource.get("category") or logsource.get("service") or ""
        if key not in LOGSOURCE_KINDS:
            raise SigmaError(f"{self.title}: unsupported logsource {logsource!r}")
        self.kind = LOGSOURCE_KINDS[key]

        detection = dict(doc.get("detection", {}))
        condition = detection.pop("condition", None)
        if not isinstance(condition, str):
            raise SigmaError(f"{self.title}: only single-string conditions are supported")
        self.condition_text = condition
        self.selections = {name: compile_selection(sel) for name, sel in detection.items()}
        self.raw_selections = detection
        tree = _Parser(condition, list(self.selections)).parse()
        self._predicate = _compile_condition(tree, self.selections)

    def matches(self, event: Event, ctx: Context | None = None) -> bool:
        if event.kind != self.kind:
            return False
        return bool(self._predicate(event, ctx or Context()))

    # ---- Splunk SPL export -------------------------------------------------------
    def to_spl(self, index: str = "main") -> str:
        """Render the rule as an approximate Splunk SPL search (for analyst review)."""
        sysmon = 'sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
        source = {
            "process_create": f"{sysmon} EventCode=1",
            "process_access": f"{sysmon} EventCode=10",
            "network_connect": f"{sysmon} EventCode=3",
            "dns_query": f"{sysmon} EventCode=22",
            "file_create": f"{sysmon} EventCode=11",
            "http_request": "sourcetype=access_combined",
            "sudo": "sourcetype=linux_secure sudo",
        }[self.kind]
        tree = _Parser(self.condition_text, list(self.raw_selections)).parse()
        expr = _render_spl(tree, self.raw_selections)
        columns = ", ".join(["_time", "host", "user", *_spl_fields(self)])
        return f"index={index} {source}\n| where {expr}\n| table {columns}"


def _spl_fields(rule: SigmaRule) -> list[str]:
    fields: list[str] = []
    for sel in rule.raw_selections.values():
        for item in sel if isinstance(sel, list) else [sel]:
            for key in item:
                name = key.split("|")[0]
                if name not in fields and name not in ("host", "user"):
                    fields.append(name)
    return fields


def _spl_term(name: str, mod: str, value: Any) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    low = f"lower({name})"
    if mod == "contains":
        return f'like({low}, "%{text.lower()}%")'
    if mod == "startswith":
        return f'like({low}, "{text.lower()}%")'
    if mod == "endswith":
        return f'like({low}, "%{text.lower()}")'
    if mod == "re":
        return f'match({name}, "(?i){text}")'
    if "*" in text or "?" in text:
        pattern = text.lower().replace("*", "%").replace("?", "_")
        return f'like({low}, "{pattern}")'
    return f'{low}="{text.lower()}"'


def _spl_selection(selection: Any) -> str:
    if isinstance(selection, list):
        return "(" + " OR ".join(_spl_selection(s) for s in selection) + ")"
    clauses = []
    for spec, value in selection.items():
        name, *mods = spec.split("|")
        mod = next((m for m in mods if m != "all"), "eq")
        values = value if isinstance(value, list) else [value]
        joiner = " AND " if "all" in mods else " OR "
        parts = [_spl_term(name, mod, v) for v in values]
        clauses.append("(" + joiner.join(parts) + ")" if len(parts) > 1 else parts[0])
    return clauses[0] if len(clauses) == 1 else "(" + " AND ".join(clauses) + ")"


def _render_spl(node: Any, selections: dict[str, Any]) -> str:
    kind = node[0]
    if kind == "name":
        return _spl_selection(selections[node[1]])
    if kind == "not":
        return f"NOT {_render_spl(node[1], selections)}"
    if kind in ("and", "or"):
        return f"({_render_spl(node[1], selections)} {kind.upper()} {_render_spl(node[2], selections)})"
    joiner = " OR " if kind == "any" else " AND "
    return "(" + joiner.join(_spl_selection(selections[n]) for n in node[1]) + ")"


def load_sigma_file(path: str | Path) -> SigmaRule:
    path = Path(path)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return SigmaRule(doc, source=path.name)


def load_sigma_dir(directory: str | Path) -> list[SigmaRule]:
    return [load_sigma_file(p) for p in sorted(Path(directory).glob("*.yml"))]
