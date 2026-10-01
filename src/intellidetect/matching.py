"""Field matching with Sigma-style modifiers (``field|contains``, ``field|re`` ...)."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .models import Event, is_public_ip


@dataclass
class Context:
    """Environment shared by all rules: named allow-lists and the asset inventory."""

    lists: dict[str, set[str]] = field(default_factory=dict)
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)  # hostname(lower) -> info

    def in_list(self, name: str, value: str) -> bool:
        return value.lower() in self.lists.get(name, set())


Predicate = Callable[[Event, Context], bool]

_STRING_OPS = {"contains", "startswith", "endswith", "re"}
_NUMERIC_OPS = {"gt", "gte", "lt", "lte"}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _equals(actual: Any, expected: Any) -> bool:
    if expected is None:
        return actual in (None, "")
    if actual is None:
        return False
    if isinstance(expected, bool):
        return bool(actual) == expected
    if isinstance(expected, (int, float)):
        a = _to_float(actual)
        return a is not None and a == float(expected)
    a, e = str(actual).lower(), str(expected).lower()
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _field_predicate(spec: str, expected: Any) -> Predicate:
    name, *mods = spec.split("|")
    values = _as_list(expected)
    require_all = "all" in mods
    ops = [m for m in mods if m != "all"]
    op = ops[0] if ops else "eq"

    if op == "is_public":
        want = bool(expected)
        return lambda ev, ctx: is_public_ip(str(ev.get(name, ""))) == want

    if op == "in_list":
        return lambda ev, ctx: any(ctx.in_list(str(v), str(ev.get(name, ""))) for v in values)

    if op in _NUMERIC_OPS:
        limit = _to_float(expected)

        def numeric(ev: Event, ctx: Context) -> bool:
            actual = _to_float(ev.get(name))
            if actual is None or limit is None:
                return False
            return {
                "gt": actual > limit,
                "gte": actual >= limit,
                "lt": actual < limit,
                "lte": actual <= limit,
            }[op]

        return numeric

    if op == "re":
        compiled = [re.compile(str(v), re.IGNORECASE) for v in values]

        def regex(ev: Event, ctx: Context) -> bool:
            actual = ev.get(name)
            if actual is None:
                return False
            checks = [c.search(str(actual)) is not None for c in compiled]
            return all(checks) if require_all else any(checks)

        return regex

    if op in _STRING_OPS:
        needles = [str(v).lower() for v in values]
        test = {
            "contains": lambda a, n: n in a,
            "startswith": lambda a, n: a.startswith(n),
            "endswith": lambda a, n: a.endswith(n),
        }[op]

        def string_op(ev: Event, ctx: Context) -> bool:
            actual = ev.get(name)
            if actual is None:
                return False
            a = str(actual).lower()
            checks = [test(a, n) for n in needles]
            return all(checks) if require_all else any(checks)

        return string_op

    if op != "eq":
        raise ValueError(f"Unknown modifier '{op}' in '{spec}'")

    def equality(ev: Event, ctx: Context) -> bool:
        actual = ev.get(name)
        return any(_equals(actual, v) for v in values)

    return equality


def compile_selection(selection: dict[str, Any] | list[dict[str, Any]]) -> Predicate:
    """Compile a selection mapping (AND of fields) or a list of mappings (OR of selections)."""
    if isinstance(selection, list):
        parts = [compile_selection(s) for s in selection]
        return lambda ev, ctx: any(p(ev, ctx) for p in parts)
    preds = [_field_predicate(k, v) for k, v in selection.items()]
    return lambda ev, ctx: all(p(ev, ctx) for p in preds)
