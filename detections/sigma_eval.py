"""A small Sigma evaluator for the subset of Sigma this lab uses.

Supported: field equality (case-insensitive, `*` wildcards), lists (OR), modifiers
contains/startswith/endswith/re/gt/gte/lt/lte/all, selections that are maps or lists of
maps, conditions with and/or/not/parentheses and `1 of x*` / `all of x*` / `them`,
and correlation rules of type event_count, value_count and temporal_ordered.

It exists so detections can be TESTED against telemetry produced by real attack runs.
It is not a SIEM backend; use pySigma to convert rules for production (see tests).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import yaml

LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Alert:
    rule: str
    level: str
    event_ids: tuple[str, ...]


def load_rules(directory: Path | str) -> list[dict[str, Any]]:
    rules = []
    for path in sorted(Path(directory).glob("*.yml")):
        data = yaml.safe_load(path.read_text())
        data["_file"] = path.name
        rules.append(data)
    return rules


def _get(event: dict[str, Any], dotted: str) -> Any:
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match_value(actual: Any, expected: Any, mods: list[str]) -> bool:
    if actual is None:
        return expected is None
    if "contains" in mods or "startswith" in mods or "endswith" in mods:
        a = str(actual).lower()
        e = str(expected).lower()
        return (e in a) if "contains" in mods else a.startswith(e) if "startswith" in mods else a.endswith(e)
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    for op, fn in (("gte", lambda x, y: x >= y), ("gt", lambda x, y: x > y), ("lte", lambda x, y: x <= y), ("lt", lambda x, y: x < y)):
        if op in mods:
            try:
                return fn(float(actual), float(expected))
            except (TypeError, ValueError):
                return False
    a, e = str(actual).lower(), str(expected).lower()
    return fnmatch.fnmatchcase(a, e) if ("*" in e or "?" in e) else a == e


def _match_field(event: dict[str, Any], key: str, expected: Any) -> bool:
    field, *mods = key.split("|")
    actual = _get(event, field)
    values = expected if isinstance(expected, list) else [expected]
    if isinstance(actual, list):  # any element equal
        results = [any(_match_value(x, v, mods) for x in actual) for v in values]
    else:
        results = [_match_value(actual, v, mods) for v in values]
    return all(results) if "all" in mods else any(results)


def _match_selection(event: dict[str, Any], sel: Any) -> bool:
    if isinstance(sel, dict):
        return all(_match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        return any(_match_selection(event, s) if isinstance(s, dict) else False for s in sel)
    return False


_TOKEN = re.compile(r"\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+")


class _Cond:
    def __init__(self, text: str, results: dict[str, bool]) -> None:
        self.toks = _TOKEN.findall(text)
        self.i = 0
        self.results = results

    def parse(self) -> bool:
        v = self._or()
        return v

    def _peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> str:
        t = self.toks[self.i]
        self.i += 1
        return t

    def _or(self) -> bool:
        v = self._and()
        while self._peek() == "or":
            self._next()
            v = self._and() or v
        return v

    def _and(self) -> bool:
        v = self._not()
        while self._peek() == "and":
            self._next()
            v = self._not() and v
        return v

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        t = self._next()
        if t == "(":
            v = self._or()
            self._next()  # ')'
            return v
        if t in ("1 of", "all of"):
            pat = self._next()
            names = list(self.results) if pat == "them" else [n for n in self.results if fnmatch.fnmatchcase(n, pat)]
            vals = [self.results[n] for n in names]
            return (any(vals) if t == "1 of" else bool(vals) and all(vals))
        return self.results.get(t, False)


def _single_match(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    det = rule["detection"]
    results = {k: _match_selection(event, v) for k, v in det.items() if k != "condition"}
    cond = det["condition"]
    if isinstance(cond, list):
        return any(_Cond(c, results).parse() for c in cond)
    return _Cond(cond, results).parse()


def _span_seconds(span: str) -> float:
    m = re.fullmatch(r"(\d+)([smhd])", span.strip())
    if not m:
        raise ValueError(f"bad timespan {span!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _ts(event: dict[str, Any]) -> float:
    return datetime.fromisoformat(event["timestamp"]).timestamp()


def evaluate(rules: Iterable[dict[str, Any]], events: list[dict[str, Any]]) -> list[Alert]:
    rules = list(rules)
    alerts: list[Alert] = []
    by_name: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        if "detection" not in rule:
            continue
        matched = [e for e in events if _single_match(rule, e)]
        by_name[rule.get("name", rule["title"])] = matched
        if matched:
            alerts.append(Alert(rule["title"], rule.get("level", "medium"), tuple(e["event_id"] for e in matched)))
    for rule in rules:
        corr = rule.get("correlation")
        if not corr:
            continue
        span = _span_seconds(corr["timespan"])
        group_by = corr.get("group-by", [])
        ctype = corr["type"]
        refs = corr["rules"]
        if ctype in ("event_count", "value_count"):
            pool = [e for r in refs for e in by_name.get(r, [])]
            groups: dict[tuple, list[dict[str, Any]]] = {}
            for e in pool:
                groups.setdefault(tuple(_get(e, g) for g in group_by), []).append(e)
            cond = corr.get("condition", {})
            op, threshold = next(iter(cond.items()))
            for evs in groups.values():
                evs.sort(key=_ts)
                lo = 0
                for hi in range(len(evs)):
                    while _ts(evs[hi]) - _ts(evs[lo]) > span:
                        lo += 1
                    window = evs[lo:hi + 1]
                    n = len({str(_get(x, corr["condition"].get("field", "event_id"))) for x in window}) if ctype == "value_count" else len(window)
                    if (op == "gte" and n >= threshold) or (op == "gt" and n > threshold):
                        alerts.append(Alert(rule["title"], rule.get("level", "medium"), tuple(x["event_id"] for x in window)))
                        break
        elif ctype == "temporal_ordered":
            groups = {}
            for idx, r in enumerate(refs):
                for e in by_name.get(r, []):
                    groups.setdefault(tuple(_get(e, g) for g in group_by), []).append((idx, e))
            for items in groups.values():
                items.sort(key=lambda p: _ts(p[1]))
                chain, matched_ids, start = 0, [], 0.0
                for idx, e in items:
                    if idx == 0 and chain == 0:
                        chain, start, matched_ids = 1, _ts(e), [e["event_id"]]
                    elif idx == chain and chain > 0 and _ts(e) - start <= span:
                        chain += 1
                        matched_ids.append(e["event_id"])
                        if chain == len(refs):
                            alerts.append(Alert(rule["title"], rule.get("level", "medium"), tuple(matched_ids)))
                            break
    return alerts


def alert_levels_at_least(alerts: list[Alert], level: str = "medium") -> list[Alert]:
    return [a for a in alerts if LEVEL_ORDER.get(a.level, 0) >= LEVEL_ORDER[level]]
