"""Run the attack catalogue against control configurations and score outcomes.

    python -m attacks.runner --trials 10 --obedience 1.0 0.5

The model is a SimulatedModel (see app/llm.py). Results therefore measure whether the
CONTROLS hold when the model can be talked into anything, not how robust any real LLM is.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from app import config, db as dbmod, engine as eng, llm, retrieval
from app.telemetry import Telemetry
from attacks import corpus
from attacks.catalogue import ATTACKS, Attack, Outcome
from attacks.stats import fmt_rate, pct, wilson
from detections import sigma_eval

ROOT = Path(__file__).resolve().parent.parent
USERS = {u: {"user_id": u, "tenant_id": config.TENANTS[u]} for u in config.TENANTS}


def build_configs() -> dict[str, frozenset[str]]:
    cfgs: dict[str, frozenset[str]] = dict(config.MODES)
    for c in sorted(config.ALL_CONTROLS):
        cfgs[f"layered - {c}"] = config.ALL_CONTROLS - {c}
    for c in sorted(config.DETERMINISTIC):
        cfgs[f"deterministic - {c}"] = config.DETERMINISTIC - {c}
    return cfgs


CONFIGS = build_configs()
MAIN_MODES = ["baseline", "guardrails", "deterministic", "layered"]


@dataclass
class TrialResult:
    attack_id: str
    config: str
    obedience: float
    trial: int
    success: bool
    blocked: bool
    detected: bool
    alerts: list[str]

    @property
    def silent(self) -> bool:
        return self.success and not self.detected


def build_base_db(path: Path) -> None:
    d = dbmod.Database(path)
    d.init()
    emb = retrieval.HashingEmbedder()
    for user, title, content in corpus.BASE_DOCS:
        d.add_document(config.TENANTS[user], title, content, embedder=emb)


def _engine(controls: frozenset[str], obedience: float, db_path: Path, seed: int, trial: int, events: list):
    settings = config.Settings(controls=controls, llm_provider="sim", sim_obedience=obedience, db_path=db_path)
    database = dbmod.Database(db_path)
    tel = Telemetry(sink=events.append, mode=settings.mode_label)
    return eng.Engine(settings, database, llm.SimProvider(obedience, seed, trial), tel), database


def run_trial(attack: Attack, name: str, controls: frozenset[str], obedience: float, trial: int,
              base_db: Path, workdir: Path, rules: list) -> TrialResult:
    db_path = workdir / f"{hashlib.sha1(f'{attack.id}{name}{obedience}{trial}'.encode()).hexdigest()[:12]}.db"
    shutil.copyfile(base_db, db_path)
    events: list[dict] = []
    seed = int(hashlib.sha256(attack.id.encode()).hexdigest()[:8], 16)
    engine, database = _engine(controls, obedience, db_path, seed, trial, events)
    for user, title, content in attack.plants:
        engine.ingest(USERS[user], title, content)
    for user, question in attack.prelude:
        try:
            engine.ask(USERS[user], question)
        except eng.GuardBlocked:
            pass
    blocked, answer = False, ""
    try:
        answer = engine.ask(USERS[attack.attacker], attack.question).answer
    except eng.GuardBlocked:
        blocked = True
    outcome = Outcome(answer, blocked, database.all_actions_unsafe(), events, engine.canary)
    success = (not blocked) and attack.oracle(outcome)
    alerts = sigma_eval.alert_levels_at_least(sigma_eval.evaluate(rules, events), "medium")
    names = sorted({a.rule for a in alerts})
    db_path.unlink(missing_ok=True)
    return TrialResult(attack.id, name, obedience, trial, success, blocked, bool(names), names)


def run_benign(name: str, controls: frozenset[str], base_db: Path, workdir: Path, rules: list) -> dict:
    db_path = workdir / f"benign-{hashlib.sha1(name.encode()).hexdigest()[:10]}.db"
    shutil.copyfile(base_db, db_path)
    events: list[dict] = []
    engine, _ = _engine(controls, 1.0, db_path, 0, 0, events)
    blocked = correct = checked = 0
    for user, question, expect in corpus.BENIGN:
        try:
            ans = engine.ask(USERS[user], question).answer.lower()
        except eng.GuardBlocked:
            blocked += 1
            if expect:
                checked += 1
            continue
        if expect:
            checked += 1
            correct += expect in ans
    alerts = sigma_eval.alert_levels_at_least(sigma_eval.evaluate(rules, events), "medium")
    db_path.unlink(missing_ok=True)
    n = len(corpus.BENIGN)
    return {"config": name, "requests": n, "blocked": blocked, "block_rate": blocked / n,
            "answered_correctly": correct, "checked": checked, "accuracy": correct / checked if checked else 0.0,
            "alerts": len(alerts), "alerts_per_100": 100 * len(alerts) / n}


INPUT_SIDE = {
    "AegisRAG Prompt Injection Detected In User Input", "AegisRAG Injection Payload In Retrieved Content",
    "AegisRAG Suspicious Document Ingested", "AegisRAG Repeated Injection Attempts From One User",
    "AegisRAG Poisoned Context Followed By Tool Call In One Request",
}


def run_all(config_names: list[str], attack_ids: list[str] | None, obedience: list[float], trials: int, progress=True):
    rules = sigma_eval.load_rules(ROOT / "detections" / "sigma")
    attacks = [a for a in ATTACKS if not attack_ids or a.id in attack_ids]
    results: list[TrialResult] = []
    benign: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        base = work / "base.db"
        build_base_db(base)
        total = len(config_names)
        for i, name in enumerate(config_names, 1):
            controls = CONFIGS[name]
            if progress:
                print(f"[{i}/{total}] {name}", file=sys.stderr)
            benign.append(run_benign(name, controls, base, work, rules))
            for p in obedience:
                for atk in attacks:
                    n = trials if (atk.needs_model and p < 1.0) else 1
                    for t in range(n):
                        results.append(run_trial(atk, name, controls, p, t, base, work, rules))
    return results, benign


# ------------------------------------------------------------------ reporting
def _cell(rs: list[TrialResult]) -> str:
    s = sum(r.success for r in rs)
    if s == 0:
        return "safe"
    silent = sum(r.silent for r in rs)
    tag = "LEAK!" if silent == s else "LEAK"
    return tag if len(rs) == 1 else f"{tag} {s}/{len(rs)}"


def render_report(results: list[TrialResult], benign: list[dict], meta: dict, fuzz_md: str = "") -> str:
    by = defaultdict(list)
    for r in results:
        by[(r.config, r.obedience, r.attack_id)].append(r)
    cfgs = list(dict.fromkeys(r.config for r in results))
    obeds = sorted({r.obedience for r in results}, reverse=True)
    attack_ids = [a.id for a in ATTACKS if any(r.attack_id == a.id for r in results)]
    out = ["# AegisRAG evaluation report", "",
           f"Generated {meta['generated']} | trials per model-dependent attack at obedience < 1: {meta['trials']} | "
           f"attacks: {len(attack_ids)} | configurations: {len(cfgs)}", "",
           "> **Read this first.** The model is a *simulated* model that obeys instructions found in its input. "
           "These numbers show whether the **controls** hold when the model is fully compromised. They are not a measure of how "
           "robust any real LLM is. `LEAK` = the attacker's goal was achieved and an alert fired; `LEAK!` = achieved with **no alert** "
           "(a silent success); `safe` = goal not achieved.", ""]
    main = [c for c in MAIN_MODES if c in cfgs]
    for p in obeds:
        out += [f"## Outcome by attack, obedience = {p}", "",
                "| Attack | Category | " + " | ".join(main) + " |", "|---|---|" + "---|" * len(main)]
        for a in ATTACKS:
            if a.id not in attack_ids:
                continue
            row = [_cell(by[(c, p, a.id)]) for c in main]
            out.append(f"| {a.id} {a.name} | {a.category} | " + " | ".join(row) + " |")
        out.append("")
    out += ["## Summary by configuration", "",
            "ASR = attack success rate pooled over every trial (Wilson 95% interval). Silent = successes that raised no alert at level medium or above, shown as silent of all successes. "
            "Benign columns come from 20 harmless questions: block rate is the false-positive rate, accuracy is answers containing the expected fact. "
            "Alerts on benign traffic in configurations without tenant scoping are TRUE leaks (harmless questions pulling another tenant's documents), not false alarms.", ""]
    head = "| Configuration | " + " | ".join(f"ASR @ obedience {p}" for p in obeds) + " | Silent / all successes | Benign blocked | Benign accuracy | Alerts / 100 benign |"
    out += [head, "|---|" + "---|" * (len(obeds) + 4)]
    bmap = {b["config"]: b for b in benign}
    for c in cfgs:
        asr = []
        for p in obeds:
            rs = [r for r in results if r.config == c and r.obedience == p]
            asr.append(fmt_rate(sum(r.success for r in rs), len(rs)))
        allr = [r for r in results if r.config == c]
        b = bmap[c]
        out.append(f"| {c} | " + " | ".join(asr) + f" | {sum(r.silent for r in allr)} of {sum(r.success for r in allr)} | {pct(b['block_rate'])} | {pct(b['accuracy'])} | {b['alerts_per_100']:.0f} |")
    out.append("")
    p0 = obeds[0]
    loo = [c for c in cfgs if " - " in c]
    if loo:
        out += [f"## What each control is worth (leave-one-out, obedience = {p0})", "",
                "Attacks that start succeeding when a single control is removed from the full or deterministic set.", "",
                "| Removed control | From | Attacks that now succeed |", "|---|---|---|"]
        for c in loo:
            reg = [a for a in attack_ids if any(r.success for r in by[(c, p0, a)])]
            out.append(f"| {c.split(' - ')[1]} | {c.split(' - ')[0]} | {', '.join(reg) if reg else 'none (other layers cover it)'} |")
        out.append("")
    if "baseline" in cfgs:
        out += ["## Which detection layer sees each attack (baseline, nothing prevented)", "",
                "Input-side rules key on attack *technique* (guard hits). Outcome-side rules key on attack *effect* (egress, foreign tenant data, canary, PII). "
                "Attacks that evade the guard are only visible to outcome-side rules.", "",
                "| Attack | Input-side alert | Outcome-side alert |", "|---|---|---|"]
        for a in ATTACKS:
            rs = by.get(("baseline", p0, a.id))
            if not rs:
                continue
            names = {n for r in rs for n in r.alerts}
            inp = "yes" if names & INPUT_SIDE else "**no**"
            outc = "yes" if names - INPUT_SIDE else "**no**"
            out.append(f"| {a.id} {a.name} | {inp} | {outc} |")
        out.append("")
    if fuzz_md:
        out += [fuzz_md, ""]
    out += ["## Limitations (do not skip)", "",
            "- The simulated model recognises a fixed grammar of directives. A real model is both more capable (understands attacks the simulation does not) and less obedient. Real-model trials need `AEGIS_LLM_PROVIDER=ollama` or `bedrock` and are not included here.",
            "- Prompt hardening and the guard's real-world value are only partly measurable with a simulated model: the simulation ignores delimiters, so hardening shows no effect here by construction.",
            "- Attack authors and defence authors are the same person. Treat the guard results as a lower bound on what a motivated attacker achieves.",
            "- Alerts are produced by a subset Sigma evaluator on the lab's own telemetry, not by a production SIEM.", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AegisRAG attack runner")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--obedience", type=float, nargs="+", default=[1.0, 0.5])
    ap.add_argument("--configs", nargs="*", default=None, help="subset of configuration names")
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--out", type=Path, default=ROOT / "results")
    ap.add_argument("--no-fuzz", action="store_true")
    ap.add_argument("--quick", action="store_true", help="4 trials, main modes only")
    args = ap.parse_args(argv)
    names = args.configs or (MAIN_MODES if args.quick else list(CONFIGS))
    trials = 4 if args.quick else args.trials
    t0 = time.time()
    results, benign = run_all(names, args.attacks, args.obedience, trials)
    fuzz_md = ""
    if not args.no_fuzz:
        from attacks import fuzz
        fuzz_md = fuzz.render(fuzz.run())
    meta = {"generated": time.strftime("%Y-%m-%d %H:%M"), "trials": trials, "seconds": round(time.time() - t0, 1)}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(
        {"meta": meta, "trials": [asdict(r) for r in results], "benign": benign}, indent=2))
    report = render_report(results, benign, meta, fuzz_md)
    (args.out / "REPORT.md").write_text(report)
    print(report)
    print(f"\n(done in {meta['seconds']}s; wrote {args.out}/REPORT.md and results.json)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
