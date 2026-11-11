"""Evaluation against planted ground truth: detection, days to detect, case volume, and false positive cases."""

from __future__ import annotations

from collections import Counter
from statistics import median

from .pipeline import Pipeline
from .scoring import Case, ScoreResult

CONFIGS = [
    ("full", "Peers and context", True, True),
    ("no_context", "Peers, no context", True, False),
    ("no_peers", "Context, no peers", False, True),
    ("neither", "Neither", False, False),
]
BENIGN_SLACK_DAYS = 3
DETECT_SLACK_DAYS = 7


def label_cases(p: Pipeline, cases: list[Case]) -> dict:
    """Match cases to planted scenarios. Each case gets the scenario it explains, or 'other'."""
    pid_of = {s.sid: p.vault.pid(s.uid) for s in p.world.scenarios}
    labels: dict[str, str] = {}
    scen_rows = []
    for s in p.world.scenarios:
        if not s.malicious:
            continue
        hits = [c for c in cases if c.pid == pid_of[s.sid] and c.end_day >= s.start
                and c.detect_day <= s.end + DETECT_SLACK_DAYS]
        first = min(hits, key=lambda c: c.detect_day) if hits else None
        for c in hits:
            labels[c.case_id] = s.sid
        scen_rows.append({"sid": s.sid, "kind": s.kind, "start_day": s.start, "detected": first is not None,
                          "case_id": first.case_id if first else None,
                          "detect_day": first.detect_day if first else None,
                          "days_to_detect": max(0, first.detect_day - s.start) if first else None,
                          "peak_score": round(first.peak_score, 1) if first else None,
                          "top_reasons": [r["reason"] for r in first.reasons(2)] if first else [],
                          "description": s.description})
    benign = Counter()
    benign_subjects = Counter(s.kind for s in p.world.scenarios if not s.malicious)
    for c in cases:
        if c.case_id in labels:
            continue
        for s in p.world.scenarios:
            if s.malicious or c.pid != pid_of[s.sid]:
                continue
            if c.end_day >= s.start and c.detect_day <= s.end + BENIGN_SLACK_DAYS:
                labels[c.case_id] = s.sid
                benign[s.kind] += 1
                break
        labels.setdefault(c.case_id, "other")
    return {"labels": labels, "scenarios": scen_rows, "benign": dict(benign),
            "benign_subjects": dict(benign_subjects)}


def summarize(p: Pipeline, res: ScoreResult) -> dict:
    lab = label_cases(p, res.cases)
    weeks = (p.ds.days - p.ds.warmup) / 7
    malicious_cases = sum(1 for v in lab["labels"].values() if v.startswith("S"))
    benign_cases = sum(lab["benign"].values())
    other = sum(1 for v in lab["labels"].values() if v == "other")
    ttd = [r["days_to_detect"] for r in lab["scenarios"] if r["detected"]]
    weekly = Counter((c.detect_day - p.ds.warmup) // 7 for c in res.cases)
    return {
        "cases": len(res.cases),
        "cases_per_week": round(len(res.cases) / weeks, 2),
        "weekly": [weekly.get(w, 0) for w in range(int(-(-(p.ds.days - p.ds.warmup) // 7)))],
        "signals": len(res.scored),
        "signals_per_week": round(len(res.scored) / weeks, 1),
        "detected": sum(r["detected"] for r in lab["scenarios"]),
        "scenarios": len(lab["scenarios"]),
        "median_days_to_detect": median(ttd) if ttd else None,
        "max_days_to_detect": max(ttd) if ttd else None,
        "malicious_cases": malicious_cases,
        "benign_cases": benign_cases,
        "benign_by_kind": lab["benign"],
        "other_cases": other,
        "precision": round(malicious_cases / len(res.cases), 3) if res.cases else None,
        "scenario_rows": lab["scenarios"],
        "labels": lab["labels"],
        "benign_subjects": lab["benign_subjects"],
    }


def evaluate(p: Pipeline, max_days: int = 3, max_benign: int = 1, results: dict | None = None) -> dict:
    """Run every configuration. `results` can hold already computed ScoreResults by config key."""
    results = dict(results or {})
    configs = {}
    for key, label, peers, ctx in CONFIGS:
        if peers not in p.detected:
            continue
        res = results.get(key) or p.score(use_peers=peers, use_context=ctx)
        s = summarize(p, res)
        s["label"] = label
        configs[key] = s
    full = configs["full"]
    failures = []
    for r in full["scenario_rows"]:
        if not r["detected"]:
            failures.append(f"{r['sid']} {r['kind']} not detected")
        elif r["days_to_detect"] > max_days:
            failures.append(f"{r['sid']} {r['kind']} took {r['days_to_detect']} days (limit {max_days})")
    if full["benign_cases"] > max_benign:
        failures.append(f"{full['benign_cases']} cases on benign surprises (limit {max_benign})")
    n = p.ds.n
    return {
        "company": p.world.company,
        "identities": n,
        "employees": sum(1 for x in p.ds.profiles if x.kind == "employee"),
        "service_accounts": sum(1 for x in p.ds.profiles if x.kind == "service"),
        "events": len(p.world.events),
        "days": p.ds.days,
        "warmup_days": p.ds.warmup,
        "scored_weeks": round((p.ds.days - p.ds.warmup) / 7, 1),
        "configs": configs,
        "scenarios": full["scenario_rows"],
        "gate": {"passed": not failures, "failures": failures, "max_days": max_days, "max_benign": max_benign},
        "timings": p.timings,
    }


def markdown(ev: dict) -> str:
    def table(header, rows):
        out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
        return "\n".join(out + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])

    rows = [[r["sid"], r["kind"].replace("_", " "), r["start_day"], "yes" if r["detected"] else "no",
             "missed" if r["days_to_detect"] is None else r["days_to_detect"],
             "" if r["peak_score"] is None else f"{r['peak_score']:.0f}",
             (r["top_reasons"][0] if r["top_reasons"] else "").replace("|", "/")]
            for r in ev["scenarios"]]
    t1 = table(["Id", "Scenario", "Starts day", "Detected", "Days to detect", "Peak risk", "Top reason"], rows)
    cfg_rows = []
    for c in ev["configs"].values():
        cfg_rows.append([c["label"], f"{c['signals']:,}", c["cases"], c["cases_per_week"],
                         f"{c['detected']} / {c['scenarios']}", c["benign_cases"], c["other_cases"],
                         "n/a" if c["precision"] is None else f"{c['precision']:.0%}"])
    t2 = table(["Configuration", "Signals", "Cases", "Cases per week", "Scenarios caught", "Benign surprise cases",
                "Other cases", "Precision"], cfg_rows)
    g = ev["gate"]
    gate = "PASSED" if g["passed"] else "FAILED: " + "; ".join(g["failures"])
    return (f"## Scenario detection\n\n{t1}\n\n## Alert volume\n\n{t2}\n\n"
            f"Gate (every scenario within {g['max_days']} days, at most {g['max_benign']} benign cases): {gate}\n")
