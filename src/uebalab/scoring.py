"""Risk scoring with decay, HR and calendar context, analyst feedback, and case building."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from .detectors import DATA_MOVEMENT, Signal
from .features import Dataset
from .generate import quarter_end_days

RESIGNATION_FACTOR = 1.5
TRAVEL_FACTOR = 0.1
TEAM_CHANGE_FACTOR = 0.3
QUARTER_END_FACTOR = 0.4
TEAM_CHANGE_DAYS = 30
FEEDBACK_FACTORS = {"benign": 0.5, "expected": 0.1, "true_positive": 1.25}


@dataclass
class ScoringConfig:
    use_context: bool = True
    use_feedback: bool = True
    half_life_days: float = 3.0
    open_at: float = 40.0  # decayed points that open a case
    close_below: float = 10.0
    lookback_days: int = 7

    @property
    def decay(self) -> float:
        return 0.5 ** (1.0 / self.half_life_days)


@dataclass
class Feedback:
    case_id: str
    idx: int
    label: str  # true_positive, benign, expected
    patterns: list[tuple[str, str]]
    effective_day: int
    peer_group: str
    analyst: str = "analyst"
    note: str = ""


@dataclass
class Scored:
    signal: Signal
    points: float
    notes: list[str] = field(default_factory=list)


@dataclass
class Case:
    case_id: str
    idx: int
    pid: str
    start_day: int
    detect_day: int
    end_day: int
    peak_risk: float
    peak_score: float
    items: list[Scored]

    def reasons(self, top: int = 3) -> list[dict]:
        agg: dict[tuple[str, str], list[Scored]] = defaultdict(list)
        for s in self.items:
            agg[s.signal.pattern].append(s)
        ranked = sorted(agg.items(), key=lambda kv: -sum(x.points for x in kv[1]))
        out = []
        for (det, key), xs in ranked[:top]:
            best = max(xs, key=lambda x: x.points)
            out.append({"detector": det, "key": key, "points": round(sum(x.points for x in xs), 1),
                        "days": len({x.signal.day for x in xs}), "reason": best.signal.reason,
                        "notes": sorted({n for x in xs for n in x.notes})})
        return out

    @property
    def patterns(self) -> list[tuple[str, str]]:
        return sorted({s.signal.pattern for s in self.items})


def risk_score(risk: float) -> float:
    """Map decayed points to 0..100. 40 points (a case) is about 49; 100 points is about 81."""
    return 100.0 * (1.0 - math.exp(-risk / 60.0))


class ContextIndex:
    def __init__(self, ds: Dataset):
        self.by_idx: dict[int, list] = defaultdict(list)
        for c in ds.context:
            self.by_idx[c.idx].append(c)
        self.team_day = ds.team_day
        self.qe = quarter_end_days()

    def adjust(self, s: Signal) -> tuple[float, list[str]]:
        mult, notes = 1.0, []
        movement = s.detector == "rare_resource" or (s.detector == "deviation" and s.key in DATA_MOVEMENT)
        for c in self.by_idx.get(s.idx, ()):
            if c.kind == "resignation" and c.start <= s.day <= c.end + 14 and movement:
                mult *= RESIGNATION_FACTOR
                notes.append(f"raised: resignation notice on day {c.start}, last day {c.end}")
            elif c.kind == "travel" and c.start <= s.day <= c.end + 1:
                countries = s.evidence.get("countries") or [s.evidence.get("country")]
                if s.detector in ("novelty", "impossible_travel", "sequence") and c.detail["country"] in countries:
                    mult *= TRAVEL_FACTOR
                    notes.append(f"lowered: approved travel to {c.detail['country']} days {c.start} to {c.end}")
            elif c.kind == "team_change" and c.start <= s.day <= c.start + TEAM_CHANGE_DAYS:
                if s.detector in ("rare_resource", "deviation", "iforest"):
                    mult *= TEAM_CHANGE_FACTOR
                    notes.append(f"lowered: team change on day {c.start}")
        if s.detector in ("deviation", "offhours") and self.team_day[s.idx][s.day].startswith("finance-") \
                and s.day in self.qe:
            mult *= QUARTER_END_FACTOR
            notes.append("lowered: quarter-end close for finance")
        return mult, notes


def feedback_adjust(s: Signal, feedback: list[Feedback], peer_group: str) -> tuple[float, list[str]]:
    mult, notes = 1.0, []
    for fb in feedback:
        if s.day < fb.effective_day or s.pattern not in fb.patterns:
            continue
        if fb.label in ("benign", "expected") and fb.idx == s.idx:
            mult *= FEEDBACK_FACTORS[fb.label]
            notes.append(f"lowered: marked {fb.label} on {fb.case_id}")
        elif fb.label == "true_positive" and fb.peer_group == peer_group:
            mult *= FEEDBACK_FACTORS["true_positive"]
            notes.append(f"raised: same pattern confirmed on {fb.case_id}")
    return mult, notes


@dataclass
class ScoreResult:
    risk: np.ndarray  # [N, D] decayed points
    cases: list[Case]
    scored: list[Scored]

    def score(self, idx: int) -> list[float]:
        return [round(risk_score(r), 1) for r in self.risk[idx]]


def score_and_build(ds: Dataset, signals: list[Signal], labels_by_day: list[list[str]],
                    cfg: ScoringConfig | None = None, feedback: list[Feedback] | None = None) -> ScoreResult:
    cfg = cfg or ScoringConfig()
    ctx = ContextIndex(ds)
    feedback = feedback or []
    N, D = ds.n, ds.days
    daily = np.zeros((N, D))
    per: dict[tuple[int, int], list[Scored]] = defaultdict(list)
    scored: list[Scored] = []
    for s in signals:
        if s.detector == "after_end_date" and not cfg.use_context:
            continue  # this rule exists only because of the HR feed
        mult, notes = 1.0, []
        if cfg.use_context:
            m, n = ctx.adjust(s)
            mult, notes = mult * m, notes + n
        if cfg.use_feedback and feedback:
            m, n = feedback_adjust(s, feedback, labels_by_day[s.day][s.idx])
            mult, notes = mult * m, notes + n
        sc = Scored(s, s.points * mult, notes)
        scored.append(sc)
        daily[s.idx, s.day] += sc.points
        per[(s.idx, s.day)].append(sc)
    risk = np.zeros((N, D))
    for d in range(D):
        risk[:, d] = (risk[:, d - 1] * cfg.decay if d else 0) + daily[:, d]
    cases: list[Case] = []
    for i in np.flatnonzero(risk.max(axis=1) >= cfg.open_at):
        active = None
        for d in range(D):
            if active is None and risk[i, d] >= cfg.open_at:
                lo = d - cfg.lookback_days
                prior = [x for dd in range(max(0, lo), d + 1) for x in per.get((i, dd), []) if x.points > 0]
                start = min(x.signal.day for x in prior)
                active = Case(f"C{d:03d}-{ds.pids[i][2:8]}", int(i), ds.pids[i], start, d, d, risk[i, d],
                              risk_score(risk[i, d]), prior)
                cases.append(active)
            elif active is not None:
                if risk[i, d] < cfg.close_below:
                    active = None
                    continue
                today = [x for x in per.get((i, d), []) if x.points > 0]
                if today:
                    active.items += today
                    active.end_day = d
                if risk[i, d] > active.peak_risk:
                    active.peak_risk, active.peak_score = risk[i, d], risk_score(risk[i, d])
    cases.sort(key=lambda c: (-c.peak_risk, c.case_id))
    return ScoreResult(risk, cases, scored)
