"""Application state behind the API: case queue, statuses, feedback, re-identification, and the audit trail."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict
from pathlib import Path

from .evaluate import evaluate
from .features import FEATURES
from .generate import CITIES
from .pipeline import Pipeline
from .privacy import AuditLog
from .scoring import Case, Feedback, risk_score

LABELS = ("true_positive", "benign", "expected")
STATUSES = ("new", "open", "closed")


class NotAllowed(Exception):
    pass


class Service:
    def __init__(self, pipeline: Pipeline, data_dir: Path | None = None, max_days: int = 3, max_benign: int = 1):
        self.p = pipeline
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.audit = AuditLog(data_dir / "audit.jsonl" if data_dir else None)
        self.status: dict[str, dict] = {}
        self.feedback: list[Feedback] = []
        if data_dir and (data_dir / "state.json").exists():
            st = json.loads((data_dir / "state.json").read_text())
            self.status = st.get("status", {})
            self.feedback = [Feedback(**{**f, "patterns": [tuple(x) for x in f["patterns"]]})
                             for f in st.get("feedback", [])]
        self.evaluation = evaluate(pipeline, max_days=max_days, max_benign=max_benign)
        self.recompute()

    # ------------------------------------------------------------------ state
    def recompute(self) -> None:
        self.result = self.p.score(feedback=self.feedback)
        self.cases: dict[str, Case] = {c.case_id: c for c in self.result.cases}

    def _save(self) -> None:
        if not self.data_dir:
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.data_dir / "state.json.tmp"
        tmp.write_text(json.dumps({"status": self.status, "feedback": [asdict(f) for f in self.feedback]}, indent=1))
        tmp.replace(self.data_dir / "state.json")

    def case(self, case_id: str) -> Case:
        if case_id not in self.cases:
            raise KeyError(case_id)
        return self.cases[case_id]

    def case_status(self, case_id: str) -> dict:
        return self.status.get(case_id, {"status": "new", "assignee": None, "label": None})

    # ------------------------------------------------------------------ read models
    def date(self, day: int) -> str:
        return self.p.world.date_of(day)

    def case_row(self, c: Case) -> dict:
        prof = self.p.ds.profiles[c.idx]
        st = self.case_status(c.case_id)
        return {"case_id": c.case_id, "subject": c.pid, "kind": prof.kind, "role": prof.role,
                "peer_group": self.p.detected[True].labels[c.detect_day][c.idx],
                "start_day": c.start_day, "detect_day": c.detect_day, "end_day": c.end_day,
                "detect_date": self.date(c.detect_day), "peak_score": round(c.peak_score, 1),
                "current_score": round(risk_score(self.result.risk[c.idx, -1]), 1),
                "signals": len(c.items), "reasons": c.reasons(3), **st}

    def queue(self, status: str | None = None) -> list[dict]:
        rows = [self.case_row(c) for c in self.result.cases]
        if status:
            rows = [r for r in rows if r["status"] == status]
        order = {"open": 0, "new": 1, "closed": 2}
        return sorted(rows, key=lambda r: (order[r["status"]], -r["peak_score"], r["case_id"]))

    def case_detail(self, case_id: str, analyst: str) -> dict:
        c = self.case(case_id)
        self.audit.record(analyst, "view_case", case_id, c.pid)
        row = self.case_row(c)
        row["timeline"] = self.timeline(c)
        row["trend"] = self.trend(c.idx)
        row["all_reasons"] = c.reasons(10)
        row["context_notes"] = sorted({n for s in c.items for n in s.notes})
        row["audit"] = self.audit.for_case(case_id)
        row["dates"] = {"start": self.date(c.start_day), "end": self.date(c.end_day)}
        return row

    def timeline(self, c: Case, limit: int = 80) -> list[dict]:
        items = []
        for s in c.items:
            sig = s.signal
            items.append({"type": "signal", "day": sig.day, "date": self.date(sig.day), "ts": sig.ts,
                          "detector": sig.detector, "key": sig.key, "points": round(s.points, 1),
                          "raw_points": round(sig.points, 1), "text": sig.reason, "notes": s.notes,
                          "evidence": sig.evidence})
        days = {s.signal.day for s in c.items}
        evs = []
        for e in self.p.ds.events[c.idx]:
            if e.day not in days:
                continue
            interesting = e.source == "idp" or e.action in ("acl_change", "iam_grant", "clone") \
                or (e.source == "files" and e.count >= 20) or e.resource == "mail:external"
            if interesting:
                evs.append({"type": "event", "day": e.day, "date": self.date(e.day), "ts": e.ts,
                            "time": f"{(e.ts % 1440) // 60:02d}:{e.ts % 60:02d} UTC", "source": e.source,
                            "action": e.action, "resource": e.resource, "city": CITIES[e.city][0],
                            "country": CITIES[e.city][1], "device": e.device, "count": e.count, "mb": e.mb})
        evs.sort(key=lambda x: (-(x["count"] or 0)))
        items += sorted(evs[:limit], key=lambda x: x["ts"])
        return sorted(items, key=lambda x: (x["day"], x["ts"] if x["ts"] is not None else x["day"] * 1440,
                                            x["type"] != "signal"))

    def trend(self, idx: int) -> list[dict]:
        return [{"day": d, "date": self.date(d), "score": round(risk_score(r), 1)}
                for d, r in enumerate(self.result.risk[idx])]

    def users(self, limit: int = 50) -> list[dict]:
        last = self.p.ds.days - 1
        peak = self.result.risk[:, max(0, last - 13):].max(axis=1)
        top = peak.argsort()[::-1][:limit]
        case_count: dict[int, int] = {}
        for c in self.result.cases:
            case_count[c.idx] = case_count.get(c.idx, 0) + 1
        out = []
        for i in top:
            prof = self.p.ds.profiles[i]
            out.append({"subject": prof.pid, "kind": prof.kind, "role": prof.role,
                        "peer_group": self.p.detected[True].labels[last][i],
                        "current_score": round(risk_score(self.result.risk[i, last]), 1),
                        "peak_14d": round(risk_score(peak[i]), 1), "cases": case_count.get(int(i), 0),
                        "spark": [round(risk_score(r)) for r in self.result.risk[i, -30:]]})
        return out

    def user(self, pid: str) -> dict:
        i = self.p.ds.index(pid)
        prof = self.p.ds.profiles[i]
        sig = [s for s in self.result.scored if s.signal.idx == i]
        return {"subject": pid, "kind": prof.kind, "role": prof.role, "team": prof.team,
                "trend": self.trend(i),
                "cases": [self.case_row(c) for c in self.result.cases if c.idx == i],
                "signals": [{"day": s.signal.day, "detector": s.signal.detector, "points": round(s.points, 1),
                             "text": s.signal.reason} for s in sig][-50:]}

    # ------------------------------------------------------------------ actions
    def open_case(self, case_id: str, analyst: str) -> dict:
        with self.lock:
            self.case(case_id)
            st = self.case_status(case_id)
            if st["status"] == "new":
                st = {**st, "status": "open", "assignee": analyst}
                self.status[case_id] = st
                self._save()
            self.audit.record(analyst, "open_case", case_id, self.cases[case_id].pid)
            return st

    def reidentify(self, case_id: str, analyst: str, reason: str) -> dict:
        with self.lock:
            c = self.case(case_id)
            st = self.case_status(case_id)
            if st["status"] == "new":
                self.audit.record(analyst, "reidentify_denied", case_id, c.pid, reason=reason)
                raise NotAllowed("open the case before re-identifying its subject")
            if not reason.strip():
                raise NotAllowed("a reason is required")
            self.audit.record(analyst, "reidentify", case_id, c.pid, reason=reason)
            return {"case_id": case_id, "subject": c.pid, **self.p.vault.reidentify(c.pid)}

    def give_feedback(self, case_id: str, analyst: str, label: str, note: str = "") -> dict:
        if label not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")
        with self.lock:
            c = self.case(case_id)
            before = set(self.cases)
            fb = Feedback(case_id, c.idx, label, c.patterns, c.end_day + 1,
                          self.p.detected[True].labels[c.detect_day][c.idx], analyst, note)
            self.feedback.append(fb)
            self.status[case_id] = {"status": "closed", "assignee": self.case_status(case_id)["assignee"] or analyst,
                                    "label": label}
            self.recompute()
            self._save()
            self.audit.record(analyst, "feedback", case_id, c.pid, label=label, note=note)
            after = set(self.cases)
            return {"case_id": case_id, "label": label, "patterns": [list(x) for x in c.patterns],
                    "effective_day": fb.effective_day, "cases_before": len(before), "cases_after": len(after),
                    "removed": sorted(before - after), "added": sorted(after - before)}

    def summary(self) -> dict:
        w = self.p.world
        by_status = {s: 0 for s in STATUSES}
        for cid in self.cases:
            by_status[self.case_status(cid)["status"]] += 1
        return {"company": w.company, "start_date": w.date_of(0), "end_date": w.date_of(w.days - 1),
                "days": w.days, "warmup_days": w.warmup, "identities": self.p.ds.n,
                "employees": self.evaluation["employees"], "service_accounts": self.evaluation["service_accounts"],
                "events": len(w.events), "signals": len(self.result.scored), "cases": len(self.cases),
                "by_status": by_status, "features": FEATURES, "feedback": len(self.feedback)}
