from collections import Counter

import pytest

from uebalab.evaluate import evaluate, label_cases, markdown
from uebalab.generate import DAYS, generate, is_workday, next_workday, quarter_end_days


@pytest.fixture(scope="module")
def ev(pipeline):
    return evaluate(pipeline, max_days=3, max_benign=1)


def test_generator_is_deterministic():
    a, b = generate(seed=3, scale=0.05), generate(seed=3, scale=0.05)
    assert len(a.events) == len(b.events) and a.events[:50] == b.events[:50]
    assert len(generate(seed=4, scale=0.05).events) != len(a.events)


def test_world_shape(pipeline):
    w = pipeline.world
    kinds = Counter(p.kind for p in w.people.values())
    assert kinds["employee"] >= 280 and kinds["service"] >= 40
    assert {s.kind for s in w.scenarios if s.malicious} == {
        "departing_bulk_download", "compromised_account", "service_account_interactive", "credential_sharing",
        "contractor_after_end_date", "admin_mass_permission_change"}
    assert {s.kind for s in w.scenarios if not s.malicious} == {"approved_travel", "team_reorg",
                                                                 "quarter_end_finance"}
    assert all(e.day < DAYS for e in w.events)


def test_every_employee_has_manager_or_is_one(pipeline):
    people = pipeline.world.people
    for p in people.values():
        if p.kind == "employee" and p.role != "manager":
            assert people[p.manager].role == "manager"


def test_calendar_helpers():
    assert not is_workday(1) and not is_workday(2) and is_workday(3)  # 2026-07-04 is a Saturday
    assert next_workday(1) == 3
    qe = quarter_end_days()
    assert qe.stop == DAYS and is_workday(qe.start)
    assert sum(is_workday(d) for d in qe) == 5


def test_every_planted_scenario_becomes_a_case(ev):
    rows = ev["scenarios"]
    assert len(rows) == 6
    assert all(r["detected"] for r in rows), [r["sid"] for r in rows if not r["detected"]]
    assert max(r["days_to_detect"] for r in rows) <= 3


def test_benign_surprises_stay_quiet_with_context(ev):
    assert ev["configs"]["full"]["benign_cases"] <= 1


def test_gate_passes_and_can_fail(pipeline, ev):
    assert ev["gate"]["passed"]
    strict = evaluate(pipeline, max_days=-1, max_benign=-1)
    assert not strict["gate"]["passed"] and len(strict["gate"]["failures"]) >= 6


def test_context_is_what_catches_the_contractor(ev):
    rows = {r["sid"]: r for r in ev["configs"]["no_context"]["scenario_rows"]}
    assert not rows["S5"]["detected"]


def test_context_and_peers_cut_case_volume(ev):
    c = ev["configs"]
    assert c["full"]["cases"] < c["neither"]["cases"]
    assert c["full"]["benign_cases"] < c["neither"]["benign_cases"]
    assert c["full"]["signals"] < c["no_peers"]["signals"]


def test_case_accounting_adds_up(ev):
    for c in ev["configs"].values():
        assert c["malicious_cases"] + c["benign_cases"] + c["other_cases"] == c["cases"]
        assert sum(c["weekly"]) == c["cases"]
        assert len(c["labels"]) == c["cases"]
        if c["cases"]:
            assert c["precision"] == pytest.approx(c["malicious_cases"] / c["cases"], abs=1e-3)


def test_label_cases_marks_unmatched_as_other(pipeline):
    res = pipeline.score()
    lab = label_cases(pipeline, res.cases)
    assert set(lab["labels"]) == {c.case_id for c in res.cases}
    assert all(v == "other" or v.startswith(("S", "B-")) for v in lab["labels"].values())


def test_markdown_tables(ev):
    md = markdown(ev)
    assert "| S1 | departing bulk download |" in md
    assert "Peers and context" in md and "Gate" in md
