import pytest
from conftest import Tiny

from uebalab.detectors import Signal
from uebalab.features import ContextEvent
from uebalab.generate import quarter_end_days
from uebalab.scoring import (
    QUARTER_END_FACTOR,
    RESIGNATION_FACTOR,
    TEAM_CHANGE_FACTOR,
    TRAVEL_FACTOR,
    ContextIndex,
    Feedback,
    ScoringConfig,
    risk_score,
    score_and_build,
)


@pytest.fixture
def ds():
    d, _ = Tiny(days=90, warmup=28).routine(days=range(3)).dataset()
    return d


def labels(ds):
    return [["engineer@eng-data"] * ds.n for _ in range(ds.days)]


def sig(day, points=50.0, idx=1, detector="deviation", key="file_reads", **evidence):
    return Signal(idx, day, detector, key, points, f"{detector} {key}", evidence)


def run(ds, signals, cfg=None, feedback=None):
    return score_and_build(ds, signals, labels(ds), cfg or ScoringConfig(), feedback)


def test_decay_halves_every_half_life(ds):
    r = run(ds, [sig(40, 40)])
    assert r.risk[1, 40] == pytest.approx(40)
    assert r.risk[1, 43] == pytest.approx(20)
    assert r.risk[1, 46] == pytest.approx(10)
    assert r.risk[0].max() == 0


def test_decay_accumulates_repeated_signals(ds):
    r = run(ds, [sig(40, 20), sig(41, 20)])
    assert r.risk[1, 41] == pytest.approx(20 * 0.5 ** (1 / 3) + 20)


def test_risk_score_mapping():
    assert risk_score(0) == 0
    assert risk_score(40) == pytest.approx(48.7, abs=0.1)
    assert risk_score(10_000) == pytest.approx(100)
    assert risk_score(30) < risk_score(60) < risk_score(120)


def test_case_opens_at_threshold_not_below(ds):
    assert run(ds, [sig(40, 39.9)]).cases == []
    r = run(ds, [sig(40, 40)])
    assert len(r.cases) == 1 and r.cases[0].detect_day == 40


def test_two_moderate_days_open_one_case(ds):
    r = run(ds, [sig(40, 25), sig(41, 25)])
    assert len(r.cases) == 1
    c = r.cases[0]
    assert (c.start_day, c.detect_day) == (40, 41) and len(c.items) == 2


def test_related_signals_join_the_open_case(ds):
    r = run(ds, [sig(40, 60), sig(42, 10, detector="novelty", key="country"), sig(44, 15)])
    assert len(r.cases) == 1
    assert r.cases[0].end_day == 44 and len(r.cases[0].items) == 3


def test_new_case_after_risk_decays(ds):
    r = run(ds, [sig(40, 60), sig(70, 60)])
    assert sorted(c.detect_day for c in r.cases) == [40, 70]
    assert len({c.case_id for c in r.cases}) == 2


def test_lookback_pulls_earlier_signals_into_the_case(ds):
    r = run(ds, [sig(30, 10, detector="novelty", key="device"), sig(36, 45)])
    assert r.cases[0].start_day == 30
    r = run(ds, [sig(20, 10, detector="novelty", key="device"), sig(36, 45)])
    assert r.cases[0].start_day == 36


def test_reasons_rank_by_points(ds):
    r = run(ds, [sig(40, 30, detector="impossible_travel", key="speed"), sig(40, 12, detector="novelty",
                 key="country"), sig(40, 20)])
    reasons = r.cases[0].reasons()
    assert [x["detector"] for x in reasons] == ["impossible_travel", "deviation", "novelty"]


def test_cases_rank_by_peak_risk(ds):
    r = run(ds, [sig(40, 45, idx=1), sig(40, 90, idx=2)])
    assert [c.idx for c in r.cases] == [2, 1]


def ctx_ds(ds, *events):
    ds.context = list(events)
    return ds


def test_resignation_raises_data_movement(ds):
    ctx_ds(ds, ContextEvent("resignation", 1, 35, 50))
    mult, notes = ContextIndex(ds).adjust(sig(40, 10, key="file_mb"))
    assert mult == RESIGNATION_FACTOR and "resignation" in notes[0]
    assert ContextIndex(ds).adjust(sig(40, 10, detector="novelty", key="device"))[0] == 1.0
    assert ContextIndex(ds).adjust(sig(30, 10, key="file_mb"))[0] == 1.0


def test_resignation_turns_a_near_miss_into_a_case(ds):
    signals = [sig(40, 30, key="file_mb")]
    assert run(ds, signals).cases == []
    ctx_ds(ds, ContextEvent("resignation", 1, 35, 50))
    assert len(run(ds, signals).cases) == 1


def test_approved_travel_lowers_matching_country_only(ds):
    ctx_ds(ds, ContextEvent("travel", 1, 38, 42, {"country": "JP", "approved": True}))
    idx = ContextIndex(ds)
    assert idx.adjust(sig(39, 15, detector="novelty", key="country", country="JP"))[0] == TRAVEL_FACTOR
    assert idx.adjust(sig(39, 30, detector="impossible_travel", key="speed", countries=["US", "JP"]))[0] == \
        TRAVEL_FACTOR
    assert idx.adjust(sig(39, 15, detector="novelty", key="country", country="IS"))[0] == 1.0
    assert idx.adjust(sig(50, 15, detector="novelty", key="country", country="JP"))[0] == 1.0


def test_team_change_lowers_rare_resource_for_30_days(ds):
    ctx_ds(ds, ContextEvent("team_change", 1, 45, 45, {"from": "a", "to": "b"}))
    idx = ContextIndex(ds)
    assert idx.adjust(sig(50, 8, detector="rare_resource", key="resource"))[0] == TEAM_CHANGE_FACTOR
    assert idx.adjust(sig(80, 8, detector="rare_resource", key="resource"))[0] == 1.0


def test_quarter_end_lowers_finance_volume(ds):
    day = quarter_end_days().start
    ds.team_day[1] = ["finance-fpa"] * ds.days
    idx = ContextIndex(ds)
    assert idx.adjust(sig(day, 20))[0] == QUARTER_END_FACTOR
    assert idx.adjust(sig(day - 10, 20))[0] == 1.0
    assert idx.adjust(sig(day, 20, idx=2))[0] == 1.0


def test_context_can_be_switched_off(ds):
    ctx_ds(ds, ContextEvent("travel", 1, 38, 42, {"country": "JP"}))
    s = [sig(39, 45, detector="novelty", key="country", country="JP"),
         sig(60, 60, idx=2, detector="after_end_date", key="contract_end")]
    on = run(ds, s)
    off = run(ds, s, ScoringConfig(use_context=False))
    assert [c.idx for c in on.cases] == [2]
    assert [c.idx for c in off.cases] == [1]


def fb(label, idx=1, patterns=(("deviation", "file_reads"),), day=50, group="engineer@eng-data"):
    return Feedback("C1", idx, label, list(patterns), day, group)


def test_benign_feedback_halves_the_same_pattern_later(ds):
    s = [sig(60, 60)]
    r = run(ds, s, feedback=[fb("benign")])
    assert r.risk[1, 60] == pytest.approx(30)
    assert r.cases == []


def test_feedback_does_not_rewrite_the_past(ds):
    r = run(ds, [sig(40, 60)], feedback=[fb("expected", day=50)])
    assert r.risk[1, 40] == pytest.approx(60)


def test_expected_feedback_nearly_silences_the_pattern(ds):
    r = run(ds, [sig(60, 60)], feedback=[fb("expected")])
    assert r.risk[1, 60] == pytest.approx(6)


def test_feedback_is_specific_to_pattern_and_subject(ds):
    r = run(ds, [sig(60, 60, key="ext_mb"), sig(60, 60, idx=2)], feedback=[fb("benign")])
    assert r.risk[1, 60] == pytest.approx(60)
    assert r.risk[2, 60] == pytest.approx(60)


def test_true_positive_raises_the_pattern_for_the_peer_group(ds):
    r = run(ds, [sig(60, 36, idx=3)], feedback=[fb("true_positive", idx=1)])
    assert r.risk[3, 60] == pytest.approx(45)
    assert len(r.cases) == 1


def test_feedback_can_be_switched_off(ds):
    r = score_and_build(ds, [sig(60, 60)], labels(ds), ScoringConfig(use_feedback=False), [fb("expected")])
    assert r.risk[1, 60] == pytest.approx(60)
