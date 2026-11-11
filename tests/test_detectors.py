import numpy as np
import pytest
from conftest import Tiny, person

from uebalab.detectors import MAX_SPEED_KMH, deviation_points, run_detectors
from uebalab.generate import HREvent, haversine_km
from uebalab.iforest import IsolationForest, c_factor


def detect(t: Tiny, use_peers=True):
    ds, vault = t.dataset()
    return run_detectors(ds, use_peers=use_peers, use_iforest=False).signals, ds, vault


def of(signals, ds, vault, uid, detector=None):
    i = ds.index(vault.pid(uid))
    return [s for s in signals if s.idx == i and (detector is None or s.detector == detector)]


def test_routine_activity_raises_nothing(tiny):
    sigs, ds, v = detect(tiny.routine())
    assert sigs == []


def test_deviation_on_volume_spike(tiny):
    tiny.routine()
    tiny.add("E1", 35, 610, "files", "read", "share:eng-data/shared", count=900, mb=2000)
    sigs, ds, v = detect(tiny)
    hits = of(sigs, ds, v, "E1", "deviation")
    assert {s.key for s in hits} >= {"file_reads", "file_mb"}
    s = next(x for x in hits if x.key == "file_reads")
    assert s.evidence["z_self"] > 4 and s.evidence["z_peer"] > 3 and s.day == 35
    assert "vs usual" in s.reason


def test_deviation_suppressed_when_peers_spike_the_same_day(tiny):
    tiny.routine()
    for uid in tiny.people:
        tiny.add(uid, 35, 610, "files", "read", "share:eng-data/shared", count=900, mb=2000)
    with_peers, ds, v = detect(tiny)
    assert not [s for s in with_peers if s.detector == "deviation"]
    without, ds, v = detect(tiny, use_peers=False)
    assert len({s.idx for s in without if s.detector == "deviation"}) == len(tiny.people)


def test_deviation_needs_minimum_absolute_volume(tiny):
    tiny.routine(files=2)
    tiny.add("E1", 35, 610, "files", "read", "share:eng-data/shared", count=60)
    sigs, ds, v = detect(tiny)
    assert not of(sigs, ds, v, "E1", "deviation")


def test_deviation_points_grow_with_z_and_cap():
    assert deviation_points(4) == 6
    assert deviation_points(8) > deviation_points(5)
    assert deviation_points(100) == deviation_points(14)
    assert deviation_points(6, "iam_changes") == pytest.approx(1.5 * deviation_points(6))


def test_rare_resource_peers_never_touch(tiny):
    tiny.routine()
    tiny.add("E2", 33, 700, "files", "read", "share:hr/reports", count=5)
    sigs, ds, v = detect(tiny)
    hits = of(sigs, ds, v, "E2", "rare_resource")
    assert len(hits) == 1 and hits[0].evidence["sensitive"] and hits[0].key == "sensitive"


def test_rare_resource_not_flagged_when_peers_use_it(tiny):
    tiny.routine()
    for d in range(10, 20):
        tiny.add("E3", d, 700, "files", "read", "share:eng-data/archive", count=5)
    tiny.add("E2", 33, 700, "files", "read", "share:eng-data/archive", count=5)
    sigs, ds, v = detect(tiny)
    assert not of(sigs, ds, v, "E2", "rare_resource")
    without, ds, v = detect(tiny, use_peers=False)
    assert of(without, ds, v, "E2", "rare_resource")


def test_new_country_and_device(tiny):
    tiny.routine()
    tiny.add("E4", 34, 600, "idp", "signin", "app:mail", city="WAW", device="ph-new")
    sigs, ds, v = detect(tiny)
    keys = {s.key for s in of(sigs, ds, v, "E4", "novelty")}
    assert keys == {"country", "device"}


@pytest.mark.parametrize("gap_min,flag", [(60, True), (300, True), (600, False)])
def test_impossible_travel_by_speed(tiny, gap_min, flag):
    # Boston to Dublin is about 4,800 km. 1 h and 5 h are too fast; 10 h is an ordinary flight.
    tiny.routine()
    t0 = 33 * 1440 + 1200  # UTC, after the routine Boston events that day
    tiny.add_utc("E5", t0, "idp", "signin", "app:mail", "BOS", day=33)
    tiny.add_utc("E5", t0 + gap_min, "idp", "signin", "app:mail", "DUB", day=33)
    sigs, ds, v = detect(tiny)
    hits = [s for s in of(sigs, ds, v, "E5", "impossible_travel") if s.day == 33]
    assert bool(hits) == flag
    if hits:
        km = haversine_km("BOS", "DUB")
        assert hits[0].evidence["speed_kmh"] == pytest.approx(km / (gap_min / 60), rel=0.02)
        assert hits[0].evidence["speed_kmh"] > MAX_SPEED_KMH


def test_impossible_travel_ignores_short_hops(tiny, monkeypatch):
    # Geo-IP is coarse, so pairs closer than MIN_TRAVEL_KM never count. Ashburn is about 650 km from Boston.
    tiny.routine()
    tiny.add("E5", 33, 1000, "idp", "signin", "app:mail", city="IAD")
    tiny.add("E5", 33, 1001, "idp", "signin", "app:mail", city="BOS")
    assert of(*detect(tiny), "E5", "impossible_travel")
    monkeypatch.setattr("uebalab.detectors.MIN_TRAVEL_KM", 700.0)
    assert not of(*detect(tiny), "E5", "impossible_travel")


def test_haversine_known_distance():
    assert haversine_km("BOS", "DUB") == pytest.approx(4800, rel=0.03)
    assert haversine_km("BOS", "BOS") == 0


def _sequence_world(gap: int, known_country: bool = False, before: bool = False):
    t = Tiny().routine()
    if known_country:
        for d in range(5, 10):
            t.add("E6", d, 800, "idp", "signin", "app:mail", city="REK")
    t.add("E6", 33, 600, "idp", "signin", "app:mail", city="REK")
    t.add("E6", 33, 600 + (-gap if before else gap), "idp", "mfa_reset", "app:idp", city="REK")
    return t


@pytest.mark.parametrize("gap,flag", [(5, True), (59, True), (61, False), (180, False)])
def test_sequence_new_country_then_privilege_within_an_hour(gap, flag):
    sigs, ds, v = detect(_sequence_world(gap))
    assert bool(of(sigs, ds, v, "E6", "sequence")) == flag


def test_sequence_needs_the_privilege_change_after_the_sign_in():
    sigs, ds, v = detect(_sequence_world(10, before=True))
    assert not of(sigs, ds, v, "E6", "sequence")


def test_sequence_ignores_known_country():
    sigs, ds, v = detect(_sequence_world(10, known_country=True))
    assert not of(sigs, ds, v, "E6", "sequence")


def test_service_account_interactive_sign_in(tiny):
    tiny.routine()
    tiny.people["svc-etl-001"] = person("svc-etl-001", role="svc-etl", office="IAD", kind="service")
    for d in range(tiny.days):
        tiny.add("svc-etl-001", d, 100, "idp", "token", "app:api", city="IAD")
    tiny.add("svc-etl-001", 36, 610, "idp", "signin", "app:wiki", city="IAD", device="lt-x")
    sigs, ds, v = detect(tiny)
    hits = of(sigs, ds, v, "svc-etl-001", "service_interactive")
    assert len(hits) == 1 and hits[0].day == 36


def test_employee_sign_in_is_not_a_service_rule(tiny):
    sigs, ds, v = detect(tiny.routine())
    assert not [s for s in sigs if s.detector == "service_interactive"]


def test_activity_after_end_date(tiny):
    tiny.routine()
    tiny.hr.append(HREvent("contract_end", "E7", 32, 32))
    sigs, ds, v = detect(tiny)
    hits = of(sigs, ds, v, "E7", "after_end_date")
    assert [s.day for s in hits] == list(range(33, 40))


def test_offhours_flags_night_work(tiny):
    tiny.routine()
    for k in range(8):
        tiny.add("E1", 35, 150 + k, "files", "read", "share:eng-data/shared", count=3)
    sigs, ds, v = detect(tiny)
    hits = of(sigs, ds, v, "E1", "offhours")
    assert hits and hits[0].evidence["offhours_events"] >= 8


def test_isolation_forest_scores_outlier_higher():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 4))
    forest = IsolationForest(n_trees=60, sample_size=128, seed=1).fit(X)
    s = forest.score(np.vstack([X[:50], [[8, 8, 8, 8]]]))
    assert s[-1] > 0.7 and s[-1] > s[:-1].max()
    assert 0.35 < float(np.median(s[:-1])) < 0.6


def test_c_factor_values():
    assert c_factor([1])[0] == 0 and c_factor([2])[0] == 1
    assert c_factor([256])[0] == pytest.approx(10.24, abs=0.05)
