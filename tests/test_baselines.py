import math

import numpy as np
import pytest

from uebalab.baselines import (
    MAD_K,
    MIN_SCALE,
    SelfBaseline,
    center_scale,
    deviation,
    nan_median,
    peer_labels,
    peer_score,
    scale_floor,
    usual_hours,
)


def test_center_is_median_in_log_space():
    med, _ = center_scale([9, 99, 999])
    assert med == pytest.approx(math.log(100))


def test_scale_is_scaled_mad():
    vals = np.expm1([1.0, 2.0, 3.0, 4.0, 5.0])
    med, scale = center_scale(vals)
    assert med == pytest.approx(3.0)
    assert scale == pytest.approx(MAD_K * 1.0)


def test_scale_floor_for_constant_history():
    med, scale = center_scale([100] * 20)
    assert scale == pytest.approx(max(MIN_SCALE, 1 / math.sqrt(101)))
    assert math.isfinite(deviation(150, [100] * 20))


def test_floor_is_wider_for_small_counts():
    assert scale_floor(1) > scale_floor(100)
    assert scale_floor(0) == pytest.approx(1.0)
    assert scale_floor(10_000) == pytest.approx(MIN_SCALE)


def test_zero_to_two_is_not_extreme():
    assert deviation(2, [0] * 20) < 2


def test_tenfold_jump_is_extreme():
    history = [100 + k % 7 for k in range(28)]
    assert deviation(1000, history) > 6


def test_one_bad_day_does_not_move_the_baseline():
    clean = [50 + k % 5 for k in range(27)]
    assert center_scale(clean + [5000]) == pytest.approx(center_scale(clean + [52]), rel=0.05)


def test_center_scale_rejects_empty():
    with pytest.raises(ValueError):
        center_scale([])


def test_nan_median_matches_numpy():
    rng = np.random.default_rng(0)
    a = rng.normal(size=(40, 30, 5))
    a[a > 0.8] = np.nan
    ref = np.nanmedian(a, axis=1)
    assert np.allclose(nan_median(a, 1), ref, equal_nan=True)


def test_nan_median_all_nan_slice_is_nan():
    a = np.full((2, 4, 1), np.nan)
    a[0, :, 0] = [1, 2, 3, 4]
    out = nan_median(a, 1)
    assert out[0, 0] == 2.5 and np.isnan(out[1, 0])


def _series(n_id=3, days=60, value=20.0):
    X = np.full((n_id, days, 1), value)
    X += np.arange(days)[None, :, None] % 3
    return X, np.ones((n_id, days), dtype=bool)


def test_self_window_is_28_days_when_active():
    _, active = _series()
    mask = SelfBaseline().window_mask(active, 59)
    assert mask.sum(axis=1).tolist() == [28, 28, 28]


def test_self_window_stretches_when_sparse():
    _, active = _series()
    active[0, :] = False
    active[0, ::4] = True  # every fourth day: 7 in the last 28
    mask = SelfBaseline().window_mask(active, 59)
    assert mask[0].sum() > 7
    assert mask[1].sum() == 28


def test_team_change_resets_window():
    _, active = _series()
    reset = np.array([50, -1, -1])
    mask = SelfBaseline().window_mask(active, 59, reset)
    assert mask[0].sum() == 9
    assert mask[1].sum() == 28


def test_self_score_flags_spike_only_for_spiking_identity():
    X, active = _series()
    X[1, 59, 0] = 400
    z, med, n_obs = SelfBaseline().score(X, active, 59)
    assert z[1, 0] > 4 and abs(z[0, 0]) < 2
    assert med[0, 0] == pytest.approx(21, abs=1)
    assert n_obs.tolist() == [28, 28, 28]


def test_self_score_warming_identity_gets_zero():
    X, active = _series()
    active[2, :] = False
    active[2, 56:] = True
    X[2, 59, 0] = 999
    z, _, n_obs = SelfBaseline().score(X, active, 59)
    assert n_obs[2] == 3 and z[2, 0] == 0


def test_peer_labels_prefer_role_and_team():
    roles = ["eng"] * 5 + ["acct"] * 5
    teams = ["a"] * 5 + ["b"] * 5
    assert peer_labels(roles, teams) == ["eng@a"] * 5 + ["acct@b"] * 5


def test_peer_labels_fall_back_to_role_then_team():
    roles = ["eng"] * 3 + ["eng"] * 3 + ["pm"] * 2 + ["qa"] * 4
    teams = ["a"] * 3 + ["b"] * 3 + ["c"] * 2 + ["c"] * 4
    labels = peer_labels(roles, teams)
    assert labels[0] == "eng@*" and labels[3] == "eng@*"
    assert labels[6] == "*@c"
    assert peer_labels(["x", "y"], ["p", "q"]) == ["*@*", "*@*"]


def test_peer_score_same_day_spike_for_whole_group_is_normal():
    X = np.full((6, 1), 400.0)  # everyone in the group at 4x: quarter end
    z, med = peer_score(X, np.ones(6, dtype=bool), ["fin@a"] * 6)
    assert np.allclose(z, 0) and med[0, 0] == pytest.approx(400)


def test_peer_score_flags_one_outlier():
    X = np.array([[20.0], [22.0], [19.0], [21.0], [20.0], [400.0]])
    z, _ = peer_score(X, np.ones(6, dtype=bool), ["eng@a"] * 6)
    assert z[5, 0] > 4 and abs(z[0, 0]) < 1


def test_peer_score_needs_active_members():
    X = np.ones((4, 1))
    active = np.array([True, True, False, False])
    z, _ = peer_score(X, active, ["g"] * 4)
    assert np.isnan(z).all()


def test_usual_hours_include_neighbors():
    hist = np.zeros((1, 24))
    hist[0, 9:17] = 10
    usual = usual_hours(hist)
    assert usual[0, 8] and usual[0, 17] and usual[0, 12]
    assert not usual[0, 2] and not usual[0, 22]
