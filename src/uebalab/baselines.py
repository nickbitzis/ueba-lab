"""Baselines: each identity against its own history, and against its peer group on the same day.

All volume math is in log1p space, so a deviation means "times more than usual" rather than "N more than usual".
Center and spread are the median and the scaled median absolute deviation (MAD), so a few odd days in the
history do not widen the band. The spread has a floor that depends on the level: counts near zero are noisy
(Poisson noise in log space is about 1/sqrt(mean)), so a jump from 0 to 2 is not 5 standard deviations.
"""

from __future__ import annotations

import warnings
from collections import Counter

import numpy as np

MAD_K = 1.4826  # makes the MAD match the standard deviation for normal data
MIN_SCALE = 0.25  # about a 28% change in raw units


def scale_floor(median_raw):
    return np.maximum(MIN_SCALE, 1.0 / np.sqrt(1.0 + np.asarray(median_raw, dtype=float)))


def center_scale(values) -> tuple[float, float]:
    """Median and floored MAD scale of raw values, computed in log1p space. Raises on empty input."""
    v = np.log1p(np.asarray(values, dtype=float))
    if v.size == 0:
        raise ValueError("no values")
    med = float(np.median(v))
    mad = float(np.median(np.abs(v - med)))
    return med, float(max(MAD_K * mad, scale_floor(np.expm1(med))))


def deviation(x_raw: float, values) -> float:
    med, scale = center_scale(values)
    return (float(np.log1p(x_raw)) - med) / scale


def nan_median(a: np.ndarray, axis: int = 1) -> np.ndarray:
    """Median ignoring NaN, NaN where a slice is all NaN. np.nanmedian falls back to masked arrays here and is
    about 20 times slower; sorting puts NaN last, so the median sits at the middle of the valid prefix."""
    s = np.sort(a, axis=axis)
    n = np.sum(~np.isnan(a), axis=axis, keepdims=True)
    lo = np.take_along_axis(s, np.maximum((n - 1) // 2, 0), axis=axis)
    hi = np.take_along_axis(s, np.maximum(n // 2, 0), axis=axis)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        med = np.where(n > 0, (lo + hi) / 2.0, np.nan)
    return np.squeeze(med, axis=axis)


class SelfBaseline:
    """Adaptive window per identity.

    Default: the last 28 days on which the identity was active. Too few active days (under `min_obs`): stretch to 56.
    A team change resets the window to start at the change, because the old team's routine no longer applies.
    Fewer than `min_hist` usable days: the identity is still warming up and gets no self deviation.
    """

    def __init__(self, window: int = 28, max_window: int = 56, min_obs: int = 10, min_hist: int = 5):
        self.window, self.max_window, self.min_obs, self.min_hist = window, max_window, min_obs, min_hist

    def window_mask(self, active: np.ndarray, d: int, reset_day: np.ndarray | None = None) -> np.ndarray:
        """Boolean [N, d - lo] mask of which past days count for each identity, with lo = max(0, d - max_window)."""
        lo = max(0, d - self.max_window)
        mask = active[:, lo:d].copy()
        days = np.arange(lo, d)
        if reset_day is not None:
            mask &= days[None, :] >= reset_day[:, None]
        recent = days >= d - self.window
        enough = (mask & recent[None, :]).sum(axis=1) >= self.min_obs
        mask[enough] &= recent[None, :]
        return mask

    def score(self, X: np.ndarray, active: np.ndarray, d: int, reset_day: np.ndarray | None = None):
        """z [N, F], median in raw units [N, F], usable history days [N]."""
        N, _, F = X.shape
        if d == 0:
            return np.zeros((N, F)), np.zeros((N, F)), np.zeros(N, dtype=int)
        lo = max(0, d - self.max_window)
        mask = self.window_mask(active, d, reset_day)
        L = np.log1p(X[:, lo:d, :])
        L = np.where(mask[:, :, None], L, np.nan)
        med = nan_median(L, axis=1)
        mad = nan_median(np.abs(L - med[:, None, :]), axis=1)
        n_obs = mask.sum(axis=1)
        med = np.nan_to_num(med)
        scale = np.maximum(MAD_K * np.nan_to_num(mad), scale_floor(np.expm1(med)))
        z = (np.log1p(X[:, d, :]) - med) / scale
        z[n_obs < self.min_hist] = 0.0
        return z, np.expm1(med), n_obs


def peer_labels(roles: list[str], teams: list[str], min_size: int = 5) -> list[str]:
    """Peer group per identity: same role and team. Small groups fall back to the role across teams, then the team."""
    by_rt = Counter(zip(roles, teams, strict=True))
    by_role = Counter(roles)
    by_team = Counter(teams)
    out = []
    for r, t in zip(roles, teams, strict=True):
        if by_rt[(r, t)] >= min_size:
            out.append(f"{r}@{t}")
        elif by_role[r] >= min_size:
            out.append(f"{r}@*")
        elif by_team[t] >= min_size:
            out.append(f"*@{t}")
        else:
            out.append("*@*")
    return out


def peer_score(X_day: np.ndarray, active_day: np.ndarray, labels: list[str], min_active: int = 3):
    """z [N, F] of each identity against peers active the same day, and the peer median in raw units.

    NaN when the group has too few active members.

    Same-day comparison is what lets a quarter-end spike across all of finance look normal.
    """
    N, F = X_day.shape
    z = np.full((N, F), np.nan)
    peer_med = np.full((N, F), np.nan)
    L = np.log1p(X_day)
    groups: dict[str, list[int]] = {}
    for i, g in enumerate(labels):
        groups.setdefault(g, []).append(i)
    for members in groups.values():
        m = np.array(members)
        act = m[active_day[m]]
        if act.size < min_active:
            continue
        med = np.median(L[act], axis=0)
        mad = np.median(np.abs(L[act] - med), axis=0)
        scale = np.maximum(MAD_K * mad, scale_floor(np.expm1(med)))
        z[m] = (L[m] - med) / scale
        peer_med[m] = np.expm1(med)
    return z, peer_med


def usual_hours(hist: np.ndarray, min_share: float = 0.01) -> np.ndarray:
    """[N, 24] bool: hours that are usual for each identity, from a summed [N, 24] history.

    An hour counts as usual when it or a neighboring hour holds at least 1% of past events.
    """
    total = hist.sum(axis=1, keepdims=True)
    smooth = hist + np.roll(hist, 1, axis=1) + np.roll(hist, -1, axis=1)
    return smooth >= np.maximum(1, min_share * total)
