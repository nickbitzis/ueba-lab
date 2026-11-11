"""Detectors. Each one turns the pseudonymized dataset into `Signal`s with points, a reason, and evidence.

deviation       volume far above the identity's own history and (optionally) above its peers today
offhours        many events in hours this identity is almost never active
rare_resource   first access to a resource that no peer has touched in 30 days
novelty         first sign-in from a new country (or on a new device)
impossible_travel  two located events whose distance and time gap imply faster than an airliner
sequence        sign-in from a new country followed by a privilege change within an hour
service_interactive  a service account used for an interactive sign-in
after_end_date  any activity after a contract end or last working day (needs HR context)
iforest         isolation forest over daily deviation vectors, a low-weight extra signal
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from .baselines import SelfBaseline, peer_labels, peer_score, usual_hours
from .features import FEATURES, FI, Dataset
from .generate import CITIES, haversine_km, is_sensitive
from .iforest import IsolationForest

# feature: (minimum raw value worth flagging, label for reasons)
DEVIATION_FEATURES: dict[str, tuple[float, str]] = {
    "signins": (8, "interactive sign-ins"),
    "signin_fails": (6, "failed sign-ins"),
    "token_signins": (30, "token sign-ins"),
    "vpn_mb": (3000, "VPN MB"),
    "file_reads": (150, "file reads"),
    "file_mb": (300, "MB read from file shares"),
    "file_shares": (5, "distinct file shares"),
    "acl_changes": (30, "share permission changes"),
    "repo_clones": (10, "repo clones"),
    "repos": (6, "distinct repos"),
    "ext_emails": (40, "external emails"),
    "ext_mb": (100, "MB emailed externally"),
    "cloud_actions": (100, "cloud console actions"),
    "iam_changes": (20, "privilege changes"),
}
DATA_MOVEMENT = {"file_reads", "file_mb", "file_shares", "repo_clones", "repos", "ext_emails", "ext_mb", "vpn_mb"}
Z_SELF = 4.0
Z_PEER = 3.0
POINTS = {"rare_resource": 8.0, "rare_sensitive": 12.0, "new_country": 15.0, "new_device": 4.0,
          "impossible_travel": 30.0, "sequence": 40.0, "service_interactive": 45.0, "after_end_date": 60.0,
          "offhours": 8.0, "iforest": 6.0}
MAX_SPEED_KMH = 900.0
MIN_TRAVEL_KM = 500.0
SEQUENCE_MINUTES = 60
PEER_WINDOW = 30


@dataclass
class Signal:
    idx: int
    day: int
    detector: str
    key: str
    points: float
    reason: str
    evidence: dict = field(default_factory=dict)
    ts: int | None = None

    @property
    def pattern(self) -> tuple[str, str]:
        return (self.detector, self.key)


@dataclass
class DetectorOutput:
    signals: list[Signal]
    z_self: np.ndarray  # [N, D, F]
    labels: list[list[str]]  # peer group per day


PRIVILEGE_WEIGHT = 1.5  # permission and role changes matter more than volume


def deviation_points(z: float, feature: str = "") -> float:
    w = PRIVILEGE_WEIGHT if feature in ("acl_changes", "iam_changes") else 1.0
    return w * (6.0 + 2.5 * min(z - Z_SELF, 10.0))


def run_detectors(ds: Dataset, use_peers: bool = True, use_iforest: bool = True, seed: int = 0,
                  iforest_signals: list[Signal] | None = None) -> DetectorOutput:
    """Run every detector. The isolation forest does not depend on peers, so its signals can be passed in."""
    N, D, F = ds.X.shape
    sb = SelfBaseline()
    roles = [p.role for p in ds.profiles]
    reset = np.full(N, -1)
    for c in ds.context:
        if c.kind == "team_change":
            reset[c.idx] = c.start
    signals: list[Signal] = []
    z_all = np.zeros((N, D, F))
    labels_by_day: list[list[str]] = []
    seen_res: list[set[str]] = [set() for _ in range(N)]
    seen_dev: list[set[str]] = [set() for _ in range(N)]
    seen_cty: list[set[str]] = [set() for _ in range(N)]
    hist_days = np.zeros(N, dtype=int)
    res_users: list[dict[str, set[int]]] = []
    for d in range(D):
        labels = peer_labels(roles, [t[d] for t in ds.team_day])
        labels_by_day.append(labels)
        day_res: dict[str, set[int]] = {}
        for i in range(N):
            for r in ds.resources[i].get(d, ()):
                day_res.setdefault(r, set()).add(i)
        res_users.append(day_res)
        if d >= ds.warmup:
            r_dev = reset_for_day(reset, d)
            z, med, n_obs = sb.score(ds.X, ds.active, d, r_dev)
            z_all[:, d, :] = z
            zp, pmed = peer_score(ds.X[:, d, :], ds.active[:, d], labels)
            act = ds.active[:, d]
            signals += _deviation(ds, d, z, med, zp, pmed, n_obs, labels, act, use_peers)
            signals += _offhours(ds, sb, d, r_dev, n_obs, labels, act, use_peers)
            for i in np.flatnonzero(act):
                if hist_days[i] < sb.min_hist:
                    continue
                signals += _rare(ds, i, d, seen_res[i], labels, res_users, use_peers)
                signals += _novelty(ds, i, d, seen_dev[i], seen_cty[i])
                if ds.profiles[i].kind == "service" and ds.X[i, d, FI["signins"]] > 0:
                    signals.append(Signal(i, d, "service_interactive", "signin", POINTS["service_interactive"],
                                          f"Service account used for {int(ds.X[i, d, FI['signins']])} interactive "
                                          "sign-in(s); it normally signs in only with tokens.",
                                          {"devices": sorted(ds.devices[i].get(d, ()))}))
        for i in np.flatnonzero(ds.active[:, d]):
            seen_res[i] |= ds.resources[i].get(d, set())
            seen_dev[i] |= ds.devices[i].get(d, set())
            seen_cty[i] |= ds.countries[i].get(d, set())
            hist_days[i] += 1
    signals += _impossible_travel(ds)
    signals += _sequence(ds)
    signals += _after_end(ds)
    if iforest_signals is not None:
        signals += iforest_signals
    elif use_iforest:
        signals += _iforest(ds, z_all, seed)
    signals.sort(key=lambda s: (s.day, s.idx, s.detector))
    return DetectorOutput(signals, z_all, labels_by_day)


def reset_for_day(reset: np.ndarray, d: int) -> np.ndarray:
    return np.where((reset >= 0) & (reset <= d), reset, -1)


def _deviation(ds, d, z, med, zp, pmed, n_obs, labels, act, use_peers) -> list[Signal]:
    out = []
    X = ds.X[:, d, :]
    for f, (min_abs, label) in DEVIATION_FEATURES.items():
        k = FI[f]
        hit = act & (z[:, k] >= Z_SELF) & (X[:, k] >= min_abs) & (X[:, k] >= 2 * med[:, k])
        if use_peers:
            hit &= ~(zp[:, k] < Z_PEER)  # NaN (too few active peers) does not suppress
        for i in np.flatnonzero(hit):
            x, m, pm = float(X[i, k]), float(med[i, k]), pmed[i, k]
            peer_txt = f"; {labels[i]} peers today median {pm:,.0f}" if not math.isnan(pm) else ""
            out.append(Signal(int(i), d, "deviation", f, deviation_points(float(z[i, k]), f),
                              f"{x:,.0f} {label} vs usual {m:,.0f} ({x / max(m, 1):.1f}x){peer_txt}",
                              {"feature": f, "value": round(x, 1), "self_median": round(m, 1),
                               "z_self": round(float(z[i, k]), 1),
                               "z_peer": None if math.isnan(zp[i, k]) else round(float(zp[i, k]), 1),
                               "peer_median": None if math.isnan(pm) else round(float(pm), 1),
                               "peer_group": labels[i], "history_days": int(n_obs[i])}))
    return out


def _offhours(ds, sb, d, r_dev, n_obs, labels, act, use_peers) -> list[Signal]:
    lo = max(0, d - sb.max_window)
    mask = sb.window_mask(ds.active, d, r_dev)
    hist = (ds.hours[:, lo:d, :] * mask[:, :, None]).sum(axis=1)
    usual = usual_hours(hist)
    today = ds.hours[:, d, :]
    off = (today * ~usual).sum(axis=1)
    total = today.sum(axis=1)
    flag = act & (n_obs >= sb.min_hist) & (off >= 5) & (off >= 0.3 * np.maximum(total, 1))
    if use_peers:
        groups: dict[str, list[int]] = {}
        for i in np.flatnonzero(act):
            groups.setdefault(labels[i], []).append(i)
        for members in groups.values():
            if len(members) >= 5 and flag[members].mean() > 0.2:
                flag[members] = False  # the whole group is working odd hours today
    out = []
    for i in np.flatnonzero(flag):
        hrs = [h for h in range(24) if today[i, h] and not usual[i, h]]
        out.append(Signal(int(i), d, "offhours", "hours", POINTS["offhours"],
                          f"{int(off[i])} of {int(total[i])} events at unusual hours "
                          f"({', '.join(f'{h:02d}:00' for h in hrs[:4])} local)",
                          {"offhours_events": int(off[i]), "events": int(total[i]), "hours": hrs}))
    return out


def _rare(ds, i, d, seen, labels, res_users, use_peers) -> list[Signal]:
    new = ds.resources[i].get(d, set()) - seen
    out = []
    for r in sorted(new):
        if use_peers:
            peers = set()
            for dd in range(max(0, d - PEER_WINDOW), d + 1):
                peers |= res_users[dd].get(r, set())
            peers.discard(i)
            if any(labels[j] == labels[i] for j in peers):
                continue
            why = f"no {labels[i]} peer accessed it in {PEER_WINDOW} days"
        else:
            why = "never accessed by this identity before"
        sens = is_sensitive(r)
        out.append(Signal(int(i), d, "rare_resource", "sensitive" if sens else "resource",
                          POINTS["rare_sensitive" if sens else "rare_resource"],
                          f"First access to {r}{' (sensitive)' if sens else ''}; {why}",
                          {"resource": r, "sensitive": sens, "peer_group": labels[i]}))
    return out[:4]


def _novelty(ds, i, d, seen_dev, seen_cty) -> list[Signal]:
    out = []
    for c in sorted(ds.countries[i].get(d, set()) - seen_cty):
        out.append(Signal(int(i), d, "novelty", "country", POINTS["new_country"],
                          f"First sign-in from country {c}", {"country": c}))
    for dev in sorted(ds.devices[i].get(d, set()) - seen_dev)[:1]:
        out.append(Signal(int(i), d, "novelty", "device", POINTS["new_device"],
                          f"First use of device {dev}", {"device": dev}))
    return out


def _impossible_travel(ds) -> list[Signal]:
    """Consecutive located events (sign-ins, file reads, VPN, anything with a geo) that imply > 900 km/h.

    Using every located event, not only sign-ins, matters for shared credentials: the second person signs in
    once in the afternoon while the owner has been reading files from another continent all day.
    """
    out = []
    for i, evs in enumerate(ds.events):
        best: dict[int, tuple] = {}
        prev = None
        for e in evs:
            if prev is not None and e.city != prev.city and e.day >= ds.warmup:
                km = haversine_km(prev.city, e.city)
                hours = max((e.ts - prev.ts) / 60.0, 1 / 60)
                speed = km / hours
                if km >= MIN_TRAVEL_KM and speed > MAX_SPEED_KMH and speed > best.get(e.day, (0,))[0]:
                    best[e.day] = (speed, prev, e, km)
            prev = e
        for day, (speed, a, b, km) in best.items():
            out.append(Signal(i, day, "impossible_travel", "speed", POINTS["impossible_travel"],
                              f"Activity from {CITIES[a.city][0]} and {CITIES[b.city][0]} {km:,.0f} km apart, "
                              f"{(b.ts - a.ts) / 60:.1f} h apart ({speed:,.0f} km/h)",
                              {"from": a.city, "to": b.city, "km": round(km), "hours": round((b.ts - a.ts) / 60, 2),
                               "speed_kmh": round(speed), "countries": [CITIES[a.city][1], CITIES[b.city][1]],
                               "devices": [a.device, b.device], "sources": [a.source, b.source]}, ts=b.ts))
    return out


def _sequence(ds) -> list[Signal]:
    out = []
    for i, sis in enumerate(ds.signins):
        if not ds.privilege[i]:
            continue
        seen: set[str] = set()
        days_seen = 0
        last_day = -1
        for s in sorted(sis, key=lambda s: s.ts):
            if s.day != last_day:
                days_seen, last_day = days_seen + 1, s.day
            new_country = s.country not in seen and days_seen > 5
            seen.add(s.country)
            if not new_country or s.day < ds.warmup:
                continue
            for ts, _day, action, count in ds.privilege[i]:
                if s.ts <= ts <= s.ts + SEQUENCE_MINUTES:
                    out.append(Signal(i, s.day, "sequence", "new_country_then_privilege", POINTS["sequence"],
                                      f"Sign-in from new country {s.country}, then {action.replace('_', ' ')} "
                                      f"{ts - s.ts} min later",
                                      {"country": s.country, "countries": [s.country], "action": action,
                                       "minutes": ts - s.ts, "count": count}, ts=ts))
                    break
    return out


def _after_end(ds) -> list[Signal]:
    out = []
    for c in ds.context:
        if c.kind not in ("contract_end", "resignation"):
            continue
        for d in range(c.end + 1, ds.days):
            if ds.active[c.idx, d]:
                n = int(ds.hours[c.idx, d].sum())
                out.append(Signal(c.idx, d, "after_end_date", c.kind, POINTS["after_end_date"],
                                  f"{n} events {d - c.end} day(s) after the {c.kind.replace('_', ' ')} date",
                                  {"end_day": c.end, "events": n}))
    return out


def _iforest(ds, z_all, seed) -> list[Signal]:
    feats = [FI[f] for f in DEVIATION_FEATURES]
    rows = [(i, d) for d in range(ds.warmup, ds.days) for i in np.flatnonzero(ds.active[:, d])]
    if len(rows) < 300:
        return []
    ii = np.array([r[0] for r in rows])
    dd = np.array([r[1] for r in rows])
    V = np.clip(z_all[ii, dd][:, feats], -4, 10)
    train = dd < ds.warmup + 14
    rng = np.random.default_rng(seed)
    tr = np.flatnonzero(train)
    tr = rng.choice(tr, min(len(tr), 20000), replace=False)
    forest = IsolationForest(n_trees=100, sample_size=256, seed=seed).fit(V[tr])
    scores = forest.score(V)
    cut = float(np.quantile(scores[train], 0.999))
    out = []
    for k in np.flatnonzero(scores > cut):
        top = np.argsort(-V[k])[:3]
        names = [list(DEVIATION_FEATURES)[t] for t in top if V[k, t] > 2]
        out.append(Signal(int(ii[k]), int(dd[k]), "iforest", "daily_vector", POINTS["iforest"],
                          f"Unusual combination of daily activity (isolation score {scores[k]:.2f}, "
                          f"cutoff {cut:.2f})" + (f": {', '.join(names)}" if names else ""),
                          {"score": round(float(scores[k]), 3), "cutoff": round(cut, 3), "features": names}))
    return out


__all__ = ["Signal", "DetectorOutput", "run_detectors", "FEATURES", "DEVIATION_FEATURES"]
