"""Ingestion: pseudonymize raw logs and roll them up into daily feature vectors per identity.

Output is a `Dataset` keyed by pseudonym index. Nothing downstream sees an employee id, name, or email.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from .generate import CITIES, World
from .privacy import Profile, Vault

FEATURES = [
    "signins", "signin_fails", "token_signins", "vpn_mb", "file_reads", "file_mb", "file_shares", "acl_changes",
    "repo_clones", "repo_pushes", "repos", "emails", "ext_emails", "ext_mb", "cloud_actions", "iam_changes",
    "badge_entries",
]
FI = {f: k for k, f in enumerate(FEATURES)}
PRIVILEGE_ACTIONS = {"mfa_reset", "role_grant", "iam_grant", "acl_change"}


@dataclass
class Signin:
    ts: int
    day: int
    city: str
    country: str
    device: str
    interactive: bool


@dataclass
class ContextEvent:
    kind: str  # resignation, contract_end, travel, team_change
    idx: int
    start: int
    end: int
    detail: dict = field(default_factory=dict)


@dataclass
class Dataset:
    pids: list[str]
    profiles: list[Profile]
    days: int
    warmup: int
    X: np.ndarray  # [N, D, F] daily counts
    active: np.ndarray  # [N, D] any activity
    hours: np.ndarray  # [N, D, 24] events by local hour
    resources: list[dict[int, set[str]]]  # per identity: day -> resources touched
    devices: list[dict[int, set[str]]]
    countries: list[dict[int, set[str]]]
    signins: list[list[Signin]]
    privilege: list[list[tuple[int, int, str, int]]]  # (ts, day, action, count)
    team_day: list[list[str]]  # team per identity per day (changes with reorgs)
    context: list[ContextEvent]
    events: list[list]  # raw events per identity, for case timelines (user field is never shown)

    @property
    def n(self) -> int:
        return len(self.pids)

    def index(self, pid: str) -> int:
        return self.pids.index(pid)


def ingest(world: World, vault: Vault) -> Dataset:
    people = list(world.people.values())
    idx = {p.uid: k for k, p in enumerate(people)}
    pids = [vault.pid(p.uid) for p in people]
    profiles = [Profile(pids[k], p.kind, p.role, p.team, p.office) for k, p in enumerate(people)]
    N, D, F = len(people), world.days, len(FEATURES)
    X = [0.0] * (N * D * F)
    H = [0] * (N * D * 24)
    resources: list[dict[int, set[str]]] = [defaultdict(set) for _ in people]
    devices: list[dict[int, set[str]]] = [defaultdict(set) for _ in people]
    countries: list[dict[int, set[str]]] = [defaultdict(set) for _ in people]
    signins: list[list[Signin]] = [[] for _ in people]
    privilege: list[list[tuple[int, int, str, int]]] = [[] for _ in people]
    events: list[list] = [[] for _ in people]
    offset = [CITIES[p.office][4] * 60 for p in people]
    shares_seen: dict[tuple[int, int], set[str]] = defaultdict(set)
    repos_seen: dict[tuple[int, int], set[str]] = defaultdict(set)

    for e in world.events:
        i = idx[e.user]
        d = e.day
        if d < 0 or d >= D:
            continue
        events[i].append(e)
        base = (i * D + d) * F
        H[(i * D + d) * 24 + ((e.ts + offset[i]) % 1440) // 60] += 1
        src, act = e.source, e.action
        country = CITIES[e.city][1]
        if src == "idp":
            if act == "signin":
                X[base + 0] += 1
            elif act == "signin_fail":
                X[base + 1] += 1
            elif act == "token":
                X[base + 2] += 1
            if act in ("signin", "token"):
                signins[i].append(Signin(e.ts, d, e.city, country, e.device, act == "signin"))
                resources[i][d].add(e.resource)
            devices[i][d].add(e.device)
            countries[i][d].add(country)
            if act in PRIVILEGE_ACTIONS:
                X[base + 15] += e.count
        elif src == "vpn":
            X[base + 3] += e.mb
        elif src == "files":
            if act == "read":
                X[base + 4] += e.count
                X[base + 5] += e.mb
                shares_seen[(i, d)].add(e.resource)
                resources[i][d].add(e.resource)
            elif act == "acl_change":
                X[base + 7] += e.count
        elif src == "repo":
            X[base + (8 if act == "clone" else 9)] += e.count
            repos_seen[(i, d)].add(e.resource)
            resources[i][d].add(e.resource)
        elif src == "email":
            X[base + 11] += e.count
            if e.resource == "mail:external":
                X[base + 12] += e.count
                X[base + 13] += e.mb
        elif src == "cloud":
            if act == "iam_grant":
                X[base + 15] += e.count
            else:
                X[base + 14] += e.count
            resources[i][d].add(e.resource)
        elif src == "badge":
            X[base + 16] += 1
        if act in PRIVILEGE_ACTIONS:
            privilege[i].append((e.ts, d, act, e.count))
    for (i, d), s in shares_seen.items():
        X[(i * D + d) * F + 6] = len(s)
    for (i, d), s in repos_seen.items():
        X[(i * D + d) * F + 10] = len(s)

    Xa = np.array(X, dtype=np.float64).reshape(N, D, F)
    Ha = np.array(H, dtype=np.int32).reshape(N, D, 24)
    active = Ha.sum(axis=2) > 0
    team_day = [[p.team_on(d) for d in range(D)] if p.team_changes else [p.team] * D for p in people]
    context = []
    for h in world.hr:
        if h.uid in idx:
            context.append(ContextEvent(h.kind, idx[h.uid], h.start, h.end, dict(h.detail)))
    return Dataset(pids, profiles, D, world.warmup, Xa, active, Ha, [dict(r) for r in resources],
                   [dict(r) for r in devices], [dict(r) for r in countries], signins, privilege, team_day,
                   context, events)
