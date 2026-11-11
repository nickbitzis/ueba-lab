from __future__ import annotations

import random

import pytest

from uebalab.features import ingest
from uebalab.generate import Event, HREvent, Person, World
from uebalab.pipeline import build
from uebalab.privacy import Vault

SCALE = 0.2


@pytest.fixture(scope="session")
def pipeline():
    return build(seed=7, scale=SCALE)


def person(uid: str, role: str = "engineer", team: str = "eng-data", office: str = "BOS", kind: str = "employee"):
    return Person(uid=uid, name=f"Name {uid}", email=f"{uid.lower()}@corvane.example", role=role, team=team,
                  office=office, manager=None, kind=kind, devices=[f"lt-{uid}"],
                  shares=["eng-data/shared", "eng-data/projects"])


class Tiny:
    """A hand-built world: 8 engineers in one team plus whatever a test adds, 40 days, 28 warm-up days."""

    def __init__(self, days: int = 40, warmup: int = 28, n: int = 8, seed: int = 1):
        self.days, self.warmup = days, warmup
        self.rng = random.Random(seed)
        self.people = {f"E{k}": person(f"E{k}") for k in range(n)}
        self.events: list[Event] = []
        self.hr: list[HREvent] = []

    def add(self, uid, day, minute, source, action, resource, city="BOS", device=None, count=1, mb=0.0):
        p = self.people[uid]
        offset = {"BOS": -4, "DUB": 1, "AUS": -5, "IAD": -4, "REK": 0, "LON": 1, "WAW": 2}[city]
        ts = int(day * 1440 + minute - offset * 60)
        self.events.append(Event(ts, day, uid, source, action, resource, city, device or p.devices[0], count, mb))

    def add_utc(self, uid, ts, source, action, resource, city, day=None, device=None, count=1):
        p = self.people[uid]
        self.events.append(Event(ts, ts // 1440 if day is None else day, uid, source, action, resource, city,
                                 device or p.devices[0], count, 0.0))

    def routine(self, uids=None, days=None, files: int = 20):
        for uid in uids or list(self.people):
            for d in days or range(self.days):
                self.add(uid, d, 540, "idp", "signin", "app:mail")
                n = max(1, files + self.rng.randint(-3, 3))
                self.add(uid, d, 600, "files", "read", "share:eng-data/shared", count=n, mb=10)
                self.add(uid, d, 900, "email", "send", "mail:internal", count=20)
        return self

    def world(self) -> World:
        evs = sorted(self.events, key=lambda e: e.ts)
        return World(self.people, evs, self.hr, [], days=self.days, warmup=self.warmup)

    def dataset(self):
        w = self.world()
        v = Vault(w.people, key="test-key")
        return ingest(w, v), v


@pytest.fixture
def tiny():
    return Tiny()
