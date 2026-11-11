"""End to end: generate logs, pseudonymize, extract features, detect, score, and build cases."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .detectors import DetectorOutput, run_detectors
from .features import Dataset, ingest
from .generate import World, generate
from .privacy import Vault
from .scoring import Feedback, ScoreResult, ScoringConfig, score_and_build


@dataclass
class Pipeline:
    world: World
    vault: Vault
    ds: Dataset
    detected: dict[bool, DetectorOutput]  # keyed by use_peers
    timings: dict[str, float] = field(default_factory=dict)

    def score(self, use_peers: bool = True, use_context: bool = True,
              feedback: list[Feedback] | None = None) -> ScoreResult:
        out = self.detected[use_peers]
        return score_and_build(self.ds, out.signals, out.labels, ScoringConfig(use_context=use_context), feedback)


def build(seed: int = 7, scale: float = 1.0, key: str | None = None, ablation: bool = True) -> Pipeline:
    t: dict[str, float] = {}
    t0 = time.perf_counter()
    world = generate(seed=seed, scale=scale)
    t["generate"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    vault = Vault(world.people, key)
    ds = ingest(world, vault)
    t["ingest"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    detected = {True: run_detectors(ds, use_peers=True, seed=seed)}
    if ablation:
        reuse = [s for s in detected[True].signals if s.detector == "iforest"]
        detected[False] = run_detectors(ds, use_peers=False, seed=seed, iforest_signals=reuse)
    t["detect"] = time.perf_counter() - t0
    return Pipeline(world, vault, ds, detected, {k: round(v, 2) for k, v in t.items()})
