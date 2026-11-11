"""A small isolation forest in numpy (Liu, Ting, Zhou 2008). Used as one extra, low-weight signal."""

from __future__ import annotations

import math

import numpy as np


def c_factor(n) -> np.ndarray:
    """Average path length of an unsuccessful binary search tree lookup among n points."""
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    big = n > 2
    out[big] = 2.0 * (np.log(n[big] - 1.0) + 0.5772156649) - 2.0 * (n[big] - 1.0) / n[big]
    out[n == 2] = 1.0
    return out


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 256, seed: int = 0):
        self.n_trees, self.sample_size = n_trees, sample_size
        self.rng = np.random.default_rng(seed)
        self.trees: list[tuple[np.ndarray, ...]] = []
        self.n = sample_size

    def fit(self, X: np.ndarray) -> IsolationForest:
        X = np.asarray(X, dtype=float)
        self.n = min(self.sample_size, len(X))
        limit = math.ceil(math.log2(max(self.n, 2)))
        self.trees = []
        for _ in range(self.n_trees):
            rows = X[self.rng.choice(len(X), self.n, replace=False)]
            self.trees.append(self._grow(rows, limit))
        return self

    def _grow(self, rows: np.ndarray, limit: int) -> tuple[np.ndarray, ...]:
        """One tree as flat arrays: split feature (-1 for a leaf), threshold, children, and node size."""
        feat: list[int] = []
        thr: list[float] = []
        left: list[int] = []
        right: list[int] = []
        size: list[int] = []

        def build(data: np.ndarray, depth: int) -> int:
            node = len(feat)
            feat.append(-1)
            thr.append(0.0)
            left.append(-1)
            right.append(-1)
            size.append(len(data))
            if depth >= limit or len(data) <= 1:
                return node
            lo, hi = data.min(axis=0), data.max(axis=0)
            spread = np.flatnonzero(hi > lo)
            if spread.size == 0:
                return node
            f = int(self.rng.choice(spread))
            t = float(self.rng.uniform(lo[f], hi[f]))
            feat[node], thr[node] = f, t
            mask = data[:, f] < t
            left[node] = build(data[mask], depth + 1)
            right[node] = build(data[~mask], depth + 1)
            return node

        build(rows, 0)
        return np.array(feat), np.array(thr), np.array(left), np.array(right), np.array(size)

    def path_length(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        total = np.zeros(len(X))
        rows = np.arange(len(X))
        for feat, thr, left, right, size in self.trees:
            node = np.zeros(len(X), dtype=int)
            depth = np.zeros(len(X))
            while True:
                internal = feat[node] >= 0
                if not internal.any():
                    break
                f = feat[node[internal]]
                go_left = X[rows[internal], f] < thr[node[internal]]
                node[internal] = np.where(go_left, left[node[internal]], right[node[internal]])
                depth[internal] += 1
            total += depth + c_factor(size[node])
        return total / len(self.trees)

    def score(self, X: np.ndarray) -> np.ndarray:
        """Anomaly score in (0, 1). Around 0.5 is ordinary; closer to 1 is easier to isolate."""
        return 2.0 ** (-self.path_length(X) / float(c_factor([self.n])[0]))
