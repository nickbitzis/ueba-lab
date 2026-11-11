"""Pseudonymization at ingestion, an identity vault for re-identification, and an append-only audit log.

The analytics layer (features, baselines, detectors, scoring, cases) only ever sees pseudonyms. Real identities
live in the vault, which hands them out only for a case an analyst has opened, and records every request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

DEMO_KEY = "ueba-lab-demo-key-not-secret"


def pseudonym(uid: str, key: str) -> str:
    digest = hmac.new(key.encode(), uid.encode(), hashlib.sha256).hexdigest()
    prefix = "s" if uid.startswith("svc-") else "u"
    return f"{prefix}-{digest[:10]}"


@dataclass(frozen=True)
class Profile:
    """What the analytics layer may know about an identity: no name, no email, no employee id."""

    pid: str
    kind: str
    role: str
    team: str
    office: str


class Vault:
    def __init__(self, people: dict, key: str | None = None):
        self.key = key or os.environ.get("UEBA_PSEUDO_KEY", DEMO_KEY)
        self._to_pid = {uid: pseudonym(uid, self.key) for uid in people}
        self._identity = {
            self._to_pid[uid]: {"employee_id": p.uid, "name": p.name, "email": p.email,
                                "manager": p.manager, "contractor": p.contractor}
            for uid, p in people.items()
        }
        if len(set(self._to_pid.values())) != len(self._to_pid):
            raise ValueError("pseudonym collision")

    def pid(self, uid: str) -> str:
        return self._to_pid[uid]

    def reidentify(self, pid: str) -> dict:
        return dict(self._identity[pid])


class AuditLog:
    """Append-only JSON lines. Every case view, re-identification, and feedback is written here."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.lock = threading.Lock()
        self.entries: list[dict] = []
        if path and path.exists():
            self.entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def record(self, analyst: str, action: str, case_id: str | None = None, subject: str | None = None,
               **detail) -> dict:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seq": len(self.entries) + 1,
                 "analyst": analyst, "action": action, "case_id": case_id, "subject": subject, **detail}
        with self.lock:
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as f:
                    f.write(json.dumps(entry) + "\n")
        return entry

    def for_case(self, case_id: str) -> list[dict]:
        return [e for e in self.entries if e["case_id"] == case_id]
