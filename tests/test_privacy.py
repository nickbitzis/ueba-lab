import json

import pytest

from uebalab.privacy import AuditLog, Vault, pseudonym
from uebalab.service import NotAllowed, Service


def test_pseudonym_is_deterministic_and_keyed():
    assert pseudonym("E10001", "k1") == pseudonym("E10001", "k1")
    assert pseudonym("E10001", "k1") != pseudonym("E10001", "k2")
    assert pseudonym("E10001", "k1") != pseudonym("E10002", "k1")


def test_pseudonym_does_not_contain_the_id():
    p = pseudonym("E10001", "k")
    assert "10001" not in p and p.startswith("u-") and len(p) == 12
    assert pseudonym("svc-ci-001", "k").startswith("s-")


def test_vault_reidentifies(pipeline):
    v = pipeline.vault
    uid, person = next(iter(pipeline.world.people.items()))
    ident = v.reidentify(v.pid(uid))
    assert ident["employee_id"] == uid and ident["name"] == person.name


def test_vault_key_from_environment(monkeypatch, pipeline):
    monkeypatch.setenv("UEBA_PSEUDO_KEY", "other")
    v = Vault(pipeline.world.people)
    uid = next(iter(pipeline.world.people))
    assert v.pid(uid) != pipeline.vault.pid(uid)


def test_analytics_layer_holds_no_identities(pipeline):
    ds = pipeline.ds
    blob = json.dumps({"pids": ds.pids, "profiles": [p.__dict__ for p in ds.profiles],
                       "context": [c.__dict__ for c in ds.context],
                       "signals": [s.reason + json.dumps(s.evidence, default=str)
                                   for s in pipeline.detected[True].signals]})
    for uid, p in list(pipeline.world.people.items())[:200]:
        assert uid not in blob and p.email not in blob
        if p.kind == "employee":
            assert p.name not in blob


def test_audit_log_appends_and_reloads(tmp_path):
    path = tmp_path / "audit.jsonl"
    a = AuditLog(path)
    a.record("ana", "view_case", "C1", "u-1")
    a.record("ana", "reidentify", "C1", "u-1", reason="why")
    b = AuditLog(path)
    assert [e["action"] for e in b.entries] == ["view_case", "reidentify"]
    assert b.entries[1]["reason"] == "why" and b.entries[1]["seq"] == 2
    assert len(b.for_case("C1")) == 2 and b.for_case("C2") == []


@pytest.fixture
def svc(pipeline, tmp_path):
    return Service(pipeline, tmp_path)


def test_reidentify_denied_until_case_is_opened(svc):
    cid = svc.result.cases[0].case_id
    with pytest.raises(NotAllowed):
        svc.reidentify(cid, "ana", "checking")
    assert svc.audit.entries[-1]["action"] == "reidentify_denied"


def test_reidentify_after_open_is_audited(svc):
    c = svc.result.cases[0]
    svc.open_case(c.case_id, "ana")
    ident = svc.reidentify(c.case_id, "ana", "case review")
    assert ident["subject"] == c.pid and ident["employee_id"]
    last = svc.audit.entries[-1]
    assert (last["analyst"], last["action"], last["case_id"], last["reason"]) == \
        ("ana", "reidentify", c.case_id, "case review")


def test_reidentify_requires_a_reason(svc):
    cid = svc.result.cases[0].case_id
    svc.open_case(cid, "ana")
    with pytest.raises(NotAllowed):
        svc.reidentify(cid, "ana", "  ")


def test_viewing_a_case_is_audited_without_names(svc, pipeline):
    c = svc.result.cases[0]
    detail = svc.case_detail(c.case_id, "bo")
    assert svc.audit.entries[-1]["action"] == "view_case" and svc.audit.entries[-1]["analyst"] == "bo"
    ident = pipeline.vault.reidentify(c.pid)
    blob = json.dumps(detail, default=str)
    assert ident["name"] not in blob and ident["employee_id"] not in blob and ident["email"] not in blob


def test_state_survives_restart(pipeline, tmp_path):
    s1 = Service(pipeline, tmp_path)
    cid = s1.result.cases[0].case_id
    s1.open_case(cid, "ana")
    s2 = Service(pipeline, tmp_path)
    assert s2.case_status(cid)["status"] == "open"
    assert len(s2.audit.entries) == len(s1.audit.entries)
