import json

import pytest
from fastapi.testclient import TestClient

from uebalab.api import create_app
from uebalab.service import Service

H = {"X-Analyst": "ana"}


@pytest.fixture
def client(pipeline, tmp_path):
    with TestClient(create_app(Service(pipeline, tmp_path))) as c:
        yield c


def first_case(client):
    return client.get("/api/cases").json()["cases"][0]


def test_healthz(client):
    r = client.get("/healthz").json()
    assert r["status"] == "ok" and r["identities"] > 300 and r["cases"] >= 6


def test_metrics_prometheus_format(client):
    client.get("/api/cases")
    text = client.get("/metrics").text
    assert "# TYPE uebalab_http_requests_total counter" in text
    assert 'uebalab_cases{status="new"}' in text and "uebalab_scenarios_detected 6" in text


def test_summary(client):
    s = client.get("/api/summary").json()
    assert s["company"] == "Corvane Analytics" and s["days"] == 90 and s["events"] > 100_000


def test_queue_ranked_by_risk(client):
    cases = client.get("/api/cases").json()["cases"]
    scores = [c["peak_score"] for c in cases]
    assert scores == sorted(scores, reverse=True)
    assert all(c["status"] == "new" and c["reasons"] for c in cases)


def test_case_detail_has_timeline_trend_and_no_identity(client, pipeline):
    c = first_case(client)
    d = client.get(f"/api/cases/{c['case_id']}", headers=H).json()
    assert d["timeline"] and len(d["trend"]) == 90 and d["all_reasons"]
    assert any(t["type"] == "signal" for t in d["timeline"]) and any(t["type"] == "event" for t in d["timeline"])
    ident = pipeline.vault.reidentify(c["subject"])
    blob = json.dumps(d)
    assert ident["name"] not in blob and ident["email"] not in blob
    assert d["audit"][-1]["action"] == "view_case" and d["audit"][-1]["analyst"] == "ana"


def test_unknown_case_404(client):
    assert client.get("/api/cases/C999-zzzzzz").status_code == 404
    assert client.post("/api/cases/C999-zzzzzz/open").status_code == 404


def test_reidentify_flow(client):
    cid = first_case(client)["case_id"]
    r = client.post(f"/api/cases/{cid}/reidentify", json={"reason": "look"}, headers=H)
    assert r.status_code == 403
    assert client.post(f"/api/cases/{cid}/open", headers=H).json()["status"] == "open"
    r = client.post(f"/api/cases/{cid}/reidentify", json={"reason": "look"}, headers=H)
    assert r.status_code == 200 and r.json()["name"]
    actions = [e["action"] for e in client.get("/api/audit").json()["entries"]]
    assert actions[:3] == ["reidentify", "open_case", "reidentify_denied"]


def test_feedback_closes_case_and_is_audited(client):
    cid = first_case(client)["case_id"]
    r = client.post(f"/api/cases/{cid}/feedback", json={"label": "true_positive", "note": "confirmed"}, headers=H)
    body = r.json()
    assert r.status_code == 200 and body["effective_day"] > 0 and body["patterns"]
    rows = {c["case_id"]: c for c in client.get("/api/cases").json()["cases"]}
    assert rows[cid]["status"] == "closed" and rows[cid]["label"] == "true_positive"
    assert client.get("/api/audit").json()["entries"][0]["action"] == "feedback"
    assert 'uebalab_analyst_actions_total{action="feedback_true_positive"} 1' in client.get("/metrics").text


def test_feedback_rejects_unknown_label(client):
    cid = first_case(client)["case_id"]
    assert client.post(f"/api/cases/{cid}/feedback", json={"label": "maybe"}).status_code == 422


def test_status_filter(client):
    cid = first_case(client)["case_id"]
    client.post(f"/api/cases/{cid}/open", headers=H)
    opened = client.get("/api/cases?status=open").json()["cases"]
    assert [c["case_id"] for c in opened] == [cid]


def test_users_and_user_detail(client):
    users = client.get("/api/users?limit=5").json()["users"]
    assert len(users) == 5 and users[0]["peak_14d"] >= users[-1]["peak_14d"]
    assert len(users[0]["spark"]) == 30
    u = client.get(f"/api/users/{users[0]['subject']}").json()
    assert len(u["trend"]) == 90 and "signals" in u
    assert client.get("/api/users/u-nobody").status_code == 404


def test_evaluation_endpoint(client):
    ev = client.get("/api/evaluation").json()
    assert ev["gate"]["passed"] and set(ev["configs"]) == {"full", "no_context", "no_peers", "neither"}
    assert all("labels" not in c for c in ev["configs"].values())


def test_ui_is_served(client):
    assert "UEBA Lab" in client.get("/").text
    assert "trendChart" in client.get("/static/app.js").text
    assert "prefers-color-scheme: dark" in client.get("/static/styles.css").text
