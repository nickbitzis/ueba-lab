"""FastAPI service and the web UI.

The analyst is identified by the X-Analyst header (a stand-in for SSO in this demo). Every case view,
re-identification, and feedback is written to the audit log with that name.
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .obs import Metrics, get_logger, log_event
from .pipeline import build
from .service import LABELS, NotAllowed, Service

WEB = Path(__file__).parent / "web"


class FeedbackRequest(BaseModel):
    label: str
    note: str = ""


class ReidentifyRequest(BaseModel):
    reason: str


def default_service() -> Service:
    data = Path(os.environ.get("UEBA_DATA", "data"))
    scale = float(os.environ.get("UEBA_SCALE", "1.0"))
    seed = int(os.environ.get("UEBA_SEED", "7"))
    return Service(build(seed=seed, scale=scale), data)


def create_app(service: Service | None = None) -> FastAPI:
    log = get_logger()
    metrics = Metrics()
    holder: dict[str, Service] = {}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        t0 = time.perf_counter()
        holder["svc"] = service or default_service()
        s = holder["svc"]
        log_event(log, "service ready", seconds=round(time.perf_counter() - t0, 2), identities=s.p.ds.n,
                  events=len(s.p.world.events), cases=len(s.cases), gate=s.evaluation["gate"]["passed"])
        yield

    app = FastAPI(title="uebalab", version="1.0.0", lifespan=lifespan)

    def svc() -> Service:
        if "svc" not in holder:
            raise HTTPException(503, "starting")
        return holder["svc"]

    @app.middleware("http")
    async def observe(request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        dt = time.perf_counter() - t0
        metrics.observe_request(path, response.status_code, dt)
        if path.startswith("/api"):
            log_event(log, "request", method=request.method, route=path, status=response.status_code,
                      ms=round(dt * 1000, 1), analyst=request.headers.get("x-analyst"))
        return response

    @app.get("/healthz")
    def healthz() -> dict:
        s = svc()
        return {"status": "ok", "identities": s.p.ds.n, "days": s.p.ds.days, "cases": len(s.cases)}

    @app.get("/metrics", response_class=PlainTextResponse)
    def prom() -> str:
        s = svc()
        full = s.evaluation["configs"]["full"]
        summ = s.summary()
        return metrics.render([
            ("uebalab_cases", "Cases by status.", [({"status": k}, v) for k, v in summ["by_status"].items()]),
            ("uebalab_signals", "Detector signals in the scored window.", [({}, summ["signals"])]),
            ("uebalab_identities", "Users and service accounts baselined.", [({}, s.p.ds.n)]),
            ("uebalab_scenarios_detected", "Planted scenarios that became a case.", [({}, full["detected"])]),
            ("uebalab_benign_cases", "Cases raised on benign surprises.", [({}, full["benign_cases"])]),
            ("uebalab_audit_entries", "Audit log entries.", [({}, len(s.audit.entries))]),
        ])

    @app.get("/api/summary")
    def summary() -> dict:
        return svc().summary()

    @app.get("/api/users")
    def users(limit: int = 50) -> dict:
        return {"users": svc().users(min(max(limit, 1), 500))}

    @app.get("/api/users/{pid}")
    def user(pid: str) -> dict:
        try:
            return svc().user(pid)
        except ValueError:
            raise HTTPException(404, "unknown subject") from None

    @app.get("/api/cases")
    def cases(status: str | None = None) -> dict:
        return {"cases": svc().queue(status)}

    @app.get("/api/cases/{case_id}")
    def case(case_id: str, x_analyst: str = Header("analyst")) -> dict:
        try:
            return svc().case_detail(case_id, x_analyst)
        except KeyError:
            raise HTTPException(404, "unknown case") from None

    @app.post("/api/cases/{case_id}/open")
    def open_case(case_id: str, x_analyst: str = Header("analyst")) -> dict:
        try:
            st = svc().open_case(case_id, x_analyst)
        except KeyError:
            raise HTTPException(404, "unknown case") from None
        metrics.inc_action("open")
        return st

    @app.post("/api/cases/{case_id}/reidentify")
    def reidentify(case_id: str, req: ReidentifyRequest, x_analyst: str = Header("analyst")) -> dict:
        try:
            out = svc().reidentify(case_id, x_analyst, req.reason)
        except KeyError:
            raise HTTPException(404, "unknown case") from None
        except NotAllowed as e:
            raise HTTPException(403, str(e)) from None
        metrics.inc_action("reidentify")
        return out

    @app.post("/api/cases/{case_id}/feedback")
    def feedback(case_id: str, req: FeedbackRequest, x_analyst: str = Header("analyst")) -> dict:
        if req.label not in LABELS:
            raise HTTPException(422, f"label must be one of {', '.join(LABELS)}")
        try:
            out = svc().give_feedback(case_id, x_analyst, req.label, req.note)
        except KeyError:
            raise HTTPException(404, "unknown case") from None
        metrics.inc_action(f"feedback_{req.label}")
        return out

    @app.get("/api/evaluation")
    def evaluation() -> dict:
        ev = dict(svc().evaluation)
        ev["configs"] = {k: {kk: vv for kk, vv in v.items() if kk != "labels"} for k, v in ev["configs"].items()}
        return ev

    @app.get("/api/audit")
    def audit(limit: int = 200) -> dict:
        return {"entries": svc().audit.entries[-max(1, min(limit, 2000)):][::-1]}

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(WEB / "index.html")

    app.mount("/static", StaticFiles(directory=WEB), name="static")
    return app


app = create_app()
