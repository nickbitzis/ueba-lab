"""Command line: run the evaluation and CI gate, serve the API and UI, and check health."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="uebalab")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ev = sub.add_parser("eval", help="evaluate against the planted scenarios")
    ev.add_argument("--seed", type=int, default=7)
    ev.add_argument("--scale", type=float, default=1.0)
    ev.add_argument("--out", type=Path, help="write the full evaluation as JSON")
    ev.add_argument("--markdown", type=Path, help="write the tables as Markdown")
    ev.add_argument("--gate", action="store_true", help="exit 1 unless the gate passes")
    ev.add_argument("--max-days", type=int, default=3, help="days allowed from scenario start to case")
    ev.add_argument("--max-benign", type=int, default=1, help="cases allowed on benign surprises")
    sv = sub.add_parser("serve", help="run the API and UI")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8892")))
    hc = sub.add_parser("healthcheck", help="exit 0 when /healthz answers ok (used by Docker)")
    hc.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8892")))
    a = ap.parse_args(argv)

    if a.cmd == "eval":
        from .evaluate import evaluate, markdown
        from .pipeline import build

        result = evaluate(build(seed=a.seed, scale=a.scale), max_days=a.max_days, max_benign=a.max_benign)
        md = markdown(result)
        print(md)
        if a.out:
            a.out.parent.mkdir(parents=True, exist_ok=True)
            slim = {**result, "configs": {k: {kk: vv for kk, vv in v.items() if kk != "labels"}
                                          for k, v in result["configs"].items()}}
            a.out.write_text(json.dumps(slim, indent=1))
        if a.markdown:
            a.markdown.parent.mkdir(parents=True, exist_ok=True)
            a.markdown.write_text(md)
        if a.gate and not result["gate"]["passed"]:
            sys.exit(1)
    elif a.cmd == "serve":
        import uvicorn

        uvicorn.run("uebalab.api:app", host=a.host, port=a.port, log_level="warning")
    elif a.cmd == "healthcheck":
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{a.port}/healthz", timeout=4) as r:
                ok = json.loads(r.read()).get("status") == "ok"
        except Exception:
            ok = False
        sys.exit(0 if ok else 1)
