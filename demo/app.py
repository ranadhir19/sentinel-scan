"""Local demo backend for sentinel-scan (FastAPI).

Run:  pip install fastapi uvicorn
      uvicorn demo.app:app --reload        (from the repo root)
Then open http://127.0.0.1:8000/ - paste a tool description or a
SKILL.md body and get the live verdict. Deployment (Render) is a
separate step; this is the local demo only.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fastapi import FastAPI  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from sentinel_scan.model import Unit  # noqa: E402
from sentinel_scan.scan import run_rules  # noqa: E402

app = FastAPI(title="sentinel-scan demo")


class ScanRequest(BaseModel):
    kind: str = "tool"  # tool | skill | source
    name: str = "pasted-input"
    text: str


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict:
    if req.kind == "skill":
        unit = Unit(kind="skill", name=req.name, origin="demo-ui",
                    source=req.text)
    elif req.kind == "source":
        unit = Unit(kind="source", name=req.name, origin="demo-ui",
                    source=req.text)
    else:
        unit = Unit(kind="tool", name=req.name, origin="demo-ui",
                    description=req.text)
    findings = run_rules([unit])
    return {"findings": [f.to_dict() for f in findings],
            "verdict": "FLAGGED" if findings else "CLEAN"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "index.html")
