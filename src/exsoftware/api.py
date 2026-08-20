from __future__ import annotations

import webbrowser
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .context import DEFAULT_MAX_BYTES
from .pipeline import analyze_bytes, analyze_path

STATIC_DIR = Path(__file__).resolve().parent / "ui" / "static"

app = FastAPI(
    title="exsoftware",
    description="Deterministic static analysis API. Does not execute uploaded files or fetch extracted URLs.",
    version="0.6.0",
)


class PathRequest(BaseModel):
    path: str
    max_bytes: int = Field(default=DEFAULT_MAX_BYTES, ge=4096, le=512 * 1024 * 1024)


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "static_only": True,
        "executes_files": False,
        "schema_version": 1,
        "engine_version": "0.6.0",
        "sandbox": False,
        "containment": "static-parser",
    }


@app.get("/api/security-status")
def security_status():
    from .isolate.status import inspect_isolation

    return inspect_isolation()


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(...),
    max_bytes: int = DEFAULT_MAX_BYTES,
):
    data = await file.read()
    if not data and not file.filename:
        raise HTTPException(status_code=400, detail="Empty upload.")
    extra = {}
    if file.headers.get("last-modified"):
        extra["last_modified_header"] = file.headers.get("last-modified")
    report = analyze_bytes(data, name=file.filename or "upload", max_bytes=max_bytes, extra=extra)
    return report.to_dict()


@app.post("/api/analyze-path")
def analyze_local_path(req: PathRequest):
    path = Path(req.path).expanduser()
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Not a file: {path}")
    try:
        report = analyze_path(path, max_bytes=req.max_bytes)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return report.to_dict()


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.is_file():
        raise HTTPException(status_code=500, detail="UI files are missing.")
    return FileResponse(index_path)


def run_server(*, host: str = "127.0.0.1", port: int = 8745, open_browser: bool = True) -> None:
    import uvicorn

    if open_browser:
        webbrowser.open(f"http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
