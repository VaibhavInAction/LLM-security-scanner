"""
Web API for the scanner, plus the simple front-end page.

Run it:
    python -m uvicorn llm_scanner.api:app --reload
Then open http://127.0.0.1:8000
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .models import Risk
from .scanner import scan

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="LLM Scanner")


class ScanRequest(BaseModel):
    text: str


@app.post("/scan", response_model=Risk)
def scan_text(request: ScanRequest) -> Risk:
    return scan(request.text)


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
