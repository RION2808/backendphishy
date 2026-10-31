import os
import time
from collections import defaultdict, deque
from typing import Any, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from redaction import redact
from detection import run_detection
from gemini_explainer import explain, fallback
from formatting import build_response
from db import save_feedback, save_analysis

MAX_MESSAGE_CHARS = 5000

app = FastAPI(title="TRUSTLENS API")

# --- Simple per-IP rate limit so a public server can't burn through the
# Gemini quota. Counted in memory; set RATE_LIMIT_PER_MIN to change it. ---
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
_recent = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/analyze":
        forwarded = request.headers.get("x-forwarded-for", "")
        ip = forwarded.split(",")[0].strip() or (
            request.client.host if request.client else "unknown"
        )
        now = time.time()
        hits = _recent[ip]
        while hits and now - hits[0] > 60:
            hits.popleft()

        if len(hits) >= RATE_LIMIT_PER_MIN:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many checks in a minute. Please wait a little and try again."},
            )
        hits.append(now)

        if len(_recent) > 5000:  # keep memory bounded
            for key in [k for k, v in _recent.items() if not v or now - v[-1] > 60]:
                _recent.pop(key, None)

    return await call_next(request)


# Added last so CORS is the outermost layer (it also covers error replies).
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # Always answer with JSON so the extension can show a useful error.
    print("Unhandled error:", repr(exc))
    return JSONResponse(status_code=500, content={"detail": f"Server error: {exc}"})


class AnalyzeRequest(BaseModel):
    message: str = ""
    channel: str = "SMS"
    language: str = "auto"
    claimed_identity: Optional[str] = None
    private_mode: bool = True
    # Links sent separately by the extension: plain strings or {"url", "visible_text"}.
    urls: List[Any] = []


class FeedbackRequest(BaseModel):
    is_false_positive: bool
    risk_level: str
    comment: Optional[str] = None


@app.get("/health")
def health():
    # "build" lets you confirm which version of the code is running.
    return {"status": "ok", "build": "hosted-v3"}


LANGUAGE_NAMES = {
    "en": "English",
    "hi": "Hindi",
    "kn": "Kannada",
}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    message = (req.message or "")[:MAX_MESSAGE_CHARS]

    detection = run_detection(
        message, req.channel, req.claimed_identity, extra_urls=req.urls
    )
    safe_text = redact(message)
    lang_name = LANGUAGE_NAMES.get(
        req.language, "the same language as the message (English if unsure)"
    )

    try:
        explanation = explain(safe_text, detection, lang_name)
    except Exception as e:
        print("Explain error:", e)
        explanation = fallback(detection)

    if not req.private_mode:
        save_analysis(
            channel=req.channel,
            language=req.language,
            risk_score=int(detection.get("risk_score", 0)),
            risk_level=str(detection.get("risk_level", "")),
            classification=str(detection.get("classification", "")),
            signal_types=[s.get("type", "") for s in detection.get("signals", [])],
        )

    return build_response(detection, explanation)


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    data = req.model_dump()
    saved = save_feedback(
        is_false_positive=bool(data.get("is_false_positive", False)),
        risk_level=str(data.get("risk_level", "")),
        comment=redact(str(data.get("comment", "") or ""))[:500],
    )
    return {"status": "received" if saved else "saved_failed"}
