from typing import Any, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from redaction import redact
from detection import run_detection
import gemini_explainer
from gemini_explainer import explain, fallback
from language import resolve_language
from formatting import build_response
from db import save_feedback, save_analysis

MAX_MESSAGE_CHARS = 5000

app = FastAPI(title="TRUSTLENS API")
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
    # Convenience: a single link (some clients send "url" instead of "urls").
    url: Optional[str] = None


class FeedbackRequest(BaseModel):
    is_false_positive: bool
    risk_level: str
    comment: Optional[str] = None


@app.get("/health")
def health():
    # "build" lets you confirm which version of the code is running.
    # "gemini.last_error" tells you why AI explanations are failing, if they are.
    return {
        "status": "ok",
        "build": "multilingual-v4",
        "languages": ["en", "hi", "kn"],
        "gemini": gemini_explainer.status(),
    }


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    message = (req.message or "")[:MAX_MESSAGE_CHARS]

    extra_urls = list(req.urls or [])
    if req.url:
        extra_urls.append(req.url)

    # Answer in the language of the message unless the user picked one.
    lang = resolve_language(req.language, message)

    detection = run_detection(
        message, req.channel, req.claimed_identity, extra_urls=extra_urls, lang=lang
    )
    safe_text = redact(message)

    try:
        explanation = explain(safe_text, detection, lang)
    except Exception as e:
        print("Explain error:", e)
        explanation = fallback(detection, lang)

    # Respect the user's privacy preference.
    # Private scans are never stored in Supabase.
    if not req.private_mode:
        saved = save_analysis(
            channel=req.channel,
            language=lang,
            risk_score=int(detection.get("risk_score", 0)),
            risk_level=str(detection.get("risk_level", "")),
            classification=str(detection.get("classification", "")),
            signal_types=[
                s.get("type", "")
                for s in detection.get("signals", [])
            ],
        )

        if saved:
            print("[supabase] Analysis saved successfully.")
        else:
            print("[supabase] Analysis could not be saved.")

    return build_response(detection, explanation, lang)


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    data = req.model_dump()
    saved = save_feedback(
        is_false_positive=bool(data.get("is_false_positive", False)),
        risk_level=str(data.get("risk_level", "")),
        comment=redact(str(data.get("comment", "") or ""))[:500],
    )
    return {"status": "received" if saved else "saved_failed"}
