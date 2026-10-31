# TrustLens API

FastAPI backend for the PhishShield extension: rule + link detection, Gemini explanations, optional Supabase storage.

## Run (Windows)
Double-click `start_backend.bat`, or:
```
venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```
First time only: `python -m venv venv`, then `venv\Scripts\python.exe -m pip install -r requirements.txt`, then copy `.env.example` to `.env` and add your keys.

Check it works: open http://127.0.0.1:8000/health (should show `{"status":"ok"}`) or http://127.0.0.1:8000/docs.

Gemini and Supabase are optional: without them the API still returns detection results and a built-in explanation.

## Endpoints
- POST /analyze: `{ "message": "...", "urls": ["..."], "private_mode": true }`
- POST /feedback: report a false positive
- GET /health: status check
