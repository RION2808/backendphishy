@echo off
REM Starts the PhishShield / TrustLens backend on http://127.0.0.1:8000
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv venv
  venv\Scripts\python.exe -m pip install -r requirements.txt
)

if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Created .env from .env.example - add your keys there for AI explanations.
)

echo Starting backend at http://127.0.0.1:8000  (Ctrl+C to stop)
venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
