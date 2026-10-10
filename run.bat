@echo off
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
if not exist .venv (
  echo Creating virtual environment...
  %PY% -m venv .venv || goto :err
)
call .venv\Scripts\activate.bat
python -m pip install --quiet -r requirements.txt || goto :err
echo.
echo DebugLens running at http://127.0.0.1:5000  (Ctrl+C to stop)
start "" http://127.0.0.1:5000
python app.py
goto :eof
:err
echo Setup failed. Is Python 3.10+ installed and on PATH?
pause
