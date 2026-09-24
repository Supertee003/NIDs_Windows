@echo off
setlocal
cd /d "%~dp0.."
python scripts\run_rules_22_safe.py
set "RC=%ERRORLEVEL%"
exit /b %RC%
