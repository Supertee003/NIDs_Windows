@echo off
setlocal
cd /d "%~dp0.."
python scripts\run_eight_groups_safe.py
set "RC=%ERRORLEVEL%"
exit /b %RC%
