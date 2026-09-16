@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0aegis.ps1" %*
exit /b %ERRORLEVEL%
