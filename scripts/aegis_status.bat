@echo off
setlocal enabledelayedexpansion
echo.
echo ================================================================
echo  AEGIS NIDS Status
echo ================================================================
echo.
set "R=0"
set "N=0"
tasklist /NH 2>nul | find /I "aegis-nose.exe" >nul
if %ERRORLEVEL% equ 0 set "N=1"
if "!N!"=="1" ( echo  [RUNNING] NOSE  Go   aegis-nose.exe & set "R=1" ) else ( echo  [STOPPED] NOSE  Go )
set "M=0"
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul
if %ERRORLEVEL% equ 0 set "M=1"
if "!M!"=="1" ( echo  [RUNNING] MOUTH Rust windows_sec_monitor.exe & set "R=1" ) else ( echo  [STOPPED] MOUTH Rust )
echo.
if "!R!"=="1" ( echo  *** AEGIS RUNNING *** ) else ( echo  *** AEGIS STOPPED *** )
echo.
pause
