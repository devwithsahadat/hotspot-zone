@echo off
:: ============================================================
::  start_hotspot.bat  -  Hotspot Zone Launcher
::  Right-click this file and select "Run as Administrator"
:: ============================================================

:: Check for Admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Hotspot Zone - Captive Portal Manager
color 0B
set PYTHONUTF8=1

echo.
echo  ==========================================
echo   HOTSPOT ZONE - Captive Portal Manager
echo  ==========================================
echo.
echo  Starting all services in one window...
echo  Portal  : http://192.168.137.1:5000/
echo  Admin   : http://192.168.137.1:5000/admin
echo.

python run.py

echo.
echo  All services stopped. Press any key to close...
pause >nul
