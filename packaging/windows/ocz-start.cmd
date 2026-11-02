@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ocz-start.ps1"
timeout /t 3 >nul
