@echo off
REM Lance le moteur local "Surveillance IP" puis ouvre le navigateur.
REM Aucune installation : utilise le PowerShell integre a Windows.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0serveur.ps1"
pause
