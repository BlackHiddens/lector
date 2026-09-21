@echo off
REM Lance le moteur "Surveillance IP" en CONTOURNANT la strategie d'execution
REM des .ps1 (le code est charge comme un bloc, pas comme un fichier .ps1).
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $code = Get-Content -Raw -LiteralPath '%~dp0serveur.ps1'; $sb = [scriptblock]::Create($code); & $sb } catch { Write-Host ''; Write-Host '=== BLOCAGE DETECTE ===' -ForegroundColor Red; Write-Host $_.Exception.Message -ForegroundColor Yellow; Write-Host ''; Write-Host 'Strategie d execution (par portee) :' -ForegroundColor Cyan; Get-ExecutionPolicy -List; Write-Host ''; Write-Host ('Mode de langage : ' + $ExecutionContext.SessionState.LanguageMode) -ForegroundColor Cyan; Write-Host ''; Write-Host 'Copie-colle tout ce bloc a Claude.' -ForegroundColor Green }"
echo.
pause
