@echo off
cd /d "%~dp0"
echo ============================================
echo  IAP Dashboard API - Installation und Start
echo ============================================
echo.
echo [1/2] Installiere Python-Pakete (flask, flask-cors, pyodbc)...
pip install -r requirements.txt
echo.
echo [2/2] Starte Backend (iap_dashboard_api.py)...
echo Dieses Fenster muss offen bleiben, waehrend das Dashboard laeuft.
echo Zum Beenden: Fenster schliessen oder Strg+C druecken.
echo.
python iap_dashboard_api.py
pause
