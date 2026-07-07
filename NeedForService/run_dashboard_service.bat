@echo off
REM Nicht-interaktiver Start fuer den Windows-Taskplaner (kein "pause", keine
REM pip-install-Ausgabe im Vordergrund - laeuft daher auch ohne angemeldeten User).
REM Vor dem ersten Einrichten des Tasks einmalig manuell ausfuehren:
REM     pip install -r requirements.txt
REM damit die benoetigten Python-Pakete (flask, flask-cors, pyodbc) installiert sind.

cd /d "%~dp0"
python iap_dashboard_api.py >> service.log 2>&1
