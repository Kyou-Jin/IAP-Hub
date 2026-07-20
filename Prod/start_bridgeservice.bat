@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================
echo  IAP Dashboard API - Installation und Start
echo ============================================
echo.

REM ------------------------------------------------------------------
REM Python robust finden.
REM
REM Windows aktualisiert PATH-Aenderungen NUR fuer neu gestartete
REM Prozesse - ein bereits offenes cmd-Fenster (oder ein Elternprozess,
REM der es gestartet hat) behaelt die zum Oeffnungszeitpunkt gueltige
REM Umgebung, auch wenn Python danach installiert/PATH aktualisiert wurde.
REM Das ist die haeufigste Ursache fuer "'python'/'pip' is not recognized"
REM direkt nach einer frischen Installation - meist reicht es, dieses
REM Fenster zu schliessen und ein NEUES zu oeffnen.
REM
REM Damit der Dienst trotzdem robust startet (z.B. spaeter auch als
REM geplante Aufgabe/Dienst unter einem Servicekonto, wo PATH-Probleme
REM aehnlich auftreten koennen), wird zusaetzlich in den ueblichen
REM Installationsordnern gesucht, falls PATH (noch) nicht passt.
REM ------------------------------------------------------------------
set "PYTHON_EXE="

where python >nul 2>nul
if not errorlevel 1 set "PYTHON_EXE=python"

if not defined PYTHON_EXE (
    where py >nul 2>nul
    if not errorlevel 1 set "PYTHON_EXE=py"
)

if not defined PYTHON_EXE (
    echo 'python'/'py' wurde ueber PATH nicht gefunden - versuche bekannte Installationsordner...
    for %%P in (
        "%LocalAppData%\Programs\Python\Python314\python.exe"
        "%LocalAppData%\Programs\Python\Python313\python.exe"
        "%LocalAppData%\Programs\Python\Python312\python.exe"
        "%LocalAppData%\Programs\Python\Python311\python.exe"
        "%LocalAppData%\Programs\Python\Python310\python.exe"
        "C:\Program Files\Python314\python.exe"
        "C:\Program Files\Python313\python.exe"
        "C:\Program Files\Python312\python.exe"
        "C:\Program Files\Python311\python.exe"
        "C:\Program Files\Python310\python.exe"
    ) do (
        if exist %%~P (
            set "PYTHON_EXE=%%~P"
            goto :python_found
        )
    )
)
:python_found

if not defined PYTHON_EXE (
    echo.
    echo FEHLER: Python wurde weder ueber PATH noch in den ueblichen
    echo Installationsordnern gefunden.
    echo.
    echo Falls Python gerade erst installiert wurde: Dieses Fenster
    echo schliessen, EIN NEUES oeffnen und start_bridgeservice.bat erneut
    echo starten - PATH-Aenderungen wirken erst in neu gestarteten Fenstern.
    echo.
    echo Falls das nicht hilft: Win+R -^> sysdm.cpl -^> Erweitert -^>
    echo Umgebungsvariablen -^> unter "Benutzervariablen" pruefen, ob
    echo "Path" den Python-Installationsordner UND dessen "Scripts"-
    echo Unterordner enthaelt.
    echo.
    pause
    exit /b 1
)

echo Verwende Python: %PYTHON_EXE%
"%PYTHON_EXE%" --version
echo.

echo [1/2] Installiere Python-Pakete (flask, flask-cors, pyodbc)...
REM "python -m pip" statt bare "pip": funktioniert auch dann, wenn nur der
REM Python-Ordner selbst (nicht zusaetzlich dessen Scripts-Unterordner mit
REM pip.exe) im PATH steht - pip ist als Modul immer Teil der Python-
REM Installation, unabhaengig vom PATH.
"%PYTHON_EXE%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo WARNUNG: pip-Installation meldete einen Fehler - siehe Ausgabe oben.
    echo.
)

echo.
echo [2/2] Starte Backend (iap_dashboard_api.py)...
echo Dieses Fenster muss offen bleiben, waehrend das Dashboard laeuft.
echo Zum Beenden: Fenster schliessen oder Strg+C druecken.
echo.
"%PYTHON_EXE%" iap_dashboard_api.py
pause
