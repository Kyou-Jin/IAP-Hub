"""
IAP Sicherung – Dashboard-API (Bridge zwischen Browser-Dashboard und SQL Server)
================================================================================

Browser können keine direkte SQL-Server-Verbindung aufbauen. Dieses Skript läuft
lokal (oder auf einem Server im gleichen Netz wie die SQL-Instanz), verbindet
sich per ODBC mit der Datenbank und stellt die Dashboard-Daten als JSON-API
bereit. Das Dashboard (askit_übersicht_dark_mockup.html) ruft diese API im
Hintergrund ab.

Installation (einmalig):
    pip install flask flask-cors pyodbc

Start:
    python iap_dashboard_api.py

Danach läuft die API standardmäßig unter http://localhost:5000
Im Dashboard über den "🔌 Verbindung"-Button oben rechts konfigurieren:
    - API-Basis-URL:  http://localhost:5000
    - Server:         localhost\\SQLEXPRESS   (oder Prod-Server später)
    - Datenbank:      IAPPowerBI
    - Authentifizierung: Windows-Authentifizierung ODER SQL Server Login

Die Verbindungseinstellungen werden in db_config.json (neben diesem Skript)
gespeichert, damit sie beim nächsten Start erhalten bleiben.

Hinweis Sicherheit: Für den produktiven Einsatz sollte das Passwort nicht im
Klartext in db_config.json liegen (z.B. stattdessen Windows-Auth verwenden,
oder die Datei durch NTFS-Rechte schützen). Für die lokale Testumgebung ist
das unkritisch.
"""

import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import pyodbc
except ImportError:
    raise SystemExit(
        "pyodbc ist nicht installiert. Bitte zuerst ausführen:\n"
        "    pip install flask flask-cors pyodbc"
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "db_config.json")
UC4_HISTORY_PATH = os.path.join(BASE_DIR, "uc4_history.json")
DEPLOY_CONFIG_PATH = os.path.join(BASE_DIR, "deploy_config.json")
A2C_CONFIG_PATH = os.path.join(BASE_DIR, "a2c_config.json")
SECURITY_CONFIG_PATH = os.path.join(BASE_DIR, "security_config.json")
ADMIN_AUTH_CONFIG_PATH = os.path.join(BASE_DIR, "admin_auth_config.json")
ACCESS_CONTROL_CONFIG_PATH = os.path.join(BASE_DIR, "access_control_config.json")
LOG_PATH = os.path.join(BASE_DIR, "iap_dashboard_api.log")
DEPLOY_AUDIT_LOG_PATH = os.path.join(BASE_DIR, "deploy_audit.log")
DASHBOARD_HTML_NAME = "IAP_Dashboard_MAIN.html"
DASHBOARD_HTML_PATH = os.path.join(BASE_DIR, DASHBOARD_HTML_NAME)

# Name, unter dem das SQL-Auth-Passwort im Windows Credential Manager (bzw. dem
# jeweiligen Backend von "keyring" auf anderen Betriebssystemen) abgelegt wird -
# es landet damit NICHT mehr im Klartext in db_config.json (siehe get_connection()
# und api_set_config()).
KEYRING_SERVICE = "IAP_Dashboard_API"

DEFAULT_CONFIG = {
    "apiPort": 5000,
    "server": "localhost\\SQLEXPRESS",
    "database": "IAPPowerBI",
    "authType": "windows",  # "windows" oder "sql"
    "username": "",
}

# Zielordner fuer den "Auf IIS veroeffentlichen"-Knopf im Dashboard-Header. Kann
# auch ein Netzwerkpfad (UNC, z.B. \\server\wwwroot) sein, falls IIS auf einem
# anderen Server als dieser Bridge-Dienst laeuft - dann braucht das Konto, unter
# dem iap_dashboard_api.py laeuft, Schreibrechte auf diese Freigabe.
DEFAULT_DEPLOY_CONFIG = {
    "targetPath": "C:\\inetpub\\wwwroot\\",
}

# Programmordner des separaten "A2C"-Tools (Servity-Export -> MSSQL -> Confluence-
# Sync), das als eigene geplante Aufgabe/GUI auf einem Server laeuft (siehe
# dessen docs/Betrieb_Start.md). Kein eigener Dienst noetig: dieser Bridge-Dienst
# liest lediglich die von A2C bereits geschriebene last_run_status.json und einen
# Ausschnitt der Logdatei aus dem hier konfigurierten Ordner (lokal oder per UNC-
# Netzwerkpfad, analog zum Deploy-Zielordner oben). Leer = noch nicht eingerichtet.
DEFAULT_A2C_CONFIG = {
    "basePath": "",
}

# Gueltige Betriebsmodi von A2C (siehe dessen constants.py -> VALID_MODES). Hier
# bewusst dupliziert statt importiert, da A2C ein komplett separates Repo/venv
# ist und nicht als Python-Paket in diesem Prozess verfuegbar ist.
A2C_VALID_MODES = ("download", "verarbeite", "confluence", "all")

# In-memory-Zustand eines von DIESEM Bridge-Dienst gestarteten A2C-Laufs (siehe
# api_a2c_run()). Bewusst nur im Prozessspeicher, kein File-Lock: last_run_status.json
# (von A2C selbst geschrieben) bleibt so oder so die Quelle der Wahrheit dafuer, WAS
# beim letzten Lauf passiert ist - dieser Zustand dient nur dazu, waehrend ein Lauf
# noch aktiv ist, "läuft gerade" anzuzeigen und einen zweiten, sich ueberschneidenden
# Start hier aus derselben Bridge-Instanz zu verhindern.
_a2c_run_lock = threading.RLock()  # reentrant: _a2c_is_running() wird auch INNERHALB
                                     # eines schon gehaltenen Locks aufgerufen (siehe
                                     # api_a2c_run()) - ein normaler Lock wuerde sich
                                     # dabei selbst blockieren (Deadlock).
_a2c_run_state = {"process": None, "mode": None, "startedAt": None}

# Optionaler Schreibschutz fuer die aendernden Endpunkte (/api/config, /api/deploy,
# /api/deploy-config, /api/security-config). Solange apiKey leer ist (Default),
# ist der Schutz deaktiviert - das entspricht dem bisherigen Verhalten (der Dienst
# ist ja standardmaessig nur unter 127.0.0.1 erreichbar). Sobald ein Schluessel
# gesetzt ist, muessen Requests ihn im Header "X-API-Key" mitschicken. Das wird
# vor allem dann wichtig, wenn der Dienst - wie im Dashboard vorgesehen - auch als
# entfernter Bridge-Dienst auf einer echten Netzwerkadresse betrieben wird.
DEFAULT_SECURITY_CONFIG = {
    "apiKey": "",
}

# Admin-Passwortsperre fuer die administrativen Dashboard-Bereiche (Schnittstellen,
# Verbindung, Deploy). Bewusst getrennt vom API-Key oben: der API-Key schuetzt die
# SCHREIBENDEN Endpunkte selbst (serverseitig, egal welches Frontend zugreift),
# dieses Passwort blendet stattdessen im BROWSER die entsprechenden Bereiche aus,
# bis es eingegeben wurde (schuetzt v.a. davor, dass jemand am selben Rechner/
# Bildschirm aus Versehen oder Neugier in diese Bereiche klickt). Es wird NIE im
# Klartext gespeichert, sondern nur als Hash (siehe api_set_admin_password()).
# Das Aendern/Entfernen dieses Passworts erfordert wiederum den API-Key - das ist
# bewusst der "Notfall-Reset" waehrend der Entwicklungsphase: falls das Admin-
# Passwort vergessen wird, kann es ueber den (bereits bekannten) API-Key jederzeit
# neu gesetzt werden, ohne das alte Passwort zu kennen.
DEFAULT_ADMIN_AUTH_CONFIG = {
    "passwordHash": "",
}

# ──────────────────────────────────────────────────────────────────────────
# GERUEST fuer eine kuenftige Domaenengruppen-basierte Freischaltung (noch NICHT
# aktiv/verdrahtet - "enabled": False bedeutet, dass diese Konfiguration aktuell
# keinerlei Auswirkung hat und einzig die Admin-Passwortsperre oben sowie der
# API-Key gelten). Gedachter Ausbau: sobald IIS vor diesem Bridge-Dienst
# Windows-Authentifizierung fuer bestimmte Pfade erzwingt, steht der authenti-
# fizierte Benutzername im WSGI-Environ (z.B. ueber den Header, den IIS/ARR beim
# Weiterleiten mitschickt, i.d.R. "X-Remote-User" o.ae., je nach ARR-Konfiguration)
# zur Verfuegung. Aus diesem Benutzernamen liesse sich dann per LDAP/AD (z.B. mit
# dem Paket "ldap3", oder unter Windows ueber pywin32/ADSI) die Gruppenmitglied-
# schaft aufloesen und mit den hier hinterlegten, je Bereich erforderlichen
# Gruppen abgleichen. Siehe get_current_username()/user_in_required_group()
# weiter unten fuer die (aktuell inaktiven) Ansatzpunkte dafuer.
# ──────────────────────────────────────────────────────────────────────────
DEFAULT_ACCESS_CONTROL_CONFIG = {
    "enabled": False,
    "requiredGroups": {
        "schnittstellen": [],
        "verbindung": [],
        "deployment": [],
    },
}

app = Flask(__name__)
CORS(app)  # Dashboard wird i.d.R. als lokale Datei (file://) oder anderer Port geöffnet


# ──────────────────────────────────────────────────────────────────────────
# Logging: alle Fehler UND sicherheitsrelevanten Aktionen (Verbindungstest,
# Config-Aenderung, Deploy) landen mit Zeitstempel in einer Logdatei statt (nur)
# in der HTTP-Antwort - siehe api_error()/GENERIC_ERROR_MESSAGE weiter unten.
# Ein zweites, separates Log fuehrt zusaetzlich Buch ueber jeden Deploy-Vorgang
# (wer/wann/wohin/Backup) fuer Nachvollziehbarkeit ("Deploy-Audit-Log").
# ──────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("iap_dashboard_api")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(_handler)

deploy_audit_logger = logging.getLogger("iap_dashboard_deploy_audit")
deploy_audit_logger.setLevel(logging.INFO)
if not deploy_audit_logger.handlers:
    _deploy_handler = RotatingFileHandler(DEPLOY_AUDIT_LOG_PATH, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    _deploy_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    deploy_audit_logger.addHandler(_deploy_handler)

# Wird an Clients zurueckgegeben statt der echten Exception-Message (die u.U.
# Servernamen, Treiber- oder Dateisystempfade preisgeben wuerde) - die echten
# Details landen stattdessen immer im Logfile (siehe oben).
GENERIC_ERROR_MESSAGE = "Es ist ein interner Fehler aufgetreten. Details siehe Server-Log (iap_dashboard_api.log)."


def log_error(context, exc):
    """Schreibt die vollen Exception-Details (inkl. Traceback) ins Logfile."""
    logger.error("%s: %s", context, exc, exc_info=True)


# ──────────────────────────────────────────────────────────────────────────
# Konfiguration
# ──────────────────────────────────────────────────────────────────────────
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update(cfg)
        return merged
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    # Das SQL-Auth-Passwort wird nie in dieser Datei gespeichert (auch nicht,
    # falls es aus Versehen im uebergebenen cfg-Dict steckt) - es landet
    # stattdessen ueber keyring im Windows Credential Manager, siehe
    # api_set_config() und _get_sql_password().
    persisted = {k: v for k, v in cfg.items() if k != "password"}
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(persisted, f, indent=2, ensure_ascii=False)


def load_deploy_config():
    if os.path.exists(DEPLOY_CONFIG_PATH):
        with open(DEPLOY_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_DEPLOY_CONFIG)
        merged.update(cfg)
        return merged
    return dict(DEFAULT_DEPLOY_CONFIG)


def save_deploy_config(cfg):
    with open(DEPLOY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def load_a2c_config():
    if os.path.exists(A2C_CONFIG_PATH):
        with open(A2C_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_A2C_CONFIG)
        merged.update(cfg)
        return merged
    return dict(DEFAULT_A2C_CONFIG)


def save_a2c_config(cfg):
    with open(A2C_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _a2c_python_exe(base_path):
    """Bevorzugt das isolierte venv von A2C (wie dessen scripts/run_all.cmd),
    faellt sonst auf ein System-Python im PATH zurueck (z.B. falls dort noch
    kein venv angelegt wurde)."""
    venv_python = os.path.join(base_path, ".venv", "Scripts", "python.exe")
    if os.path.exists(venv_python):
        return venv_python
    return "python"


def _a2c_is_running():
    """Prueft, ob der zuletzt von diesem Bridge-Dienst gestartete A2C-Prozess noch
    laeuft, und raeumt den In-Memory-Zustand auf, sobald er beendet ist. Erkennt
    NUR Laeufe, die ueber api_a2c_run() gestartet wurden - ein parallel von der
    geplanten Aufgabe oder der GUI gestarteter Lauf ist davon unabhaengig."""
    with _a2c_run_lock:
        proc = _a2c_run_state.get("process")
        if proc is None:
            return False
        if proc.poll() is None:
            return True
        _a2c_run_state["process"] = None
        _a2c_run_state["mode"] = None
        _a2c_run_state["startedAt"] = None
        return False


def compute_dashboard_hash():
    """SHA-256 (gekuerzt auf 12 Zeichen) der aktuellen IAP_Dashboard_MAIN.html.

    Dient als kurze, gut vergleichbare "Versionskennung" fuer die
    Deploy-Bestaetigung: Nutzer sieht vor dem eigentlichen Veroeffentlichen,
    welcher Stand tatsaechlich kopiert wuerde, und der Server prueft beim
    Ausfuehren erneut, ob sich die Datei zwischenzeitlich geaendert hat
    (verhindert, dass versehentlich ein zwischenzeitlich veraenderter Stand
    unbemerkt live geht).
    """
    with open(DASHBOARD_HTML_PATH, "rb") as f:
        data = f.read()
    full_hash = hashlib.sha256(data).hexdigest()
    stat = os.stat(DASHBOARD_HTML_PATH)
    return {
        "hash": full_hash[:12],
        "size": stat.st_size,
        "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%d.%m.%Y %H:%M:%S"),
    }


def load_security_config():
    if os.path.exists(SECURITY_CONFIG_PATH):
        with open(SECURITY_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_SECURITY_CONFIG)
        merged.update(cfg)
        return merged
    return dict(DEFAULT_SECURITY_CONFIG)


def save_security_config(cfg):
    with open(SECURITY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def load_admin_auth_config():
    if os.path.exists(ADMIN_AUTH_CONFIG_PATH):
        with open(ADMIN_AUTH_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_ADMIN_AUTH_CONFIG)
        merged.update(cfg)
        return merged
    return dict(DEFAULT_ADMIN_AUTH_CONFIG)


def save_admin_auth_config(cfg):
    with open(ADMIN_AUTH_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def load_access_control_config():
    if os.path.exists(ACCESS_CONTROL_CONFIG_PATH):
        with open(ACCESS_CONTROL_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = dict(DEFAULT_ACCESS_CONTROL_CONFIG)
        merged.update(cfg)
        merged_groups = dict(DEFAULT_ACCESS_CONTROL_CONFIG["requiredGroups"])
        merged_groups.update(cfg.get("requiredGroups") or {})
        merged["requiredGroups"] = merged_groups
        return merged
    return json.loads(json.dumps(DEFAULT_ACCESS_CONTROL_CONFIG))  # deep copy


def save_access_control_config(cfg):
    with open(ACCESS_CONTROL_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def get_current_username():
    """GERUEST (noch nicht aktiv genutzt): soll spaeter den authentifizierten
    Windows-Benutzernamen liefern, sobald IIS vor diesem Dienst Windows-
    Authentifizierung erzwingt und den Benutzernamen per Header durchreicht
    (z.B. "X-Remote-User" - abhaengig von der ARR/IIS-Konfiguration). Liefert
    aktuell immer None, da dieser Pfad noch nicht eingerichtet ist."""
    return request.headers.get("X-Remote-User") or None


def user_in_required_group(section):
    """GERUEST (noch nicht aktiv genutzt): soll spaeter pruefen, ob der aktuell
    angemeldete Benutzer (siehe get_current_username()) Mitglied einer der fuer
    "section" (z.B. "schnittstellen", "verbindung", "deployment") hinterlegten
    Domaenengruppen ist - via LDAP/AD-Abfrage (z.B. Paket "ldap3", oder unter
    Windows ueber pywin32/ADSI) gegen die in access_control_config.json
    hinterlegten Gruppennamen. Solange "enabled" dort False ist (Default),
    liefert diese Funktion immer True (= keine zusaetzliche Einschraenkung) und
    hat damit aktuell KEINE Auswirkung auf irgendeinen Endpunkt."""
    cfg = load_access_control_config()
    if not cfg.get("enabled"):
        return True
    # TODO (kuenftig): echten Benutzernamen ermitteln, Gruppenmitgliedschaft per
    # LDAP/AD gegen cfg["requiredGroups"].get(section, []) abgleichen.
    return True


def check_api_key():
    """Prueft (falls ein API-Key konfiguriert ist) den Header 'X-API-Key' gegen
    den in security_config.json hinterlegten Schluessel. Gibt None zurueck, wenn
    der Request weitermachen darf (kein Schluessel konfiguriert ODER Schluessel
    stimmt ueberein), sonst ein fertiges (response, status)-Tupel zum Zurueckgeben.
    Solange kein Schluessel gesetzt ist, bleibt das Verhalten wie bisher (kein
    Schutz) - das entspricht dem heutigen Stand, in dem der Dienst i.d.R. nur
    unter 127.0.0.1 erreichbar ist."""
    required = (load_security_config().get("apiKey") or "").strip()
    if not required:
        return None
    provided = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided, required):
        logger.warning(
            "Abgelehnter Zugriff auf %s ohne/mit falschem API-Key (Absender: %s)",
            request.path, request.remote_addr,
        )
        return jsonify({"success": False, "message": "Nicht autorisiert (API-Key fehlt oder ist falsch)."}), 401
    return None


def _get_sql_password(username):
    """Liest das SQL-Auth-Passwort aus dem Windows Credential Manager (ueber das
    Paket 'keyring') statt aus db_config.json - dort wird es bewusst nie im
    Klartext abgelegt (siehe api_set_config() und save_config())."""
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, username or "default") or ""
    except Exception as exc:  # noqa: BLE001
        log_error("Passwort konnte nicht aus dem Credential-Manager gelesen werden", exc)
        return ""


def pick_driver():
    """Wählt den besten verfügbaren SQL-Server-ODBC-Treiber."""
    available = [d for d in pyodbc.drivers() if "SQL Server" in d]
    for preferred in ("ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server"):
        if preferred in available:
            return preferred
    return available[0] if available else "SQL Server"


def get_connection(cfg=None):
    cfg = cfg or load_config()
    driver = pick_driver()
    if cfg.get("authType") == "sql":
        password = cfg.get("password") or _get_sql_password(cfg.get("username"))
        conn_str = (
            f"DRIVER={{{driver}}};SERVER={cfg['server']};DATABASE={cfg['database']};"
            f"UID={cfg.get('username', '')};PWD={password};"
            f"Encrypt=yes;TrustServerCertificate=yes;"
        )
    else:
        conn_str = (
            f"DRIVER={{{driver}}};SERVER={cfg['server']};DATABASE={cfg['database']};"
            f"Trusted_Connection=yes;Encrypt=yes;TrustServerCertificate=yes;"
        )
    return pyodbc.connect(conn_str, timeout=5)


# ──────────────────────────────────────────────────────────────────────────
# UC4 – Snapshot-Historie (lokal, da der Datenexport nur ~4 Tage Historie hat)
# ──────────────────────────────────────────────────────────────────────────
def load_uc4_history():
    if os.path.exists(UC4_HISTORY_PATH):
        with open(UC4_HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_uc4_history(history):
    with open(UC4_HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# dbo.ticket_changes speichert JEDEN Datenexport als eigenen Snapshot
# (erkennbar an unterschiedlichen [Export-Datum]-Werten pro Nummer). Für den
# "aktuellen Stand" darf pro Task (Nummer) nur die neueste Zeile gezaehlt
# werden, sonst werden Tasks/Changes mehrfach (einmal je Snapshot) gezaehlt.
#
# Die Tabelle enthaelt seit dem Nachimport vom 26.06.2026 den kompletten
# Servity-Rohexport (alle Changes im Konzern, nicht nur dieses Projekt).
# Projekt-Scope: alle Changes, deren Change-Labels "INF-Kunde"/"INF-Intern"
# (Bindestrich, alte Schreibweise bis 13.07.2026) ODER "INF_Kunde"/"INF_Intern"
# (Unterstrich, seit 14.07.2026 in Servity-Prod so umbenannt) enthalten - beide
# Schreibweisen werden bewusst weiter gematcht, damit historische Snapshots vor
# der Umbenennung (z.B. fuer UC4/Historie) nicht ploetzlich aus dem Scope fallen.
# So gewuenscht statt einer festen ChangeID-Liste - neue Changes mit diesen
# Labels erscheinen automatisch, ohne Code-Aenderung.
LATEST_CTE = """
WITH latest AS (
    SELECT *,
           ROW_NUMBER() OVER (PARTITION BY Nummer ORDER BY [Export-Datum] DESC) AS rn
    FROM dbo.vw_ticket_changes_powerbi
    WHERE [Change-Labels] LIKE '%INF-Kunde%' OR [Change-Labels] LIKE '%INF-Intern%'
       OR [Change-Labels] LIKE '%INF_Kunde%' OR [Change-Labels] LIKE '%INF_Intern%'
)
"""


def _normalize_col(name):
    """Reduziert einen Spaltennamen auf a-z0-9 (klein) zum toleranten Vergleich -
    'Change-Bearbeitergruppe', 'Change Bearbeitergruppe' und 'change_bearbeitergruppe'
    werden dadurch alle zu 'changebearbeitergruppe' und gelten als gleich."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def find_column(cur, table_name, target_norm):
    """Sucht per INFORMATION_SCHEMA in table_name nach einer Spalte, deren normalisierter
    Name target_norm entspricht - unabhaengig von genauer Schreibweise/Trennzeichen.
    Gibt den exakten Spaltennamen zurueck (fuer Verwendung in eckigen Klammern in SQL)
    oder None, wenn keine passende Spalte gefunden wurde."""
    cur.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?",
        (table_name,),
    )
    for row in cur.fetchall():
        if _normalize_col(row[0]) == target_norm:
            return row[0]
    return None


def compute_core_metrics(cur):
    cur.execute(LATEST_CTE + "SELECT COUNT(DISTINCT ChangeID) FROM latest WHERE rn = 1")
    changes_total = cur.fetchone()[0]

    cur.execute(
        LATEST_CTE + "SELECT COUNT(DISTINCT ChangeID) FROM latest "
        "WHERE rn = 1 AND [Change Status] <> 'Geschlossen'"
    )
    changes_open = cur.fetchone()[0]
    changes_closed = changes_total - changes_open

    cur.execute(LATEST_CTE + "SELECT COUNT(*) FROM latest WHERE rn = 1")
    tasks_total = cur.fetchone()[0]

    cur.execute(
        LATEST_CTE + "SELECT COUNT(*) FROM latest WHERE rn = 1 AND Ticketstatus <> 'Geschlossen'"
    )
    tasks_open = cur.fetchone()[0]
    tasks_closed = tasks_total - tasks_open

    return {
        "changesTotal": changes_total,
        "changesOpen": changes_open,
        "changesClosed": changes_closed,
        "tasksTotal": tasks_total,
        "tasksOpen": tasks_open,
        "tasksClosed": tasks_closed,
    }


# ──────────────────────────────────────────────────────────────────────────
# API-Endpunkte
# ──────────────────────────────────────────────────────────────────────────
@app.route("/api/config", methods=["GET"])
def api_get_config():
    cfg = load_config()
    safe = dict(cfg)
    has_password = bool(_get_sql_password(safe.get("username"))) if safe.get("authType") == "sql" else False
    safe["password"] = "***" if has_password else ""
    return jsonify(safe)


@app.route("/api/config", methods=["POST"])
def api_set_config():
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    cfg = load_config()
    for key in ("server", "database", "authType", "username"):
        if key in body and body[key] is not None:
            cfg[key] = body[key]
    save_config(cfg)  # persistiert NIE das Passwort, siehe save_config()

    if body.get("password"):
        try:
            import keyring
            keyring.set_password(KEYRING_SERVICE, cfg.get("username") or "default", body["password"])
        except Exception as exc:  # noqa: BLE001
            log_error("Passwort konnte nicht im Credential-Manager gespeichert werden", exc)
            return jsonify({
                "success": False,
                "message": "Passwort konnte nicht sicher gespeichert werden. Details siehe Server-Log.",
            }), 200

    logger.info(
        "DB-Konfiguration aktualisiert: server=%s database=%s authType=%s",
        cfg.get("server"), cfg.get("database"), cfg.get("authType"),
    )

    try:
        conn = get_connection(dict(cfg, password=body.get("password", "")))
        conn.close()
        logger.info("Verbindungstest erfolgreich (%s / %s)", cfg["server"], cfg["database"])
        return jsonify({"success": True, "message": f"Verbunden mit {cfg['server']} / {cfg['database']}"})
    except Exception as exc:  # noqa: BLE001
        log_error("Verbindungstest fehlgeschlagen", exc)
        return jsonify({"success": False, "message": "Verbindung fehlgeschlagen. Details siehe Server-Log."}), 200


@app.route("/api/status", methods=["GET"])
def api_status():
    cfg = load_config()
    try:
        conn = get_connection(cfg)
        conn.close()
        return jsonify({"connected": True, "server": cfg["server"], "database": cfg["database"]})
    except Exception as exc:  # noqa: BLE001
        log_error("Statusabfrage: Verbindung fehlgeschlagen", exc)
        return jsonify({"connected": False, "message": "Verbindung fehlgeschlagen. Details siehe Server-Log."})


@app.route("/api/security-config", methods=["GET"])
def api_get_security_config():
    cfg = load_security_config()
    return jsonify({"apiKeySet": bool((cfg.get("apiKey") or "").strip())})


@app.route("/api/security-config", methods=["POST"])
def api_set_security_config():
    # Absichtlich derselbe Guard wie bei den anderen aendernden Endpunkten: Ist
    # schon ein Schluessel gesetzt, kann er nur mit Kenntnis dieses Schluessels
    # geaendert/entfernt werden. Ist noch keiner gesetzt (Erstkonfiguration),
    # laesst check_api_key() den Request ungeprueft durch.
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    cfg = load_security_config()
    if "apiKey" in body:
        cfg["apiKey"] = (body["apiKey"] or "").strip()
    save_security_config(cfg)
    logger.info("Security-Konfiguration aktualisiert (API-Key %s).", "gesetzt" if cfg.get("apiKey") else "entfernt")
    return jsonify({"success": True, "message": "Gespeichert."})


@app.route("/api/admin-auth-status", methods=["GET"])
def api_get_admin_auth_status():
    """Oeffentlich lesbar (kein API-Key noetig) - sagt dem Frontend nur, OB eine
    Admin-Passwortsperre konfiguriert ist, nie das Passwort/den Hash selbst."""
    cfg = load_admin_auth_config()
    return jsonify({"configured": bool((cfg.get("passwordHash") or "").strip())})


@app.route("/api/admin-unlock", methods=["POST"])
def api_admin_unlock():
    """Prueft das im Browser eingegebene Admin-Passwort gegen den gespeicherten
    Hash. Ist keine Sperre konfiguriert, gilt jeder Versuch als Erfolg (nichts
    zu entsperren) - das Frontend fragt in dem Fall ohnehin gar nicht erst."""
    cfg = load_admin_auth_config()
    required_hash = (cfg.get("passwordHash") or "").strip()
    if not required_hash:
        return jsonify({"success": True})

    body = request.get_json(force=True) or {}
    provided = body.get("password") or ""
    if check_password_hash(required_hash, provided):
        return jsonify({"success": True})

    logger.warning("Admin-Bereich: falsches Passwort eingegeben (Absender: %s)", request.remote_addr)
    return jsonify({"success": False, "message": "Falsches Passwort."}), 200


@app.route("/api/admin-set-password", methods=["POST"])
def api_set_admin_password():
    # Bewusst per API-Key geschuetzt statt per (evtl. vergessenem) Admin-Passwort
    # selbst - das ist der in der Doku oben beschriebene "Notfall-Reset": mit dem
    # API-Key laesst sich das Admin-Passwort jederzeit neu setzen oder entfernen,
    # auch ohne das alte zu kennen. Ist noch gar kein API-Key konfiguriert, laesst
    # check_api_key() (wie bei den anderen Endpunkten) den Request ungeprueft durch.
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    new_password = (body.get("password") or "").strip()
    cfg = load_admin_auth_config()
    if new_password:
        cfg["passwordHash"] = generate_password_hash(new_password)
        logger.info("Admin-Passwort gesetzt/geaendert.")
        message = "Admin-Passwort gespeichert."
    else:
        cfg["passwordHash"] = ""
        logger.info("Admin-Passwort entfernt (Sperre deaktiviert).")
        message = "Admin-Passwortsperre entfernt."
    save_admin_auth_config(cfg)
    return jsonify({"success": True, "message": message})


@app.route("/api/access-control-config", methods=["GET"])
def api_get_access_control_config():
    """GERUEST (siehe user_in_required_group() oben) - liefert die aktuell
    hinterlegte Konfiguration fuer eine kuenftige Domaenengruppen-Freischaltung.
    Solange "enabled" False ist, hat das keine Auswirkung auf irgendeinen
    anderen Endpunkt."""
    return jsonify(load_access_control_config())


@app.route("/api/access-control-config", methods=["POST"])
def api_set_access_control_config():
    """GERUEST - erlaubt das Hinterlegen von Gruppennamen je Bereich schon jetzt,
    auch wenn die eigentliche Pruefung (user_in_required_group()) noch nicht
    verdrahtet ist. Wie die anderen aendernden Endpunkte per API-Key geschuetzt."""
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    cfg = load_access_control_config()
    if "enabled" in body:
        cfg["enabled"] = bool(body["enabled"])
    if "requiredGroups" in body and isinstance(body["requiredGroups"], dict):
        for section, groups in body["requiredGroups"].items():
            if isinstance(groups, list):
                cfg["requiredGroups"][section] = [str(g).strip() for g in groups if str(g).strip()]
    save_access_control_config(cfg)
    logger.info("Access-Control-Konfiguration aktualisiert (enabled=%s).", cfg.get("enabled"))
    return jsonify({"success": True, "message": "Gespeichert."})


@app.route("/api/deploy-config", methods=["GET"])
def api_get_deploy_config():
    return jsonify(load_deploy_config())


@app.route("/api/deploy-config", methods=["POST"])
def api_set_deploy_config():
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    cfg = load_deploy_config()
    if body.get("targetPath"):
        cfg["targetPath"] = body["targetPath"]
    save_deploy_config(cfg)
    logger.info("Deploy-Zielordner aktualisiert: %s", cfg.get("targetPath"))
    return jsonify({"success": True, "message": "Zielordner gespeichert."})


@app.route("/api/deploy-info", methods=["GET"])
def api_deploy_info():
    """Liefert Groesse/Zeitstempel/Pruefsumme der aktuell lokal liegenden
    IAP_Dashboard_MAIN.html, damit das Dashboard vor dem eigentlichen Deploy
    eine Bestaetigung mit diesen Angaben anzeigen kann (siehe api_deploy())."""
    if not os.path.exists(DASHBOARD_HTML_PATH):
        return jsonify({
            "available": False,
            "message": f"{DASHBOARD_HTML_NAME} wurde neben iap_dashboard_api.py nicht gefunden.",
        })
    try:
        info = compute_dashboard_hash()
        info["available"] = True
        return jsonify(info)
    except Exception as exc:  # noqa: BLE001
        log_error("Deploy-Info konnte nicht ermittelt werden", exc)
        return jsonify({"error": GENERIC_ERROR_MESSAGE}), 500


@app.route("/api/deploy", methods=["POST"])
def api_deploy():
    """Veröffentlicht die aktuelle IAP_Dashboard_MAIN.html auf dem IIS (oder einem
    anderen Webserver). Die Seite selbst ist eine einzelne, in sich geschlossene
    HTML-Datei (Chart.js kommt per CDN aus dem Internet, alle Daten holt sich die
    Seite dynamisch zur Laufzeit per Browser-JavaScript vom Bridge-Dienst) - daher
    reicht es, genau diese eine Datei zu kopieren, um "alles fuer die (dynamische)
    Darstellung Notwendige" zu veroeffentlichen.

    Der Zielordner kann ein lokaler Pfad auf diesem Server sein (Normalfall, da der
    Bridge-Dienst laut Setup auf demselben Server wie IIS laeuft) oder ein
    Netzwerkpfad (UNC, z.B. \\\\anderer-server\\wwwroot), falls stattdessen ein
    entfernter Webserver angesprochen werden soll - das Konto, unter dem dieser
    Dienst laeuft, braucht dann Schreibrechte auf diese Freigabe.
    """
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    cfg = load_deploy_config()
    target_path = (body.get("targetPath") or cfg.get("targetPath") or "").strip()
    expected_hash = (body.get("expectedHash") or "").strip()
    caller = request.remote_addr

    if not target_path:
        deploy_audit_logger.info("FEHLGESCHLAGEN (kein Zielordner angegeben) - Absender %s", caller)
        return jsonify({"success": False, "message": "Kein Zielordner angegeben."}), 200
    if not os.path.exists(DASHBOARD_HTML_PATH):
        deploy_audit_logger.info(
            "FEHLGESCHLAGEN (%s nicht gefunden) - Absender %s", DASHBOARD_HTML_NAME, caller
        )
        return jsonify({
            "success": False,
            "message": f"{DASHBOARD_HTML_NAME} wurde neben iap_dashboard_api.py nicht gefunden.",
        }), 200

    # Wurde vorher eine Bestaetigung mit Pruefsumme angezeigt (siehe
    # /api/deploy-info + Frontend-Bestaetigungsschritt), pruefen wir hier, dass
    # sich die Datei seitdem nicht veraendert hat (schuetzt vor der
    # "Time-of-check to time-of-use"-Situation, in der zwischen Anzeige und
    # Bestaetigung jemand eine neue Version speichert und diese unbemerkt
    # live geht).
    if expected_hash:
        try:
            current_info = compute_dashboard_hash()
        except Exception as exc:  # noqa: BLE001
            log_error("Pruefsumme fuer Deploy-Bestaetigung konnte nicht ermittelt werden", exc)
            return jsonify({"success": False, "message": GENERIC_ERROR_MESSAGE}), 200
        if current_info["hash"] != expected_hash:
            deploy_audit_logger.info(
                "FEHLGESCHLAGEN (Datei hat sich seit Bestaetigung geaendert) - Absender %s", caller
            )
            return jsonify({
                "success": False,
                "message": "Die Datei hat sich seit der Bestätigung geändert. Bitte erneut prüfen und bestätigen.",
            }), 200

    # Zielordner merken (auch wenn er zuvor noch nie gespeichert wurde)
    if target_path != cfg.get("targetPath"):
        cfg["targetPath"] = target_path
        save_deploy_config(cfg)

    deploy_audit_logger.info("GESTARTET - Ziel %s - Absender %s", target_path, caller)
    try:
        if not os.path.isdir(target_path):
            os.makedirs(target_path, exist_ok=True)

        dest_file = os.path.join(target_path, DASHBOARD_HTML_NAME)
        backup_note = ""
        backup_name = None
        if os.path.exists(dest_file):
            backup_dir = os.path.join(target_path, "_deploy_backups")
            os.makedirs(backup_dir, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{os.path.splitext(DASHBOARD_HTML_NAME)[0]}.{stamp}.bak.html"
            shutil.copy2(dest_file, os.path.join(backup_dir, backup_name))
            backup_note = f" (Vorherige Version gesichert als _deploy_backups/{backup_name})"

        shutil.copy2(DASHBOARD_HTML_PATH, dest_file)

        stamp_display = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        deploy_audit_logger.info(
            "ERFOLGREICH - Ziel %s - Absender %s - Backup %s",
            dest_file, caller, backup_name or "(keins, Datei existierte noch nicht)",
        )
        return jsonify({
            "success": True,
            "message": f"Veröffentlicht nach {dest_file} um {stamp_display}.{backup_note}",
        })
    except Exception as exc:  # noqa: BLE001
        log_error(f"Deploy nach {target_path} fehlgeschlagen", exc)
        deploy_audit_logger.info("FEHLGESCHLAGEN - Ziel %s - Absender %s - siehe iap_dashboard_api.log", target_path, caller)
        return jsonify({
            "success": False,
            "message": "Deploy fehlgeschlagen. Details siehe Server-Log (iap_dashboard_api.log).",
        }), 200


@app.route("/api/a2c-config", methods=["GET"])
def api_get_a2c_config():
    return jsonify(load_a2c_config())


@app.route("/api/a2c-config", methods=["POST"])
def api_set_a2c_config():
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    body = request.get_json(force=True) or {}
    cfg = load_a2c_config()
    if "basePath" in body:
        cfg["basePath"] = (body["basePath"] or "").strip()
    save_a2c_config(cfg)
    logger.info("A2C-Basisordner aktualisiert: %s", cfg.get("basePath"))
    return jsonify({"success": True, "message": "Pfad gespeichert."})


@app.route("/api/a2c-run", methods=["POST"])
def api_a2c_run():
    """Startet A2C headless im konfigurierten Basisordner - exakt der gleiche
    Aufruf wie dessen scripts/run_all.cmd (venv-Python main.py <mode>), nur ohne
    Konsolenfenster. Laeuft als eigener Hintergrundprozess; diese Route wartet
    NICHT auf dessen Ende, sondern kehrt sofort zurueck. Den Fortschritt zeigt
    /api/a2c-status (last_run_status.json + laufender-Prozess-Zustand)."""
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    base_path = (load_a2c_config().get("basePath") or "").strip()
    if not base_path or not os.path.isdir(base_path):
        return jsonify({"success": False, "message": "Kein gültiger A2C-Ordner konfiguriert."}), 200

    body = request.get_json(force=True) or {}
    mode = (body.get("mode") or "all").strip().lower()
    if mode not in A2C_VALID_MODES:
        return jsonify({
            "success": False,
            "message": f"Ungültiger Modus: {mode} (erlaubt: {', '.join(A2C_VALID_MODES)}).",
        }), 200

    main_py = os.path.join(base_path, "main.py")
    if not os.path.exists(main_py):
        return jsonify({"success": False, "message": f"main.py wurde in {base_path} nicht gefunden."}), 200

    with _a2c_run_lock:
        if _a2c_is_running():
            return jsonify({
                "success": False,
                "message": "Es läuft bereits ein A2C-Lauf (von hier gestartet). Bitte warten, bis dieser fertig ist.",
            }), 200

        python_exe = _a2c_python_exe(base_path)
        log_dir = os.path.join(base_path, "logs")
        try:
            os.makedirs(log_dir, exist_ok=True)
            log_file = open(os.path.join(log_dir, "cli-run.log"), "a", encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            log_error(f"A2C-Log konnte nicht geoeffnet werden ({base_path})", exc)
            return jsonify({"success": False, "message": GENERIC_ERROR_MESSAGE}), 200

        try:
            creationflags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
            proc = subprocess.Popen(
                [python_exe, "main.py", mode],
                cwd=base_path,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
        except Exception as exc:  # noqa: BLE001
            log_error(f"A2C-Lauf ({mode}) konnte nicht gestartet werden", exc)
            return jsonify({
                "success": False,
                "message": "Lauf konnte nicht gestartet werden. Details siehe Server-Log.",
            }), 200
        finally:
            # Das Kind-Prozess haelt sein eigenes Duplikat des Filedeskriptors -
            # das Elternhandle kann (und sollte) daher direkt wieder geschlossen
            # werden, sonst haeuft sich pro Lauf ein offener Filehandle in diesem
            # Bridge-Prozess an.
            log_file.close()

        _a2c_run_state["process"] = proc
        _a2c_run_state["mode"] = mode
        _a2c_run_state["startedAt"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    logger.info("A2C-Lauf gestartet: Modus=%s Ordner=%s PID=%s", mode, base_path, proc.pid)
    return jsonify({"success": True, "message": f"Lauf gestartet (Modus: {mode})."})


@app.route("/api/a2c-start-gui", methods=["POST"])
def api_a2c_start_gui():
    """Startet A2C OHNE Modus-Argument, also im normalen GUI-Modus von dessen
    main.py (siehe main(): 'if len(sys.argv) == 1: start_gui()') - ein echtes,
    sichtbares Programmfenster, nicht der headless Hintergrundlauf von
    api_a2c_run(). Wird bewusst NICHT in _a2c_run_state nachverfolgt: es ist kein
    "eingebetteter" Lauf mit Live-Status/Log-Anzeige im Dashboard, sondern nur ein
    einmaliger Anstoss - wie ein Doppelklick auf main.py.

    Ein "Popen hat geklappt" bedeutet NUR, dass Windows den Prozess angelegt hat -
    NICHT, dass tatsaechlich ein Fenster erscheint. Deshalb: stdout/stderr werden
    in logs/gui-start.log umgeleitet (sonst sind Absturzursachen unsichtbar,
    besonders wenn dieser Bridge-Dienst selbst ohne Konsolenfenster laeuft), und
    es wird kurz gewartet, ob der Prozess sofort wieder beendet ist (typisches
    Anzeichen fuer einen Absturz direkt beim Start, z.B. fehlende PySide6/Tkinter-
    Abhaengigkeit oder falsches venv) - das laesst sich so ehrlich zurueckmelden,
    statt pauschal "gestartet" zu behaupten.

    WICHTIG: Auch wenn der Prozess sauber laeuft, erscheint das Fenster nur, wenn
    dieser Bridge-Dienst selbst in einer interaktiven Desktop-Sitzung laeuft.
    Laeuft er unsichtbar (z.B. als Windows-Dienst oder als geplante Aufgabe in
    Session 0 - siehe A2C-eigene docs/Betrieb_Start.md), kann Windows dort
    grundsaetzlich kein Fenster auf einem Desktop anzeigen; das ist eine
    Betriebssystem-Beschraenkung, die sich von hier aus nicht umgehen laesst.
    """
    auth_err = check_api_key()
    if auth_err:
        return auth_err

    base_path = (load_a2c_config().get("basePath") or "").strip()
    if not base_path or not os.path.isdir(base_path):
        return jsonify({"success": False, "message": "Kein gültiger A2C-Ordner konfiguriert."}), 200

    main_py = os.path.join(base_path, "main.py")
    if not os.path.exists(main_py):
        return jsonify({"success": False, "message": f"main.py wurde in {base_path} nicht gefunden."}), 200

    python_exe = _a2c_python_exe(base_path)
    log_dir = os.path.join(base_path, "logs")
    gui_log_path = os.path.join(log_dir, "gui-start.log")
    try:
        os.makedirs(log_dir, exist_ok=True)
        log_file = open(gui_log_path, "a", encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        log_error(f"A2C-GUI-Log konnte nicht geoeffnet werden ({base_path})", exc)
        return jsonify({"success": False, "message": GENERIC_ERROR_MESSAGE}), 200

    try:
        proc = subprocess.Popen(
            [python_exe, "main.py"],
            cwd=base_path,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:  # noqa: BLE001
        log_error("A2C-GUI konnte nicht gestartet werden", exc)
        return jsonify({
            "success": False,
            "message": "Konnte nicht gestartet werden. Details siehe Server-Log.",
        }), 200
    finally:
        log_file.close()

    # Kurze Gnadenfrist: staerzt der Prozess (z.B. fehlende GUI-Abhaengigkeit)
    # ab, passiert das i.d.R. innerhalb von Millisekunden bis wenigen Sekunden -
    # das laesst sich hier noch mit abwarten, ohne den Request spuerbar zu blockieren.
    time.sleep(1.5)
    exit_code = proc.poll()

    if exit_code is not None:
        logger.warning("A2C-GUI (PID %s) sofort wieder beendet, Exit-Code %s (Ordner=%s)", proc.pid, exit_code, base_path)
        return jsonify({
            "success": False,
            "message": (
                f"Prozess wurde gestartet, ist aber sofort wieder beendet (Exit-Code {exit_code}). "
                f"Kein Fenster erschienen? Details in logs/gui-start.log pruefen "
                f"(z.B. fehlende PySide6/Tkinter-Abhaengigkeit oder falsches venv)."
            ),
        }), 200

    logger.info("A2C-GUI gestartet (PID %s, Ordner=%s)", proc.pid, base_path)
    return jsonify({
        "success": True,
        "message": (
            f"Prozess läuft (PID {proc.pid}). Falls trotzdem kein Fenster erscheint: "
            f"Der Bridge-Dienst läuft vermutlich nicht in einer sichtbaren Desktop-Sitzung "
            f"(z.B. als Dienst/geplante Aufgabe) - das kann Windows grundsätzlich nicht anzeigen."
        ),
    })


@app.route("/api/a2c-status", methods=["GET"])
def api_a2c_status():
    """Liest den zuletzt von A2C geschriebenen Laufstatus (last_run_status.json,
    siehe job_runner.py in dessen Repo) sowie einen kurzen Log-Ausschnitt aus dem
    hier konfigurierten Basisordner - rein lesend, A2C selbst wird von hier aus
    nicht gesteuert oder gestartet."""
    running = _a2c_is_running()
    running_info = None
    if running:
        running_info = {"mode": _a2c_run_state["mode"], "startedAt": _a2c_run_state["startedAt"]}

    base_path = (load_a2c_config().get("basePath") or "").strip()
    if not base_path:
        return jsonify({
            "configured": False,
            "available": False,
            "message": "Noch kein A2C-Ordner konfiguriert.",
            "status": None,
            "logTail": None,
            "running": running,
            "runningInfo": running_info,
        })

    if not os.path.isdir(base_path):
        return jsonify({
            "configured": True,
            "available": False,
            "message": f"Ordner nicht gefunden oder nicht erreichbar: {base_path}",
            "status": None,
            "logTail": None,
            "running": running,
            "runningInfo": running_info,
        })

    status_path = os.path.join(base_path, "logs", "last_run_status.json")
    log_path = os.path.join(base_path, "logs", "Servity-log.txt")

    status = None
    message = None
    if os.path.exists(status_path):
        try:
            with open(status_path, "r", encoding="utf-8") as f:
                status = json.load(f)
        except Exception as exc:  # noqa: BLE001
            log_error("A2C-Laufstatus konnte nicht gelesen werden", exc)
            message = "Laufstatus-Datei konnte nicht gelesen werden. Details siehe Server-Log."
    else:
        message = "Noch kein Lauf protokolliert (logs/last_run_status.json nicht gefunden)."

    log_tail = None
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            log_tail = "".join(lines[-60:])
        except Exception as exc:  # noqa: BLE001
            log_error("A2C-Logdatei konnte nicht gelesen werden", exc)

    return jsonify({
        "configured": True,
        "available": True,
        "message": message,
        "status": status,
        "logTail": log_tail,
        "running": running,
        "runningInfo": running_info,
    })


@app.route("/api/usecase2", methods=["GET"])
def api_usecase2():
    """Offene Changes nach Label (Kunde/Intern) + Offene Tasks nach Team."""
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(LATEST_CTE + "SELECT COUNT(DISTINCT ChangeID) FROM latest WHERE rn = 1")
        total_changes = cur.fetchone()[0]

        cur.execute(LATEST_CTE + "SELECT COUNT(*) FROM latest WHERE rn = 1")
        total_tasks = cur.fetchone()[0]

        cur.execute(
            LATEST_CTE + "SELECT COUNT(DISTINCT ChangeID) FROM latest "
            "WHERE rn = 1 AND [Change Status] <> 'Geschlossen'"
        )
        offene_changes = cur.fetchone()[0]

        cur.execute(
            LATEST_CTE + "SELECT COUNT(*) FROM latest WHERE rn = 1 AND Ticketstatus <> 'Geschlossen'"
        )
        offene_tasks = cur.fetchone()[0]

        cur.execute(
            LATEST_CTE
            + """
            SELECT CASE WHEN [Change-Labels] LIKE '%Kunde%' THEN 'Kunde' ELSE 'Intern' END AS Kategorie,
                   COUNT(DISTINCT ChangeID) AS Anzahl
            FROM latest
            WHERE rn = 1 AND [Change Status] <> 'Geschlossen'
            GROUP BY CASE WHEN [Change-Labels] LIKE '%Kunde%' THEN 'Kunde' ELSE 'Intern' END
            """
        )
        label_counts = {row[0]: row[1] for row in cur.fetchall()}

        cur.execute(
            LATEST_CTE
            + """
            SELECT Bearbeitergruppe, COUNT(*) AS Anzahl
            FROM latest
            WHERE rn = 1 AND Ticketstatus <> 'Geschlossen'
            GROUP BY Bearbeitergruppe
            ORDER BY Anzahl DESC
            """
        )
        teams = [{"team": row[0], "count": row[1]} for row in cur.fetchall()]

        # Anzahl Changes je Team - nutzt die Bearbeitergruppe auf CHANGE-Ebene (nicht die
        # Task-Bearbeitergruppe oben), da ein Change mehrere Tasks bei unterschiedlichen
        # Teams haben kann. Spaltenname wird dynamisch ermittelt (INFORMATION_SCHEMA), da
        # die genaue Schreibweise in der View nicht bekannt ist (z.B. "Change-Bearbeitergruppe",
        # "Change Bearbeitergruppe" ...). Wird die Spalte nicht gefunden, bleibt die Liste leer
        # und changesByTeamNote erklaert im Dashboard, woran es liegt.
        change_team_col = find_column(cur, "vw_ticket_changes_powerbi", "changebearbeitergruppe")
        changes_by_team = []
        changes_by_team_note = None
        if change_team_col:
            cur.execute(
                LATEST_CTE
                + f"""
                SELECT [{change_team_col}], COUNT(DISTINCT ChangeID) AS Anzahl
                FROM latest
                WHERE rn = 1
                GROUP BY [{change_team_col}]
                ORDER BY Anzahl DESC
                """
            )
            changes_by_team = [{"team": row[0], "count": row[1]} for row in cur.fetchall()]
        else:
            changes_by_team_note = (
                "Keine Spalte fuer die Change-Bearbeitergruppe in "
                "dbo.vw_ticket_changes_powerbi gefunden."
            )

        # Neuestes Export-Datum im aktuellen Projekt-Scope – wird im Dashboard-Header
        # als "Stand: ..." angezeigt, damit dort immer der tatsaechlich verwendete
        # Datenstand steht (nicht das Datum des Seitenaufrufs).
        cur.execute(LATEST_CTE + "SELECT MAX([Export-Datum]) FROM latest")
        stand_row = cur.fetchone()
        stand_datum = stand_row[0].isoformat() if stand_row and stand_row[0] else None

        # Rohdaten je Task fuer clientseitiges Cross-Filtering zwischen den vier
        # Kuchencharts (Klick auf ein Segment filtert die anderen drei Charts mit,
        # PowerBI-Stil). Jede Zeile = ein Task mit Label (Kunde/Intern), Team auf
        # Task-Ebene, Team auf Change-Ebene (falls die Spalte gefunden wurde) sowie
        # Open/Closed-Status von Task und zugehoerigem Change. Wird bewusst hier mit
        # abgefragt (gleiche Connection/CTE), damit kein zusaetzlicher Request noetig ist.
        change_team_select = f"[{change_team_col}]" if change_team_col else "NULL"
        cur.execute(
            LATEST_CTE
            + f"""
            SELECT ChangeID,
                   CASE WHEN [Change-Labels] LIKE '%Kunde%' THEN 'Kunde' ELSE 'Intern' END AS Label,
                   [Change Status] AS ChangeStatus,
                   Ticketstatus AS TaskStatus,
                   Bearbeitergruppe AS TaskTeam,
                   {change_team_select} AS ChangeTeam
            FROM latest
            WHERE rn = 1
            """
        )
        raw_tasks = [
            {
                "changeId": row[0],
                "label": row[1],
                "changeOpen": row[2] != "Geschlossen",
                "taskOpen": row[3] != "Geschlossen",
                "taskTeam": row[4],
                "changeTeam": row[5],
            }
            for row in cur.fetchall()
        ]

        conn.close()

        return jsonify(
            {
                "totalChanges": total_changes,
                "totalTasks": total_tasks,
                "offeneChanges": offene_changes,
                "offeneTasks": offene_tasks,
                "changesByLabel": {
                    "intern": label_counts.get("Intern", 0),
                    "kunde": label_counts.get("Kunde", 0),
                },
                "openTasksByTeam": teams,
                "teamsCount": len(teams),
                "changesByTeam": changes_by_team,
                "changesByTeamNote": changes_by_team_note,
                "standDatum": stand_datum,
                "rawTasks": raw_tasks,
            }
        )
    except Exception as exc:  # noqa: BLE001
        log_error("/api/usecase2 fehlgeschlagen", exc)
        return jsonify({"error": GENERIC_ERROR_MESSAGE}), 500


@app.route("/api/uc1", methods=["GET"])
def api_uc1():
    """Rohdaten je Change für Gantt (UC1) und Balkenchart (UC3)."""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            LATEST_CTE
            + """
            SELECT ChangeID,
                   MIN([Zusammenfassung.1]) AS Beschreibung,
                   MIN([Change-Labels]) AS Labels,
                   MIN([Change Status]) AS ChangeStatus,
                   MIN([Geplanter Start]) AS GeplanterStart,
                   MAX([Geplantes Ende]) AS GeplantesEnde,
                   COUNT(*) AS TasksGesamt,
                   SUM(CASE WHEN Ticketstatus = 'Geschlossen' THEN 1 ELSE 0 END) AS TasksErledigt
            FROM latest
            WHERE rn = 1
            GROUP BY ChangeID
            ORDER BY ChangeID
            """
        )
        changes = []
        for row in cur.fetchall():
            changes.append(
                {
                    "changeId": row[0],
                    "description": row[1],
                    "labels": row[2],
                    "status": row[3],
                    "start": row[4].isoformat() if row[4] else None,
                    "end": row[5].isoformat() if row[5] else None,
                    "tasksTotal": row[6],
                    "tasksDone": row[7],
                }
            )
        conn.close()
        return jsonify({"changes": changes})
    except Exception as exc:  # noqa: BLE001
        log_error("/api/uc1 fehlgeschlagen", exc)
        return jsonify({"error": GENERIC_ERROR_MESSAGE}), 500


@app.route("/api/uc3", methods=["GET"])
def api_uc3():
    """Gleiche Rohdaten wie UC1 – Frontend sortiert/rendert als Balkenchart."""
    return api_uc1()


@app.route("/api/uc4", methods=["GET"])
def api_uc4():
    """
    Historischer Verlauf (Changes/Tasks gesamt/offen/geschlossen).
    Der SQL-Export selbst deckt nur ~4 Tage ab – deshalb wird bei jedem Aufruf
    ein Snapshot von heute lokal abgelegt (uc4_history.json). So waechst die
    echte Historie ab sofort taeglich, unabhaengig vom Datenexport-Zeitraum.
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        metrics = compute_core_metrics(cur)
        conn.close()

        today = datetime.date.today().isoformat()
        history = load_uc4_history()
        history = [h for h in history if h.get("date") != today]
        history.append({"date": today, **metrics})
        history.sort(key=lambda h: h["date"])
        save_uc4_history(history)

        return jsonify({"history": history})
    except Exception as exc:  # noqa: BLE001
        log_error("/api/uc4 fehlgeschlagen", exc)
        return jsonify({"error": GENERIC_ERROR_MESSAGE}), 500


if __name__ == "__main__":
    config = load_config()
    if not os.path.exists(CONFIG_PATH):
        save_config(config)
    port = config.get("apiPort", 5000)
    print(f"IAP Dashboard API läuft auf http://localhost:{port}")
    print(f"Aktuelle Verbindung: {config['server']} / {config['database']} ({config['authType']})")
    print(f"Konfiguration: {CONFIG_PATH}")
    # Bewusst wieder 127.0.0.1 (Loopback), NICHT 0.0.0.0: Architekturentscheidung
    # ist IIS als Reverse-Proxy (siehe Setup-Doku) - IIS terminiert HTTPS auf
    # Port 443 und leitet /api/* intern an genau diesen Bridge-Dienst weiter.
    # Der eingebaute Flask-Entwicklungsserver (siehe Warnung beim Start: "Do not
    # use it in a production deployment") muss dadurch selbst NICHT mehr direkt
    # aus dem Netzwerk erreichbar sein - nur IIS auf demselben Server spricht
    # ihn ueber Loopback an. Das ist strenger/sicherer als eine direkte
    # 0.0.0.0-Bindung mit offener Firewall-Regel dafuer.
    app.run(host="127.0.0.1", port=port, debug=False)
