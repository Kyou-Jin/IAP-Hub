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
import json
import os
import re

from flask import Flask, jsonify, request
from flask_cors import CORS

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

DEFAULT_CONFIG = {
    "apiPort": 5000,
    "server": "localhost\\SQLEXPRESS",
    "database": "IAPPowerBI",
    "authType": "windows",  # "windows" oder "sql"
    "username": "",
    "password": "",
}

app = Flask(__name__)
CORS(app)  # Dashboard wird i.d.R. als lokale Datei (file://) oder anderer Port geöffnet


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
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


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
        conn_str = (
            f"DRIVER={{{driver}}};SERVER={cfg['server']};DATABASE={cfg['database']};"
            f"UID={cfg.get('username', '')};PWD={cfg.get('password', '')};"
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
# Projekt-Scope: alle Changes, deren Change-Labels "INF-Kunde" oder
# "INF-Intern" enthalten (so gewuenscht statt einer festen ChangeID-Liste –
# neue Changes mit diesen Labels erscheinen automatisch, ohne Code-Aenderung).
LATEST_CTE = """
WITH latest AS (
    SELECT *,
           ROW_NUMBER() OVER (PARTITION BY Nummer ORDER BY [Export-Datum] DESC) AS rn
    FROM dbo.vw_ticket_changes_powerbi
    WHERE [Change-Labels] LIKE '%INF-Kunde%' OR [Change-Labels] LIKE '%INF-Intern%'
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
    safe["password"] = "***" if safe.get("password") else ""
    return jsonify(safe)


@app.route("/api/config", methods=["POST"])
def api_set_config():
    body = request.get_json(force=True) or {}
    cfg = load_config()
    for key in ("server", "database", "authType", "username"):
        if key in body and body[key] is not None:
            cfg[key] = body[key]
    if body.get("password"):
        cfg["password"] = body["password"]
    save_config(cfg)

    try:
        conn = get_connection(cfg)
        conn.close()
        return jsonify({"success": True, "message": f"Verbunden mit {cfg['server']} / {cfg['database']}"})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"success": False, "message": str(exc)}), 200


@app.route("/api/status", methods=["GET"])
def api_status():
    cfg = load_config()
    try:
        conn = get_connection(cfg)
        conn.close()
        return jsonify({"connected": True, "server": cfg["server"], "database": cfg["database"]})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"connected": False, "message": str(exc)})


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
            }
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


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
        return jsonify({"error": str(exc)}), 500


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
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    config = load_config()
    if not os.path.exists(CONFIG_PATH):
        save_config(config)
    port = config.get("apiPort", 5000)
    print(f"IAP Dashboard API läuft auf http://localhost:{port}")
    print(f"Aktuelle Verbindung: {config['server']} / {config['database']} ({config['authType']})")
    print(f"Konfiguration: {CONFIG_PATH}")
    app.run(host="127.0.0.1", port=port, debug=False)
