import openpyxl
import datetime

SRC = "Grid-202606301619.xlsx"
OUT = "backfill_20260630_full.sql"
EXPORT_DATUM_SQL = "20260630 00:00:00"

DB_COLUMNS = [
    "neue_aenderung", "nummer", "zusammenfassung", "beschreibung", "ticketstatus",
    "bearbeitergruppe", "bearbeiter", "erfasst_von", "letzte_aenderung", "labels",
    "reihenfolge", "changeid", "zusammenfassung2", "change_labels", "anforderer",
    "betroffene_organisationseinheiten", "change_manager", "geplanter_start",
    "geplantes_ende", "start_echtbetrieb", "change_status", "change_bearbeitergruppe",
    "dringlichkeit", "auswirkung", "komplexitaet", "risiko",
    "compliance_check_notwendig", "projektlink", "export_datum",
]

DATE_COLS = {8, 17, 18, 19, 28}
INT_COLS = {10}


def esc(v):
    if v is None:
        return "NULL"
    s = str(v).replace("'", "''")
    return "'" + s + "'"


def parse_de_date(v):
    if v is None:
        return None
    if isinstance(v, datetime.datetime):
        dt = v
    elif isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        s2 = s.replace(",", "")
        parts = s2.split()
        datepart = parts[0]
        timepart = parts[1] if len(parts) > 1 else "00:00"
        try:
            d, m, y = datepart.split(".")
            d, m, y = int(d), int(m), int(y)
            hh, mm = timepart.split(":")
            dt = datetime.datetime(y, m, d, int(hh), int(mm))
        except Exception:
            return None
    else:
        return None
    if dt.year < 1753 or dt.year > 9999:
        return None
    return dt


def parse_int(v):
    if v is None or v == "":
        return None
    try:
        return int(v)
    except Exception:
        return None


def fmt_val(col_idx, v):
    if col_idx in DATE_COLS:
        dt = parse_de_date(v)
        if dt is None:
            return "NULL"
        return "'" + dt.strftime("%Y%m%d %H:%M:%S") + "'"
    if col_idx in INT_COLS:
        iv = parse_int(v)
        return "NULL" if iv is None else str(iv)
    return esc(v)


wb = openpyxl.load_workbook(SRC, read_only=True, data_only=True)
ws = wb.active
rows = ws.iter_rows(values_only=True)
header = next(rows)

data_rows = list(rows)
print("Total data rows:", len(data_rows))

bad_dates = 0
value_tuples = []
for r in data_rows:
    vals = []
    for i in range(29):
        v = r[i] if i < len(r) else None
        if i in DATE_COLS:
            dt = parse_de_date(v)
            if v is not None and dt is None:
                bad_dates += 1
        vals.append(fmt_val(i, v))
    value_tuples.append("(" + ",".join(vals) + ")")

print("Bad date cells nulled:", bad_dates)

BATCH = 500
with open(OUT, "w", encoding="utf-8") as f:
    f.write("-- Nachimport: " + SRC + " (export_datum 2026-06-30), ALLE Changes\n")
    f.write("-- Fehlerhafte Datumswerte (Jahr ausserhalb DATETIME-Bereich) -> NULL\n")
    f.write("-- Korrektur: letzte_aenderung (DB: datetime) wird jetzt ebenfalls als Datum geparst\n")
    f.write("SET NOCOUNT ON;\n")
    f.write("SET XACT_ABORT ON;\n")
    f.write("DELETE FROM dbo.ticket_changes WHERE export_datum = '" + EXPORT_DATUM_SQL + "';\n")
    f.write("GO\n")
    f.write("BEGIN TRAN;\n")
    f.write("GO\n")

    cols_sql = ",\n    ".join(DB_COLUMNS)
    for start in range(0, len(value_tuples), BATCH):
        batch = value_tuples[start:start + BATCH]
        f.write("INSERT INTO dbo.ticket_changes (\n    " + cols_sql + "\n) VALUES\n")
        f.write(",\n".join(batch))
        f.write(";\nGO\n")

    f.write("COMMIT TRAN;\n")
    f.write("GO\n")
    f.write(
        "SELECT COUNT(*) AS EingefuegteZeilen, COUNT(DISTINCT changeid) AS DistinctChanges "
        "FROM dbo.ticket_changes WHERE export_datum = '" + EXPORT_DATUM_SQL + "';\n"
    )
    f.write("GO\n")

print("Wrote " + OUT)
