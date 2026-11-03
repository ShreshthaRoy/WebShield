"""Consistent CSV history storage shared by WebShield's API and dashboard."""
import csv
import os
import tempfile
import threading
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
HISTORY_PATH = BASE_DIR / "phishing_history.csv"
HISTORY_COLUMNS = [
    "url", "risk_score", "status", "ml_score", "dl_score", "model_score",
    "url_risk", "domain_risk", "page_risk", "page_analysis_available", "time",
]
_LOCK = threading.Lock()


def _normalise_row(row):
    clean = {key: row.get(key, "") for key in HISTORY_COLUMNS}
    clean["url"] = str(clean.get("url", "") or "")
    clean["status"] = str(clean.get("status", "UNKNOWN") or "UNKNOWN")
    clean["time"] = str(clean.get("time", "") or datetime.now().isoformat(timespec="seconds"))
    for key in ("risk_score", "ml_score", "dl_score", "model_score", "url_risk", "domain_risk"):
        try:
            clean[key] = round(float(clean[key]), 2) if clean[key] not in (None, "") else ""
        except (TypeError, ValueError):
            clean[key] = ""
    if clean["page_risk"] in (None, ""):
        clean["page_risk"] = ""
    else:
        try:
            clean["page_risk"] = round(float(clean["page_risk"]), 2)
        except (TypeError, ValueError):
            clean["page_risk"] = ""
    available = clean["page_analysis_available"]
    if isinstance(available, str):
        clean["page_analysis_available"] = available.strip().lower() in {"true", "1", "yes"}
    else:
        clean["page_analysis_available"] = bool(available)
    return clean


def append_scan(row):
    """Append a scan and transparently migrate older/mixed-schema CSV files."""
    clean = _normalise_row(row)
    with _LOCK:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing_rows = []
        if HISTORY_PATH.exists() and HISTORY_PATH.stat().st_size:
            try:
                with HISTORY_PATH.open("r", newline="", encoding="utf-8-sig") as handle:
                    reader = csv.reader(handle)
                    old_header = next(reader, [])
                    if old_header == HISTORY_COLUMNS:
                        with HISTORY_PATH.open("a", newline="", encoding="utf-8") as append_handle:
                            writer = csv.DictWriter(append_handle, fieldnames=HISTORY_COLUMNS)
                            writer.writerow(clean)
                        return
                    for values in reader:
                        # Ignore malformed rows instead of crashing future scans.
                        if len(values) != len(old_header):
                            continue
                        existing_rows.append(dict(zip(old_header, values)))
            except (OSError, csv.Error, UnicodeError):
                existing_rows = []

        fd, temp_name = tempfile.mkstemp(prefix="webshield-history-", suffix=".csv", dir=str(HISTORY_PATH.parent))
        try:
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=HISTORY_COLUMNS)
                writer.writeheader()
                for old in existing_rows:
                    writer.writerow(_normalise_row(old))
                writer.writerow(clean)
            os.replace(temp_name, HISTORY_PATH)
        finally:
            if os.path.exists(temp_name):
                os.remove(temp_name)
