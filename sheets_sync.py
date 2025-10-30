# sheets_sync.py
import os, json, logging, re
import gspread
from datetime import datetime
from google.oauth2.service_account import Credentials

logger = logging.getLogger(__name__)

# Column headers you want in the sheet (left to right)
HEADERS = [
    "Locations", "Dates", "OSA Rep", "Announcer", "Extra Person / Gopher",
    "Backstage Manager", "Trophies", "Judge 1", "Judge 2", "Judge 3",
    "Clothes Vendor", "GAP", "Hotel"
]

POSITION_TO_HEADER = {
    "osa rep": "OSA Rep",
    "representative": "OSA Rep",
    "announcer": "Announcer",
    "extra": "Extra Person / Gopher",
    "gopher": "Extra Person / Gopher",
    "backstage": "Backstage Manager",
    "troph": "Trophies",
    "judge 1": "Judge 1",
    "judge 2": "Judge 2",
    "judge 3": "Judge 3",
    "clothes": "Clothes Vendor",
    "vendor": "Clothes Vendor",
    "gap": "GAP",
}

def _normalize_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower().strip())

def _find_header_for_position(pos_name: str) -> str | None:
    t = (pos_name or "").lower()
    for key, hdr in POSITION_TO_HEADER.items():
        if key in t:
            return hdr
    return None

def _get_client_and_sheet():
    sid = os.getenv("GOOGLE_SHEETS_SPREADSHEET_ID")
    tab = os.getenv("GOOGLE_SHEETS_TAB_NAME", "Assignments")
    creds_json = os.getenv("GOOGLE_SHEETS_CREDS_JSON")
    if not sid or not creds_json:
        raise RuntimeError("Missing GOOGLE_SHEETS_SPREADSHEET_ID or GOOGLE_SHEETS_CREDS_JSON")
    info = json.loads(creds_json)
    creds = Credentials.from_service_account_info(info, scopes=["https://www.googleapis.com/auth/spreadsheets"])
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(sid)
    try:
        ws = sh.worksheet(tab)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=tab, rows=200, cols=len(HEADERS))
    return ws

def _ensure_headers(ws):
    existing = ws.row_values(1)
    if existing != HEADERS:
        ws.resize(rows=max(200, ws.row_count), cols=len(HEADERS))
        ws.update('A1', [HEADERS])

def _format_date_range(ev, days):
    if days:
        dts = sorted([d.start_dt for d in days if d.start_dt])
        if dts:
            first = dts[0].strftime("%b %-d")
            last = dts[-1].strftime("%-d, %Y")
            return f"{first}-{last}"
    dt = getattr(ev, "event_start", None)
    return dt.strftime("%b %-d, %Y") if dt else ""

def sync_assignments_sheet(db, only_event_id=None, rows_for_event=None, event=None) -> int:
    from models import Assignment, EventDay
    from sqlalchemy.orm import joinedload
    ws = _get_client_and_sheet()
    _ensure_headers(ws)

    # --- get current sheet values ---
    all_vals = ws.get_all_values()
    header = all_vals[0] if all_vals else []
    data = all_vals[1:] if len(all_vals) > 1 else []
    col_idx = {h: i for i, h in enumerate(HEADERS)}

    # build existing key map
    existing_keys = {}
    for idx, row in enumerate(data, start=2):
        loc = row[col_idx["Locations"]] if len(row) > col_idx["Locations"] else ""
        dat = row[col_idx["Dates"]] if len(row) > col_idx["Dates"] else ""
        existing_keys[_normalize_key(loc + dat)] = idx

    # get event + days if not passed
    if not (event and rows_for_event):
        event = db.get(__import__("models").Event, only_event_id)
        rows_for_event = (
            db.query(Assignment)
              .filter(Assignment.event_id == only_event_id)
              .options(joinedload(Assignment.person), joinedload(Assignment.position))
              .all()
        )
    days = db.query(EventDay).filter(EventDay.event_id == event.id).all()
    date_label = _format_date_range(event, days)

    # build row payload
    payload = {h: "" for h in HEADERS}
    payload["Locations"] = event.city or ""
    payload["Dates"] = date_label
    payload["Hotel"] = event.hotel or ""

    for a in rows_for_event:
        if not a.person or not a.position:
            continue
        header = _find_header_for_position(a.position.name)
        if not header:
            continue
        current = payload.get(header, "")
        add = (a.person.name or "").strip()
        if add:
            payload[header] = f"{current}, {add}".strip(", ")

    # decide insert/update
    key = _normalize_key(payload["Locations"] + payload["Dates"])
    row_idx = existing_keys.get(key)
    ordered = [payload.get(h, "") for h in HEADERS]

    if row_idx:
        ws.update(f"A{row_idx}", [ordered])
        logger.info(f"SHEETS: updated row {row_idx} for {payload['Locations']}")
    else:
        ws.append_row(ordered, value_input_option="USER_ENTERED")
        logger.info(f"SHEETS: appended {payload['Locations']}")

    # --- Improved sorting by real date ---
    try:
        from dateutil import parser
        vals = ws.get_all_values()
        if len(vals) > 1:
            rows = vals[1:]

            def _parse_date_label(label: str):
                label = (label or "").strip()
                if not label:
                    return datetime.max
                try:
                    # Handle formats like "March 7-9, 2025" -> "March 7, 2025"
                    if re.search(r"[A-Za-z]", label) and "-" in label:
                        # Split at dash and drop trailing range
                        first = label.split("-")[0].strip()
                        year = re.search(r"(\d{4})", label)
                        if year and year.group(1) not in first:
                            first = f"{first}, {year.group(1)}"
                        return parser.parse(first, fuzzy=True)
                    # Handle short forms "3/7-9/2025"
                    m = re.search(r"(\d{1,2})[/-](\d{1,2})[/-](\d{4})", label)
                    if m:
                        return datetime(int(m.group(3)), int(m.group(1)), int(m.group(2)))
                    # Fallback generic parse
                    return parser.parse(label, fuzzy=True)
                except Exception:
                    return datetime.max

            col_idx = {h: i for i, h in enumerate(HEADERS)}
            rows.sort(key=lambda r: _parse_date_label(r[col_idx["Dates"]]))
            ws.update('A2', rows)
            logger.info("SHEETS: re-sorted by date successfully")
    except Exception as e:
        logger.warning("SHEETS sort failed: %s", e)

    # After sorting:
    _apply_row_striping(ws)
    return 1

   # return 1
    
def _apply_row_striping(ws):
    """Apply alternating background colors for readability."""
    try:
        sh = ws.spreadsheet
        sheet_id = ws.id
        total_rows = ws.row_count
        total_cols = ws.col_count
        # simple gray-white alternating pattern
        requests = [
            {
                "addBanding": {
                    "bandedRange": {
                        "range": {
                            "sheetId": sheet_id,
                            "startRowIndex": 1,  # skip header row
                            "endRowIndex": total_rows,
                            "startColumnIndex": 0,
                            "endColumnIndex": total_cols,
                        },
                        "rowProperties": {
                            "firstBandColor": {"red": 0.98, "green": 0.98, "blue": 0.98},  # light gray
                            "secondBandColor": {"red": 1, "green": 1, "blue": 1},         # white
                        },
                        "headerRowColor": {"red": 0.85, "green": 0.9, "blue": 0.95},  # light blue header
                    }
                }
            }
        ]
        sh.batch_update({"requests": requests})
        logger.info("SHEETS: applied alternating row colors")
    except Exception as e:
        logger.warning("SHEETS: failed to apply striping: %s", e)
