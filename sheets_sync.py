# sheets_sync.py
import os
import json
import logging
from datetime import datetime
import gspread
from google.oauth2.service_account import Credentials

logger = logging.getLogger(__name__)

# Column headers you want in the sheet (left to right)
HEADERS = [
    "Locations", "Dates", "OSA Rep", "Announcer", "Extra Person",
    "Backstage Manager", "Trophies", "Judge 1", "Judge 2", "Judge 3",
    "Sales Desk", "PHOTO", "VIDEO", "Hotel"
]

# Map your Position names -> column header
POSITION_TO_HEADER = {
    "Director": "OSA Rep",
    "Emcee": "Announcer",
    "Extra hand": "Extra Person",
    #"Gopher": "Extra Person / Gopher",
    "Backstage Manager": "Backstage Manager",
    "Trophies": "Trophies",
    "Judge 1": "Judge 1",
    "Judge 2": "Judge 2",
    "Judge 3": "Judge 3",
    "Sales": "Sales Desk",
    "Photo": "Photo",
    "Video": "Video",
}

def _get_client_and_sheet():
    sid = os.getenv("GOOGLE_SHEETS_SPREADSHEET_ID")
    tab = os.getenv("GOOGLE_SHEETS_TAB_NAME", "Assignments")
    creds_json = os.getenv("GOOGLE_SHEETS_CREDS_JSON")

    if not sid or not creds_json:
        raise RuntimeError("Missing GOOGLE_SHEETS_SPREADSHEET_ID or GOOGLE_SHEETS_CREDS_JSON")

    info = json.loads(creds_json)
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_info(info, scopes=scopes)
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(sid)
    try:
        ws = sh.worksheet(tab)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=tab, rows=100, cols=len(HEADERS))
    return ws

def _ensure_headers(ws):
    existing = ws.row_values(1)
    if existing != HEADERS:
        ws.resize(rows=max(100, ws.row_count), cols=len(HEADERS))
        ws.update('A1', [HEADERS])

def _event_key(city: str, date_label: str) -> str:
    return f"{(city or '').strip()}|{(date_label or '').strip()}".lower()

def _format_date_range(ev, days):
    # Use multi-day range if EventDay exists; else fall back to ev.date or ev.event_start
    """
    if days:
        dts = sorted([d.start_dt for d in days if d.start_dt])
        if dts:
            first = dts[0].strftime("%B %-d, %Y")
            last = dts[-1].strftime("%B %-d, %Y")
            if first == last:
                return first
            return f"{first} - {last}"
    """
    # single-day fallback
    dt = ev.date or ev.event_start
    return dt.strftime("%B %-d, %Y") if dt else ""

def sync_assignments_sheet(db, only_event_id=None, rows_for_event=None, event=None) -> int:
    """
    Upsert one row per event in the target sheet. Returns number of rows written.
    """
    logger.info("SHEETS: starting sync for event_id=%s", only_event_id)
    ws = _get_client_and_sheet()
    _ensure_headers(ws)

    # Load existing rows into a map for upsert
    all_values = ws.get_all_values()
    header = all_values[0] if all_values else []
    rows = all_values[1:] if len(all_values) > 1 else []
    col_index = {h: i for i, h in enumerate(HEADERS)}  # header -> 0-based index

    # Build a key->row_index map from existing rows
    existing_map = {}
    for idx, row in enumerate(rows, start=2):  # row 2..N
        loc = row[col_index["Locations"]] if len(row) > col_index["Locations"] else ""
        dat = row[col_index["Dates"]] if len(row) > col_index["Dates"] else ""
        existing_map[_event_key(loc, dat)] = idx

    # Build our row payload for this event
    if not (event and rows_for_event is not None):
        # Defensive: pull fresh if not provided
        from models import Assignment, Position, Event, EventDay
        from sqlalchemy.orm import joinedload, aliased
        if only_event_id is None:
            return 0
        event = db.get(Event, only_event_id)
        Pos = aliased(Position)
        rows_for_event = (
            db.query(Assignment)
              .filter(Assignment.event_id == only_event_id)
              .options(joinedload(Assignment.person), joinedload(Assignment.position))
              .all()
        )
        days = db.query(EventDay).filter(EventDay.event_id == only_event_id).all()
    else:
        # caller passed both
        from models import EventDay
        days = db.query(EventDay).filter(EventDay.event_id == event.id).all()

    date_label = _format_date_range(event, days)
    row_payload = {h: "" for h in HEADERS}
    row_payload["Locations"] = event.city or ""
    row_payload["Dates"] = date_label
    row_payload["Hotel"] = (event.hotel or "").strip()

    # Fill positions -> names
    for a in rows_for_event:
        pos_name = (a.position.name if a.position else "").strip()
        header_name = POSITION_TO_HEADER.get(pos_name)
        if not header_name:
            # Try loose match, e.g., "Judge 1 (panel A)" → "Judge 1"
            if pos_name.lower().startswith("judge 1"):
                header_name = "Judge 1"
            elif pos_name.lower().startswith("judge 2"):
                header_name = "Judge 2"
            elif pos_name.lower().startswith("judge 3"):
                header_name = "Judge 3"
            elif "backstage" in pos_name.lower():
                header_name = "Backstage Manager"
            elif "troph" in pos_name.lower():
                header_name = "Trophies"
        if header_name and a.person:
            # Prefer the person's name; append if the cell already has someone
            current = row_payload.get(header_name, "")
            add = (a.person.name or "").strip()
            if add:
                row_payload[header_name] = f"{current}, {add}".strip(", ").replace("  ", " ")

    # Decide insert vs update
    key = _event_key(row_payload["Locations"], row_payload["Dates"])
    target_row_idx = existing_map.get(key)

    # Ensure sheet has enough rows
    needed_rows = max(ws.row_count, (target_row_idx or 0), 2 + len(rows))
    if ws.row_count < needed_rows:
        ws.add_rows(needed_rows - ws.row_count)

    # Build row list in header order
    ordered = [row_payload.get(h, "") for h in HEADERS]

    if target_row_idx:
        # Update existing row
        ws.update(f"A{target_row_idx}", [ordered])
        logger.info("SHEETS: updated row %s for key=%s", target_row_idx, key)
        return 1
    else:
        # Append to end
        ws.append_row(ordered, value_input_option="USER_ENTERED")
        logger.info("SHEETS: appended row for key=%s", key)
        return 1
