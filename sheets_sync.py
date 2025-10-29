# sheets_sync.py
import os
from datetime import datetime

# We only import gspread/auth when used so the app can run without Sheets creds.
def _get_gspread_client():
    try:
        import gspread
        from google.oauth2.service_account import Credentials
    except ImportError as e:
        raise RuntimeError(
            "gspread / google-auth not installed. "
            "Add them to requirements.txt."
        ) from e

    json_path = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")
    json_inline = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]

    if json_path and os.path.exists(json_path):
        creds = Credentials.from_service_account_file(json_path, scopes=scopes)
    elif json_inline:
        import json
        creds = Credentials.from_service_account_info(json.loads(json_inline), scopes=scopes)
    else:
        raise RuntimeError(
            "Google service account creds not provided. "
            "Set GOOGLE_SERVICE_ACCOUNT_FILE or GOOGLE_SERVICE_ACCOUNT_JSON."
        )

    import gspread
    return gspread.authorize(creds)

def _event_header(ev):
    # Header like: "2025-11-11 — City" (falls back to city only if date missing)
    if getattr(ev, "date", None):
        try:
            return f"{ev.date:%Y-%m-%d} — {ev.city or ''}".strip()
        except Exception:
            pass
    return (ev.city or "Event").strip()

def _ensure_worksheet(sh, title):
    # Create or get a worksheet named `title`
    try:
        ws = sh.worksheet(title)
    except Exception:
        ws = sh.add_worksheet(title=title, rows=200, cols=50)
    return ws

def _ensure_positions_column(ws, positions):
    """
    Column A:
      A1 = "Position"
      A2.. = each position name (ordered)
    Returns the number of rows written.
    """
    # Read first column quickly
    try:
        current = ws.col_values(1)
    except Exception:
        current = []

    desired = ["Position"] + [p.name or "" for p in positions]
    if current[:len(desired)] == desired:
        return len(desired)

    # Write in one batch
    data = [[v] for v in desired]
    ws.update(f"A1:A{len(desired)}", data)
    return len(desired)

def _ensure_event_column(ws, header, col_after=1):
    """
    Find a column with the given header (row1). If not present, append to the right.
    Returns the 1-based column index.
    """
    headers = ws.row_values(1)  # first row
    for idx, h in enumerate(headers, start=1):
        if h == header:
            return idx

    # Not found -> append at end
    col_idx = max(len(headers) + 1, col_after + 1)
    ws.update_cell(1, col_idx, header)
    return col_idx

def _assignment_matrix_for_event(db, models, ev_id, positions):
    """Return list of names per position for a single event (same order as `positions`)."""
    Event, Position, Assignment, Person = models
    # Build map pos_id -> person_name
    rows = (
        db.query(Assignment)
          .filter(Assignment.event_id == ev_id)
          .all()
    )
    name_by_pos = {}
    for a in rows:
        # lazy load is fine; we only need name if present
        person_name = (a.person.name if a.person else "") if hasattr(a, "person") else ""
        name_by_pos[a.position_id] = person_name

    # ordered list by positions
    return [name_by_pos.get(p.id, "") for p in positions]

def sync_assignments_sheet(db, only_event_id=None):
    """
    Update a Google Sheet with columns per event and rows per position.
    Env needed:
      - SHEETS_SPREADSHEET_ID (required)
      - SHEETS_WORKSHEET (optional, default "Assignments")
      - GOOGLE_SERVICE_ACCOUNT_FILE or GOOGLE_SERVICE_ACCOUNT_JSON (required)
    """
    from models import Event, Position, Assignment, Person  # late import to avoid circulars

    spreadsheet_id = os.getenv("SHEETS_SPREADSHEET_ID")
    worksheet_title = os.getenv("SHEETS_WORKSHEET", "Assignments")
    if not spreadsheet_id:
        raise RuntimeError("SHEETS_SPREADSHEET_ID is not set.")

    gc = _get_gspread_client()
    sh = gc.open_by_key(spreadsheet_id)
    ws = _ensure_worksheet(sh, worksheet_title)

    # Positions ordered by display_order
    positions = db.query(Position).order_by(Position.display_order.asc()).all()
    last_row = _ensure_positions_column(ws, positions)

    # Determine events to update
    if only_event_id:
        evs = [db.get(Event, only_event_id)]
    else:
        evs = db.query(Event).order_by(Event.date.asc()).all()

    # Build/ensure columns and write names
    updates = []  # list of (range, values)

    for ev in evs:
        if not ev:
            continue
        header = _event_header(ev)
        col = _ensure_event_column(ws, header, col_after=1)  # ensure header in row 1

        names = _assignment_matrix_for_event(
            db,
            (Event, Position, Assignment, Person),
            ev.id,
            positions
        )
        # Range like: B2:B{last_row} etc. (col may vary)
        start_row = 2
        end_row = start_row + len(names) - 1
        col_letter = _col_to_letter(col)
        rng = f"{col_letter}{start_row}:{col_letter}{end_row}"
        updates.append((rng, [[n] for n in names]))

    # Batch update
    if updates:
        body = [{"range": r, "values": v} for r, v in updates]
        ws.batch_update(body)

def _col_to_letter(col_idx):
    """1 -> A, 2 -> B, ..."""
    out = ""
    while col_idx:
        col_idx, rem = divmod(col_idx - 1, 26)
        out = chr(65 + rem) + out
    return out
