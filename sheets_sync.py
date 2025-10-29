# sheets_sync.py
import os
from datetime import datetime
import gspread
from google.oauth2.service_account import Credentials

# ENV you must set in Render:
# GOOGLE_SERVICE_ACCOUNT_JSON: full JSON credentials (recommended) OR path to a json file
# SHEET_ID: the Google Spreadsheet ID
# SHEETS_TAB: tab name (default 'Staff Matrix')

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets"
]

SHEET_ID = os.getenv("SHEET_ID")
SHEETS_TAB = os.getenv("SHEETS_TAB", "Staff Matrix")

def _get_gc():
    raw = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")
    if raw.strip().startswith("{"):
        import json, tempfile
        data = json.loads(raw)
        # create temp file for gspread
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(json.dumps(data).encode("utf-8"))
        tf.flush()
        json_path = tf.name
    else:
        # treat as path mounted in filesystem
        json_path = raw or "/etc/secrets/google_sa.json"

    creds = Credentials.from_service_account_file(json_path, scopes=SCOPES)
    return gspread.authorize(creds)

def _event_header(ev) -> str:
    # Header text that keys the event column
    # ex: 2025-11-11 — Atlantic City
    d = ev.date.strftime("%Y-%m-%d") if ev.date else "TBD"
    city = ev.city or "Event"
    return f"{d} — {city}"

def _parse_header_date(header: str) -> datetime:
    # Expected header: "YYYY-MM-DD — City"
    # Fallback: put at end if parse fails
    try:
        dpart = header.split("—", 1)[0].strip()
        return datetime.strptime(dpart, "%Y-%m-%d")
    except Exception:
        # large value so it sorts to end
        return datetime(9999, 12, 31)

def sync_assignments_sheet(db, only_event_id=None):
    """Append/update a single event column in place, keep other columns.
       Assumes rows=positions, columns=events (by header).
    """
    if not SHEET_ID:
        return  # quietly skip if not configured

    from models import Event, Assignment, Position, Person

    gc = _get_gc()
    sh = gc.open_by_key(SHEET_ID)
    try:
        ws = sh.worksheet(SHEETS_TAB)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=SHEETS_TAB, rows=100, cols=26)

    # Ensure basic skeleton: A1 = "Position"
    values = ws.get_all_values()
    if not values:
        values = [["Position"]]  # header row
        ws.update("A1", values)

    # Ensure first cell header
    if values and (not values[0] or values[0][0] != "Position"):
        # Put "Position" at A1, keep rest
        ws.update("A1", [["Position"]])

    # Build current header list from row 1
    values = ws.get_all_values()  # reload after any update
    header = values[0] if values else ["Position"]
    # header[0] = "Position", header[1:] are event columns
    # Map: header title -> column index (1-based)
    header_map = {h: idx+1 for idx, h in enumerate(header) if h}

    # Pull the event we need to sync
    if only_event_id is None:
        return  # nothing to do
    ev = db.get(Event, int(only_event_id))
    if not ev:
        return

    # Compute header text & target col
    target_header = _event_header(ev)
    target_date = _parse_header_date(target_header)

    # Ensure all positions in the sheet include those used by assignments
    # Build set of sheet positions (column A)
    values = ws.get_all_values()
    colA = [row[0] if row else "" for row in values]  # includes header "Position"
    sheet_positions = set([p.strip() for p in colA[1:] if p.strip()])

    # Pull the assignments for this event
    assigns = (
        db.query(Assignment)
          .join(Position, Position.id == Assignment.position_id)
          .join(Person, Person.id == Assignment.person_id)
          .filter(Assignment.event_id == ev.id)
          .all()
    )

    # Positions we must at least have
    needed_positions = set()
    for a in assigns:
        if a.position and a.position.name:
            needed_positions.add(a.position.name.strip())

    # Insert missing position rows at the bottom
    add_rows = []
    for pname in sorted(needed_positions):
        if pname not in sheet_positions:
            add_rows.append([pname])
    if add_rows:
        # append below existing
        ws.add_rows(len(add_rows))
        start_row = len(colA) + 1  # next empty row index
        ws.update(f"A{start_row}", add_rows)
        # refresh values
        values = ws.get_all_values()
        colA = [row[0] if row else "" for row in values]
        sheet_positions = set([p.strip() for p in colA[1:] if p.strip()])

    # Build (position -> row index) map (rows start at 2)
    pos_to_row = {}
    for ridx in range(1, len(colA)):  # skip header row (index 0)
        nm = colA[ridx].strip()
        if nm:
            pos_to_row[nm] = ridx + 1  # 1-based row number

    # Determine if header already exists
    if target_header in header_map:
        target_col = header_map[target_header]  # 1-based
    else:
        # Find correct insertion index by date order among existing headers
        # Collect (col_index, header_text, parsed_date) for existing event headers
        existing = []
        for idx, htext in enumerate(header[1:], start=2):  # columns B..end
            if not htext:
                continue
            existing.append((idx, htext, _parse_header_date(htext)))

        # Find insertion column (so that dates ascending left->right)
        insert_at = len(header) + 1  # default append to end
        for idx, htext, hdate in existing:
            if target_date < hdate:
                insert_at = idx
                break

        # Insert new blank column at insert_at
        ws.add_cols(1)  # ensure capacity
        ws.insert_cols([[""]], insert_at)  # gspread allows a single column inserted

        # Write the header text
        ws.update_cell(1, insert_at, target_header)
        target_col = insert_at

        # Refresh header_map for future operations
        values = ws.get_all_values()
        header = values[0]
        header_map = {h: i+1 for i, h in enumerate(header) if h}

    # Now write the column cells for this event
    # Build a write list with row->value (name of person assigned to that position)
    # If multiple assignments per position somehow exist, last one wins.
    col_updates = {}
    for a in assigns:
        if not (a.position and a.person):
            continue
        pname = a.position.name.strip()
        row = pos_to_row.get(pname)
        if row:
            col_updates[row] = a.person.name or ""

    # Make sure the sheet has enough rows
    last_needed_row = max(col_updates.keys(), default=2)
    if ws.row_count < last_needed_row:
        ws.add_rows(last_needed_row - ws.row_count)

    # Prepare a vertical range update in a single request
    # We’ll collect consecutive ranges to minimize API calls
    # But simplest (and fine for < few hundred rows): update per cell
    # To be kinder, do it in one range if dense
    if col_updates:
        # Build a contiguous block starting at row 2 to max row we touch
        start_row = 2
        end_row = max(last_needed_row, start_row)
        block = []
        for r in range(start_row, end_row + 1):
            block.append([col_updates.get(r, "")])
        # e.g., "C2:C50"
        col_letter = gspread.utils.rowcol_to_a1(1, target_col)[0:1]  # crude but works for up to Z
        # Better: compute A1 for start and end precisely
        start_a1 = gspread.utils.rowcol_to_a1(start_row, target_col)
        end_a1 = gspread.utils.rowcol_to_a1(end_row, target_col)
        ws.update(f"{start_a1}:{end_a1}", block)

    # Done
    return
