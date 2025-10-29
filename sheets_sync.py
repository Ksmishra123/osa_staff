# sheets_sync.py
import os
from datetime import datetime, date, timedelta
from typing import List, Dict, Optional, Tuple

import gspread
from google.oauth2.service_account import Credentials

# ============ CONFIG ============
GOOGLE_SA_JSON = os.getenv("GOOGLE_CREDENTIALS_JSON", "/data/google_service_account.json")
SHEET_ID       = os.getenv("GOOGLE_SHEET_ID", "")
TAB_NAME       = os.getenv("GOOGLE_SHEET_TAB", "Assignments")

HEADERS = [
    "Locations", "Dates", "OSA Rep", "Announcer", "Extra Person / Gopher",
    "Backstage Manager", "Trophies", "Judge 1", "Judge 2", "Judge 3",
    "Clothes Vendor", "GAP", "Hotel"
]

# Map your Position names -> target sheet columns
# Edit keys here to match EXACT Position.name values in your DB.
POSITION_TO_COL = {
    "Director": "OSA Rep",
    "OSA Rep": "OSA Rep",
    "Emcee": "Announcer",
    "Announcer": "Announcer",
    "Extra hand": "Extra Person / Gopher",
    "Gopher": "Extra Person / Gopher",
    "Backstage": "Backstage Manager",
    "Backstage Manager": "Backstage Manager",
    "Trophies": "Trophies",
    "Clothes Vendor": "Clothes Vendor",
    "GAP": "GAP",
    "Judge 1": "Judge 1",
    "Judge 2": "Judge 2",
    "Judge 3": "Judge 3",
    # If you have a generic "Judge" position, it will be auto-slotted into the first empty of Judge1-3.
    "Judge": "JUDGES_AUTO",
}

# Colors for zebra striping (0..1 floats)
ROW_EVEN_BG = {"red": 0.98, "green": 0.98, "blue": 0.98}
ROW_ODD_BG  = {"red": 1.00, "green": 1.00, "blue": 1.00}
HEADER_BG   = {"red": 0.88, "green": 0.88, "blue": 0.88}

# ============ GOOGLE HELPERS ============
def _gc():
    scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
    creds = Credentials.from_service_account_file(GOOGLE_SA_JSON, scopes=scopes)
    return gspread.authorize(creds)

def _open_ws():
    if not SHEET_ID:
        raise RuntimeError("GOOGLE_SHEET_ID is not set.")
    sh = _gc().open_by_key(SHEET_ID)
    try:
        ws = sh.worksheet(TAB_NAME)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=TAB_NAME, rows=200, cols=len(HEADERS) + 20)
    return ws

def _ensure_header(ws):
    current = ws.row_values(1)
    if current != HEADERS:
        # replace the entire header row
        ws.update("A1", [HEADERS], value_input_option="USER_ENTERED")
        try:
            ws.format(f"A1:{gspread.utils.rowcol_to_a1(1, len(HEADERS))}", {
                "backgroundColor": HEADER_BG,
                "textFormat": {"bold": True}
            })
            ws.freeze(rows=1, cols=1)
        except Exception:
            pass

def _col_index(header: str) -> int:
    return HEADERS.index(header) + 1  # 1-based

# ============ DATE FORMATTING ============
def _best_event_datestr(ev, db) -> Tuple[datetime, str]:
    """
    Returns (sort_key_date, display_text).
    - sort_key_date: the event's start date (for row sorting)
    - display_text: like "Feb 7-9, 2025" or "November 11, 2025" or "2025-11-11"
    Uses EventDay range if available; else falls back to ev.date/event_start/event_end.
    """
    # Try EventDay
    try:
        from models import EventDay
        days = (db.query(EventDay)
                  .filter(EventDay.event_id == ev.id)
                  .order_by(EventDay.start_dt.asc())
                  .all())
    except Exception:
        days = []

    def fmt_mmm_d(dt: date) -> str:
        return dt.strftime("%b %-d, %Y") if hasattr(dt, "strftime") else ""

    def fmt_range(sd: date, ed: date) -> str:
        if sd.year == ed.year and sd.month == ed.month:
            # "Feb 7-9, 2025"
            return f"{sd.strftime('%b')} {sd.day}-{ed.day}, {sd.year}"
        elif sd.year == ed.year:
            # "Feb 28 - Mar 2, 2025"
            return f"{sd.strftime('%b %d')} - {ed.strftime('%b %d')}, {sd.year}"
        else:
            # cross-year
            return f"{fmt_mmm_d(sd)} - {fmt_mmm_d(ed)}"

    if days:
        sd = days[0].start_dt.date()
        ed = days[-1].start_dt.date()
        return (datetime(sd.year, sd.month, sd.day), fmt_range(sd, ed))

    # Fallbacks
    dt_candidates = [ev.date, ev.event_start, ev.setup_start, ev.event_end]
    dt_candidates = [d for d in dt_candidates if d]
    dt_candidates.sort()
    if dt_candidates:
        start = dt_candidates[0]
        end   = dt_candidates[-1]
        sd = start.date() if hasattr(start, "date") else start
        ed = end.date() if hasattr(end, "date") else end
        disp = fmt_range(sd, ed) if ed != sd else start.strftime("%b %-d, %Y")
        return (datetime(sd.year, sd.month, sd.day), disp)

    # Last resort: now
    now = datetime.utcnow()
    return (datetime(now.year, now.month, now.day), now.strftime("%b %-d, %Y"))

# ============ ROW OPS ============
def _existing_rows(ws) -> List[List[str]]:
    return ws.get_all_values()

def _find_row_by_city(values: List[List[str]], city: str) -> Optional[int]:
    # Assumes "Locations" is column A
    for r_idx in range(2, len(values) + 1):
        row = values[r_idx - 1]
        if not row:
            continue
        loc = row[0] if len(row) > 0 else ""
        if loc.strip().lower() == (city or "").strip().lower():
            return r_idx
    return None

def _insert_row_at(ws, r_index: int, values: List[str]):
    ws.insert_row(values, r_index, value_input_option="USER_ENTERED")

def _update_row(ws, r_index: int, values: List[str]):
    rng = f"A{r_index}:{gspread.utils.rowcol_to_a1(r_index, len(HEADERS))}"
    ws.update(rng, [values], value_input_option="USER_ENTERED")

def _apply_zebra(ws):
    vals = ws.get_all_values()
    if len(vals) <= 1:
        return
    # Format body (rows 2..N)
    requests = []
    start_col = 1
    end_col = len(HEADERS)
    for r in range(2, len(vals) + 1):
        color = ROW_EVEN_BG if (r % 2 == 0) else ROW_ODD_BG
        requests.append({
            "repeatCell": {
                "range": {
                    "sheetId": ws.id,
                    "startRowIndex": r - 1,
                    "endRowIndex": r,
                    "startColumnIndex": start_col - 1,
                    "endColumnIndex": end_col
                },
                "cell": {"userEnteredFormat": {"backgroundColor": color}},
                "fields": "userEnteredFormat.backgroundColor"
            }
        })
    try:
        ws.spreadsheet.batch_update({"requests": requests})
    except Exception:
        pass

# ============ PUBLIC ENTRY ============
def sync_assignments_sheet(db, only_event_id: Optional[int] = None, rows_for_event=None, event=None):
    """
    Upsert a single row per event (city). Columns fixed per HEADERS.
    - Keeps rows sorted by start date.
    - Updates only the relevant row (no wiping).
    - Alternating row colors for readability.
    Call this after you commit assignments in /admin/events/<eid>/assign.
    """
    if not SHEET_ID or not os.path.exists(GOOGLE_SA_JSON):
        return  # not configured, silently skip

    ws = _open_ws()
    _ensure_header(ws)

    if not event or rows_for_event is None:
        return

    # Build row dict
    sort_key, datestr = _best_event_datestr(event, db)
    row_dict = {h: "" for h in HEADERS}
    row_dict["Locations"] = event.city or ""
    row_dict["Dates"]     = datestr
    row_dict["Hotel"]     = getattr(event, "hotel", "") or ""

    # Judges auto-fill helper
    judge_cols = ["Judge 1", "Judge 2", "Judge 3"]

    def _place_judge(name: str):
        for c in judge_cols:
            if not row_dict[c]:
                row_dict[c] = name
                return

    # Fill people into columns based on POSITION_TO_COL
    for a in (rows_for_event or []):
        pos = (a.position.name if a.position else "") or ""
        per = (a.person.name if a.person else "") or ""
        if not pos or not per:
            continue
        target = POSITION_TO_COL.get(pos, None)
        if target == "JUDGES_AUTO":
            _place_judge(per)
        elif target and target in row_dict:
            row_dict[target] = per
        else:
            # unknown position -> try naive judge auto if name startswith 'Judge'
            if pos.lower().startswith("judge"):
                _place_judge(per)

    # Compose row values in header order
    new_row_values = [row_dict[h] for h in HEADERS]

    # Fetch sheet, find existing row by city, else we will insert
    values = _existing_rows(ws)
    existing_row = _find_row_by_city(values, row_dict["Locations"])

    if existing_row:
        # Update existing row in place first
        _update_row(ws, existing_row, new_row_values)
        # Then re-sort all rows by "Dates" using parsed sort_key:
        # We'll rebuild all rows with a sortable hidden key.
        body = values[1:]  # rows after header
        # Replace that row in memory too for sorting
        body[existing_row - 2] = new_row_values
    else:
        # Insert at bottom first
        _insert_row_at(ws, len(values) + 1, new_row_values)
        # Re-read body to sort
        values = _existing_rows(ws)
        body = values[1:]

    # Sort rows by computed start date
    # We recompute a sorting key per row using the first date in "Dates".
    def parse_datestr(s: str) -> datetime:
        # Try formats like "Feb 7-9, 2025", "November 11, 2025", "2025-11-11"
        s = (s or "").strip()
        # If it's a range with comma year at end, take first token up to comma
        # Extract first month/day/year occurrence
        fmts = ["%b %d, %Y", "%B %d, %Y", "%Y-%m-%d"]
        guess = s
        if "-" in s and "," in s:
            # "Mar 7-9, 2025" -> "Mar 7, 2025"
            left = s.split("-", 1)[0].strip()
            year = s.split(",")[-1].strip()
            # if left like "Mar 7"
            if any(m in left for m in ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]) or len(left.split())==2:
                guess = f"{left}, {year}"
        for f in fmts:
            try:
                return datetime.strptime(guess, f)
            except Exception:
                continue
        # fallback now
        return datetime.utcnow()

    # Build list of (parsed_date, row_values)
    rows_with_keys: List[Tuple[datetime, List[str]]] = []
    for r in body:
        # pad to HEADERS length
        r = (r + [""] * len(HEADERS))[:len(HEADERS)]
        d = parse_datestr(r[1])  # Dates is column B (index 1)
        rows_with_keys.append((d, r))

    rows_with_keys.sort(key=lambda x: x[0])

    # Write back the sorted body
    if rows_with_keys:
        sorted_vals = [rwk[1] for rwk in rows_with_keys]
        ws.update(f"A2:{gspread.utils.rowcol_to_a1(1 + len(sorted_vals), len(HEADERS))}",
                  sorted_vals, value_input_option="USER_ENTERED")

    # Apply zebra striping
    _apply_zebra(ws)
