# sheets_sync.py
import os
from datetime import datetime

def _get_gspread_client():
    import gspread
    from google.oauth2.service_account import Credentials
    import json

    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]

    json_path = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")
    json_inline = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")

    if json_path and os.path.exists(json_path):
        creds = Credentials.from_service_account_file(json_path, scopes=scopes)
    elif json_inline:
        creds = Credentials.from_service_account_info(json.loads(json_inline), scopes=scopes)
    else:
        raise RuntimeError("Missing Google service account credentials.")

    return gspread.authorize(creds)

def sync_assignments_sheet(db, only_event_id=None):
    """Writes events as rows, positions as columns."""
    from models import Event, Position, Assignment, Person

    spreadsheet_id = os.getenv("SHEETS_SPREADSHEET_ID")
    worksheet_title = os.getenv("SHEETS_WORKSHEET", "Assignments")
    if not spreadsheet_id:
        raise RuntimeError("SHEETS_SPREADSHEET_ID not set.")

    gc = _get_gspread_client()
    sh = gc.open_by_key(spreadsheet_id)
    try:
        ws = sh.worksheet(worksheet_title)
    except Exception:
        ws = sh.add_worksheet(title=worksheet_title, rows=500, cols=50)

    # Gather data
    positions = db.query(Position).order_by(Position.display_order.asc()).all()
    events_q = db.query(Event).order_by(Event.date.asc())
    if only_event_id:
        events_q = events_q.filter(Event.id == only_event_id)
    events = events_q.all()

    # Build header row
    header = ["Date", "City"] + [p.name for p in positions]

    # Build rows for each event
    rows = []
    for ev in events:
        date_str = ev.date.strftime("%Y-%m-%d") if ev.date else ""
        city = ev.city or ""
        name_map = {}
        assigns = db.query(Assignment).filter(Assignment.event_id == ev.id).all()
        for a in assigns:
            if a.person_id:
                person = db.get(Person, a.person_id)
                name_map[a.position_id] = person.name if person else ""
        row = [date_str, city] + [name_map.get(p.id, "") for p in positions]
        rows.append(row)

    # Clear and write new data
    ws.clear()
    ws.update("A1", [header] + rows)

    # Format header row
    try:
        fmt = {
            "textFormat": {"bold": True, "fontSize": 12},
            "horizontalAlignment": "CENTER",
        }
        ws.format("1:1", fmt)
        ws.format("A:A", {"textFormat": {"bold": True}})
        ws.format("B:B", {"textFormat": {"bold": True}})
        ws.freeze(rows=1)
    except Exception as e:
        print("Formatting skipped:", e)
