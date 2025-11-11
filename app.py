import os
import re
import threading
import bcrypt
from flask import make_response

from datetime import datetime, date, timedelta

from flask import (
    Flask, render_template, redirect, url_for, request, flash, abort,
    send_from_directory, current_app, send_file
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from sqlalchemy.orm import joinedload, aliased
from sqlalchemy.exc import SQLAlchemyError
from models import (
    init_db, SessionLocal,
    Person, Event, Position, Assignment,
    Hotel, Room, Roommate, EventDay, Attachment
)

# ReportLab for PDFs
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch

# Optional email (SendGrid)
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret')

# Bind DB and create tables at startup (important under gunicorn)
init_db()

# -----------------------------------------------------------------------------
# Uploads config (headshots)
# -----------------------------------------------------------------------------
UPLOAD_ATTACHMENTS_DIR = os.path.join(os.getcwd(), 'uploads', 'attachments')
os.makedirs(UPLOAD_ATTACHMENTS_DIR, exist_ok=True)

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/data/uploads")
ALLOWED_HEADSHOT_EXTS = {"png", "jpg", "jpeg", "gif"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

def allowed_headshot(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_HEADSHOT_EXTS

# -----------------------------------------------------------------------------
# Auth setup
# -----------------------------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, person: Person):
        self.id = str(person.id)
        self.person = person

@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    person = db.get(Person, int(user_id))
    db.close()
    return User(person) if person else None

@app.teardown_appcontext
def remove_session(exc=None):
    SessionLocal.remove()

@app.context_processor
def inject_nav_flags():
    # exposes a boolean you can use in templates
    return {"has_register": 'register' in app.view_functions}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def truthy(v) -> bool:
    return str(v).strip().lower() in ('1', 'true', 'on', 'yes')

def normalize_phone(raw: str) -> str | None:
    if not raw:
        return None
    s = str(raw).strip()
    digits = re.sub(r"\D", "", s)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10:
        return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    return s

def parse_dt(v: str):
    """Accepts HTML datetime-local (YYYY-MM-DDTHH:MM) or 'YYYY-MM-DD HH:MM'. Empty -> None."""
    if not v:
        return None
    v = v.strip()
    try:
        if "T" in v:
            return datetime.fromisoformat(v)
        return datetime.strptime(v, "%Y-%m-%d %H:%M")
    except Exception:
        return None

def is_admin() -> bool:
    try:
        if not current_user.is_authenticated or not getattr(current_user, "person", None):
            return False
        # role-based admin
        if (current_user.person.role or '').lower() == 'admin':
            return True
        # legacy: also allow the configured ADMIN_EMAIL
        admin_email = (os.getenv('ADMIN_EMAIL', 'admin@example.com') or '').strip().lower()
        return (current_user.person.email or '').strip().lower() == admin_email
    except Exception:
        return False

def is_viewer() -> bool:
    try:
        return (
            current_user.is_authenticated and
            getattr(current_user, "person", None) is not None and
            (current_user.person.role or '').lower() == 'viewer'
        )
    except Exception:
        return False


# Expose helpers in templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

@app.context_processor
def inject_helpers():
    return {"is_admin": is_admin, "is_viewer": is_viewer}

@app.template_filter('dt_long')  # e.g., November 11, 2025 - 4:00 PM
def dt_long(v):
    if not v:
        return ''
    # Linux/Render supports %-d / %-I; on Windows use %#d / %#I
    return v.strftime('%B %-d, %Y - %-I:%M %p')

@app.template_filter('t_short')  # e.g., 4:00 PM
def t_short(v):
    if not v:
        return ''
    return v.strftime('%-I:%M %p')

@app.template_filter('datetime_local')
def datetime_local(v):
    """Format a datetime for <input type='datetime-local'> (YYYY-MM-DDTHH:MM)."""
    if not v:
        return ''
    return v.strftime('%Y-%m-%dT%H:%M')
    
@app.context_processor
def inject_helpers():
    return {"is_admin": is_admin}

# -----------------------------------------------------------------------------
# Email helper (async via SendGrid)
# -----------------------------------------------------------------------------

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from jinja2 import TemplateNotFound

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@onstageamerica.com")

def send_email_async(to_email: str, subject: str, html: str) -> bool:
    """
    Fire-and-forget email via SendGrid in a thread.
    Returns True if the send was scheduled, False if we skipped due to config.
    Any SendGrid errors are logged.
    """
    if not SENDGRID_API_KEY:
        app.logger.error("SENDGRID_API_KEY is not set; skipping email send.")
        return False
    if not to_email:
        app.logger.error("No recipient email; skipping email send.")
        return False

    def _send():
        try:
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            msg = Mail(from_email=FROM_EMAIL, to_emails=to_email, subject=subject, html_content=html)
            sg.send(msg)
            app.logger.info(f"✔ Assignment email sent to {to_email}")
        except Exception:
            app.logger.exception(f"Email send failed for {to_email}")

    import threading
    threading.Thread(target=_send, daemon=True).start()
    return True
# --- Google Sheets sync helpers ---------------------------------------------
import json
import gspread
from google.oauth2.service_account import Credentials

def _get_gspread_client():
    sa_json = os.getenv("GOOGLE_SA_JSON", "")
    if not sa_json:
        return None
    try:
        info = json.loads(sa_json)
        scopes = ["https://www.googleapis.com/auth/spreadsheets"]
        creds = Credentials.from_service_account_info(info, scopes=scopes)
        return gspread.authorize(creds)
    except Exception:
        app.logger.exception("Failed to build gspread client")
        return None

def _event_col_title(ev: Event) -> str:
    if ev.date:
        return f"{ev.date.strftime('%Y-%m-%d')} — {ev.city}"
    return f"{ev.city or 'Event'}"

def sync_assignments_sheet(db, only_event_id: int | None = None):
    """
    Sheet layout:
      Row 1: ["Position", <event1>, <event2>, ...]
      Subsequent rows: one row per Position (display_order asc),
                       cells filled with assigned person's name per event.
    If only_event_id is provided, we re-sync headers & that event's column.
    Otherwise we sync all future events (today or later).
    """
    sheet_id = os.getenv("ASSIGN_SHEET_ID", "")
    if not sheet_id:
        return  # silently skip if not configured

    gc = _get_gspread_client()
    if not gc:
        return

    try:
        sh = gc.open_by_key(sheet_id)
        try:
            ws = sh.worksheet("Assignments")
        except gspread.exceptions.WorksheetNotFound:
            ws = sh.add_worksheet(title="Assignments", rows=100, cols=26)
    except Exception:
        app.logger.exception("Unable to open/create Google Sheet")
        return

    # Positions (row headers)
    positions = db.query(Position).order_by(Position.display_order.asc()).all()
    pos_names = [p.name for p in positions]

    # Which events to consider
    ev_query = db.query(Event).order_by(Event.date.asc())
    if only_event_id:
        ev_query = ev_query.filter(Event.id == only_event_id)
    else:
        # default: future & today
        today = datetime.utcnow().date()
        ev_query = ev_query.filter(Event.date >= datetime(today.year, today.month, today.day))

    events = ev_query.all()
    if not events:
        # still make sure we at least have the Position column
        header = ["Position"]
        data = [[n] for n in pos_names] if pos_names else []
        # Resize and write
        ws.resize(rows=max(2, len(data) + 1), cols=len(header))
        ws.update("A1", [header] + data)
        return

    # Build a full header: Position + each event column
    headers = ["Position"] + [_event_col_title(ev) for ev in events]

    # Build a mapping: (pos_id, ev_id) -> person name (or "")
    # For efficiency, fetch all needed assignments at once.
    ev_ids = [ev.id for ev in events]
    assigns = (
        db.query(Assignment)
          .join(Position, Assignment.position_id == Position.id)
          .options(joinedload(Assignment.person), joinedload(Assignment.position))
          .filter(Assignment.event_id.in_(ev_ids))
          .all()
    )
    cell_map = {(a.position_id, a.event_id): (a.person.name if a.person else "") for a in assigns}

    # Table to write
    # First column = position names, subsequent columns = per-event person names
    table = []
    for p in positions:
        row = [p.name]
        for ev in events:
            row.append(cell_map.get((p.id, ev.id), ""))
        table.append(row)

    # Resize sheet to fit (a bit generous)
    ws.resize(rows=len(table) + 5, cols=len(headers) + 2)

    # Write header row
    ws.update("A1", [headers])

    # Write the body (positions + cells)
    if table:
        ws.update("A2", table)


# -----------------------------------------------------------------------------
# Static uploads (secured)
# -----------------------------------------------------------------------------
@app.route("/uploads/<path:fname>")
@login_required
def uploaded_file(fname):
    # Only admin or the owner can view a headshot
    if not is_admin():
        if not current_user.person or not current_user.person.headshot_path:
            abort(403)
        myfn = current_user.person.headshot_path.split("/")[-1]
        if fname != myfn:
            abort(403)
    return send_from_directory(UPLOAD_DIR, fname)

# -----------------------------------------------------------------------------
# Maintenance / init route (optional)
# -----------------------------------------------------------------------------
@app.route('/init')
def init():
    init_db()
    return "DB initialized. Run: python seed.py", 200

# -----------------------------------------------------------------------------
# Auth routes
# -----------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    db = SessionLocal()
    if request.method == 'POST':
        try:
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            p = db.query(Person).filter(Person.email == email).first()
            if not p:
                flash('No user with that email.')
                return redirect(url_for('login'))
            if not p.password_hash:
                # first-time set
                p.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                db.commit()
            if bcrypt.checkpw(password.encode(), p.password_hash.encode()):
                login_user(User(p))
                flash('Logged in.')
                return redirect(url_for('me'))
            flash('Invalid password.')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.exception("Login failed")
            return f"Login error: {type(e).__name__}: {e}", 500
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# -----------------------------------------------------------------------------
# Admin: Event Days (multi-day schedule)
# -----------------------------------------------------------------------------
@app.route('/admin/events/<int:eid>/days', methods=['GET', 'POST'])
@login_required
def admin_event_days(eid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    def parse_iso(s):
        try:
            return datetime.fromisoformat(s) if s else None
        except Exception:
            return None

    if request.method == 'POST':
        action = request.form.get('action')

        # --- Add new day ---
        if action == 'add_day':
            start_dt = parse_iso(request.form.get('start_dt'))
            setup_dt = parse_iso(request.form.get('setup_dt'))
            staff_arrival_dt = parse_iso(request.form.get('staff_arrival_dt'))
            judges_arrival_dt = parse_iso(request.form.get('judges_arrival_dt'))
            day_date = start_dt.date() if start_dt else None
            setup_only = bool(request.form.get('setup_only'))

            if not start_dt:
                flash("Start date/time is required for a day.")
            else:
                d = EventDay(
                    event_id=eid,
                    day_date=day_date,
                    start_dt=start_dt,
                    setup_dt=setup_dt,
                    staff_arrival_dt=staff_arrival_dt,
                    judges_arrival_dt=judges_arrival_dt,
                    setup_only=setup_only,
                    notes=(request.form.get('notes') or '').strip()
                )
                db.add(d)
                db.commit()
                flash("Day added.")

        # --- Edit existing day ---
        elif action == 'edit_day':
            did = int(request.form.get('day_id') or 0)
            d = db.get(EventDay, did)
            if d and d.event_id == eid:
                d.start_dt = parse_iso(request.form.get('start_dt'))
                d.setup_dt = parse_iso(request.form.get('setup_dt'))
                d.staff_arrival_dt = parse_iso(request.form.get('staff_arrival_dt'))
                d.judges_arrival_dt = parse_iso(request.form.get('judges_arrival_dt'))
                d.day_date = d.start_dt.date() if d.start_dt else d.day_date
                d.notes = (request.form.get('notes') or '').strip()
                d.setup_only = bool(request.form.get('setup_only'))
                db.commit()
                flash("Day updated.")
            else:
                flash("Invalid day selected for edit.")

        # --- Delete ---
        elif action == 'delete_day':
            did = int(request.form.get('day_id') or 0)
            if did:
                db.query(EventDay).filter(
                    EventDay.id == did,
                    EventDay.event_id == eid
                ).delete()
                db.commit()
                flash("Day removed.")

        return redirect(url_for('admin_event_days', eid=eid))

    # --- GET ---
    days = (
        db.query(EventDay)
        .filter(EventDay.event_id == eid)
        .order_by(EventDay.start_dt.asc())
        .all()
    )
    return render_template('event_days.html', ev=ev, days=days)


# -----------------------------------------------------------------------------
# Register (enhanced profile + headshot)
# -----------------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    db = SessionLocal()
    if request.method == 'POST':
        try:
            form = request.form
            name = (form.get('name') or '').strip()
            email = (form.get('email') or '').strip().lower()
            password = form.get('password') or ''
            confirm  = form.get('confirm') or ''
            
            phone = normalize_phone(form.get('phone',''))
            address = (form.get('address') or '').strip()
            preferred_airport = (form.get('preferred_airport') or '').strip()
            willing_to_drive = (form.get('willing_to_drive') == 'yes')
            car_or_rental = (form.get('car_or_rental') or '').strip() if willing_to_drive else None
            dietary_preference = (form.get('dietary_preference') or '').strip()

            # DOB (from <input type="date">). Accept empty.
            dob = None
            dob_str = (form.get('dob') or '').strip()
            if dob_str:
                try:
                    dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
                except Exception:
                    flash("Could not parse Date of Birth (use YYYY-MM-DD).")

            errors = []
            if not name: errors.append("Name is required.")
            if not email: errors.append("Email is required.")
            if not password: errors.append("Password is required.")
            if password != confirm: errors.append("Passwords do not match.")
            if db.query(Person).filter(Person.email == email).first():
                errors.append("An account with that email already exists. Try logging in.")

            # Optional headshot upload
            headshot_path = None
            file = request.files.get('headshot')
            if file and file.filename:
                if not allowed_headshot(file.filename):
                    errors.append("Headshot must be an image (png, jpg, jpeg, gif).")
                else:
                    os.makedirs(UPLOAD_DIR, exist_ok=True)
                    fname = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
                    file.save(os.path.join(UPLOAD_DIR, fname))
                    headshot_path = f"/uploads/{fname}"

            bio = (form.get('bio') or '').strip()  # keep it, saved below

            if errors:
                for e in errors: flash(e)
                return render_template('register.html', form=form)

            phash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            person = Person(
                name=name, email=email, password_hash=phash,
                phone=phone, address=address, preferred_airport=preferred_airport,
                willing_to_drive=willing_to_drive, car_or_rental=car_or_rental,
                dietary_preference=dietary_preference, dob=dob,
                headshot_path=headshot_path, bio=bio
            )
            db.add(person); db.commit()

            login_user(User(person))
            flash('Account created. Welcome!')
            return redirect(url_for('me'))

        except Exception as e:
            app.logger.exception("Register failed")
            return f"Register error: {type(e).__name__}: {e}", 500

    return render_template('register.html', form={})

# -----------------------------------------------------------------------------
# Update Profile
# -----------------------------------------------------------------------------
@app.route('/account/profile', methods=['GET', 'POST'])
@login_required
def account_profile():
    db = SessionLocal()
    p = db.get(Person, int(current_user.id))
    if not p:
        abort(404)

    if request.method == 'POST':
        form = request.form

        # Basic fields
        p.name = form.get('name','').strip() or p.name
        new_email = form.get('email','').strip().lower()
        p.phone = normalize_phone(form.get('phone',''))
        p.address = form.get('address','').strip()
        p.preferred_airport = form.get('preferred_airport','').strip()
        p.willing_to_drive = (form.get('willing_to_drive') == 'yes')
        p.car_or_rental = form.get('car_or_rental','').strip() if p.willing_to_drive else None
        p.dietary_preference = form.get('dietary_preference','').strip()
        p.bio = form.get('bio','').strip()

        # DOB
        dob_str = form.get('dob','').strip()
        if dob_str:
            try:
                p.dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
            except Exception:
                flash("Could not parse Date of Birth (use YYYY-MM-DD).")

        # Email change (ensure uniqueness)
        if new_email and new_email != p.email:
            if db.query(Person).filter(Person.email == new_email).first():
                flash("That email is already in use by another account.")
                return render_template('profile.html', person=p)
            p.email = new_email

        # Headshot removal
        if form.get('remove_headshot') == 'on' and p.headshot_path:
            try:
                old_fn = p.headshot_path.split('/')[-1]
                old_abs = os.path.join(UPLOAD_DIR, old_fn)
                if os.path.exists(old_abs):
                    os.remove(old_abs)
            except Exception:
                pass
            p.headshot_path = None

        # New headshot upload
        file = request.files.get('headshot')
        if file and file.filename:
            if not allowed_headshot(file.filename):
                flash("Headshot must be an image (png, jpg, jpeg, gif).")
                return render_template('profile.html', person=p)
            # remove old file if present
            if p.headshot_path:
                try:
                    old_fn = p.headshot_path.split('/')[-1]
                    old_abs = os.path.join(UPLOAD_DIR, old_fn)
                    if os.path.exists(old_abs):
                        os.remove(old_abs)
                except Exception:
                    pass
            fname = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
            file.save(os.path.join(UPLOAD_DIR, fname))
            p.headshot_path = f"/uploads/{fname}"

        db.commit()
        flash("Profile updated.")
        return redirect(url_for('account_profile'))

    # GET
    return render_template('profile.html', person=p)

# -----------------------------------------------------------------------------
# Change password
# -----------------------------------------------------------------------------
@app.route('/account/password', methods=['GET','POST'])
@login_required
def change_password():
    db = SessionLocal()
    if request.method == 'POST':
        current = request.form.get('current','')
        new = request.form.get('new','')
        confirm = request.form.get('confirm','')

        p = db.get(Person, int(current_user.id))
        errors = []
        if not p:
            errors.append("User not found.")
        elif not p.password_hash or not bcrypt.checkpw(current.encode(), p.password_hash.encode()):
            errors.append("Current password is incorrect.")
        if not new:
            errors.append("New password cannot be empty.")
        if new != confirm:
            errors.append("New password and confirmation do not match.")

        if errors:
            for e in errors: flash(e)
            return render_template('change_password.html')

        p.password_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
        db.commit()
        flash("Password updated.")
        return redirect(url_for('me'))

    return render_template('change_password.html')

# -----------------------------------------------------------------------------
# Basic routes
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('me'))
    return redirect(url_for('login'))

from datetime import datetime, timedelta
...
@app.route('/me')
@login_required
def me():
    db = SessionLocal()
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    Ev = aliased(Event)
    Pos = aliased(Position)

    rows = (db.query(Assignment)
              .join(Ev, Assignment.event_id == Ev.id)
              .join(Pos, Assignment.position_id == Pos.id)
              .options(joinedload(Assignment.event), joinedload(Assignment.position))
              .filter(Assignment.person_id == int(current_user.id),
                      Ev.date != None)
              .order_by(Ev.date.asc(), Pos.display_order.asc())
              .all())

    # --- NEW: stamp seen_at the first time the user loads /me ---
    now = datetime.utcnow()
    any_updates = False
    for a in rows:
        if a.seen_at is None:
            a.seen_at = now
            any_updates = True
    if any_updates:
        db.commit()

    # Lodging for future events only
    user_lodging = (
        db.query(Room, Hotel, Event)
          .join(Hotel, Room.hotel_id == Hotel.id)
          .join(Event, Hotel.event_id == Event.id)
          .join(Roommate, Roommate.room_id == Room.id)
          .filter(
              Roommate.person_id == int(current_user.id),
              Event.date != None,
              Event.date >= today
          )
          .all()
    )
    lodging_by_event = {}
    for room, hotel, ev in user_lodging:
        lodging_by_event.setdefault(ev.id, []).append({"hotel": hotel, "room": room})

    return render_template('me.html', rows=rows, lodging_by_event=lodging_by_event)
    
@app.route('/ack/<int:aid>', methods=['POST'])
@login_required
def ack(aid):
    db = SessionLocal()
    a = db.get(Assignment, aid)
    if not a or a.person_id != int(current_user.id):
        abort(403)
    a.ack = True
    a.ack_at = datetime.utcnow()         # NEW
    a.ack_ip = request.remote_addr or '' # NEW
    db.commit()
    flash('Acknowledged.')
    return redirect(url_for('me'))


# -----------------------------------------------------------------------------
# Admin: Events & Assignments
# -----------------------------------------------------------------------------
@app.route('/admin/events')
@login_required
def admin_events():
    if not is_admin():
        abort(403)
    db = SessionLocal()
    events = db.query(Event).order_by(Event.date.asc()).all()
    return render_template('events.html', events=events)

@app.route('/admin/events/new', methods=['GET', 'POST'])
@login_required
def admin_new_event():
    if not is_admin():
        abort(403)

    if request.method == 'POST':
        form = request.form

        city         = (form.get('city') or '').strip()
        date         = parse_dt(form.get('date'))
        setup_start  = parse_dt(form.get('setup_start'))
        event_start  = parse_dt(form.get('event_start'))
        event_end    = parse_dt(form.get('event_end'))
        venue        = (form.get('venue') or '').strip()
        hotel        = (form.get('hotel') or '').strip()

        # NEW/OPTIONAL FIELDS (make sure these columns exist on Event)
        call_sheet_published = bool(form.get('call_sheet_published'))
        coordinator_name  = (form.get('coordinator_name') or '').strip()
        coordinator_phone = normalize_phone(form.get('coordinator_phone') or '')
        dress_code        = (form.get('dress_code') or '').strip()
        notes             = (form.get('notes') or '').strip()

        errors = []
        if not city:
            errors.append("City is required.")
        if not date:
            errors.append("Main event date/time is required.")

        if errors:
            for e in errors:
                flash(e)
            # re-render the form with what the user typed
            return render_template(
                'new_event.html',
                ev=None,  # template can use ev? if it expects it
                form=form
            )

        db = SessionLocal()
        ev = Event(
            city=city,
            date=date,
            setup_start=setup_start,
            event_start=event_start,
            event_end=event_end,
            venue=venue,
            hotel=hotel,
            # optional fields:
            call_sheet_published=call_sheet_published,
            coordinator_name=coordinator_name,
            coordinator_phone=coordinator_phone,
            dress_code=dress_code,
            notes=notes,
            setup_only=setup_only,
        )
        db.add(ev)
        db.commit()
        flash('Event created.')
        return redirect(url_for('admin_events'))

    # GET
    return render_template('new_event.html', ev=None)

@app.route('/admin/events/<int:eid>/edit', methods=['GET','POST'])
@login_required
def admin_edit_event(eid):
    if not is_admin(): abort(403)
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev: abort(404)

    if request.method == 'POST':
        ev.city = (request.form.get('city') or '').strip()
        ev.date = parse_dt(request.form.get('date'))
        ev.setup_start = parse_dt(request.form.get('setup_start'))
        ev.event_start = parse_dt(request.form.get('event_start'))
        ev.event_end = parse_dt(request.form.get('event_end'))
        ev.venue = (request.form.get('venue') or '').strip()
        ev.hotel = (request.form.get('hotel') or '').strip()
        # Optional extra admin-only notes/dress code if you have those fields:
        ev.dress_code = (request.form.get('dress_code') or '').strip()
        ev.notes = (request.form.get('notes') or '').strip()
        ev.coordinator_name = (request.form.get('coordinator_name') or '').strip()
        ev.coordinator_phone = normalize_phone(request.form.get('coordinator_phone',''))
        ev.call_sheet_published = truthy(request.form.get('call_sheet_published'))
        ev.setup_only = ('setup_only' in request.form)
        
        db.commit()
     
        for day in ev.days:
            day.setup_only = (f"setup_only_{day.id}" in request.form)
        db.commit()

        flash('Event updated.')
        return redirect(url_for('admin_events'))

    return render_template('edit_event.html', ev=ev)

@app.route('/admin/events/<int:eid>/publish', methods=['POST'])
@login_required
def admin_toggle_publish(eid):
    if not is_admin(): abort(403)
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev: abort(404)
    ev.call_sheet_published = truthy(request.form.get('publish'))
    db.commit()
    flash('Call sheet ' + ('published.' if ev.call_sheet_published else 'unpublished.'))
    return redirect(url_for('admin_events'))

@app.route('/admin/events/<int:eid>/delete', methods=['POST'])
@login_required
def admin_delete_event(eid):
    if not is_admin(): abort(403)
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev: abort(404)
    # This cascades if you defined cascade on relationships; otherwise delete children first.
    db.delete(ev)
    db.commit()
    flash('Event deleted.')
    return redirect(url_for('admin_events'))

# ---------------------------------------------------------------------
# Admin: Assign people to positions for an event (with email + sheets)
# ---------------------------------------------------------------------
from sqlalchemy.orm import joinedload, aliased

@app.route('/admin/events/<int:eid>/assign', methods=['GET', 'POST'])
@login_required
def admin_assign(eid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    people = db.query(Person).order_by(Person.name.asc()).all()
    positions = db.query(Position).order_by(Position.display_order.asc()).all()

    # Load existing assignments for comparison
    existing = {
        a.position_id: a
        for a in db.query(Assignment)
                  .filter(Assignment.event_id == eid)
                  .all()
    }

    if request.method == 'POST':
        send_emails = (request.form.get('send_emails') == 'yes')
        changed_people = []

        for pos in positions:
            pid_raw = request.form.get(f'pos_{pos.id}')
            if not pid_raw:
                # if nothing selected, skip
                continue

            pid = int(pid_raw)
            mode = request.form.get(f'pos_{pos.id}_mode') or None
            booking = request.form.get(f'pos_{pos.id}_booking') or None
            arrival = parse_dt(request.form.get(f'pos_{pos.id}_arrival') or "")
            notes = request.form.get(f'pos_{pos.id}_notes') or None

            current = existing.get(pos.id)

            if current:
                # update only if something changed
                has_change = (
                    current.person_id != pid or
                    current.transport_mode != mode or
                    current.transport_booking != booking or
                    current.arrival_ts != arrival or
                    (current.transport_notes or '') != (notes or '')
                )
                if has_change:
                    current.person_id = pid
                    current.transport_mode = mode
                    current.transport_booking = booking
                    current.arrival_ts = arrival
                    current.transport_notes = notes
                    changed_people.append((pid, pos.name))
            else:
                # new assignment
                new_a = Assignment(
                    event_id=eid,
                    position_id=pos.id,
                    person_id=pid,
                    transport_mode=mode,
                    transport_booking=booking,
                    arrival_ts=arrival,
                    transport_notes=notes,
                )
                db.add(new_a)
                changed_people.append((pid, pos.name))

        # Check if any assignments were removed (someone unassigned)
        form_pos_ids = {int(k.split('_')[1]) for k in request.form.keys() if k.startswith('pos_') and not k.endswith(('_mode', '_booking', '_arrival', '_notes'))}
        removed = [pid for pid in existing.keys() if pid not in form_pos_ids]
        if removed:
            db.query(Assignment).filter(Assignment.event_id == eid, Assignment.position_id.in_(removed)).delete(synchronize_session=False)

        db.commit()

        # Send emails to only changed staff
        notified = 0
        if send_emails and changed_people:
            for pid, pos_name in changed_people:
                person = db.get(Person, pid)
                if person and person.email:
                    html = render_template(
                        'emails/assignment_notice.html',
                        person=person, ev=ev, position=pos_name
                    )
                    subject = f"Assignment Update: {ev.city or 'Event'} – {pos_name}"
                    send_email_async(person.email, subject, html)
                    notified += 1

        if send_emails:
            flash(f"Assignments saved. {notified} staff notified.")
        else:
            if changed_people:
                flash(f"Assignments saved. {len(changed_people)} change(s) detected, emails not sent (checkbox off).")
            else:
                flash("Assignments saved. No changes detected; no emails queued.")

        # Google Sheet sync
        try:
            from sheets_sync import sync_assignments_sheet
            rows_for_event = (
                db.query(Assignment)
                  .filter(Assignment.event_id == eid)
                  .options(joinedload(Assignment.person), joinedload(Assignment.position))
                  .all()
            )
            sync_assignments_sheet(db, only_event_id=eid, rows_for_event=rows_for_event, event=ev)
        except Exception:
            app.logger.exception("Sheets sync failed for event %s", eid)

        return redirect(url_for('admin_events'))

    # GET branch
    currents = existing
    return render_template('assign.html', ev=ev, people=people, positions=positions, current=currents)

# -----------------------------------------------------------------------------
# Admin: test route for email to see if it is working
# -----------------------------------------------------------------------------
@app.route('/admin/test-email')
@login_required
def admin_test_email():
    if not is_admin():
        abort(403)

    # quick config report (redacted)
    key_set = bool(os.getenv("SENDGRID_API_KEY"))
    from_email = os.getenv("FROM_EMAIL")
    to = request.args.get('to') or (current_user.person.email if current_user.is_authenticated else None)

    if not key_set or not from_email:
        return (
            "Email not queued — check SENDGRID_API_KEY / FROM_EMAIL on Render.<br>"
            f"SENDGRID_API_KEY set? {'yes' if key_set else 'no'}<br>"
            f"FROM_EMAIL present? {'yes' if bool(from_email) else 'no'}",
            500
        )

    # Try sending and surface the exact exception if any
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        msg = Mail(
            from_email=from_email,
            to_emails=to or from_email,  # fallback to from_email
            subject="OSA test email",
            html_content="<p>This is a test email from OSA staff app.</p>"
        )
        resp = sg.send(msg)
        return (
            f"Queued test email to {to or from_email}. "
            f"SendGrid status: {resp.status_code}", 200
        )
    except Exception as e:
        # shows exact failure (e.g., 'The from address does not match a verified Sender Identity')
        return (f"Send failed: {type(e).__name__}: {e}", 500)


# -----------------------------------------------------------------------------
# Admin: People Delete or Bulk Delete
# -----------------------------------------------------------------------------
from sqlalchemy.exc import SQLAlchemyError

def delete_person_by_id(db, pid: int) -> tuple[bool, str]:
    """Delete a person and their dependent rows safely. Returns (ok, message)."""
    p = db.get(Person, pid)
    if not p:
        return False, f"Person #{pid} not found."

    # don't let admin nuke themselves or the configured admin account
    # inside delete_person_by_id(...) after the admin email check:
    if p.id == getattr(current_user, "id", None):
        return False, "You can’t delete the account you’re currently logged in as."

    try:
        # remove dependent rows first
        db.query(Assignment).filter(Assignment.person_id == pid).delete()
        db.query(Roommate).filter(Roommate.person_id == pid).delete()

        # (headshot cleanup optional)
        if p.headshot_path:
            try:
                fn = p.headshot_path.rsplit('/', 1)[-1]
                abs_path = os.path.join(UPLOAD_DIR, fn)
                if os.path.exists(abs_path):
                    os.remove(abs_path)
            except Exception:
                pass

        db.delete(p)
        db.commit()
        return True, f"Deleted {p.name or p.email or ('Person #' + str(pid))}."
    except SQLAlchemyError as e:
        db.rollback()
        return False, f"Delete failed for #{pid}: {e.__class__.__name__}"

@app.route('/admin/people/<int:pid>/delete', methods=['POST'])
@login_required
def admin_delete_person(pid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ok, msg = delete_person_by_id(db, pid)
    flash(msg)
    # keep any search filter
    q = request.args.get('q') or ''
    return redirect(url_for('admin_people', q=q))

@app.route('/admin/people/bulk-delete', methods=['POST'])
@login_required
def admin_bulk_delete_people():
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ids = request.form.getlist('ids')
    if not ids:
        flash("No people selected.")
        return redirect(url_for('admin_people'))

    # normalize to ints and dedupe
    ids_int = sorted({int(x) for x in ids if str(x).isdigit()})
    successes, errors = 0, 0
    for pid in ids_int:
        ok, msg = delete_person_by_id(db, pid)
        flash(msg)
        if ok: successes += 1
        else: errors += 1

    flash(f"Bulk delete complete: {successes} deleted, {errors} errors.")
    # preserve search query if any
    q = request.args.get('q') or ''
    return redirect(url_for('admin_people', q=q))


# -----------------------------------------------------------------------------
# Admin: Bios
# -----------------------------------------------------------------------------
@app.route('/admin/events/<int:eid>/bios', methods=['GET', 'POST'])
@login_required
def admin_event_bios(eid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    Pos = aliased(Position)
    assigns = (
        db.query(Assignment)
          .join(Pos, Assignment.position_id == Pos.id)
          .options(
              joinedload(Assignment.person),
              joinedload(Assignment.position)
          )
          .filter(Assignment.event_id == eid)
          .order_by(Pos.display_order.asc())
          .all()
    )

    # Unique people list
    people_map = {}
    for a in assigns:
        if a.person:
            people_map[a.person.id] = a.person
    people = sorted(people_map.values(), key=lambda p: (p.name or '').lower())

    if request.method == 'POST':
        ids = request.form.getlist('person_id')
        if not ids:
            flash("Select at least one person to print bios.")
            return render_template('event_bios.html', ev=ev, people=people)

        id_ints = [int(i) for i in ids]
        selected = db.query(Person).filter(Person.id.in_(id_ints)).all()
        selected_by_id = {p.id: p for p in selected}
        ordered = [selected_by_id[i] for i in id_ints if i in selected_by_id]

        return render_template('bios_print.html', ev=ev, people=ordered)

    return render_template('event_bios.html', ev=ev, people=people)

# -----------------------------------------------------------------------------
# Admin: People (list/search, create, edit, delete, bulk delete)
# -----------------------------------------------------------------------------
from sqlalchemy.exc import SQLAlchemyError

@app.route('/admin/people')
@login_required
def admin_people():
    if not is_admin():
        abort(403)
    db = SessionLocal()
    q = (request.args.get('q') or '').strip()
    query = db.query(Person)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Person.name.ilike(like)) |
            (Person.email.ilike(like)) |
            (Person.phone.ilike(like)) |
            (Person.preferred_airport.ilike(like))
        )
    people = query.order_by(Person.name.asc()).all()
    return render_template('people.html', people=people, q=q)


@app.route('/admin/people/new', methods=['GET', 'POST'])
@login_required
def admin_new_person():
    if not is_admin():
        abort(403)

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        phone = normalize_phone(request.form.get('phone', ''))
        address = (request.form.get('address') or '').strip()

        errors = []
        if not name:
            errors.append("Name is required.")
        if not email:
            errors.append("Email is required.")
        db = SessionLocal()
        if email and db.query(Person).filter(Person.email == email).first():
            errors.append("A user with that email already exists.")

        if errors:
            for e in errors:
                flash(e)
            return render_template('new_person.html')
        role = (request.form.get('role') or 'user').strip().lower()
        if role not in ('user', 'viewer', 'admin'):
            role = 'user'

        pwd_hash = bcrypt.hashpw(b'changeme', bcrypt.gensalt()).decode()
        db.add(Person(name=name, email=email, phone=phone, address=address, password_hash=pwd_hash, role=role))
        db.commit()
        flash("Person created (initial password: changeme).")
        return redirect(url_for('admin_people'))

    # GET
    return render_template('new_person.html')


@app.route('/admin/people/<int:pid>', methods=['GET', 'POST'])
@login_required
def admin_edit_person(pid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    p = db.get(Person, pid)
    if not p:
        abort(404)

    if request.method == 'POST':
        form = request.form

        # Basic fields
        new_name = (form.get('name') or '').strip()
        new_email = (form.get('email') or '').strip().lower()
        p.phone = normalize_phone(form.get('phone', ''))
        p.address = (form.get('address') or '').strip()
        p.preferred_airport = (form.get('preferred_airport') or '').strip()
        p.willing_to_drive = (form.get('willing_to_drive') == 'yes')
        p.car_or_rental = (form.get('car_or_rental') or '').strip() if p.willing_to_drive else None
        p.dietary_preference = (form.get('dietary_preference') or '').strip()
        p.bio = (form.get('bio') or '').strip()

        # DOB
        dob_str = (form.get('dob') or '').strip()
        if dob_str:
            try:
                p.dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
            except Exception:
                flash("Could not parse Date of Birth (use YYYY-MM-DD).")

        # Name & email with uniqueness check
        if new_name:
            p.name = new_name
        if new_email and new_email != p.email:
            if db.query(Person).filter(Person.email == new_email, Person.id != p.id).first():
                flash("That email is already in use by another account.")
                return render_template('edit_person.html', person=p)
            p.email = new_email

        # Headshot removal
        if form.get('remove_headshot') == 'on' and p.headshot_path:
            try:
                old_fn = p.headshot_path.split('/')[-1]
                old_abs = os.path.join(UPLOAD_DIR, old_fn)
                if os.path.exists(old_abs):
                    os.remove(old_abs)
            except Exception:
                pass
            p.headshot_path = None

        # New headshot upload
        file = request.files.get('headshot')
        if file and file.filename:
            if not allowed_headshot(file.filename):
                flash("Headshot must be an image (png, jpg, jpeg, gif).")
                return render_template('edit_person.html', person=p)
            # remove old if exists
            if p.headshot_path:
                try:
                    old_fn = p.headshot_path.split('/')[-1]
                    old_abs = os.path.join(UPLOAD_DIR, old_fn)
                    if os.path.exists(old_abs):
                        os.remove(old_abs)
                except Exception:
                    pass
            fname = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
            file.save(os.path.join(UPLOAD_DIR, fname))
            p.headshot_path = f"/uploads/{fname}"

        # Optional: reset password to 'changeme'
        if form.get('reset_password') == 'on':
            p.password_hash = bcrypt.hashpw(b'changeme', bcrypt.gensalt()).decode()
            flash("Password reset to 'changeme'.")
   
    new_role = (request.form.get('role') or '').strip().lower()
    if new_role in ('user', 'viewer', 'admin'):
        # Optional safety: prevent demoting yourself out of admin by mistake
        if p.id == int(current_user.id) and p.role == 'admin' and new_role != 'admin':
            flash("You can’t change your own role away from admin while logged in.")
        else:
            p.role = new_role
        db.commit()
        flash("Person updated.")
        return redirect(url_for('admin_edit_person', pid=p.id))

    # GET
    return render_template('edit_person.html', person=p)


# ---------- deletion helpers & routes ----------

def delete_person_by_id(db, pid: int) -> tuple[bool, str]:
    """Delete a person and their dependent rows safely. Returns (ok, message)."""
    p = db.get(Person, pid)
    if not p:
        return False, f"Person #{pid} not found."

    # protect admin account & current session user
    admin_email = (os.getenv('ADMIN_EMAIL', 'admin@example.com') or '').strip().lower()
    if (p.email or '').strip().lower() == admin_email:
        return False, f"Cannot delete the admin account ({admin_email})."

    if str(getattr(current_user, "id", "")) == str(p.id):
        return False, "You can’t delete the account you’re currently logged in as."

    try:
        # dependent rows (if relationships don't already cascade)
        db.query(Assignment).filter(Assignment.person_id == pid).delete()
        db.query(Roommate).filter(Roommate.person_id == pid).delete()

        # headshot file
        if p.headshot_path:
            try:
                fn = p.headshot_path.rsplit('/', 1)[-1]
                abs_path = os.path.join(UPLOAD_DIR, fn)
                if os.path.exists(abs_path):
                    os.remove(abs_path)
            except Exception:
                pass

        db.delete(p)
        db.commit()
        return True, f"Deleted {p.name or p.email or ('Person #' + str(pid))}."
    except SQLAlchemyError as e:
        db.rollback()
        return False, f"Delete failed for #{pid}: {e.__class__.__name__}"


@app.route('/admin/people/<int:pid>/delete', methods=['POST'], endpoint='admin_delete_person_v2')
@login_required
def admin_delete_person_v2(pid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ok, msg = delete_person_by_id(db, pid)
    flash(msg)
    # preserve search query if present
    q = request.args.get('q') or ''
    return redirect(url_for('admin_people', q=q))


@app.route('/admin/people/bulk-delete', methods=['POST'], endpoint='admin_bulk_delete_people_v2')
@login_required
def admin_bulk_delete_people_v2():
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ids = request.form.getlist('ids')
    if not ids:
        flash("No people selected.")
        return redirect(url_for('admin_people'))

    # normalize to ints and dedupe
    ids_int = sorted({int(x) for x in ids if str(x).isdigit()})
    successes, errors = 0, 0
    for pid in ids_int:
        ok, msg = delete_person_by_id(db, pid)
        flash(msg)
        if ok: successes += 1
        else: errors += 1

    flash(f"Bulk delete complete: {successes} deleted, {errors} errors.")
    q = request.args.get('q') or ''
    return redirect(url_for('admin_people', q=q))

# -----------------------------------------------------------------------------
# Admin: Lodging
# -----------------------------------------------------------------------------
@app.route('/admin/events/<int:eid>/lodging', methods=['GET','POST'])
@login_required
def admin_event_lodging(eid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    # -----------------------------
    # POST: add hotel
    # -----------------------------
    if request.method == 'POST' and request.form.get('action') == 'add_hotel':
        name = (request.form.get('name') or '').strip()
        address = (request.form.get('address') or '').strip()
        phone = normalize_phone(request.form.get('phone',''))
        notes = (request.form.get('notes') or '').strip()
        state = (request.form.get('state') or '').strip().upper()[:2] or None
        if not name:
            flash("Hotel name is required.")
        else:
            h = Hotel(event_id=eid, name=name, address=address, phone=phone, notes=notes, state=state)
            db.add(h)
            db.commit()
            flash("Hotel added.")
        return redirect(url_for('admin_event_lodging', eid=eid))

    # -----------------------------
    # POST: add room
    # -----------------------------
    if request.method == 'POST' and request.form.get('action') == 'add_room':
        hotel_id = int(request.form.get('hotel_id') or 0)
        room_number = (request.form.get('room_number') or '').strip()
        check_in = (request.form.get('check_in') or '').strip()
        check_out = (request.form.get('check_out') or '').strip()
        confirmation = (request.form.get('confirmation') or '').strip()
        ci = datetime.strptime(check_in, "%Y-%m-%d").date() if check_in else None
        co = datetime.strptime(check_out, "%Y-%m-%d").date() if check_out else None
        if not hotel_id:
            flash("Choose a hotel.")
        else:
            r = Room(hotel_id=hotel_id, room_number=room_number, check_in=ci, check_out=co, confirmation=confirmation)
            db.add(r)
            db.commit()
            flash("Room added.")
        return redirect(url_for('admin_event_lodging', eid=eid))

    # -----------------------------
    # POST: assign roommates
    # -----------------------------
    if request.method == 'POST' and request.form.get('action') == 'assign_roommates':
        room_id = int(request.form.get('room_id') or 0)
        p1 = request.form.get('person1')
        p2 = request.form.get('person2')

        if not room_id:
            flash("Choose a room.")
            return redirect(url_for('admin_event_lodging', eid=eid))

        db.query(Roommate).filter(Roommate.room_id == room_id).delete()

        for pid in [p1, p2]:
            if pid:
                db.add(Roommate(room_id=room_id, person_id=int(pid)))

        db.commit()
        flash("Roommates saved.")

        # notify by email, but don't block UI
        try:
            room = db.get(Room, room_id)
            if room and room.occupants:
                occ_people = [rm.person for rm in room.occupants if rm.person and rm.person.email]
                for person in occ_people:
                    html = render_template('emails/room_notice.html',
                                           person=person, room=room, hotel=room.hotel, ev=ev)
                    send_email_async(
                        person.email,
                        f"Lodging Assigned: {room.hotel.name} / Room {room.room_number or ''}",
                        html
                    )
        except Exception:
            app.logger.exception("Roommate email notify failed")

        return redirect(url_for('admin_event_lodging', eid=eid))

    # -----------------------------
    # POST: clone hotel from existing
    # -----------------------------
    if request.method == 'POST' and request.form.get('action') == 'clone_hotel':
        src_id = int(request.form.get('src_hotel_id') or 0)
        src = db.get(Hotel, src_id)
        if not src:
            flash("Select an existing hotel to clone.")
            return redirect(url_for('admin_event_lodging', eid=eid))
        clone = Hotel(
            event_id=eid,
            name=src.name,
            address=src.address,
            phone=src.phone,
            notes=src.notes,
            state=src.state
        )
        db.add(clone)
        db.commit()
        flash("Hotel cloned onto this event.")
        return redirect(url_for('admin_event_lodging', eid=eid))

    # -----------------------------
    # GET: load page data
    # -----------------------------
    hotels = (
        db.query(Hotel)
          .options(joinedload(Hotel.rooms).joinedload(Room.occupants).joinedload(Roommate.person))
          .filter(Hotel.event_id == eid)
          .all()
    )

    assigned_people = (
        db.query(Person)
          .join(Assignment, Assignment.person_id == Person.id)
          .filter(Assignment.event_id == eid)
          .order_by(Person.name.asc())
          .all()
    )

    # same-state reuse picker
    target_state = request.args.get('state')
    if not target_state:
        first = db.query(Hotel).filter(Hotel.event_id == eid).first()
        if first and getattr(first, "state", None):
            target_state = first.state


    same_state_hotels = []
    if target_state:
        same_state_hotels = (
            db.query(Hotel)
              .filter(Hotel.state == target_state, Hotel.event_id != eid)
              .order_by(Hotel.name.asc())
              .all()
        )

    return render_template(
        'lodging.html',
        ev=ev,
        hotels=hotels,
        people=assigned_people,
        same_state_hotels=same_state_hotels,
        target_state=target_state
    )
# -----------------------------------------------------------------------------
# Admin: Edit and Delete Hotels (integrates with reuse-by-state logic)
# -----------------------------------------------------------------------------

@app.route('/admin/hotel/<int:hid>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_hotel(hid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    hotel = db.get(Hotel, hid)
    if not hotel:
        abort(404)

    if request.method == 'POST':
        hotel.name = request.form.get('name', '').strip()
        hotel.address = request.form.get('address', '').strip()
        hotel.phone = request.form.get('phone', '').strip()
        hotel.state = request.form.get('state', '').strip().upper()
        hotel.notes = request.form.get('notes', '').strip()
        db.commit()
        flash(f"Hotel '{hotel.name}' updated successfully.")
        return redirect(url_for('admin_event_lodging', eid=request.form.get('event_id')))

    eid = request.args.get('eid')
    return render_template('edit_hotel.html', hotel=hotel, eid=eid)


@app.route('/admin/hotel/<int:hid>/delete', methods=['POST'])
@login_required
def admin_delete_hotel(hid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    h = db.get(Hotel, hid)
    if not h:
        abort(404)

    event_id = request.form.get('event_id')
    try:
        # delete any roommates linked to rooms of this hotel
        room_ids = [r.id for r in h.rooms]
        if room_ids:
            db.query(Roommate).filter(Roommate.room_id.in_(room_ids)).delete(synchronize_session=False)
            db.query(Room).filter(Room.id.in_(room_ids)).delete(synchronize_session=False)

        # finally delete the hotel itself
        db.delete(h)
        db.commit()
        flash(f"Hotel '{h.name}' and its rooms were deleted.")
    except Exception as e:
        db.rollback()
        flash(f"Error deleting hotel: {e.__class__.__name__}")
    
    return redirect(url_for('admin_event_lodging', eid=event_id))

@app.route('/admin/rooms/<int:rid>/delete', methods=['POST'])
@login_required
def admin_delete_room(rid):
    """Delete a specific room (and any roommates) from a hotel."""
    if not is_admin():
        abort(403)
    db = SessionLocal()
    room = db.get(Room, rid)
    if not room:
        abort(404)
    event_id = room.hotel.event_id if room.hotel else None
    try:
        # delete roommates first
        db.query(Roommate).filter(Roommate.room_id == rid).delete(synchronize_session=False)
        db.delete(room)
        db.commit()
        flash(f"Room {room.room_number or rid} deleted.")
    except Exception as e:
        db.rollback()
        flash(f"Error deleting room: {e.__class__.__name__}")
    return redirect(url_for('admin_event_lodging', eid=event_id))

# -----------------------------------------------------------------------------
# Call Sheet (HTML)
# -----------------------------------------------------------------------------
from datetime import timedelta
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import aliased

# -----------------------------------------------------------------------------
# Call Sheet (secured)
# -----------------------------------------------------------------------------
@app.route('/events/<int:eid>/call-sheet')
@login_required
def call_sheet(eid):
    db = SessionLocal()
    try:
        ev = db.get(Event, eid)
        if not ev:
            abort(404)

        # Determine if current_user is admin, viewer, or assigned staff
        person = getattr(current_user, "person", None)
        role = getattr(person, "role", None)

        is_admin_user = is_admin()
        is_viewer_user = (role == "viewer")

        assigned_count = 0
        if person:
            assigned_count = db.query(Assignment).filter(
                Assignment.event_id == eid,
                Assignment.person_id == person.id
            ).count()

        # Access rules
        allowed = is_admin_user or is_viewer_user or assigned_count > 0
        if not allowed:
            abort(403)

        # If not published: allow only admin and viewer roles
        if not ev.call_sheet_published and not (is_admin_user or is_viewer_user):
            abort(403)

        # Load assignments
        Pos = aliased(Position)
        rows = (
            db.query(Assignment)
              .join(Pos, Assignment.position_id == Pos.id)
              .options(joinedload(Assignment.person), joinedload(Assignment.position))
              .filter(Assignment.event_id == eid)
              .order_by(Pos.display_order.asc())
              .all()
        )

        # Load hotels
        hotels = (
            db.query(Hotel)
              .options(
                  joinedload(Hotel.rooms)
                  .joinedload(Room.occupants)
                  .joinedload(Roommate.person)
              )
              .filter(Hotel.event_id == eid)
              .all()
        )

        # Load day schedule
        days = (
            db.query(EventDay)
              .filter(EventDay.event_id == eid)
              .order_by(EventDay.start_dt.asc())
              .all()
        )
        day_rows = []
        for d in days:
            staff_dt = d.staff_arrival_dt or (
                d.start_dt - timedelta(minutes=60) if d.start_dt else None
            )
            judges_dt = d.judges_arrival_dt or (
                d.start_dt - timedelta(minutes=30) if d.start_dt else None
            )
            day_rows.append({
                "start": d.start_dt,
                "setup": d.setup_dt,
                "staff": staff_dt,
                "judges": judges_dt,
                "notes": d.notes or '',
                "setup_only": d.setup_only or False
            })

        # Mark call sheet seen (staff only)
        if not is_admin_user and assigned_count > 0 and hasattr(Assignment, "callsheet_seen_at"):
            rec = (
                db.query(Assignment)
                  .filter(Assignment.event_id == eid,
                          Assignment.person_id == person.id)
                  .first()
            )
            if rec and rec.callsheet_seen_at is None:
                rec.callsheet_seen_at = datetime.utcnow()
                db.commit()

        # Show unpublished banner only for admin/viewer
        show_unpublished_banner = not ev.call_sheet_published and (is_admin_user or is_viewer_user)

        return render_template(
            'call_sheet.html',
            ev=ev,
            rows=rows,
            hotels=hotels,
            day_rows=day_rows,
            show_unpublished_banner=show_unpublished_banner
        )
    finally:
        db.close()

@app.route('/events')
@login_required
def events_list():
    db = SessionLocal()
    now = datetime.utcnow()
    evs = (
        db.query(Event)
          .filter((Event.date == None) | (Event.date >= now))
          .order_by(Event.date.asc())
          .all()
    )
    return render_template('events_public.html', events=evs)

@app.route('/callsheet/<int:eid>')
def public_call_sheet(eid):
    db = SessionLocal()
    try:
        ev = db.get(Event, eid)
        if not ev or not ev.call_sheet_published:
            abort(403)

        Pos = aliased(Position)
        rows = (
            db.query(Assignment)
              .join(Pos, Assignment.position_id == Pos.id)
              .options(joinedload(Assignment.person), joinedload(Assignment.position))
              .filter(Assignment.event_id == eid)
              .order_by(Pos.display_order.asc())
              .all()
        )

        hotels = (
            db.query(Hotel)
              .options(
                  joinedload(Hotel.rooms)
                  .joinedload(Room.occupants)
                  .joinedload(Roommate.person)
              )
              .filter(Hotel.event_id == eid)
              .all()
        )

        days = (
            db.query(EventDay)
              .filter(EventDay.event_id == eid)
              .order_by(EventDay.start_dt.asc())
              .all()
        )
        day_rows = []
        for d in days:
            staff_dt = d.staff_arrival_dt or (
                d.start_dt - timedelta(minutes=60) if d.start_dt else None
            )
            judges_dt = None if d.setup_only else (
                d.judges_arrival_dt or (d.start_dt - timedelta(minutes=30) if d.start_dt else None)
            )
            day_rows.append({
                "start": d.start_dt,
                "setup": d.setup_dt,
                "staff": staff_dt,
                "judges": judges_dt,
                "notes": d.notes or '',
                "setup_only": d.setup_only or False
            })

        return render_template('call_sheet.html', ev=ev, rows=rows, hotels=hotels, day_rows=day_rows)
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Who has seen and acknowledged
# -----------------------------------------------------------------------------
@app.route('/admin/events/<int:eid>/receipts')
@login_required
def admin_event_receipts(eid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev: abort(404)

    Pos = aliased(Position)
    acks = (db.query(Assignment)
              .join(Pos, Assignment.position_id == Pos.id)
              .options(joinedload(Assignment.person), joinedload(Assignment.position))
              .filter(Assignment.event_id == eid)
              .order_by(Pos.display_order.asc())
              .all())
    return render_template('receipts.html', ev=ev, acks=acks)

@app.route('/admin/events/<int:eid>/attachments', methods=['GET', 'POST'])
@login_required
def admin_event_attachments(eid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    if request.method == 'POST':
        file = request.files.get('file')
        desc = request.form.get('description', '').strip()
        vis = request.form.get('visibility', 'staff')

        if not file or not file.filename:
            flash("Please choose a file to upload.")
            return redirect(url_for('admin_event_attachments', eid=eid))

        fname = secure_filename(file.filename)
        timestamp = int(datetime.utcnow().timestamp())
        save_path = os.path.join(UPLOAD_ATTACHMENTS_DIR, f"{timestamp}_{fname}")
        file.save(save_path)

        att = Attachment(
            event_id=eid,
            filename=fname,
            file_path=save_path,
            description=desc,
            visibility=vis,
            uploaded_by=current_user.id if current_user else None
        )
        db.add(att)
        db.commit()
        flash("Attachment uploaded successfully.")
        return redirect(url_for('admin_event_attachments', eid=eid))

    attachments = db.query(Attachment).filter_by(event_id=eid).order_by(Attachment.uploaded_at.desc()).all()
    return render_template('event_attachments.html', ev=ev, attachments=attachments)

@app.route('/admin/attachments/<int:aid>/delete', methods=['POST'])
@login_required
def admin_delete_attachment(aid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    att = db.get(Attachment, aid)
    if not att:
        abort(404)

    try:
        if os.path.exists(att.file_path):
            os.remove(att.file_path)
        eid = att.event_id
        db.delete(att)
        db.commit()
        flash("Attachment deleted.")
    except Exception as e:
        flash(f"Error deleting file: {e}")
        eid = att.event_id if att else None

    return redirect(url_for('admin_event_attachments', eid=eid))
# -----------------------------------------------------------------------------
# Send Emails
# -----------------------------------------------------------------------------
@app.route('/admin/events/<int:eid>/email', methods=['GET', 'POST'])
@login_required
def admin_event_email(eid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    # All staff with assignments for this event
    people = (
        db.query(Person)
        .join(Assignment, Assignment.person_id == Person.id)
        .filter(Assignment.event_id == eid)
        .distinct()
        .all()
    )

    if request.method == 'POST':
        subject = (request.form.get('subject') or '').strip()
        body = (request.form.get('body') or '').strip()
        send_mode = request.form.get('send_mode', 'all')

        if not subject or not body:
            flash("Subject and message are required.")
            return redirect(url_for('admin_event_email', eid=eid))

        # Determine recipient list
        if send_mode == 'test':
            # Try to find admin's person email; fallback to FROM_EMAIL
            admin_person = db.query(Person).filter_by(id=current_user.id).first()
            test_email = getattr(admin_person, 'email', None) or os.getenv('FROM_EMAIL', 'no-reply@onstageamerica.com')
            recipient_list = [test_email]
            flash_target = f"✅ Test email sent to {test_email}."
        else:
            recipient_list = [p.email for p in people if p.email]
            flash_target = f"✅ Email sent to {len(recipient_list)} staff."

        # Send emails via SendGrid async
        for email in recipient_list:
            person = (
                current_user if send_mode == 'test'
                else next((p for p in people if p.email == email), None)
            )
            html_body = render_template(
                'emails/generic_staff_notice.html',
                person=person,
                ev=ev,
                body=body
            )
            send_email_async(email, subject, html_body)

        flash(flash_target)
        return redirect(url_for('admin_event_email', eid=eid))

    return render_template('event_email.html', ev=ev, people=people)

# -----------------------------------------------------------------------------
# Call Sheet (PDF)
# -----------------------------------------------------------------------------
@app.route('/admin/events/<int:eid>/callsheet.pdf')
@login_required
def admin_call_sheet_pdf(eid):
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
    from reportlab.lib.units import inch
    from reportlab.lib.utils import ImageReader

    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='HeaderTitle', fontSize=18, leading=22, alignment=1, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='HeaderSub', fontSize=11, leading=14, alignment=1))
    styles.add(ParagraphStyle(name='SectionHeader', fontSize=13, leading=15, spaceAfter=8, spaceBefore=10, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='NormalText', fontSize=9, leading=12))

    story = []

    # --- TOP HEADER: Centered Logo + Event Info ---
    try:
        logo_path = os.path.join(app.static_folder, "OSA_Logo_Silver_Gold.png")
        story.append(Image(logo_path, width=2.5*inch, height=2*inch))
    except Exception as e:
        app.logger.warning(f"Logo load failed: {e}")

    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Call Sheet — {ev.city or ''}", styles['HeaderTitle']))
    if ev.event_start:
        story.append(Paragraph(f"{ev.event_start.strftime('%B %d, %Y')}", styles['HeaderSub']))
    story.append(Spacer(1, 16))

    # --- EVENT INFO TABLE (full-width or 80%) ---
    story.append(Paragraph("Event Information", styles['SectionHeader']))
    info_data = [
        ['City', ev.city or '—'],
        ['Venue', ev.venue or '—'],
        ['Setup', ev.setup_start.strftime('%B %d, %Y - %I:%M %p') if ev.setup_start else '—'],
        ['Start', ev.event_start.strftime('%B %d, %Y - %I:%M %p') if ev.event_start else '—'],
        ['End', ev.event_end.strftime('%B %d, %Y - %I:%M %p') if ev.event_end else '—'],
        ['Coordinator', f"{ev.coordinator_name or ''}  {ev.coordinator_phone or ''}"],
    ]

    info_table = Table(info_data, colWidths=[1.5 * inch, 5.5 * inch])
    info_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f5e8b8')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 12))

    # --- DAILY SCHEDULE ---
    days = (
        db.query(EventDay)
        .filter(EventDay.event_id == eid)
        .order_by(EventDay.start_dt.asc())
        .all()
    )
    if days:
        story.append(Paragraph("Daily Schedule", styles['SectionHeader']))
        day_data = [['Day Start', 'Setup', 'Staff Arrival', 'Judges Arrival', 'Notes']]
        for d in days:
            if d.setup_only:
                judges_val = '<b><font color="red">Setup Only — No Judges Required</font></b>'
            else:
                judges_val = (
                    d.judges_arrival_dt.strftime('%B %d, %Y %I:%M %p') if d.judges_arrival_dt else ''
                )
            day_data.append([
                Paragraph(d.start_dt.strftime('%B %d, %Y %I:%M %p') if d.start_dt else '', styles['NormalText']),
                Paragraph(d.setup_dt.strftime('%B %d, %Y %I:%M %p') if d.setup_dt else '', styles['NormalText']),
                Paragraph(d.staff_arrival_dt.strftime('%B %d, %Y %I:%M %p') if d.staff_arrival_dt else '', styles['NormalText']),
                Paragraph(judges_val, styles['NormalText']),
                Paragraph(d.notes or '', styles['NormalText']),
            ])
        day_table = Table(day_data, repeatRows=1, colWidths=[1.4*inch, 1.4*inch, 1.4*inch, 1.5*inch, 1.8*inch])
        day_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f5e8b8')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(day_table)
        story.append(Spacer(1, 12))

    # --- ASSIGNMENTS ---
    assigns = (
        db.query(Assignment)
        .join(Person)
        .join(Position)
        .filter(Assignment.event_id == eid)
        .order_by(Position.name.asc(), Person.name.asc())
        .all()
    )
    if assigns:
        story.append(Paragraph("Staff Assignments", styles['SectionHeader']))
        data = [['Position', 'Name', 'Phone', 'Email', 'Transport / Notes']]
        for a in assigns:
            lines = []
            if a.transport_mode:
                lines.append(f"Mode: {a.transport_mode}")
            if a.arrival_ts:
                lines.append(f"Arrival: {a.arrival_ts.strftime('%B %d, %Y %I:%M %p')}")
            if a.transport_booking:
                lines.append(f"Booking: {a.transport_booking}")
            if a.transport_notes:
                lines.append(a.transport_notes)
            notes = "<br/>".join(lines)
            data.append([
                Paragraph(a.position.name if a.position else '', styles['NormalText']),
                Paragraph(a.person.name if a.person else '', styles['NormalText']),
                Paragraph(a.person.phone or '', styles['NormalText']),
                Paragraph(a.person.email or '', styles['NormalText']),
                Paragraph(notes, styles['NormalText']),
            ])
        t = Table(data, repeatRows=1, colWidths=[1.2*inch, 1.5*inch, 1.2*inch, 2*inch, 2*inch])
        t.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f5e8b8')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(PageBreak())

    # --- HOTELS ---
    hotels = db.query(Hotel).filter(Hotel.event_id == eid).all()
    if hotels:
        story.append(Paragraph("Hotel & Room Assignments", styles['SectionHeader']))
        for h in hotels:
            story.append(Paragraph(f"<b>{h.name}</b>", styles['NormalText']))
            if h.address or h.phone:
                story.append(Paragraph(f"{h.address or ''} — {h.phone or ''}", styles['NormalText']))
            if h.notes:
                story.append(Paragraph(f"<em>{h.notes}</em>", styles['NormalText']))
            room_data = [['Room', 'Occupants', 'Check-in', 'Check-out', 'Confirmation']]
            for r in h.rooms:
                occupants = ", ".join([rm.person.name for rm in r.occupants if rm.person])
                room_data.append([
                    Paragraph(r.room_number or '-', styles['NormalText']),
                    Paragraph(occupants or '—', styles['NormalText']),
                    Paragraph(r.check_in.strftime('%B %d, %Y') if r.check_in else '', styles['NormalText']),
                    Paragraph(r.check_out.strftime('%B %d, %Y') if r.check_out else '', styles['NormalText']),
                    Paragraph(r.confirmation or '', styles['NormalText']),
                ])
            table = Table(room_data, repeatRows=1, colWidths=[1*inch, 2.5*inch, 1.2*inch, 1.2*inch, 1.2*inch])
            table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f5e8b8')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(table)
            story.append(Spacer(1, 10))

    # --- WATERMARK ---
def draw_watermark(canvas, doc):
    from reportlab.lib.colors import Color
    from reportlab.pdfbase.pdfmetrics import stringWidth

    canvas.saveState()

    watermark_text = "DRAFT"
    gold = Color(0.75, 0.65, 0.25, alpha=0.15)
    canvas.setFont("Helvetica-Bold", 120)
    text_width = stringWidth(watermark_text, "Helvetica-Bold", 120)

    page_width, page_height = doc.pagesize
    x = (page_width - text_width) / 2
    y = page_height / 2

    canvas.translate(x, y)
    canvas.rotate(45)
    canvas.setFillColor(gold)
    canvas.drawString(0, 0, watermark_text)

    canvas.restoreState()
    # no return statement here ✅


    doc.build(story, onFirstPage=draw_watermark, onLaterPages=draw_watermark)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=callsheet_{eid}.pdf'
    return response

# -----------------------------------------------------------------------------
# Secure Attachment Downloads Route
# -----------------------------------------------------------------------------

@app.route('/attachments/<int:aid>')
@login_required
def download_attachment(aid):
    db = SessionLocal()
    att = db.get(Attachment, aid)
    if not att:
        abort(404)

    ev = db.get(Event, att.event_id)
    if not ev:
        abort(404)

    can_view = False
    if is_admin():
        can_view = True
    elif att.visibility == 'public' and ev.call_sheet_published:
        can_view = True
    elif att.visibility == 'staff':
        assigned_ids = [a.person_id for a in db.query(Assignment).filter_by(event_id=ev.id).all()]
        if current_user.id in assigned_ids:
            can_view = True

    if not can_view:
        abort(403)

    return send_file(att.file_path, as_attachment=True, download_name=att.filename)

# -----------------------------------------------------------------------------
# Dev entrypoint
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
