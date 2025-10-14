import os
import bcrypt
import re
from sqlalchemy.orm import joinedload, aliased
from datetime import datetime, date
from flask import (
    Flask, render_template, redirect, url_for, request, flash, abort,
    send_from_directory, current_app
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from models import init_db, SessionLocal, Person, Event, Position, Assignment, Hotel, Room, Roommate
from io import BytesIO
from flask import send_file, make_response  # already have?

import os, threading
from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch
import os

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


load_dotenv()

# -----------------------------------------------------------------------------
# Flask app FIRST, then decorators
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret')

# Bind DB and create tables at startup (important under gunicorn)
init_db()

# -----------------------------------------------------------------------------
# Uploads config (headshots)
# -----------------------------------------------------------------------------
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
import re
def normalize_phone(raw: str) -> str | None:
    if not raw: return None
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
        return (
            current_user.is_authenticated
            and getattr(current_user, "person", None) is not None
            and current_user.person.email == os.getenv('ADMIN_EMAIL', 'admin@example.com')
        )
    except Exception:
        return False

# Expose helpers in templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

@app.context_processor
def inject_helpers():
    return {"is_admin": is_admin}

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@onstageamerica.com")

def send_email_async(to_email: str, subject: str, html: str):
    """Fire-and-forget email via SendGrid in a thread."""
    if not SENDGRID_API_KEY or not to_email:
        return
    def _send():
        try:
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            msg = Mail(from_email=FROM_EMAIL, to_emails=to_email, subject=subject, html_content=html)
            sg.send(msg)
        except Exception as e:
            app.logger.exception("Email send failed")
    threading.Thread(target=_send, daemon=True).start()
from flask import current_app

def html_to_pdf(html: str) -> BytesIO:
    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf, link_callback=xhtml_link_callback)
    pdf.seek(0)
    return pdf

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
            bio = (form.get('bio') or '').strip()
            if errors:
                for e in errors: flash(e)
                return render_template('register.html', form=form)

            phash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            person = Person(
                name=name, email=email, password_hash=phash,
                phone=phone, address=address, preferred_airport=preferred_airport,
                willing_to_drive=willing_to_drive, car_or_rental=car_or_rental,
                dietary_preference=dietary_preference, dob=dob,
                headshot_path=headshot_path
            )
            db.add(person); db.commit()

            login_user(User(person))
            flash('Account created. Welcome!')
            return redirect(url_for('me'))

        except Exception as e:
            app.logger.exception("Register failed")
            # TEMP: surface the error so we can see what’s wrong
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

@app.route('/me')
@login_required
def me():
    db = SessionLocal()

    Ev = aliased(Event)
    Pos = aliased(Position)

    rows = (
        db.query(Assignment)
          .join(Ev, Assignment.event_id == Ev.id)
          .join(Pos, Assignment.position_id == Pos.id)
          .options(
              joinedload(Assignment.event),
              joinedload(Assignment.position)
          )
          .filter(Assignment.person_id == int(current_user.id))
          .order_by(Ev.date.asc(), Pos.display_order.asc())
          .all()
    )
    # Lodging by event for this user
    # (Room -> Hotel -> Event)
    user_lodging = (
        db.query(Room, Hotel, Event)
          .join(Hotel, Room.hotel_id == Hotel.id)
          .join(Event, Hotel.event_id == Event.id)
          .join(Roommate, Roommate.room_id == Room.id)
          .filter(Roommate.person_id == int(current_user.id))
          .all()
    )
    # Map: event_id -> list of dicts
    lodging_by_event = {}
    for room, hotel, ev in user_lodging:
        lodging_by_event.setdefault(ev.id, []).append({
            "hotel": hotel,
            "room": room
        })

    return render_template('me.html', rows=rows, lodging_by_event=lodging_by_event)

@app.route('/ack/<int:aid>', methods=['POST'])
@login_required
def ack(aid):
    db = SessionLocal()
    a = db.get(Assignment, aid)
    if not a or a.person_id != int(current_user.id):
        abort(403)
    a.ack = True
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
        city = request.form.get('city', '').strip()
        date = parse_dt(request.form.get('date'))
        setup_start = parse_dt(request.form.get('setup_start'))
        event_start = parse_dt(request.form.get('event_start'))
        event_end = parse_dt(request.form.get('event_end'))
        venue = request.form.get('venue', '').strip()
        hotel = request.form.get('hotel', '').strip()

        errors = []
        if not city:
            errors.append("City is required.")
        if not date:
            errors.append("Date (main event date/time) is required.")

        if errors:
            for e in errors:
                flash(e)
            return render_template('new_event.html')

        db = SessionLocal()
        ev = Event(
            city=city,
            date=date,
            setup_start=setup_start,
            event_start=event_start,
            event_end=event_end,
            venue=venue,
            hotel=hotel
        )
        db.add(ev)
        db.commit()
        flash('Event created.')
        return redirect(url_for('admin_events'))

    return render_template('new_event.html')

@app.route('/admin/events/<int:eid>/assign', methods=['GET', 'POST'])
@login_required
def admin_assign(eid):
    if not is_admin():
        abort(403)

    db = SessionLocal()
    ev = db.get(Event, eid)
    people = db.query(Person).order_by(Person.name.asc()).all()
    positions = db.query(Position).order_by(Position.display_order.asc()).all()

    if request.method == 'POST':
        # Clear existing assignments for this event, then re-add with transport fields
        db.query(Assignment).filter(Assignment.event_id == eid).delete()

        for p in positions:
            pid = request.form.get(f'pos_{p.id}')
            if not pid:
                continue
            a = Assignment(
                event_id=eid,
                position_id=p.id,
                person_id=int(pid),
                transport_mode=request.form.get(f'pos_{p.id}_mode') or None,
                transport_booking=request.form.get(f'pos_{p.id}_booking') or None,
                arrival_ts=parse_dt(request.form.get(f'pos_{p.id}_arrival') or ""),
                transport_notes=request.form.get(f'pos_{p.id}_notes') or None,
            )
            db.add(a)
        # notify assigned people
        for p in positions:
            pid = request.form.get(f'pos_{p.id}')
            if not pid:
                continue
            person = db.get(Person, int(pid))
            if person and person.email:
                html = render_template('emails/assignment_notice.html', person=person, ev=ev, position=p.name)
                send_email_async(person.email, f"Assignment: {ev.city} ({ev.date.strftime('%Y-%m-%d') if ev.date else ''})", html)
   
        db.commit()
        flash('Assignments saved (including transportation).')
        return redirect(url_for('admin_events'))

    # Prefill current assignments + transport
    currents = {
        a.position_id: a
        for a in db.query(Assignment).filter(Assignment.event_id == eid).all()
    }
    return render_template('assign.html', ev=ev, people=people, positions=positions, current=currents)
from sqlalchemy.orm import joinedload

@app.route('/admin/events/<int:eid>/bios', methods=['GET', 'POST'])
@login_required
def admin_event_bios(eid):
    if not is_admin():
        abort(403)
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    # Load assignments for this event, eager-load person & position, stable ordering
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

    # Unique people list (a person could hold multiple positions)
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

    # GET: selection screen
    return render_template('event_bios.html', ev=ev, people=people)

# -----------------------------------------------------------------------------
# Admin: People
# -----------------------------------------------------------------------------
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
        # search by name, email, phone, preferred airport
        query = query.filter(
            (Person.name.ilike(like)) |
            (Person.email.ilike(like)) |
            (Person.phone.ilike(like)) |
            (Person.preferred_airport.ilike(like))
        )
    people = query.order_by(Person.name.asc()).all()
    return render_template('people.html', people=people, q=q)

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
        new_name = form.get('name','').strip()
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
            p.bio = (form.get('bio') or '').strip()

        db.commit()
        flash("Person updated.")
        return redirect(url_for('admin_edit_person', pid=p.id))

    # GET
    return render_template('edit_person.html', person=p)

@app.route('/admin/people/new', methods=['GET', 'POST'])
@login_required
def admin_new_person():
    if not is_admin():
        abort(403)
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        phone = request.form.get('phone','').strip()
        address = request.form.get('address','').strip()

        errors = []
        if not name: errors.append("Name is required.")
        if not email: errors.append("Email is required.")
        if errors:
            for e in errors: flash(e)
            return render_template('new_person.html')

        pwd_hash = bcrypt.hashpw(b'changeme', bcrypt.gensalt()).decode()
        db = SessionLocal()
        if db.query(Person).filter(Person.email==email).first():
            flash('A user with that email already exists.')
            return render_template('new_person.html')

        db.add(Person(name=name, email=email, phone=phone, address=address, password_hash=pwd_hash))
        db.commit()
        flash('Person created (initial password: changeme).')
        return redirect(url_for('admin_people'))

    return render_template('new_person.html')
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

    # Create hotel
    if request.method == 'POST' and request.form.get('action') == 'add_hotel':
        name = (request.form.get('name') or '').strip()
        address = (request.form.get('address') or '').strip()
        phone = (request.form.get('phone') or '').strip()
        notes = (request.form.get('notes') or '').strip()
        if not name:
            flash("Hotel name is required.")
        else:
            h = Hotel(event_id=eid, name=name, address=address, phone=phone, notes=notes)
            db.add(h); db.commit()
            flash("Hotel added.")
        return redirect(url_for('admin_event_lodging', eid=eid))

    # Create room
    if request.method == 'POST' and request.form.get('action') == 'add_room':
        hotel_id = int(request.form.get('hotel_id') or 0)
        room_number = (request.form.get('room_number') or '').strip()
        check_in = (request.form.get('check_in') or '').strip()
        check_out = (request.form.get('check_out') or '').strip()
        confirmation = (request.form.get('confirmation') or '').strip()
        from datetime import datetime
        ci = datetime.strptime(check_in, "%Y-%m-%d").date() if check_in else None
        co = datetime.strptime(check_out, "%Y-%m-%d").date() if check_out else None
        if not hotel_id:
            flash("Choose a hotel.")
        else:
            r = Room(hotel_id=hotel_id, room_number=room_number, check_in=ci, check_out=co, confirmation=confirmation)
            db.add(r); db.commit()
            flash("Room added.")
        return redirect(url_for('admin_event_lodging', eid=eid))

        # Assign roommates (max 2) + notify
    if request.method == 'POST' and request.form.get('action') == 'assign_roommates':
        room_id = int(request.form.get('room_id') or 0)
        p1 = request.form.get('person1')
        p2 = request.form.get('person2')

        if not room_id:
            flash("Choose a room.")
            return redirect(url_for('admin_event_lodging', eid=eid))

        # clear current occupants
        db.query(Roommate).filter(Roommate.room_id == room_id).delete()

        # add up to two occupants
        new_people_ids = []
        for pid in [p1, p2]:
            if pid:
                pid_int = int(pid)
                db.add(Roommate(room_id=room_id, person_id=pid_int))
                new_people_ids.append(pid_int)

        db.commit()
        flash("Roommates saved.")

        # ---- email notifications (guarded; won't run on GET) ----
        try:
            room = db.get(Room, room_id)
            if room and room.occupants:
                occ_people = [rm.person for rm in room.occupants if rm.person and rm.person.email]
                for person in occ_people:
                    html = render_template(
                        'emails/room_notice.html',
                        person=person, room=room, hotel=room.hotel, ev=ev
                    )
                    send_email_async(
                        person.email,
                        f"Lodging Assigned: {room.hotel.name} / Room {room.room_number or ''}",
                        html
                    )
        except Exception:
            # don't let email hiccups break the UI
            app.logger.exception("Roommate email notify failed")

        return redirect(url_for('admin_event_lodging', eid=eid))


    hotels = (
        db.query(Hotel)
          .options(joinedload(Hotel.rooms).joinedload(Room.occupants).joinedload(Roommate.person))
          .filter(Hotel.event_id == eid)
          .all()
    )
    # staff assigned to this event for convenience in dropdowns
    assigned_people = (
        db.query(Person)
          .join(Assignment, Assignment.person_id == Person.id)
          .filter(Assignment.event_id == eid)
          .order_by(Person.name.asc())
          .all()
    )

    return render_template('lodging.html', ev=ev, hotels=hotels, people=assigned_people)


# -----------------------------------------------------------------------------
# Call Sheet (secured)
# -----------------------------------------------------------------------------
@app.route('/events/<int:eid>/call-sheet')
@login_required
def call_sheet(eid):
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    allowed = is_admin() or db.query(Assignment).filter(
        Assignment.event_id == eid,
        Assignment.person_id == int(current_user.id)
    ).count() > 0
    if not allowed:
        abort(403)

    Pos = aliased(Position)
    rows = (
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

    hotels = (
        db.query(Hotel)
          .options(joinedload(Hotel.rooms).joinedload(Room.occupants).joinedload(Roommate.person))
          .filter(Hotel.event_id == eid)
          .all()
    )

    return render_template('call_sheet.html', ev=ev, rows=rows, hotels=hotels)

@app.route('/events/<int:eid>/call-sheet.pdf')
@login_required
def call_sheet_pdf(eid):
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev: abort(404)

    allowed = is_admin() or db.query(Assignment).filter(
        Assignment.event_id == eid,
        Assignment.person_id == int(current_user.id)
    ).count() > 0
    if not allowed: abort(403)

    Pos = aliased(Position)
    rows = (
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
    hotels = (
        db.query(Hotel)
          .options(joinedload(Hotel.rooms).joinedload(Room.occupants).joinedload(Roommate.person))
          .filter(Hotel.event_id == eid)
          .all()
    )

    pdf_io = build_call_sheet_pdf(ev, rows, hotels)
    filename = f"CallSheet_{ev.city}_{ev.date.strftime('%Y%m%d') if ev.date else 'event'}.pdf"
    return send_file(pdf_io, mimetype='application/pdf', as_attachment=True, download_name=filename)

def build_call_sheet_pdf(ev, rows, hotels):
    """
    Build a PDF for the call sheet using ReportLab and return BytesIO.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=36, bottomMargin=36, leftMargin=36, rightMargin=36
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleBig", parent=styles["Title"], fontSize=18, leading=22, alignment=1))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=6))

    story = []

    # Header with logo
    logo_path = os.path.join(app.root_path, 'static', 'osa_logo.png')
    if os.path.exists(logo_path):
        img = Image(logo_path, width=1.6*inch, height=1.0*inch)
        img.hAlign = 'CENTER'
        story.append(img)
        story.append(Spacer(1, 6))

    title_text = f"Call Sheet — {ev.city}"
    if ev.date:
        title_text += f" — {ev.date.strftime('%B %d, %Y')}"
    story.append(Paragraph(title_text, styles["TitleBig"]))
    story.append(Spacer(1, 10))

    # Assignments table
    story.append(Paragraph("Assignments", styles["H2"]))
    data = [["Position", "Name", "Phone", "Email", "Transport"]]
    for a in rows:
        trans_bits = []
        if a.transport_mode: trans_bits.append(a.transport_mode)
        if a.arrival_ts: trans_bits.append("Arr: " + a.arrival_ts.strftime("%Y-%m-%d %H:%M"))
        if a.transport_booking: trans_bits.append(a.transport_booking)
        if a.transport_notes: trans_bits.append(a.transport_notes)
        data.append([
            a.position.name if a.position else "",
            a.person.name if a.person else "",
            a.person.phone if a.person else "",
            a.person.email if a.person else "",
            " | ".join(trans_bits)
        ])

    tbl = Table(data, colWidths=[1.2*inch, 1.5*inch, 1.3*inch, 2.0*inch, None])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('FONTSIZE', (0,1), (-1,-1), 9),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.3, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(tbl)

    # Hotels & Rooms
    story.append(Spacer(1, 14))
    story.append(Paragraph("Hotel & Room Assignments", styles["H2"]))

    if hotels:
        for h in hotels:
            story.append(Paragraph(f"<b>{h.name}</b>", styles["Normal"]))
            line2_parts = []
            if h.address: line2_parts.append(h.address)
            if h.phone: line2_parts.append(h.phone)
            if line2_parts:
                story.append(Paragraph(" — ".join(line2_parts), styles["Normal"]))
            if h.notes:
                story.append(Paragraph(f"<i>{h.notes}</i>", styles["Normal"]))
            story.append(Spacer(1, 4))

            if h.rooms:
                rdata = [["Room", "Occupants", "Check-in", "Check-out", "Confirmation"]]
                for r in h.rooms:
                    occ_names = ", ".join([rm.person.name for rm in (r.occupants or []) if rm.person])
                    rdata.append([
                        r.room_number or "-",
                        occ_names or "—",
                        r.check_in.strftime("%Y-%m-%d") if r.check_in else "",
                        r.check_out.strftime("%Y-%m-%d") if r.check_out else "",
                        r.confirmation or ""
                    ])
                rt = Table(rdata, colWidths=[0.9*inch, 2.8*inch, 1.0*inch, 1.0*inch, 1.2*inch])
                rt.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,0), 10),
                    ('FONTSIZE', (0,1), (-1,-1), 9),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('GRID', (0,0), (-1,-1), 0.3, colors.grey),
                ]))
                story.append(rt)
                story.append(Spacer(1, 8))
            else:
                story.append(Paragraph("No rooms added yet.", styles["Normal"]))
                story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No hotel assignments yet.", styles["Normal"]))

    doc.build(story)
    buf.seek(0)
    return buf

# -----------------------------------------------------------------------------
# Dev entrypoint
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
