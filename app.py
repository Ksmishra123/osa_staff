import os
import bcrypt
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

from models import init_db, SessionLocal, Person, Event, Position, Assignment

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

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
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
        form = request.form
        name = form.get('name', '').strip()
        email = form.get('email', '').strip().lower()
        password = form.get('password', '')
        confirm  = form.get('confirm', '')

        phone = form.get('phone','').strip()
        address = form.get('address','').strip()
        preferred_airport = form.get('preferred_airport','').strip()
        willing_to_drive = form.get('willing_to_drive') == 'yes'
        car_or_rental = form.get('car_or_rental','').strip() if willing_to_drive else None
        dietary_preference = form.get('dietary_preference','').strip()

        # DOB from <input type="date">
        dob = None
        dob_str = form.get('dob','').strip()
        if dob_str:
            try:
                dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
            except Exception:
                pass

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
                fname = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
                save_path = os.path.join(UPLOAD_DIR, fname)
                file.save(save_path)
                headshot_path = f"/uploads/{fname}"

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

    return render_template('register.html', form={})

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
    rows = (
        db.query(Assignment)
        .join(Event, Assignment.event_id == Event.id)
        .join(Position, Assignment.position_id == Position.id)
        .filter(Assignment.person_id == int(current_user.id))
        .order_by(Event.date.asc(), Position.display_order.asc())
        .all()
    )
    return render_template('me.html', rows=rows)

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

        db.commit()
        flash('Assignments saved (including transportation).')
        return redirect(url_for('admin_events'))

    # Prefill current assignments + transport
    currents = {
        a.position_id: a
        for a in db.query(Assignment).filter(Assignment.event_id == eid).all()
    }
    return render_template('assign.html', ev=ev, people=people, positions=positions, current=currents)

# -----------------------------------------------------------------------------
# Admin: People
# -----------------------------------------------------------------------------
@app.route('/admin/people')
@login_required
def admin_people():
    if not is_admin():
        abort(403)
    db = SessionLocal()
    people = db.query(Person).order_by(Person.name.asc()).all()
    return render_template('people.html', people=people)

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
# Call Sheet (secured)
# -----------------------------------------------------------------------------
@app.route('/events/<int:eid>/call-sheet')
@login_required
def call_sheet(eid):
    db = SessionLocal()
    ev = db.get(Event, eid)
    if not ev:
        abort(404)

    # Allow if admin or the current user is assigned to this event
    allowed = is_admin() or db.query(Assignment).filter(
        Assignment.event_id == eid,
        Assignment.person_id == int(current_user.id)
    ).count() > 0

    if not allowed:
        abort(403)

    rows = (
        db.query(Assignment)
          .join(Position, Assignment.position_id == Position.id)
          .join(Person, Assignment.person_id == Person.id, isouter=True)
          .filter(Assignment.event_id == eid)
          .order_by(Position.display_order.asc())
          .all()
    )
    return render_template('call_sheet.html', ev=ev, rows=rows)

# -----------------------------------------------------------------------------
# Dev entrypoint
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
