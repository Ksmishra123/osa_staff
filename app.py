import os
import bcrypt
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from dotenv import load_dotenv
from models import init_db, SessionLocal, Person, Event, Position, Assignment

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret')
init_db()
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, person):
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


@app.route('/init')
def init():
    init_db()
    return "DB initialized. Run: python seed.py", 200


#@app.route('/login', methods=['GET', 'POST'])
#def login():
#    db = SessionLocal()
 #   if request.method == 'POST':
  #      email = request.form.get('email', '').strip().lower()
   #     password = request.form.get('password', '')
    #    p = db.query(Person).filter(Person.email == email).first()
     #   if not p:
      #      flash('No user with that email.')
       #     return redirect(url_for('login'))
       # if not p.password_hash:
       #     # first-time set
       #     p.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
       #     db.commit()
      #  if bcrypt.checkpw(password.encode(), p.password_hash.encode()):
     #       login_user(User(p))
#            flash('Logged in.')
  #          return redirect(url_for('me'))
  #      flash('Invalid password.')
  #      return redirect(url_for('login'))
  #  return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = SessionLocal()
    if request.method == 'POST':
        try:
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            p = db.query(Person).filter(Person.email==email).first()
            if not p:
                flash('No user with that email.')
                return redirect(url_for('login'))
            if not p.password_hash:
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
            # TEMP: show the exception so we see it in the browser while debugging
            return f"Login error: {type(e).__name__}: {e}", 500
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


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

def parse_dt(v: str):
    """Accepts HTML datetime-local (YYYY-MM-DDTHH:MM) or 'YYYY-MM-DD HH:MM'. Empty -> None."""
    if not v:
        return None
    v = v.strip()
    try:
        # from <input type="datetime-local">
        if "T" in v:
            return datetime.fromisoformat(v)
        # fallback "YYYY-MM-DD HH:MM"
        return datetime.strptime(v, "%Y-%m-%d %H:%M")
    except Exception:
        return None


def is_admin():
    return (
        current_user.is_authenticated
        and current_user.person.email == os.getenv('ADMIN_EMAIL', 'admin@example.com')
    )


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
        # clear and re-add assignments for this event
        db.query(Assignment).filter(Assignment.event_id == eid).delete()
        for p in positions:
            pid = request.form.get(f'pos_{p.id}')
            if pid:
                db.add(Assignment(event_id=eid, position_id=p.id, person_id=int(pid)))
        db.commit()
        flash('Assignments saved.')
        return redirect(url_for('admin_events'))

    current_map = {
        a.position_id: a.person_id
        for a in db.query(Assignment).filter(Assignment.event_id == eid).all()
    }
    return render_template('assign.html', ev=ev, people=people, positions=positions, current=current_map)


@app.route('/events/<int:eid>/call-sheet')
@login_required
def call_sheet(eid):
    db = SessionLocal()
    ev = db.get(Event, eid)
    rows = (
        db.query(Assignment)
        .join(Position, Assignment.position_id == Position.id)
        .filter(Assignment.event_id == eid)
        .order_by(Position.display_order.asc())
        .all()
    )
    return render_template('call_sheet.html', ev=ev, rows=rows)


if __name__ == '__main__':
    init_db()
    # local dev server; on Render, use gunicorn start command
    app.run(host='0.0.0.0', port=5000, debug=True)

