import os, bcrypt
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from dotenv import load_dotenv
from models import init_db, SessionLocal, Person, Event, Position, Assignment
load_dotenv()
app=Flask(__name__); app.secret_key=os.getenv('SECRET_KEY','dev')
lm=LoginManager(app); lm.login_view='login'
class User(UserMixin):
    def __init__(self, p): self.id=str(p.id); self.person=p
@lm.user_loader
def load_user(uid):
    db=SessionLocal(); p=db.get(Person,int(uid)); db.close()
    return User(p) if p else None
@app.teardown_appcontext
def remove_session(exc=None): SessionLocal.remove()
@app.route('/init')
def init(): init_db(); return 'DB ready. Run: python seed.py',200
@app.route('/login', methods=['GET','POST'])
def login():
    db=SessionLocal()
    if request.method=='POST':
        email=request.form.get('email','').strip().lower()
        pwd=request.form.get('password','')
        p=db.query(Person).filter(Person.email==email).first()
        if not p: flash('No user with that email.'); return redirect(url_for('login'))
        if not p.password_hash:
            p.password_hash=bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode(); db.commit()
        if bcrypt.checkpw(pwd.encode(), p.password_hash.encode()):
            login_user(User(p)); return redirect(url_for('me'))
        flash('Invalid password.'); return redirect(url_for('login'))
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout(): 
    logout_user()
    return redirect(url_for('login'))
@app.route('/')
def index(): return redirect(url_for('me')) if current_user.is_authenticated else redirect(url_for('login'))
@app.route('/me'); @login_required
def me():
    db=SessionLocal()
    rows=(db.query(Assignment).join(Event, Assignment.event_id==Event.id)
            .join(Position, Assignment.position_id==Position.id)
            .filter(Assignment.person_id==int(current_user.id))
            .order_by(Event.date.asc(), Position.display_order.asc()).all())
    return render_template('me.html', rows=rows)
@app.route('/ack/<int:aid>', methods=['POST']); @login_required
def ack(aid):
    db=SessionLocal(); a=db.get(Assignment,aid)
    if not a or a.person_id!=int(current_user.id): abort(403)
    a.ack=True; db.commit(); flash('Acknowledged.'); return redirect(url_for('me'))
def is_admin(): return current_user.is_authenticated and current_user.person.email==os.getenv('ADMIN_EMAIL','admin@example.com')
@app.route('/admin/events'); @login_required
def admin_events():
    if not is_admin(): abort(403)
    db=SessionLocal(); evs=db.query(Event).order_by(Event.date.asc()).all()
    return render_template('events.html', events=evs)
@app.route('/admin/events/<int:eid>/assign', methods=['GET','POST']); @login_required
def admin_assign(eid):
    if not is_admin(): abort(403)
    db=SessionLocal(); ev=db.get(Event,eid)
    people=db.query(Person).order_by(Person.name.asc()).all()
    positions=db.query(Position).order_by(Position.display_order.asc()).all()
    if request.method=='POST':
        db.query(Assignment).filter(Assignment.event_id==eid).delete()
        for p in positions:
            pid=request.form.get(f'pos_{p.id}')
            if pid: db.add(Assignment(event_id=eid, position_id=p.id, person_id=int(pid)))
        db.commit(); flash('Assignments saved.'); return redirect(url_for('admin_events'))
    current={a.position_id:a.person_id for a in db.query(Assignment).filter(Assignment.event_id==eid).all()}
    return render_template('assign.html', ev=ev, people=people, positions=positions, current=current)
@app.route('/events/<int:eid>/call-sheet'); @login_required
def call_sheet(eid):
    db=SessionLocal(); ev=db.get(Event,eid)
    rows=(db.query(Assignment).join(Position, Assignment.position_id==Position.id)
            .filter(Assignment.event_id==eid).order_by(Position.display_order.asc()).all())
    return render_template('call_sheet.html', ev=ev, rows=rows)
if __name__=='__main__':
    init_db(); app.run(host='0.0.0.0', port=5000, debug=True)
