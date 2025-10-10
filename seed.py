import bcrypt
from datetime import datetime
from models import init_db, SessionLocal, Person, Event, Position
def main():
    init_db(); db=SessionLocal()
    if db.query(Position).count()==0:
        for n,o in [('Director',1),('Emcee',2),('Backstage',3),('Trophies',4),
                    ('Judge 1',5),('Judge 2',6),('Judge 3',7),
                    ('Sales',8),('Extra hand',9),('Video',10),('Photo',11)]:
            db.add(Position(name=n, display_order=o))
        db.commit()
    if db.query(Person).count()==0:
        for name,email in [('Admin User','admin@example.com'),('EJ Ferencak','ej@onstageamerica.com'),
                           ('Tina Vittorioso','tina@onstageamerica.com'),('Alonzo Smith','alonzo@onstageamerica.com'),
                           ('Autumn Reed','autumn@onstageamerica.com')]:
            ph=bcrypt.hashpw(b'changeme', bcrypt.gensalt()).decode()
            db.add(Person(name=name, email=email, phone='(555) 555-0000', address='Address', password_hash=ph))
        db.commit()
    if db.query(Event).count()==0:
        db.add(Event(date=datetime(2025,3,14,8,0), city='Long Island, NY',
                     setup_start=datetime(2025,3,13,15,0),
                     event_start=datetime(2025,3,14,8,0),
                     event_end=datetime(2025,3,16,21,0),
                     venue='Bayport-Blue Point HS', hotel='Hilton Garden Inn Islip')); db.commit()
    print('Seeded. Admin: admin@example.com / changeme')
if __name__=='__main__': main()
