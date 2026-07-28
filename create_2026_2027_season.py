"""One-off script: create the 2026-2027 season and its events.

Idempotent-ish: aborts if a season named "2026-2027" already exists.
Run with:  python3 create_2026_2027_season.py
"""
from datetime import datetime, date

from models import init_db, SessionLocal, Season, Event, EventDay

# Default clock time used for the main event `date` and each EventDay.start_dt
DEFAULT_HOUR, DEFAULT_MIN = 8, 0


def dt(y, m, d):
    return datetime(y, m, d, DEFAULT_HOUR, DEFAULT_MIN)


# Each entry: (city, list-of-(year, month, day) for each day, notes)
# For single-date / TBA events the day list may be empty.
EVENTS = [
    ("Voorhees, NJ",       [(2026, 11, 13), (2026, 11, 14), (2026, 11, 15)], ""),
    ("Pittsburgh, PA",     [(2027, 2, 19), (2027, 2, 20), (2027, 2, 21)],    ""),
    ("Haymarket, VA",      [(2027, 2, 26), (2027, 2, 27), (2027, 2, 28)],    ""),
    ("Altoona, PA",        [(2027, 3, 5), (2027, 3, 6), (2027, 3, 7)],       ""),
    ("Mansfield, MA",      [(2027, 3, 5), (2027, 3, 6), (2027, 3, 7)],       ""),
    ("Trenton, NJ",        [(2027, 3, 12), (2027, 3, 13), (2027, 3, 14)],    ""),
    ("Springfield, MA",    [(2027, 3, 19), (2027, 3, 20), (2027, 3, 21)],    ""),
    ("Laurel, MD",         [(2027, 4, 9), (2027, 4, 10), (2027, 4, 11)],     ""),
    ("Coral Springs, FL",  [(2027, 4, 23), (2027, 4, 24), (2027, 4, 25)],    ""),
    ("East Brunswick, NJ", [(2027, 4, 30), (2027, 5, 1), (2027, 5, 2)],      ""),
    ("Long Island, NY",    [(2027, 5, 14), (2027, 5, 15)],                   ""),
    ("Nationals, NJ",      [(2027, 7, 18)],                                  "Week of July 18, 2027"),
    ("Des Moines, IA",     [],                                               "Date TBA"),
]


def main():
    init_db()
    db = SessionLocal()

    if db.query(Season).filter(Season.name == "2026-2027").first():
        print('Season "2026-2027" already exists — aborting to avoid duplicates.')
        return

    # display_order = max + 1 (matches admin_create_season)
    max_order = db.query(Season.display_order).order_by(Season.display_order.desc()).first()
    next_order = (max_order[0] if max_order else 0) + 1

    season = Season(
        name="2026-2027",
        starts_on=date(2026, 11, 13),
        ends_on=date(2027, 7, 24),
        is_active=False,
        display_order=next_order,
    )
    db.add(season)
    db.flush()

    # Make it the only active season
    db.query(Season).update({Season.is_active: False})
    season.is_active = True

    for city, days, notes in EVENTS:
        main_date = dt(*days[0]) if days else None
        ev = Event(
            city=city,
            date=main_date,
            notes=notes,
            season_id=season.id,
        )
        db.add(ev)
        db.flush()

        for (y, m, d) in days:
            start = dt(y, m, d)
            db.add(EventDay(
                event_id=ev.id,
                day_date=date(y, m, d),
                start_dt=start,
            ))

    db.commit()

    # Report
    print(f'Created season "{season.name}" (id={season.id}, active={season.is_active}).')
    for ev in db.query(Event).filter(Event.season_id == season.id).order_by(Event.date.asc().nullslast()).all():
        n_days = db.query(EventDay).filter(EventDay.event_id == ev.id).count()
        date_str = ev.date.strftime("%Y-%m-%d") if ev.date else "TBA"
        print(f"  - {ev.city}: main date {date_str}, {n_days} day(s)")


if __name__ == "__main__":
    main()
