"""One-off script: create/complete the 2026-2027 season and its events.

Safe to re-run. It reconciles against whatever is already in the database
rather than assuming a clean slate:

  * Season is matched by name. If it already exists it is reused as-is --
    its date range and is_active flag are NOT modified.
  * Events are matched by city within that season. Missing ones are created;
    existing ones keep their own date/notes.
  * EventDays are matched by day_date within each event. Only missing days
    are added, so an event that was set up by hand is filled in, not doubled.

Run with:  python3 create_2026_2027_season.py [--dry-run]
"""
import sys
from datetime import datetime, date

from models import init_db, SessionLocal, Season, Event, EventDay

SEASON_NAME = "2026-2027"
SEASON_STARTS = date(2026, 11, 13)
SEASON_ENDS = date(2027, 7, 24)

# Default clock time used for the main event `date` and each EventDay.start_dt.
# When an event already exists, its own time-of-day is reused instead.
DEFAULT_HOUR, DEFAULT_MIN = 8, 0


def dt(y, m, d, hour=DEFAULT_HOUR, minute=DEFAULT_MIN):
    return datetime(y, m, d, hour, minute)


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


def get_or_create_season(db, dry_run):
    season = db.query(Season).filter(Season.name == SEASON_NAME).first()
    if season:
        print(f'Season "{SEASON_NAME}" already exists (id={season.id}) — reusing it.')
        if season.starts_on != SEASON_STARTS or season.ends_on != SEASON_ENDS:
            print(f"  note: its range is {season.starts_on}..{season.ends_on}, "
                  f"script default is {SEASON_STARTS}..{SEASON_ENDS} (left unchanged)")
        if not season.is_active:
            print("  note: season is not active (left unchanged)")
        return season

    # display_order = max + 1 (matches admin_create_season)
    max_order = db.query(Season.display_order).order_by(Season.display_order.desc()).first()
    next_order = (max_order[0] if max_order else 0) + 1

    season = Season(
        name=SEASON_NAME,
        starts_on=SEASON_STARTS,
        ends_on=SEASON_ENDS,
        is_active=False,
        display_order=next_order,
    )
    db.add(season)
    if dry_run:
        print(f'Would create season "{SEASON_NAME}".')
        return season
    db.flush()
    print(f'Created season "{SEASON_NAME}" (id={season.id}).')
    return season


def main():
    dry_run = "--dry-run" in sys.argv

    init_db()
    db = SessionLocal()

    season = get_or_create_season(db, dry_run)

    existing = {}
    if season.id is not None:
        for ev in db.query(Event).filter(Event.season_id == season.id).all():
            existing[ev.city] = ev

    created_events = filled_events = 0
    added_days = 0

    for city, days, notes in EVENTS:
        ev = existing.get(city)

        if ev is None:
            main_date = dt(*days[0]) if days else None
            ev = Event(city=city, date=main_date, notes=notes, season_id=season.id)
            db.add(ev)
            if not dry_run:
                db.flush()
            created_events += 1
            print(f"  + {city}: creating event ({len(days)} day(s))")
            have_days = set()
            hour, minute = DEFAULT_HOUR, DEFAULT_MIN
        else:
            have_days = {
                d.day_date for d in
                db.query(EventDay).filter(EventDay.event_id == ev.id).all()
            }
            # Keep new day rows consistent with the time-of-day already on the event
            hour = ev.date.hour if ev.date else DEFAULT_HOUR
            minute = ev.date.minute if ev.date else DEFAULT_MIN

        missing = [(y, m, d) for (y, m, d) in days if date(y, m, d) not in have_days]
        for (y, m, d) in missing:
            row = EventDay(
                event_id=ev.id,
                day_date=date(y, m, d),
                start_dt=dt(y, m, d, hour, minute),
            )
            db.add(row)
            added_days += 1

        if ev is not None and city in existing:
            if missing:
                filled_events += 1
                print(f"  ~ {city}: event exists, adding {len(missing)} missing day(s)")
            else:
                print(f"  = {city}: already complete, skipping")

    if dry_run:
        db.rollback()
        print(f"\nDRY RUN — nothing written. "
              f"Would create {created_events} event(s), "
              f"fill {filled_events} existing event(s), add {added_days} day(s).")
        return

    db.commit()
    print(f"\nCreated {created_events} event(s), filled {filled_events} existing event(s), "
          f"added {added_days} day(s).")

    # Report full current state of the season
    evs = db.query(Event).filter(Event.season_id == season.id).all()
    evs.sort(key=lambda e: (e.date is None, e.date or datetime.min))
    print(f'\nSeason "{season.name}" (id={season.id}, active={season.is_active}) '
          f'now has {len(evs)} event(s):')
    for ev in evs:
        n_days = db.query(EventDay).filter(EventDay.event_id == ev.id).count()
        date_str = ev.date.strftime("%Y-%m-%d") if ev.date else "TBA"
        print(f"  - {ev.city}: main date {date_str}, {n_days} day(s)")


if __name__ == "__main__":
    main()
