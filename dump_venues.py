"""One-off: dump seasons + events + venue/hotel data so we can plan the
venue-address copy. Safe, read-only. Run on Render:

    python3 dump_venues.py
"""
from app import SessionLocal
from models import Event, Season


def main():
    db = SessionLocal()
    try:
        seasons = db.query(Season).order_by(Season.display_order.asc()).all()

        print("=== SEASONS ===")
        if not seasons:
            print("  (no seasons found)")
        for s in seasons:
            n = db.query(Event).filter(Event.season_id == s.id).count()
            print(f"  id={s.id}  name={s.name!r}  active={s.is_active}  events={n}")

        # Events with no season attached at all.
        orphan = db.query(Event).filter(Event.season_id.is_(None)).count()
        print(f"  (events with NO season: {orphan})")
        print(f"  TOTAL EVENTS: {db.query(Event).count()}")

        print("\n=== EVENTS (grouped by season) ===")
        groups = [(s.id, s.name) for s in seasons] + [(None, "(no season)")]
        for sid, sname in groups:
            evs = (
                db.query(Event)
                .filter(Event.season_id == sid if sid is not None else Event.season_id.is_(None))
                .order_by(Event.date.asc())
                .all()
            )
            if not evs:
                continue
            print(f"\n--- Season {sname!r} (id={sid}) ---")
            for e in evs:
                d = e.date.strftime('%Y-%m-%d') if e.date else '(no date)'
                print(f"  [{e.id}] {d} | city={e.city!r}")
                print(f"        venue         = {e.venue!r}")
                print(f"        venue_address = {e.venue_address!r}")
                for h in e.hotels:
                    print(f"        hotel: {h.name!r}  addr={h.address!r}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
