"""One-off: copy last year's (Legacy season) venue text into this year's
(2026-2027) venue_address field, matched by explicit event-ID pairs.

Only venue_address is written; the venue name field is never touched.

Usage (on Render):
    python3 copy_venue_addresses.py            # dry-run: preview only, no changes
    python3 copy_venue_addresses.py --apply    # write the changes

Re-running is safe: by default it skips any target whose venue_address is
already set. Pass --force to overwrite those too.

The mapping is (this_year_event_id -> last_year_event_id), derived from the
data dump. Event IDs are stable, so this is unambiguous even where the
city-name strings differ between years (e.g. Haymarket vs Woodbridge).
"""
import sys
from app import SessionLocal
from models import Event

# this-year event id  ->  last-year (Legacy) event id to copy the address from
MAPPING = {
    16: 1,    # Voorhees, NJ            <- Voorhees
    17: 2,    # Pittsburgh, PA          <- Pittsburgh, PA
    18: 10,   # Haymarket, VA           <- Woodbridge, VA (Battlefield HS, Haymarket)
    19: 6,    # Altoona, PA             <- Altoona, PA
    20: 5,    # Mansfield, MA           <- Mansfield, MA
    21: 4,    # Trenton, NJ             <- Trenton, NJ
    22: 7,    # Springfield, MA         <- Springfield, MA
    23: 9,    # Laurel, MD              <- Laurel, MD
    24: 11,   # Coral Springs, FL       <- Coral Springs, FL
    25: 12,   # East Brunswick, NJ      <- East Brunswick, NJ
    26: 8,    # Long Island, NY         <- Long Island, NY
    27: 15,   # Nationals, NJ           <- Nationals, NJ
    28: 13,   # Des Moines, IA          <- Des Moines, IA
}


def main():
    apply = "--apply" in sys.argv
    force = "--force" in sys.argv

    db = SessionLocal()
    try:
        planned = 0
        skipped_existing = 0
        problems = 0

        for target_id, source_id in MAPPING.items():
            target = db.get(Event, target_id)
            source = db.get(Event, source_id)

            if target is None or source is None:
                print(f"!! MISSING  target #{target_id} or source #{source_id} not found — skipping")
                problems += 1
                continue

            src_text = (source.venue or "").strip()
            if not src_text:
                print(f"!! NO SOURCE  #{target_id} {target.city!r}: source #{source_id} has empty venue — skipping")
                problems += 1
                continue

            existing = (target.venue_address or "").strip()
            if existing and not force:
                print(f"-- SKIP (already set)  #{target_id} {target.city!r}: venue_address={existing!r}")
                skipped_existing += 1
                continue

            print(f"** COPY  #{target_id} {target.city!r}  <-  #{source_id} {source.city!r}")
            print(f"         venue_address = {src_text!r}")
            if apply:
                target.venue_address = src_text
            planned += 1

        if apply:
            db.commit()
            print(f"\nAPPLIED. {planned} updated, {skipped_existing} skipped (already set), {problems} problems.")
        else:
            print(f"\nDRY-RUN. {planned} would be updated, {skipped_existing} skipped (already set), {problems} problems.")
            print("Re-run with --apply to write these changes.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
