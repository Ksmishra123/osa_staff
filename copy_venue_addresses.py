"""One-off: copy last year's (Legacy season) venue data into this year's
(2026-2027) events, matched by explicit event-ID pairs.

For each target event:
  - venue         <- just the NAME (the part before the address)
  - venue_address <- the FULL last-year "name, address" text

Each field is only filled when it's currently empty, so anything you've
already typed in is preserved. Pass --force to overwrite.

The name is parsed as the text before the first comma; if there's no
comma before the street number (a mashed-together string), we split at
the first digit instead. Names that look unusual are printed with a
"FLAG" so you can eyeball and fix them by hand.

Usage (on Render):
    python3 copy_venue_addresses.py            # dry-run: preview only, no changes
    python3 copy_venue_addresses.py --apply    # write the changes

Re-running is safe: by default it skips writing a field that's already
set. Pass --force to overwrite already-set fields too.

The mapping is (this_year_event_id -> last_year_event_id), derived from the
data dump. Event IDs are stable, so this is unambiguous even where the
city-name strings differ between years (e.g. Haymarket vs Woodbridge).
"""
import re
import sys
from app import SessionLocal
from models import Event


def parse_venue_name(full_text):
    """Return (name, is_flagged) where name is the venue name portion.

    Rule: name = text before the first comma. But some legacy entries mash
    the street address onto the name with no comma (e.g.
    'Cornell High School1099 Maple St...'), so if the first comma-chunk
    contains a digit, we cut at the first digit instead. Anything that
    still looks off is flagged for manual review."""
    text = (full_text or "").strip()
    name = text.split(",", 1)[0].strip()

    # If the address bled into the name (has a digit), cut at the first digit.
    if re.search(r"\d", name):
        name = re.split(r"\d", name, maxsplit=1)[0].strip()

    # Trim any dangling separator left behind (trailing "-", "," or ".").
    name = re.sub(r"[\s\-,.]+$", "", name).strip()

    # Flag names that may still have the address mixed in or look truncated.
    flagged = (
        (not name)
        or len(name) > 45
        or " - " in name          # dash-joined "Name - Sub - address" cases
        or name.endswith(("St", "St.", "Ave", "Blvd", "Dr", "Rd"))
    )
    return name, flagged

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
        flagged_count = 0

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

            venue_name, flagged = parse_venue_name(src_text)

            cur_addr = (target.venue_address or "").strip()
            cur_venue = (target.venue or "").strip()

            set_addr = force or not cur_addr
            set_venue = force or not cur_venue

            if not set_addr and not set_venue:
                print(f"-- SKIP (both already set)  #{target_id} {target.city!r}")
                skipped_existing += 1
                continue

            flag = "   *** FLAG: check this name ***" if flagged else ""
            print(f"** COPY  #{target_id} {target.city!r}  <-  #{source_id} {source.city!r}{flag}")
            if set_venue:
                print(f"         venue         = {venue_name!r}")
                if apply:
                    target.venue = venue_name
            else:
                print(f"         venue         (kept existing {cur_venue!r})")
            if set_addr:
                print(f"         venue_address = {src_text!r}")
                if apply:
                    target.venue_address = src_text
            else:
                print(f"         venue_address (kept existing {cur_addr!r})")
            if flagged:
                flagged_count += 1
            planned += 1

        if apply:
            db.commit()
            print(f"\nAPPLIED. {planned} events updated, {skipped_existing} skipped (already set), "
                  f"{flagged_count} flagged names to review, {problems} problems.")
        else:
            print(f"\nDRY-RUN. {planned} events would be updated, {skipped_existing} skipped (already set), "
                  f"{flagged_count} flagged names to review, {problems} problems.")
            print("Re-run with --apply to write these changes.")
        if flagged_count:
            print("Flagged names may have the address mixed in — check the *** FLAG *** lines "
                  "above and fix those venue names by hand if needed.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
