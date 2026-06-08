"""
Best-effort extraction of flight and hotel details from an itinerary.

The staff app lets admins attach an itinerary to an assignment either as a link
or as an uploaded file. Historically the app only *stored* those — staff saw a
raw "Link"/"File" with no details. This module reads the contents of an
uploaded itinerary (PDF or text) and pulls out the useful bits — flight legs and
hotel/lodging info — so they can be shown directly in the app.

This is heuristic, pattern-based parsing. It targets the common layouts from
Expedia, Orbitz, and the major airlines. Anything it can't confidently read is
simply left out; the original file is always still downloadable as a fallback.

Travel *links* (Expedia/Orbitz trip URLs, airline "manage my trip" pages) are
not parsed here: they almost always sit behind a login, so their contents can't
be fetched server-side. For those, attach the PDF/email confirmation instead.
"""

from __future__ import annotations

import re

# pypdf is an optional dependency. If it's not installed we still parse plain
# text itineraries; PDF extraction just returns no text and parsing yields {}.
try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - import guard
    PdfReader = None


# IATA airline code -> display name. Covers the carriers staff actually fly.
AIRLINE_CODES = {
    "AA": "American Airlines",
    "DL": "Delta",
    "UA": "United",
    "WN": "Southwest",
    "B6": "JetBlue",
    "AS": "Alaska Airlines",
    "NK": "Spirit",
    "F9": "Frontier",
    "HA": "Hawaiian Airlines",
    "G4": "Allegiant",
    "SY": "Sun Country",
    "AC": "Air Canada",
    "WS": "WestJet",
    "BA": "British Airways",
    "VS": "Virgin Atlantic",
    "LH": "Lufthansa",
    "AF": "Air France",
    "KL": "KLM",
    "IB": "Iberia",
    "EK": "Emirates",
    "QR": "Qatar Airways",
    "AM": "Aeromexico",
}

# Full airline names found in body text -> IATA code. Longer names first so that
# e.g. "american airlines" matches before a bare "american".
AIRLINE_NAMES = {
    "american airlines": "AA",
    "delta air lines": "DL",
    "delta airlines": "DL",
    "united airlines": "UA",
    "southwest airlines": "WN",
    "jetblue airways": "B6",
    "alaska airlines": "AS",
    "spirit airlines": "NK",
    "frontier airlines": "F9",
    "hawaiian airlines": "HA",
    "allegiant air": "G4",
    "sun country airlines": "SY",
    "air canada": "AC",
    "british airways": "BA",
    "virgin atlantic": "VS",
    "air france": "AF",
}

# Hotel brand / type keywords used to spot a lodging line.
HOTEL_KEYWORDS = (
    "hotel", "inn", "resort", "suites", "lodge", "motel", "hostel",
    "marriott", "hilton", "hyatt", "sheraton", "westin", "ritz-carlton",
    "ritz carlton", "courtyard", "hampton", "holiday inn", "fairfield",
    "doubletree", "embassy suites", "residence inn", "la quinta",
    "best western", "wyndham", "four seasons", "intercontinental",
    "renaissance", "aloft", "springhill", "homewood", "candlewood",
    "comfort inn", "comfort suites", "hyatt place", "ac hotel", "kimpton",
    "omni", "loews", "sofitel", "fairmont", "radisson",
)

# --- Regex building blocks -------------------------------------------------

_TIME_RE = re.compile(r"\b(\d{1,2}:\d{2}\s*[APap]\.?\s?[Mm]\.?)")
_AIRPORT_PAREN_RE = re.compile(r"\(([A-Z]{3})\)")
# Flight number: carrier code + 1-4 digits. No trailing word boundary, because
# web-print itineraries glue it to the next word (e.g. "DL1546Boeing"); the
# negative lookahead just stops us splitting a longer number.
_FLIGHT_NO_RE = re.compile(r"\b([A-Z]{2})\s?(\d{1,4})(?!\d)")
# Two airport codes glued together at the start of a line and followed by a
# date, e.g. "DTWBWI Sat, Jul 4". The trailing date requirement keeps a bare
# 6-letter confirmation code (e.g. "HBZORF" on its own line) from matching.
_GLUED_ROUTE_RE = re.compile(
    r"^([A-Z]{3})([A-Z]{3})\s+"
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|\d)"
)
_CONFIRM_RE = re.compile(
    r"(?:confirmation(?:\s+(?:code|number|no\.?|#))?|record\s+locator|"
    r"booking\s+(?:id|reference|number|code|ref)|reservation\s+(?:number|code|id)|"
    r"itinerary\s+(?:number|#)|pnr|airline\s+ref(?:erence)?)\s*[:#]?\s*"
    r"([A-Z0-9]{5,8})\b",
    re.IGNORECASE,
)
_DATE_RE = re.compile(
    r"\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s+)?"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2}"
    r"(?:,?\s+\d{4})?\b"
    r"|\b\d{1,2}/\d{1,2}/\d{2,4}\b",
    re.IGNORECASE,
)
_CHECKIN_RE = re.compile(r"check[\s-]*in\s*[:\-]?\s*(.+)", re.IGNORECASE)
_CHECKOUT_RE = re.compile(r"check[\s-]*out\s*[:\-]?\s*(.+)", re.IGNORECASE)

# Route written inline as "DTW>BWI", "DTW > BWI", "DTW -> BWI" or "DEN to LAX".
# Both ends must be 3-letter airport codes; a bare space is NOT a connector, so
# headings like "DETAILED CHARGES" don't match.
_ROUTE_RE = re.compile(
    r"\b([A-Z]{3})(?:\s*(?:>|->|→|—|–)\s*|\s+to\s+)([A-Z]{3})\b"
)

# Compact date used on airline receipts, e.g. "04Jul2026" or "4 Jul 2026".
_COMPACT_DATE_RE = re.compile(
    r"\b(\d{1,2})\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s*(\d{4})\b",
    re.IGNORECASE,
)

# Hotel keywords matched on word boundaries so substrings like the "inn" inside
# "Dinner" don't produce a phantom hotel.
_HOTEL_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in HOTEL_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def _find_date(line: str) -> str | None:
    """Return a human-readable date found in the line, or None.

    Handles compact airline dates ("04Jul2026" -> "Jul 4, 2026") as well as the
    spelled-out and numeric forms used by Expedia/Orbitz.
    """
    m = _COMPACT_DATE_RE.search(line)
    if m:
        return f"{m.group(2)[:3].title()} {int(m.group(1))}, {m.group(3)}"
    m = _DATE_RE.search(line)
    if m:
        # Normalize ALL-CAPS web-print dates ("SAT, JUL 4" -> "Sat, Jul 4").
        return m.group(0).strip().title()
    return None


# --- Text extraction -------------------------------------------------------

def extract_text_from_file(path: str) -> str:
    """Return the readable text of an itinerary file (.pdf or .txt).

    Returns an empty string for unsupported types, unreadable files, or when
    pypdf is unavailable for a PDF. Never raises.
    """
    if not path:
        return ""
    lower = path.lower()
    try:
        if lower.endswith(".pdf"):
            if PdfReader is None:
                return ""
            reader = PdfReader(path)
            chunks = []
            for page in reader.pages:
                try:
                    chunks.append(page.extract_text() or "")
                except Exception:
                    continue
            return "\n".join(chunks)
        if lower.endswith((".txt", ".eml", ".ics")):
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
    except Exception:
        return ""
    return ""


# --- Parsing ---------------------------------------------------------------

def _airline_name(code: str) -> str:
    return AIRLINE_CODES.get(code.upper(), code.upper())


def _looks_like_flight(prefix: str, line_lower: str) -> bool:
    """A 2-letter+digits token is a flight only if it's a known carrier code or
    the line is clearly a flight line. Avoids matching seat/gate/etc. noise."""
    if prefix.upper() in AIRLINE_CODES:
        return True
    return "flight" in line_lower


def parse_flights(text: str) -> list[dict]:
    """Walk the itinerary line by line, accumulating flight legs.

    A new leg starts at a flight-number token (e.g. "DL 1546" or
    "American Airlines 1234"). Airports come either inline as "DTW>BWI", in
    parentheses like "(JFK)", or on the line just above the flight number (the
    Delta/Expedia receipt layout). Dates and times are picked up from the same
    leg's lines. This covers the common airline, Expedia and Orbitz formats.
    """
    flights: list[dict] = []
    cur: dict | None = None
    pending_route: tuple[str, str] | None = None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    def flush():
        nonlocal cur
        if cur and (cur.get("flight") or cur.get("from") or cur.get("to")):
            flights.append(cur)
        cur = None

    for line in lines:
        low = line.lower()

        # A flight-number token: "DL 1546" (known carrier) or "Delta 567".
        flight_label = None
        m = _FLIGHT_NO_RE.search(line)
        if m and _looks_like_flight(m.group(1), low):
            flight_label = f"{m.group(1).upper()} {m.group(2)}"
        else:
            # Full airline name immediately followed by a flight number, e.g.
            # "American Airlines 1234". The number must follow the name directly
            # so prose like "call the Delta Flightline at 800.325.1999" or
            # "© 2026 Delta Air Lines" does not register as a flight.
            for name, code in AIRLINE_NAMES.items():
                nm = re.search(re.escape(name) + r"\s+(?:flight\s+)?#?(\d{1,4})\b", low)
                if nm:
                    flight_label = f"{code} {nm.group(1)}"
                    break

        route = _ROUTE_RE.search(line) or _GLUED_ROUTE_RE.match(line)

        if flight_label:
            flush()
            code = flight_label.split()[0]
            cur = {
                "airline": _airline_name(code),
                "flight": flight_label,
                "from": None, "to": None,
                "depart_time": None, "arrive_time": None,
                "date": None,
            }
            # Route from this same line, else one seen on the preceding line.
            if route:
                cur["from"], cur["to"] = route.group(1), route.group(2)
            elif pending_route:
                cur["from"], cur["to"] = pending_route
            pending_route = None
        elif route:
            # Standalone route line. Attach to the current leg if it still needs
            # airports; otherwise hold it for the next flight number we hit.
            if cur and not cur["from"] and not cur["to"]:
                cur["from"], cur["to"] = route.group(1), route.group(2)
            else:
                pending_route = (route.group(1), route.group(2))

        if cur is None:
            continue

        # Parenthesized airports (Expedia/Orbitz "Depart ... (JFK)" style).
        is_depart = "depart" in low or low.startswith(("from", "origin", "lv "))
        is_arrive = "arriv" in low or low.startswith(("to", "destination", "ar "))
        for ap in _AIRPORT_PAREN_RE.findall(line):
            if is_depart and not cur["from"]:
                cur["from"] = ap
            elif is_arrive and not cur["to"]:
                cur["to"] = ap
            elif not cur["from"]:
                cur["from"] = ap
            elif not cur["to"] and ap != cur["from"]:
                cur["to"] = ap

        if not cur["date"]:
            cur["date"] = _find_date(line)

        for tm in _TIME_RE.findall(line):
            tm = re.sub(r"\s+", "", tm).upper()
            if is_depart and not cur["depart_time"]:
                cur["depart_time"] = tm
            elif is_arrive and not cur["arrive_time"]:
                cur["arrive_time"] = tm
            elif not cur["depart_time"]:
                cur["depart_time"] = tm
            elif not cur["arrive_time"]:
                cur["arrive_time"] = tm

    flush()
    return flights


def parse_hotels(text: str) -> list[dict]:
    """Pull hotel name plus check-in/out and confirmation when present."""
    hotels: list[dict] = []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    for idx, line in enumerate(lines):
        low = line.lower()
        if not _HOTEL_RE.search(line):
            continue
        # Skip obvious non-name lines (labels, very long paragraphs).
        if len(line) > 80 or low.startswith(("check", "room", "guest")):
            continue

        hotel = {
            "name": line.strip(" .-"),
            "check_in": None, "check_out": None, "confirmation": None,
        }
        # Look at a small window after the name for dates / confirmation.
        for follow in lines[idx + 1: idx + 8]:
            ci = _CHECKIN_RE.search(follow)
            co = _CHECKOUT_RE.search(follow)
            if ci and not hotel["check_in"]:
                d = _DATE_RE.search(ci.group(1))
                hotel["check_in"] = (d.group(0) if d else ci.group(1)).strip()[:40]
            if co and not hotel["check_out"]:
                d = _DATE_RE.search(co.group(1))
                hotel["check_out"] = (d.group(0) if d else co.group(1)).strip()[:40]
            cm = _CONFIRM_RE.search(follow)
            if cm and not hotel["confirmation"]:
                hotel["confirmation"] = cm.group(1)

        # De-dupe by name.
        if not any(h["name"].lower() == hotel["name"].lower() for h in hotels):
            hotels.append(hotel)

    return hotels


def parse_itinerary_text(text: str) -> dict:
    """Parse raw itinerary text into structured flight + hotel data.

    Returns {} when nothing useful could be extracted, so callers can fall back
    to showing the raw link/file.
    """
    if not text or not text.strip():
        return {}

    flights = parse_flights(text)
    hotels = parse_hotels(text)
    confirmations = []
    for m in _CONFIRM_RE.finditer(text):
        code = m.group(1)
        if code not in confirmations:
            confirmations.append(code)

    result = {}
    if flights:
        result["flights"] = flights
    if hotels:
        result["hotels"] = hotels
    if confirmations:
        result["confirmations"] = confirmations[:5]
    return result


def parse_itinerary_file(path: str) -> dict:
    """Convenience: extract text from a file then parse it."""
    return parse_itinerary_text(extract_text_from_file(path))


def parse_itinerary_bytes(data: bytes, filename: str) -> dict:
    """Parse itinerary bytes (e.g. an email attachment) without keeping them.

    Writes to a temporary file only long enough to read its text, then removes
    it, so nothing is persisted to disk.
    """
    if not data:
        return {}
    import os
    import tempfile

    suffix = ""
    if filename and "." in filename:
        suffix = "." + filename.rsplit(".", 1)[1].lower()
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return parse_itinerary_file(tmp_path)
    except Exception:
        return {}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
