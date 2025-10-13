# models.py
import os
from datetime import datetime, date

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, Date,
    ForeignKey, Text
)
from sqlalchemy.orm import (
    declarative_base, relationship, sessionmaker, scoped_session
)

# ------------------------------------------------------------------------------
# Engine / Session
# ------------------------------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////data/osa_app.db")

# SQLite needs this flag in multi-threaded server environments
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    future=True,
    echo=False,
    connect_args=connect_args
)

SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()


def init_db():
    """
    Ensures all tables exist and returns the bound engine.
    Call this once on startup (and in shell scripts before using SessionLocal()).
    """
    # Ensure SQLite foreign keys are on
    if DATABASE_URL.startswith("sqlite"):
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA foreign_keys=ON;")
    Base.metadata.create_all(bind=engine)
    return engine


# ------------------------------------------------------------------------------
# Core Models
# ------------------------------------------------------------------------------

class Person(Base):
    __tablename__ = "people"

    id = Column(Integer, primary_key=True)

    # Identity / auth
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)

    # Profile
    phone = Column(String)                   # normalized to "(XXX) XXX-XXXX"
    address = Column(String)
    dob = Column(Date)                       # YYYY-MM-DD
    preferred_airport = Column(String)
    willing_to_drive = Column(Boolean)       # True/False
    car_or_rental = Column(String)           # "car" | "rental" | None
    dietary_preference = Column(String)
    headshot_path = Column(String)           # "/uploads/<file>"
    bio = Column(Text)                       # free-form bio

    # Relationships
    assignments = relationship("Assignment", back_populates="person", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Person id={self.id} name={self.name!r} email={self.email!r}>"


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)

    # When / where
    date = Column(DateTime, index=True)      # main event date/time
    city = Column(String, nullable=False)
    setup_start = Column(DateTime)
    event_start = Column(DateTime)
    event_end = Column(DateTime)

    # Venues
    venue = Column(Text)
    hotel = Column(Text)

    # Relationships
    assignments = relationship("Assignment", back_populates="event", cascade="all, delete-orphan")
    hotels = relationship("Hotel", back_populates="event", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Event id={self.id} city={self.city!r} date={self.date!r}>"


class Position(Base):
    __tablename__ = "positions"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    display_order = Column(Integer, default=0, index=True)

    assignments = relationship("Assignment", back_populates="position", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Position id={self.id} name={self.name!r} order={self.display_order}>"


class Assignment(Base):
    __tablename__ = "assignments"

    id = Column(Integer, primary_key=True)

    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    position_id = Column(Integer, ForeignKey("positions.id", ondelete="CASCADE"), nullable=False, index=True)
    person_id = Column(Integer, ForeignKey("people.id", ondelete="CASCADE"), nullable=False, index=True)

    ack = Column(Boolean, default=False)  # person acknowledged

    # Transportation fields (optional)
    transport_mode = Column(String)       # e.g., "flight", "drive"
    transport_booking = Column(Text)      # PNR / booking ref
    arrival_ts = Column(DateTime)         # arrival timestamp
    transport_notes = Column(Text)

    # Relationships
    event = relationship("Event", back_populates="assignments")
    position = relationship("Position", back_populates="assignments")
    person = relationship("Person", back_populates="assignments")

    def __repr__(self) -> str:
        return (f"<Assignment id={self.id} event_id={self.event_id} "
                f"position_id={self.position_id} person_id={self.person_id} ack={self.ack}>")


# ------------------------------------------------------------------------------
# Lodging Models (Hotels / Rooms / Roommates)
# ------------------------------------------------------------------------------

class Hotel(Base):
    __tablename__ = "hotels"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String, nullable=False)
    address = Column(Text)
    phone = Column(String)
    notes = Column(Text)

    event = relationship("Event", back_populates="hotels")
    rooms = relationship("Room", back_populates="hotel", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Hotel id={self.id} event_id={self.event_id} name={self.name!r}>"


class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True)
    hotel_id = Column(Integer, ForeignKey("hotels.id", ondelete="CASCADE"), nullable=False, index=True)

    room_number = Column(String)
    check_in = Column(Date)
    check_out = Column(Date)
    confirmation = Column(String)

    hotel = relationship("Hotel", back_populates="rooms")
    occupants = relationship("Roommate", back_populates="room", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Room id={self.id} hotel_id={self.hotel_id} room={self.room_number!r}>"


class Roommate(Base):
    __tablename__ = "roommates"

    id = Column(Integer, primary_key=True)
    room_id = Column(Integer, ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False, index=True)
    person_id = Column(Integer, ForeignKey("people.id", ondelete="CASCADE"), nullable=False, index=True)

    room = relationship("Room", back_populates="occupants")
    person = relationship("Person")

    def __repr__(self) -> str:
        return f"<Roommate id={self.id} room_id={self.room_id} person_id={self.person_id}>"
