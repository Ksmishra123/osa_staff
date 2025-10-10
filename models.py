import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
Base = declarative_base()
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False))
def get_engine():
    db_url = os.getenv('DATABASE_URL','sqlite:///osa_app.db')
    if db_url.startswith('mysql://') and 'charset' not in db_url:
        db_url += ('&' if '?' in db_url else '?') + 'charset=utf8mb4'
    return create_engine(db_url, pool_pre_ping=True)
def init_db():
    engine = get_engine()
    SessionLocal.configure(bind=engine)
    Base.metadata.create_all(bind=engine); return engine
class Person(Base):
    __tablename__='people'
    id=Column(Integer, primary_key=True); name=Column(String, nullable=False)
    address=Column(Text); phone=Column(String)
    email=Column(String, unique=True, nullable=False)
    password_hash=Column(String, default='')
    assignments=relationship('Assignment', back_populates='person', cascade='all,delete')
class Position(Base):
    __tablename__='positions'
    id=Column(Integer, primary_key=True); name=Column(String, unique=True, nullable=False)
    display_order=Column(Integer, nullable=False)
    assignments=relationship('Assignment', back_populates='position', cascade='all,delete')
class Event(Base):
    __tablename__='events'
    id=Column(Integer, primary_key=True); date=Column(DateTime, nullable=False)
    city=Column(String, nullable=False); setup_start=Column(DateTime)
    event_start=Column(DateTime); event_end=Column(DateTime)
    venue=Column(Text); hotel=Column(Text)
    assignments=relationship('Assignment', back_populates='event', cascade='all,delete')
class Assignment(Base):
    __tablename__='assignments'
    id=Column(Integer, primary_key=True)
    event_id=Column(Integer, ForeignKey('events.id'), nullable=False)
    position_id=Column(Integer, ForeignKey('positions.id'), nullable=False)
    person_id=Column(Integer, ForeignKey('people.id'), nullable=False)
    ack=Column(Boolean, default=False, nullable=False)
    transport_mode=Column(String); transport_booking=Column(String)
    arrival_ts=Column(DateTime); transport_notes=Column(Text)
    __table_args__=(UniqueConstraint('event_id','position_id','person_id', name='uq_evt_pos_person'),)
    event=relationship('Event', back_populates='assignments')
    position=relationship('Position', back_populates='assignments')
    person=relationship('Person', back_populates='assignments')
