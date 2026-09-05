from sqlalchemy import create_engine, Column, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class IncidentDB(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    raw_text = Column(Text)
    sanitized_text = Column(Text, nullable=True)
    sector = Column(String, nullable=True)
    attack_type = Column(String, nullable=True)
    tactics = Column(Text, nullable=True)
    techniques = Column(Text, nullable=True)
    iocs = Column(Text, nullable=True)
    cves = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)