#backend\models.py

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base


class IOCResult(Base):
    __tablename__ = "ioc_results"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String, index=True)
    ioc_type = Column(String)  # ip, domain, hash, email
    threat_score = Column(Float, default=0.0)
    severity = Column(String, default="Low")  # Low, Medium, High, Critical
    raw_results = Column(Text)  # JSON string of all source results
    graph_data = Column(Text)   # JSON string of nodes and edges
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)


class FeedItem(Base):
    __tablename__ = "feed_items"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String)          # malwarebazaar, urlhaus, threatfox, feodotracker
    ioc_type = Column(String)        # ip, domain, hash, url
    ioc_value = Column(String, index=True)
    malware_family = Column(String, nullable=True)
    country = Column(String, nullable=True)
    severity = Column(String, default="Medium")
    tags = Column(Text, nullable=True)
    raw_data = Column(Text)          # JSON string of original feed entry
    first_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)


class DarkWebVictim(Base):
    __tablename__ = "dark_web_victims"

    id = Column(Integer, primary_key=True, index=True)
    gang = Column(String, index=True)
    victim_name = Column(String)
    country = Column(String, nullable=True)
    sector = Column(String, nullable=True)
    data_volume = Column(String, nullable=True)
    status = Column(String, nullable=True)   # partial, full, countdown
    description = Column(Text, nullable=True)
    date_posted = Column(DateTime, nullable=True)
    onion_url = Column(String, nullable=True)
    correlated_ioc_id = Column(Integer, ForeignKey("ioc_results.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)


class PasteEntry(Base):
    __tablename__ = "paste_entries"

    id = Column(Integer, primary_key=True, index=True)
    paste_key = Column(String, unique=True, index=True)
    title = Column(String, nullable=True)
    content_snippet = Column(Text, nullable=True)
    signal_type = Column(String, nullable=True)  # credential, api_key, corporate, hacker, ioc
    signals_found = Column(Text, nullable=True)  # JSON list of matched patterns
    paste_date = Column(DateTime, nullable=True)
    correlated_ioc_id = Column(Integer, ForeignKey("ioc_results.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text, nullable=True)
    status = Column(String, default="Open")   # Open, Closed
    severity = Column(String, default="Medium")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    report_type = Column(String)   # ioc, darkweb, case
    file_path = Column(String)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))