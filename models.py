"""
Database models for the Cybersecurity Detection Framework
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class Scan(Base):
    """Represents a scanning operation"""
    __tablename__ = "scans"
    
    scan_id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)  # 'sensitive_data' or 'spoofed_website'
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), default="in_progress")  # in_progress, completed, failed
    results_count = Column(Integer, default=0)
    
    # Relationships
    detected_leaks = relationship("DetectedLeak", back_populates="scan")
    email_reports = relationship("EmailReport", back_populates="scan")


class DetectedLeak(Base):
    """Represents a detected sensitive data leak"""
    __tablename__ = "detected_leaks"
    
    leak_id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.scan_id"))
    data_type = Column(String(50), nullable=False)  # aadhaar, pan, bank_account, etc.
    file_url = Column(Text, nullable=False)
    confidence = Column(Float, default=0.0)  # Confidence score 0-100
    evidence = Column(Text, nullable=True)  # JSON string with extracted data (anonymized)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="detected_leaks")


class SpoofedWebsite(Base):
    """Represents a detected spoofed/phishing website"""
    __tablename__ = "spoofed_websites"
    
    website_id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.scan_id"))
    url = Column(Text, nullable=False)
    redirect_chain = Column(Text, nullable=True)  # JSON array
    risk_score = Column(Float, default=0.0)  # Risk score 0-100
    classification = Column(String(50), nullable=True)  # legitimate, phishing, hijacked, etc.
    evidence = Column(Text, nullable=True)  # JSON string with analysis details
    timestamp = Column(DateTime, default=datetime.utcnow)


class EmailReport(Base):
    """Represents sent email reports"""
    __tablename__ = "email_reports"
    
    report_id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.scan_id"))
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(String(20), default="pending")  # pending, sent, failed
    sent_time = Column(DateTime, nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="email_reports")


class Configuration(Base):
    """Stores user configurations"""
    __tablename__ = "configurations"
    
    config_id = Column(Integer, primary_key=True, index=True)
    user_filters = Column(Text, nullable=True)  # JSON string
    selected_keywords = Column(Text, nullable=True)  # JSON array
    file_types = Column(Text, nullable=True)  # JSON array
    domain_scope = Column(String(255), default="gov.in")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Audit log for all system actions"""
    __tablename__ = "audit_log"
    
    log_id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(Text, nullable=True)  # JSON string
    status = Column(String(20), default="success")  # success, failure
