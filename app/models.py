import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    nmap_start_time = Column(DateTime, nullable=True)
    raw_xml_path = Column(String, nullable=False)

    hosts = relationship("Host", back_populates="scan")


class Host(Base):
    __tablename__ = "hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    state = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="hosts")
    services = relationship("Service", back_populates="host")


class Service(Base):
    __tablename__ = "services"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    port = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    service_name = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)
    cpe = Column(String, nullable=True)

    host = relationship("Host", back_populates="services")
    cve_matches = relationship("CVEMatch", back_populates="service")


class CVEMatch(Base):
    __tablename__ = "cve_matches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id"), nullable=False)
    cve_id = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    confidence = Column(String, nullable=False)
    description = Column(String, nullable=True)
    matched_at = Column(DateTime, default=datetime.utcnow)

    service = relationship("Service", back_populates="cve_matches")
