"""
Database models using SQLAlchemy 2.0 with async support
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
from enum import Enum

from sqlalchemy import String, Text, Integer, DateTime, Boolean, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, ENUM
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(AsyncAttrs, DeclarativeBase):
    """Base model with async attributes"""
    pass


# Enums
class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTool(str, Enum):
    NMAP = "nmap"
    ZAP = "zap"
    NUCLEI = "nuclei"
    OPENVAS = "openvas"
    METASPLOIT = "metasploit"
    TSHARK = "tshark"
    NIKTO = "nikto"


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class AssetType(str, Enum):
    HOST = "host"
    NETWORK_RANGE = "network_range"
    WEB_APPLICATION = "web_application"
    SERVICE = "service"


# Models
class Asset(Base):
    """Asset management table"""
    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[AssetType] = mapped_column(ENUM(AssetType), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Relationships
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="asset")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship("Vulnerability", back_populates="asset")

    # Indexes
    __table_args__ = (
        Index("ix_assets_type", "type"),
        Index("ix_assets_active", "is_active"),
        Index("ix_assets_created_at", "created_at"),
    )


class Scan(Base):
    """Scan execution table with TimescaleDB hypertable support"""
    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    tool: Mapped[ScanTool] = mapped_column(ENUM(ScanTool), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(ENUM(ScanStatus), default=ScanStatus.QUEUED)
    
    # Scan configuration
    profile: Mapped[Optional[str]] = mapped_column(String(100))
    options: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # Execution details
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    
    # Results
    raw_output: Mapped[Optional[str]] = mapped_column(Text)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    
    # Worker details
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255))
    worker_id: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[Optional[str]] = mapped_column(String(255))  # User ID from Keycloak
    
    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="scans")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship("Vulnerability", back_populates="scan")

    # Indexes for TimescaleDB hypertable
    __table_args__ = (
        Index("ix_scans_created_at", "created_at"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_tool", "tool"),
        Index("ix_scans_asset_id", "asset_id"),
    )


class Vulnerability(Base):
    """Vulnerability findings table"""
    __tablename__ = "vulnerabilities"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    scan_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    
    # Vulnerability identification
    vuln_id: Mapped[str] = mapped_column(String(255), nullable=False)  # CVE, CWE, or tool-specific ID
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Classification
    severity: Mapped[VulnerabilitySeverity] = mapped_column(ENUM(VulnerabilitySeverity), nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column()
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255))
    epss_score: Mapped[Optional[float]] = mapped_column()
    
    # Location details
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer)
    service: Mapped[Optional[str]] = mapped_column(String(100))
    path: Mapped[Optional[str]] = mapped_column(String(1024))  # For web vulns
    
    # Evidence and details
    evidence: Mapped[Optional[str]] = mapped_column(Text)
    impact: Mapped[Optional[str]] = mapped_column(Text)
    recommendation: Mapped[Optional[str]] = mapped_column(Text)
    references: Mapped[List[str]] = mapped_column(JSON, default=list)
    
    # Status and tracking
    status: Mapped[VulnerabilityStatus] = mapped_column(ENUM(VulnerabilityStatus), default=VulnerabilityStatus.OPEN)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255))  # User ID from Keycloak
    
    # Deduplication hash
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 hash for deduplication
    
    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="vulnerabilities")
    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")

    # Indexes
    __table_args__ = (
        Index("ix_vulnerabilities_severity", "severity"),
        Index("ix_vulnerabilities_status", "status"),
        Index("ix_vulnerabilities_dedup_hash", "dedup_hash"),
        Index("ix_vulnerabilities_first_seen", "first_seen"),
        Index("ix_vulnerabilities_asset_id", "asset_id"),
        Index("ix_vulnerabilities_vuln_id", "vuln_id"),
    )


class ScanProfile(Base):
    """Predefined scan profiles and configurations"""
    __tablename__ = "scan_profiles"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    tool: Mapped[ScanTool] = mapped_column(ENUM(ScanTool), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    
    # Configuration
    command_template: Mapped[str] = mapped_column(Text, nullable=False)
    default_options: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=600)
    
    # Metadata
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[Optional[str]] = mapped_column(String(255))

    # Indexes
    __table_args__ = (
        Index("ix_scan_profiles_tool", "tool"),
        Index("ix_scan_profiles_active", "is_active"),
    )


class CVEData(Base):
    """CVE database for vulnerability enrichment"""
    __tablename__ = "cve_data"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CVE-YYYY-NNNN
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_v3_score: Mapped[Optional[float]] = mapped_column()
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(255))
    cvss_v4_score: Mapped[Optional[float]] = mapped_column()
    cvss_v4_vector: Mapped[Optional[str]] = mapped_column(String(255))
    epss_score: Mapped[Optional[float]] = mapped_column()
    
    # Dates
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    modified_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # References and metadata
    references: Mapped[List[str]] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    
    # Cache timestamp
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes
    __table_args__ = (
        Index("ix_cve_data_cvss_v3_score", "cvss_v3_score"),
        Index("ix_cve_data_published_date", "published_date"),
    )


class UserPreferences(Base):
    """User preferences and settings"""
    __tablename__ = "user_preferences"

    user_id: Mapped[str] = mapped_column(String(255), primary_key=True)  # Keycloak user ID
    preferences: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
