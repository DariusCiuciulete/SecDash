"""
Pydantic v2 schemas for API serialization and validation
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict, field_validator
from pydantic.types import Json


def serialize_datetime_with_tz(dt: datetime) -> str:
    """Serialize datetime with timezone info"""
    if dt.tzinfo is None:
        # Assume it's UTC if no timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# Base schemas
class BaseSchema(BaseModel):
    """Base schema with common configuration"""
    model_config = ConfigDict(
        from_attributes=True,
        use_enum_values=True,
        validate_assignment=True,
        arbitrary_types_allowed=True,
        json_encoders={datetime: serialize_datetime_with_tz}
    )


# Enums (matching models.py)
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


# Asset schemas
class AssetBase(BaseSchema):
    """Base asset schema"""
    name: str = Field(..., min_length=1, max_length=255, description="Asset name")
    type: AssetType = Field(..., description="Asset type")
    target: str = Field(..., min_length=1, max_length=512, description="Asset target (IP, URL, range)")
    description: Optional[str] = Field(None, description="Asset description")
    tags: List[str] = Field(default_factory=list, description="Asset tags")
    metadata_: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata", alias="metadata")


class AssetCreate(AssetBase):
    """Schema for creating assets"""
    
    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        return [tag.strip().lower() for tag in v if tag.strip()]


class AssetUpdate(BaseSchema):
    """Schema for updating assets (JSON Merge Patch)"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[AssetType] = None
    target: Optional[str] = Field(None, min_length=1, max_length=512)
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")
    is_active: Optional[bool] = None


class AssetResponse(BaseSchema):
    """Schema for asset responses"""
    id: UUID
    name: str
    type: AssetType
    target: str
    description: Optional[str]
    tags: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_scan_at: Optional[datetime] = None


# Scan schemas
class ScanBase(BaseSchema):
    """Base scan schema"""
    tool: ScanTool = Field(..., description="Scanning tool")
    profile: Optional[str] = Field(None, max_length=100, description="Scan profile name")
    options: Dict[str, Any] = Field(default_factory=dict, description="Scan options")


class ScanCreate(ScanBase):
    """Schema for creating scans"""
    asset_id: UUID = Field(..., description="Target asset ID")


class ScanUpdate(BaseSchema):
    """Schema for updating scans"""
    status: Optional[ScanStatus] = None
    error_message: Optional[str] = None


class ScanResponse(ScanBase):
    """Schema for scan responses"""
    id: UUID
    asset_id: UUID
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    findings_count: int = 0
    error_message: Optional[str] = None
    celery_task_id: Optional[str] = None
    created_at: datetime
    created_by: Optional[str] = None


class ScanDetailResponse(ScanResponse):
    """Detailed scan response with raw output"""
    raw_output: Optional[str] = None


# Vulnerability schemas
class VulnerabilityBase(BaseSchema):
    """Base vulnerability schema"""
    vuln_id: str = Field(..., max_length=255, description="Vulnerability ID (CVE, CWE, etc.)")
    name: str = Field(..., max_length=512, description="Vulnerability name")
    description: str = Field(..., description="Vulnerability description")
    severity: VulnerabilitySeverity = Field(..., description="Vulnerability severity")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score")
    cvss_vector: Optional[str] = Field(None, max_length=255, description="CVSS vector")
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS score")
    host: str = Field(..., max_length=255, description="Affected host")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Affected port")
    service: Optional[str] = Field(None, max_length=100, description="Affected service")
    path: Optional[str] = Field(None, max_length=1024, description="Affected path (for web vulns)")
    evidence: Optional[str] = Field(None, description="Evidence or proof of concept")
    impact: Optional[str] = Field(None, description="Impact description")
    recommendation: Optional[str] = Field(None, description="Remediation recommendation")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating vulnerabilities"""
    asset_id: UUID = Field(..., description="Related asset ID")
    scan_id: UUID = Field(..., description="Related scan ID")


class VulnerabilityUpdate(BaseSchema):
    """Schema for updating vulnerabilities (JSON Merge Patch)"""
    status: Optional[VulnerabilityStatus] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(None, max_length=255)


class VulnerabilityResponse(VulnerabilityBase):
    """Schema for vulnerability responses"""
    id: UUID
    asset_id: UUID
    scan_id: UUID
    status: VulnerabilityStatus
    notes: Optional[str] = None
    assigned_to: Optional[str] = None
    dedup_hash: str
    first_seen: datetime
    last_seen: datetime
    updated_at: datetime


# Scan profile schemas
class ScanProfileBase(BaseSchema):
    """Base scan profile schema"""
    name: str = Field(..., min_length=1, max_length=255, description="Profile name")
    tool: ScanTool = Field(..., description="Associated tool")
    description: Optional[str] = Field(None, description="Profile description")
    command_template: str = Field(..., description="Command template")
    default_options: Dict[str, Any] = Field(default_factory=dict, description="Default options")
    timeout_seconds: int = Field(default=600, ge=60, le=86400, description="Timeout in seconds")


class ScanProfileCreate(ScanProfileBase):
    """Schema for creating scan profiles"""
    pass


class ScanProfileUpdate(BaseSchema):
    """Schema for updating scan profiles"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    command_template: Optional[str] = None
    default_options: Optional[Dict[str, Any]] = None
    timeout_seconds: Optional[int] = Field(None, ge=60, le=86400)
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None


class ScanProfileResponse(ScanProfileBase):
    """Schema for scan profile responses"""
    id: UUID
    is_active: bool
    is_default: bool
    created_at: datetime
    created_by: Optional[str] = None


# Dashboard and analytics schemas
class ScanStatsResponse(BaseSchema):
    """Schema for scan statistics"""
    total_scans: int
    running_scans: int
    completed_scans: int
    failed_scans: int
    total_assets: int
    active_assets: int


class VulnerabilityStatsResponse(BaseSchema):
    """Schema for vulnerability statistics"""
    total_vulnerabilities: int
    open_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int


class DashboardResponse(BaseSchema):
    """Schema for dashboard data"""
    scan_stats: ScanStatsResponse
    vulnerability_stats: VulnerabilityStatsResponse
    recent_scans: List[ScanResponse]
    recent_vulnerabilities: List[VulnerabilityResponse]


# Pagination schemas
class PaginationParams(BaseSchema):
    """Pagination parameters"""
    page: int = Field(default=1, ge=1, description="Page number")
    size: int = Field(default=20, ge=1, le=100, description="Page size")


class PaginatedResponse(BaseSchema):
    """Paginated response wrapper"""
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int


# Filter schemas
class AssetFilter(BaseSchema):
    """Asset filtering parameters"""
    type: Optional[AssetType] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None
    search: Optional[str] = Field(None, description="Search in name, target, description")


class ScanFilter(BaseSchema):
    """Scan filtering parameters"""
    tool: Optional[ScanTool] = None
    status: Optional[ScanStatus] = None
    asset_id: Optional[UUID] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


class VulnerabilityFilter(BaseSchema):
    """Vulnerability filtering parameters"""
    severity: Optional[List[VulnerabilitySeverity]] = None
    status: Optional[List[VulnerabilityStatus]] = None
    asset_id: Optional[UUID] = None
    assigned_to: Optional[str] = None
    search: Optional[str] = Field(None, description="Search in name, description")


# Error schemas
class ErrorResponse(BaseSchema):
    """Standard error response"""
    error: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationErrorResponse(BaseSchema):
    """Validation error response"""
    error: str = "Validation Error"
    details: List[Dict[str, Any]] = Field(..., description="Validation error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
