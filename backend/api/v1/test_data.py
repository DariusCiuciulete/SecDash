"""
Test data endpoints for development and testing
"""
from datetime import datetime, timezone
from uuid import uuid4
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db_session
from models import Asset, Scan, Vulnerability, AssetType, ScanStatus, ScanTool, VulnerabilitySeverity, VulnerabilityStatus
from schemas import AssetResponse

router = APIRouter()


@router.post("/create-test-data", summary="Create test data for development")
async def create_test_data(db: AsyncSession = Depends(get_db_session)):
    """
    Create sample assets, scans, and vulnerabilities for testing.
    """
    # Check if test data already exists
    existing_assets = await db.execute(select(Asset))
    if existing_assets.scalars().first():
        return {"message": "Test data already exists"}
    
    # Create test assets
    assets = [
        Asset(
            id=uuid4(),
            name="Test Web Server",
            type=AssetType.HOST,
            target="192.168.1.100",
            description="Production web server",
            tags=["web", "production"],
            metadata_={"environment": "prod", "criticality": "high"},
        ),
        Asset(
            id=uuid4(),
            name="Development Database",
            type=AssetType.HOST,
            target="192.168.1.101",
            description="Development database server",
            tags=["database", "development"],
            metadata_={"environment": "dev", "criticality": "medium"},
        ),
        Asset(
            id=uuid4(),
            name="Local Test Host",
            type=AssetType.HOST,
            target="127.0.0.1",
            description="Local host for testing",
            tags=["test", "local"],
            metadata_={"environment": "test", "criticality": "low"},
        ),
        Asset(
            id=uuid4(),
            name="Internal Network",
            type=AssetType.NETWORK_RANGE,
            target="10.0.0.0/24",
            description="Internal company network",
            tags=["network", "internal"],
            metadata_={"environment": "prod", "criticality": "high"},
        ),
    ]
    
    for asset in assets:
        db.add(asset)
    
    await db.commit()
    
    # Create test scans
    scans = [
        Scan(
            id=uuid4(),
            asset_id=assets[0].id,
            tool=ScanTool.NMAP,
            options={"profile": "Quick Scan", "ports": "1-1000"},
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_seconds=45,
            findings_count=3,
            raw_output="Nmap scan report for 192.168.1.100\\nHost is up (0.0001s latency)\\nPORT   STATE SERVICE\\n22/tcp open  ssh\\n80/tcp open  http\\n443/tcp open  https",
        ),
        Scan(
            id=uuid4(),
            asset_id=assets[1].id,
            tool=ScanTool.ZAP,
            options={"profile": "Baseline", "scan_type": "baseline"},
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_seconds=120,
            findings_count=1,
            raw_output="ZAP baseline scan completed for 192.168.1.101",
        ),
        Scan(
            id=uuid4(),
            asset_id=assets[2].id,
            tool=ScanTool.NUCLEI,
            options={"profile": "CVE Check", "severity": "high,critical"},
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            duration_seconds=30,
            findings_count=0,
        ),
        Scan(
            id=uuid4(),
            asset_id=assets[3].id,
            tool=ScanTool.NMAP,
            options={"profile": "Network Discovery", "ports": "1-65535"},
            status=ScanStatus.QUEUED,
            findings_count=0,
        ),
    ]
    
    for scan in scans:
        db.add(scan)
    
    await db.commit()
    
    # Create test vulnerabilities
    vulnerabilities = [
        Vulnerability(
            id=uuid4(),
            asset_id=assets[0].id,
            scan_id=scans[0].id,
            vuln_id="CVE-2023-1234",
            name="SSH Version Disclosure",
            description="SSH version information can be retrieved",
            severity=VulnerabilitySeverity.LOW,
            status=VulnerabilityStatus.OPEN,
            host="192.168.1.100",
            port=22,
            service="ssh",
            evidence="SSH-2.0-OpenSSH_8.0",
            dedup_hash="ssh_version_192.168.1.100_22",
        ),
        Vulnerability(
            id=uuid4(),
            asset_id=assets[0].id,
            scan_id=scans[0].id,
            vuln_id="CVE-2023-5678",
            name="HTTP Server Header Disclosure",
            description="Web server version disclosed in headers",
            severity=VulnerabilitySeverity.INFO,
            status=VulnerabilityStatus.OPEN,
            host="192.168.1.100",
            port=80,
            service="http",
            evidence="Server: nginx/1.18.0",
            dedup_hash="http_header_192.168.1.100_80",
        ),
        Vulnerability(
            id=uuid4(),
            asset_id=assets[0].id,
            scan_id=scans[0].id,
            vuln_id="CVE-2023-9999",
            name="SSL/TLS Certificate Issue",
            description="SSL certificate has issues",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.ACKNOWLEDGED,
            host="192.168.1.100",
            port=443,
            service="https",
            evidence="Certificate expires in 30 days",
            dedup_hash="ssl_cert_192.168.1.100_443",
        ),
        Vulnerability(
            id=uuid4(),
            asset_id=assets[1].id,
            scan_id=scans[1].id,
            vuln_id="CVE-2023-0001",
            name="Weak SQL Configuration",
            description="Database configuration allows weak authentication",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.OPEN,
            host="192.168.1.101",
            port=3306,
            service="mysql",
            evidence="Authentication method allows empty passwords",
            dedup_hash="sql_config_192.168.1.101_3306",
        ),
    ]
    
    for vuln in vulnerabilities:
        db.add(vuln)
    
    await db.commit()
    
    return {
        "message": "Test data created successfully",
        "assets_created": len(assets),
        "scans_created": len(scans),
        "vulnerabilities_created": len(vulnerabilities)
    }


@router.delete("/clear-test-data", summary="Clear all test data")
async def clear_test_data(db: AsyncSession = Depends(get_db_session)):
    """
    Clear all test data from the database.
    """
    # Delete in reverse order of dependencies
    await db.execute("DELETE FROM vulnerabilities")
    await db.execute("DELETE FROM scans")
    await db.execute("DELETE FROM assets")
    await db.commit()
    
    return {"message": "Test data cleared successfully"}
