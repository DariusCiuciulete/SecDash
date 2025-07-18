"""
Dashboard API endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db_session
from schemas import DashboardResponse

router = APIRouter()


@router.get("/", summary="Get dashboard data", response_model=DashboardResponse)
async def get_dashboard_data(
    db: AsyncSession = Depends(get_db_session)
):
    """Get aggregated dashboard data."""
    # Placeholder implementation
    from schemas import ScanStatsResponse, VulnerabilityStatsResponse
    
    scan_stats = ScanStatsResponse(
        total_scans=0,
        running_scans=0,
        completed_scans=0,
        failed_scans=0,
        total_assets=0,
        active_assets=0
    )
    
    vuln_stats = VulnerabilityStatsResponse(
        total_vulnerabilities=0,
        open_vulnerabilities=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0
    )
    
    return DashboardResponse(
        scan_stats=scan_stats,
        vulnerability_stats=vuln_stats,
        recent_scans=[],
        recent_vulnerabilities=[]
    )
