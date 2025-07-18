"""
Vulnerability management API endpoints
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from database import get_db_session
from models import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from schemas import (
    VulnerabilityResponse, VulnerabilityUpdate, VulnerabilityFilter,
    PaginationParams, PaginatedResponse
)

router = APIRouter()


@router.get("/", summary="List vulnerabilities", response_model=PaginatedResponse)
async def list_vulnerabilities(
    pagination: PaginationParams = Depends(),
    filters: VulnerabilityFilter = Depends(),
    scan_id: Optional[UUID] = Query(None, description="Filter by scan ID"),
    host: Optional[str] = Query(None, description="Filter by host"),
    db: AsyncSession = Depends(get_db_session)
):
    """List vulnerabilities with filtering and pagination."""
    # Build query
    query = select(Vulnerability)
    
    # Apply filters
    conditions = []
    if filters.severity:
        conditions.append(Vulnerability.severity.in_(filters.severity))
    if filters.status:
        conditions.append(Vulnerability.status.in_(filters.status))
    if filters.asset_id:
        conditions.append(Vulnerability.asset_id == filters.asset_id)
    if scan_id:
        conditions.append(Vulnerability.scan_id == scan_id)
    if host:
        conditions.append(Vulnerability.host.ilike(f"%{host}%"))
    if filters.search:
        search_term = f"%{filters.search}%"
        conditions.append(
            or_(
                Vulnerability.name.ilike(search_term),
                Vulnerability.description.ilike(search_term)
            )
        )
    
    if conditions:
        query = query.where(and_(*conditions))
    
    # Count total items
    count_query = select(func.count(Vulnerability.id))
    if conditions:
        count_query = count_query.where(and_(*conditions))
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (pagination.page - 1) * pagination.size
    query = query.offset(offset).limit(pagination.size)
    query = query.order_by(Vulnerability.last_seen.desc())
    
    # Execute query
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()
    
    # Calculate pagination info
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=[VulnerabilityResponse.model_validate(vuln) for vuln in vulnerabilities],
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )


@router.get("/{vuln_id}", summary="Get vulnerability", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get vulnerability by ID."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vulnerability = result.scalar_one_or_none()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return VulnerabilityResponse.model_validate(vulnerability)


@router.patch("/{vuln_id}", summary="Update vulnerability", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: UUID,
    vuln_data: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db_session)
):
    """Update vulnerability status, notes, etc."""
    # Get existing vulnerability
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vulnerability = result.scalar_one_or_none()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Apply updates
    update_data = vuln_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vulnerability, field, value)
    
    await db.commit()
    await db.refresh(vulnerability)
    
    return VulnerabilityResponse.model_validate(vulnerability)
