"""
Asset management API endpoints
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from database import get_db_session
from models import Asset, Scan, Vulnerability
from schemas import (
    AssetResponse, AssetCreate, AssetUpdate, AssetFilter,
    PaginationParams, PaginatedResponse, ErrorResponse,
    ScanResponse, VulnerabilityResponse
)

router = APIRouter()


@router.get("/", summary="List assets", response_model=PaginatedResponse)
async def list_assets(
    pagination: PaginationParams = Depends(),
    filters: AssetFilter = Depends(),
    db: AsyncSession = Depends(get_db_session)
):
    """
    List assets with filtering and pagination.
    """
    # Build query
    query = select(Asset)
    
    # Apply filters
    conditions = []
    if filters.type:
        conditions.append(Asset.type == filters.type)
    if filters.is_active is not None:
        conditions.append(Asset.is_active == filters.is_active)
    if filters.tags:
        for tag in filters.tags:
            conditions.append(Asset.tags.contains([tag]))
    if filters.search:
        search_term = f"%{filters.search}%"
        conditions.append(or_(
            Asset.name.ilike(search_term),
            Asset.target.ilike(search_term),
            Asset.description.ilike(search_term)
        ))
    
    if conditions:
        query = query.where(and_(*conditions))
    
    # Count total items
    count_query = select(func.count(Asset.id)).where(and_(*conditions)) if conditions else select(func.count(Asset.id))
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (pagination.page - 1) * pagination.size
    query = query.offset(offset).limit(pagination.size)
    query = query.order_by(Asset.created_at.desc())
    
    # Execute query
    result = await db.execute(query)
    assets = result.scalars().all()
    
    # Calculate pagination info
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=[
            AssetResponse(
                id=asset.id,
                name=asset.name,
                type=asset.type,
                target=asset.target,
                description=asset.description,
                tags=asset.tags or [],
                metadata=asset.metadata_ or {},
                is_active=asset.is_active,
                created_at=asset.created_at,
                updated_at=asset.updated_at,
                last_scan_at=asset.last_scan_at
            ) for asset in assets
        ],
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )


@router.post("/", summary="Create asset", response_model=AssetResponse, status_code=201)
async def create_asset(
    asset_data: AssetCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new asset.
    """
    # Check if asset with same target already exists
    existing = await db.execute(
        select(Asset).where(Asset.target == asset_data.target)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="Asset with this target already exists"
        )
    
    # Create new asset
    asset_dict = asset_data.model_dump()
    # Handle the metadata field alias
    if "metadata" in asset_dict:
        asset_dict["metadata_"] = asset_dict.pop("metadata")
    
    asset = Asset(**asset_dict)
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    
    return AssetResponse(
        id=asset.id,
        name=asset.name,
        type=asset.type,
        target=asset.target,
        description=asset.description,
        tags=asset.tags or [],
        metadata=asset.metadata_ or {},
        is_active=asset.is_active,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        last_scan_at=asset.last_scan_at
    )


@router.get("/{asset_id}", summary="Get asset", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get asset by ID.
    """
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return AssetResponse(
        id=asset.id,
        name=asset.name,
        type=asset.type,
        target=asset.target,
        description=asset.description,
        tags=asset.tags or [],
        metadata=asset.metadata_ or {},
        is_active=asset.is_active,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        last_scan_at=asset.last_scan_at
    )


@router.patch("/{asset_id}", summary="Update asset", response_model=AssetResponse)
async def update_asset(
    asset_id: UUID,
    asset_data: AssetUpdate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update asset using JSON Merge Patch semantics.
    """
    # Get existing asset
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Apply updates
    update_data = asset_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)
    
    await db.commit()
    await db.refresh(asset)
    
    return AssetResponse(
        id=asset.id,
        name=asset.name,
        type=asset.type,
        target=asset.target,
        description=asset.description,
        tags=asset.tags or [],
        metadata=asset.metadata_ or {},
        is_active=asset.is_active,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        last_scan_at=asset.last_scan_at
    )


@router.delete("/{asset_id}", summary="Delete asset", status_code=204)
async def delete_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete asset and associated data.
    """
    # Check if asset exists
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Delete asset (cascading deletes will handle scans and vulnerabilities)
    await db.delete(asset)
    await db.commit()


@router.get("/{asset_id}/scans", summary="Get asset scans")
async def get_asset_scans(
    asset_id: UUID,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get scans for a specific asset.
    """
    # Verify asset exists
    asset_result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    if not asset_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Get scans for asset
    offset = (pagination.page - 1) * pagination.size
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.asset_id == asset_id)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(pagination.size)
    )
    scans = scans_result.scalars().all()
    
    # Count total scans
    count_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.asset_id == asset_id)
    )
    total = count_result.scalar()
    
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=[
            ScanResponse(
                id=scan.id,
                asset_id=scan.asset_id,
                tool=scan.tool,
                status=scan.status,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                duration_seconds=scan.duration_seconds,
                findings_count=scan.findings_count,
                error_message=scan.error_message,
                celery_task_id=scan.celery_task_id,
                created_at=scan.created_at,
                created_by=scan.created_by,
                profile=scan.profile,
                options=scan.options or {}
            ) for scan in scans
        ],
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )


@router.get("/{asset_id}/vulnerabilities", summary="Get asset vulnerabilities")
async def get_asset_vulnerabilities(
    asset_id: UUID,
    pagination: PaginationParams = Depends(),
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get vulnerabilities for a specific asset.
    """
    # Verify asset exists
    asset_result = await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    if not asset_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Build vulnerability query
    query = select(Vulnerability).where(Vulnerability.asset_id == asset_id)
    
    # Apply filters
    if severity:
        query = query.where(Vulnerability.severity.in_(severity))
    if status:
        query = query.where(Vulnerability.status.in_(status))
    
    # Count total
    count_query = select(func.count(Vulnerability.id)).where(Vulnerability.asset_id == asset_id)
    if severity:
        count_query = count_query.where(Vulnerability.severity.in_(severity))
    if status:
        count_query = count_query.where(Vulnerability.status.in_(status))
    
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    
    # Apply pagination
    offset = (pagination.page - 1) * pagination.size
    query = query.order_by(Vulnerability.first_seen.desc()).offset(offset).limit(pagination.size)
    
    # Execute query
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()
    
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=[
            VulnerabilityResponse(
                id=vuln.id,
                name=vuln.name,
                description=vuln.description,
                severity=vuln.severity,
                cvss_score=vuln.cvss_score,
                cve_id=vuln.cve_id,
                host=vuln.host,
                port=vuln.port,
                protocol=vuln.protocol,
                service=vuln.service,
                status=vuln.status,
                first_seen=vuln.first_seen,
                last_seen=vuln.last_seen,
                asset_id=vuln.asset_id,
                scan_id=vuln.scan_id,
                evidence=vuln.evidence or {},
                recommendation=vuln.recommendation
            ) for vuln in vulnerabilities
        ],
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )
