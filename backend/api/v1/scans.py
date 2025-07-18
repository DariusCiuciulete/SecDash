"""
Scan management API endpoints
"""
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from celery.result import AsyncResult

from database import get_db_session
from models import Scan, Asset, ScanStatus, ScanTool
from schemas import (
    ScanResponse, ScanDetailResponse, ScanCreate, ScanUpdate, ScanFilter,
    PaginationParams, PaginatedResponse
)
from celery_app import celery_app

router = APIRouter()


@router.get("/", summary="List scans", response_model=PaginatedResponse)
async def list_scans(
    pagination: PaginationParams = Depends(),
    filters: ScanFilter = Depends(),
    db: AsyncSession = Depends(get_db_session)
):
    """
    List scans with filtering and pagination.
    """
    # Build query
    query = select(Scan)
    
    # Apply filters
    conditions = []
    if filters.tool:
        conditions.append(Scan.tool == filters.tool)
    if filters.status:
        conditions.append(Scan.status == filters.status)
    if filters.asset_id:
        conditions.append(Scan.asset_id == filters.asset_id)
    if filters.date_from:
        conditions.append(Scan.created_at >= filters.date_from)
    if filters.date_to:
        conditions.append(Scan.created_at <= filters.date_to)
    
    if conditions:
        query = query.where(and_(*conditions))
    
    # Count total items
    count_query = select(func.count(Scan.id))
    if conditions:
        count_query = count_query.where(and_(*conditions))
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (pagination.page - 1) * pagination.size
    query = query.offset(offset).limit(pagination.size)
    query = query.order_by(Scan.created_at.desc())
    
    # Execute query
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Calculate pagination info
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=[ScanResponse.model_validate(scan) for scan in scans],
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )


@router.post("/", summary="Create scan", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create and start a new security scan.
    """
    # Verify asset exists
    asset_result = await db.execute(
        select(Asset).where(Asset.id == scan_data.asset_id)
    )
    asset = asset_result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Create scan record
    scan = Scan(**scan_data.model_dump())
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Submit scan to Celery worker
    try:
        task = celery_app.send_task(
            "execute_scan",
            args=[str(scan.id)],
            queue="scans"
        )
        
        # Update scan with Celery task ID
        scan.celery_task_id = task.id
        await db.commit()
        
    except Exception as e:
        # Update scan status to failed if task submission fails
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Failed to submit scan task: {str(e)}"
        await db.commit()
        raise HTTPException(
            status_code=500, 
            detail="Failed to start scan"
        )
    
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", summary="Get scan", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get scan details by ID.
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanDetailResponse.model_validate(scan)


@router.patch("/{scan_id}", summary="Update scan", response_model=ScanResponse)
async def update_scan(
    scan_id: UUID,
    scan_data: ScanUpdate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update scan status or other fields.
    """
    # Get existing scan
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Apply updates
    update_data = scan_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scan, field, value)
    
    await db.commit()
    await db.refresh(scan)
    
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel", summary="Cancel scan")
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Cancel a running scan.
    """
    # Get scan
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in [ScanStatus.QUEUED, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400, 
            detail="Can only cancel queued or running scans"
        )
    
    # Cancel Celery task if exists
    if scan.celery_task_id:
        try:
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception as e:
            print(f"Failed to cancel Celery task {scan.celery_task_id}: {e}")
    
    # Update scan status
    scan.status = ScanStatus.CANCELLED
    await db.commit()
    
    return {"message": "Scan cancelled successfully"}


@router.get("/{scan_id}/status", summary="Get scan status")
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get real-time scan status including Celery task progress.
    """
    # Get scan from database
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    response = {
        "scan_id": str(scan.id),
        "status": scan.status,
        "created_at": scan.created_at.replace(tzinfo=timezone.utc).isoformat() if scan.created_at else None,
        "started_at": scan.started_at.replace(tzinfo=timezone.utc).isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.replace(tzinfo=timezone.utc).isoformat() if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "findings_count": scan.findings_count,
        "error_message": scan.error_message,
        "progress": 0,
        "progress_message": "Unknown"
    }
    
    # Calculate progress based on status
    if scan.status == ScanStatus.QUEUED:
        response["progress"] = 5
        response["progress_message"] = "Scan queued"
    elif scan.status == ScanStatus.RUNNING:
        response["progress"] = 50
        response["progress_message"] = "Scan in progress"
        # If we have a start time, calculate an estimated progress
        if scan.started_at:
            elapsed = (datetime.utcnow() - scan.started_at).total_seconds()
            # Estimate 5 minutes for a typical scan, adjust progress accordingly
            estimated_duration = 300  # 5 minutes
            calculated_progress = min(90, 20 + (elapsed / estimated_duration * 70))
            response["progress"] = int(calculated_progress)
    elif scan.status == ScanStatus.COMPLETED:
        response["progress"] = 100
        response["progress_message"] = f"Completed with {scan.findings_count or 0} findings"
    elif scan.status == ScanStatus.FAILED:
        response["progress"] = 0
        response["progress_message"] = f"Failed: {scan.error_message or 'Unknown error'}"
    elif scan.status == ScanStatus.CANCELLED:
        response["progress"] = 0
        response["progress_message"] = "Scan cancelled"
    
    # Get Celery task status if available
    if scan.celery_task_id:
        try:
            task_result = AsyncResult(scan.celery_task_id, app=celery_app)
            response["task_status"] = task_result.status
            
            # Get detailed progress from Celery task
            if task_result.status == "PROGRESS" and task_result.info:
                task_info = task_result.info
                if isinstance(task_info, dict):
                    response["progress"] = task_info.get("progress", response["progress"])
                    response["progress_message"] = task_info.get("message", response["progress_message"])
                    response["task_step"] = task_info.get("step", "unknown")
            
            response["task_info"] = task_result.info
        except Exception as e:
            response["task_status"] = "UNKNOWN"
            response["task_info"] = f"Error getting task status: {str(e)}"
    
    return response


@router.delete("/{scan_id}", summary="Delete scan", status_code=204)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete scan and associated data.
    """
    # Check if scan exists
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Cancel scan if running
    if scan.status in [ScanStatus.QUEUED, ScanStatus.RUNNING] and scan.celery_task_id:
        try:
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception:
            pass  # Continue with deletion even if cancellation fails
    
    # Delete scan
    await db.delete(scan)
    await db.commit()


@router.get("/stats/overview", summary="Get scan statistics")
async def get_scan_stats(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get overview statistics for scans.
    """
    # Count scans by status
    status_counts = {}
    for status in ScanStatus:
        count_result = await db.execute(
            select(func.count(Scan.id)).where(Scan.status == status)
        )
        status_counts[status.value] = count_result.scalar()
    
    # Count scans by tool
    tool_counts = {}
    for tool in ScanTool:
        count_result = await db.execute(
            select(func.count(Scan.id)).where(Scan.tool == tool)
        )
        tool_counts[tool.value] = count_result.scalar()
    
    # Total scans
    total_result = await db.execute(select(func.count(Scan.id)))
    total_scans = total_result.scalar()
    
    return {
        "total_scans": total_scans,
        "status_counts": status_counts,
        "tool_counts": tool_counts,
    }
