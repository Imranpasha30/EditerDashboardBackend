from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
from components.auth.models import User, UserRole
from typing import List, Optional
import asyncio
from sse_starlette.sse import EventSourceResponse
import logging
import json
from pydantic import BaseModel, EmailStr

router = APIRouter(tags=["Admin Dashboard"])
logger = logging.getLogger(__name__)

# Global list to hold Admin SSE clients
admin_sse_clients: List[asyncio.Queue] = []

# Pydantic models for request validation
class CreateUserRequest(BaseModel):
    full_name: str
    email: EmailStr
    role: str

class UpdateUserRoleRequest(BaseModel):
    user_id: str
    new_role: str

@router.get("/dashboard-data", response_model=None)
async def get_admin_dashboard_data(
    db: AsyncSession = Depends(get_db)
):
    """
    Fetches all initial data for the admin dashboard.
    """
    logger.info("Fetching admin dashboard data")
    
    from components.adminDashboard.service import AdminService
    
    try:
        # Get comprehensive dashboard data
        overview = await AdminService.get_dashboard_overview(db)
        daily_submissions = await AdminService.get_daily_submissions_data(db, days=7)
        editor_performance = await AdminService.get_editor_performance_data(db)
        volunteer_performance = await AdminService.get_volunteer_performance_data(db)
        recent_submissions = await AdminService.get_recent_submissions(db, limit=10)
        assignments = await AdminService.get_all_assignments(db)
        users = await AdminService.get_all_users(db)
        
        logger.info("✅ Successfully fetched all admin dashboard data")
        
        return {
            "overview": overview,
            "daily_submissions": daily_submissions,
            "editor_performance": editor_performance,
            "volunteer_performance": volunteer_performance,
            "recent_submissions": recent_submissions,
            "assignments": assignments,
            "users": users
        }
        
    except HTTPException as e:
        logger.error(f"Service HTTPException: {e.detail}")
        raise e
    except Exception as e:
        logger.error(f"💥 Unexpected error fetching admin dashboard data: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch admin dashboard data"
        )

@router.get("/dashboard-stream")
async def admin_dashboard_stream(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Establishes an SSE connection for real-time admin dashboard updates.
    """
    # Create a new Queue for this admin client
    client_queue = asyncio.Queue()
    admin_sse_clients.append(client_queue)
    
    logger.info("New Admin SSE client connected")

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    logger.info("Admin SSE client disconnected.")
                    break
                
                try:
                    # Wait for new messages from the queue
                    message = await asyncio.wait_for(client_queue.get(), timeout=30.0)
                    
                    if isinstance(message, dict):
                        logger.info(f"📡 Sending admin update: {message.get('event', 'unknown')}")
                        yield {
                            "event": message.get("event", "update"),
                            "data": message.get("data", "")
                        }
                    else:
                        yield {"data": str(message)}
                        
                except asyncio.TimeoutError:
                    # Send keep-alive message
                    yield {"event": "keep-alive", "data": "ping"}
        finally:
            # Clean up the queue when client disconnects
            if client_queue in admin_sse_clients:
                admin_sse_clients.remove(client_queue)
                logger.info("Admin SSE client queue removed from active clients.")

    return EventSourceResponse(event_generator())

@router.get("/analytics/overview")
async def get_analytics_overview(
    db: AsyncSession = Depends(get_db)
):
    """
    Get analytics overview data.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info("📊 Fetching analytics overview")
        overview = await AdminService.get_dashboard_overview(db)
        
        return {"overview": overview}
        
    except Exception as e:
        logger.error(f"💥 Failed to get analytics overview: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get analytics overview"
        )

@router.get("/analytics/daily-submissions")
async def get_daily_submissions_analytics(
    days: Optional[int] = 7,
    db: AsyncSession = Depends(get_db)
):
    """
    Get daily submissions analytics for specified number of days.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info(f"📈 Fetching daily submissions analytics for {days} days")
        daily_data = await AdminService.get_daily_submissions_data(db, days)
        
        return {"daily_submissions": daily_data}
        
    except Exception as e:
        logger.error(f"💥 Failed to get daily submissions analytics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get daily submissions analytics"
        )

@router.get("/analytics/performance")
async def get_performance_analytics(
    db: AsyncSession = Depends(get_db)
):
    """
    Get editor and volunteer performance analytics.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info("🎯 Fetching performance analytics")
        editor_performance = await AdminService.get_editor_performance_data(db)
        volunteer_performance = await AdminService.get_volunteer_performance_data(db)
        
        return {
            "editor_performance": editor_performance,
            "volunteer_performance": volunteer_performance
        }
        
    except Exception as e:
        logger.error(f"💥 Failed to get performance analytics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get performance analytics"
        )

@router.get("/management/users")
async def get_all_users(
    db: AsyncSession = Depends(get_db)
):
    """
    Get all users for management.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info("👥 Fetching all users for management")
        users = await AdminService.get_all_users(db)
        
        return {"users": users}
        
    except Exception as e:
        logger.error(f"💥 Failed to get users: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get users"
        )

@router.post("/management/users")
async def create_new_user(
    user_data: CreateUserRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new user.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info(f"👤 Creating new user: {user_data.email}")
        new_user = await AdminService.create_user(
            db, 
            user_data.full_name, 
            user_data.email, 
            user_data.role
        )
        
        # Broadcast to admin SSE clients
        sse_message = {
            "event": "admin-update",
            "data": json.dumps({
                "event": "user_created",
                "user": new_user
            })
        }
        
        for client_queue in admin_sse_clients:
            try:
                client_queue.put_nowait(sse_message)
            except asyncio.QueueFull:
                logger.warning("⚠️ Admin client queue is full")
        
        return {"message": "User created successfully", "user": new_user, "success": True}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to create user: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

@router.put("/management/users/role")
async def update_user_role(
    role_update: UpdateUserRoleRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Update user role.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info(f"🔄 Updating user role: {role_update.user_id} to {role_update.new_role}")
        result = await AdminService.update_user_role(
            db, 
            role_update.user_id, 
            role_update.new_role
        )
        
        # Broadcast to admin SSE clients
        sse_message = {
            "event": "admin-update",
            "data": json.dumps({
                "event": "user_role_updated",
                "update": result
            })
        }
        
        for client_queue in admin_sse_clients:
            try:
                client_queue.put_nowait(sse_message)
            except asyncio.QueueFull:
                logger.warning("⚠️ Admin client queue is full")
        
        return {"message": "User role updated successfully", "update": result, "success": True}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to update user role: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user role"
        )

@router.post("/management/users/{user_id}/toggle-status")
async def toggle_user_status(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Toggle user active status.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info(f"🔄 Toggling user status: {user_id}")
        result = await AdminService.toggle_user_status(db, user_id)
        
        # Broadcast to admin SSE clients
        sse_message = {
            "event": "admin-update",
            "data": json.dumps({
                "event": "user_status_toggled",
                "update": result
            })
        }
        
        for client_queue in admin_sse_clients:
            try:
                client_queue.put_nowait(sse_message)
            except asyncio.QueueFull:
                logger.warning("⚠️ Admin client queue is full")
        
        return {"message": "User status updated successfully", "update": result, "success": True}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to toggle user status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle user status"
        )

@router.get("/assignments")
async def get_all_assignments(
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get all assignments with optional status filtering.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info(f"📋 Fetching all assignments (filter: {status_filter})")
        assignments = await AdminService.get_all_assignments(db)
        
        # Apply status filter if provided
        if status_filter:
            assignments = [a for a in assignments if a["status"] == status_filter]
        
        return {"assignments": assignments}
        
    except Exception as e:
        logger.error(f"💥 Failed to get assignments: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get assignments"
        )

@router.get("/submissions/recent")
async def get_recent_submissions(
    limit: Optional[int] = 10,
    db: AsyncSession = Depends(get_db)
):
    """
    Get recent submissions.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info(f"📝 Fetching {limit} recent submissions")
        submissions = await AdminService.get_recent_submissions(db, limit)
        
        return {"submissions": submissions}
        
    except Exception as e:
        logger.error(f"💥 Failed to get recent submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get recent submissions"
        )

@router.get("/stats/summary")
async def get_stats_summary(
    db: AsyncSession = Depends(get_db)
):
    """
    Get summary statistics for admin dashboard.
    """
    try:
        from components.adminDashboard.service import AdminService
        
        logger.info("📊 Fetching stats summary")
        overview = await AdminService.get_dashboard_overview(db)
        
        # Calculate additional stats
        week_data = await AdminService.get_daily_submissions_data(db, days=7)
        week_total = sum(day["submissions"] for day in week_data)
        week_completed = sum(day["completed"] for day in week_data)
        
        return {
            "summary": {
                **overview,
                "week_submissions": week_total,
                "week_completed": week_completed,
                "completion_rate": round((week_completed / week_total * 100) if week_total > 0 else 0, 1)
            }
        }
        
    except Exception as e:
        logger.error(f"💥 Failed to get stats summary: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get stats summary"
        )
