from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
from components.auth.models import User
from components.auth.dependencies import get_current_user, require_manager_role
from core.security import security
from typing import List, Optional
import asyncio
from sse_starlette.sse import EventSourceResponse
import logging
import json
from uuid import UUID

router = APIRouter(tags=["Manager Dashboard"])
logger = logging.getLogger(__name__)

# Global list to hold Manager SSE clients
sse_clients: List[asyncio.Queue] = []

# ✅ Custom dependency for SSE token authentication
async def get_current_user_from_token_param(
    token: str = Query(..., description="JWT token for SSE authentication"),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Authenticate user from token query parameter (for SSE endpoints)
    SSE cannot use Authorization headers, so we use query parameters
    """
    try:
        # Verify and decode token with blacklist check
        payload = await security.verify_token(token, db=db, token_type="access")
        user_id: str = payload.get("user_id")
        
        if user_id is None:
            logger.error("No user_id in SSE token payload")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Convert to UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            logger.error(f"Invalid UUID in SSE token: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user from database
        result = await db.get(User, user_uuid)
        if not result:
            logger.error(f"User not found with ID: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not result.is_active:
            logger.warning(f"Inactive user attempted SSE access: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user account"
            )

        # Check if user has manager privileges
        if not result.is_manager:
            logger.warning(f"Non-manager user attempted SSE access: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Manager privileges required"
            )
            
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SSE Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.get("/dashboard-data", response_model=None)
async def get_initial_dashboard_data(
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Fetches all initial data for the authenticated manager's dashboard.
    """
    manager_id = str(current_user.user_id)
    logger.info(f"Fetching manager dashboard data for manager: {current_user.username} (ID: {manager_id})")
    
    from components.managerDashboard.service import ManagerService
    
    try:
        # Get all submissions and editors
        submissions = await ManagerService.get_all_submissions(db)
        editors = await ManagerService.get_all_editors(db)
        
        # Get manager profile info - use current_user data directly
        manager_profile = {
            "user_id": str(current_user.user_id),
            "full_name": current_user.full_name,
            "username": current_user.username,
            "email": current_user.email,
            "role": current_user.role.value,
            "is_verified": current_user.is_verified,
            "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        }
        
        logger.info(f"✅ Fetched {len(submissions)} submissions and {len(editors)} editors for manager {current_user.username}")
        
        return {
            "submissions": submissions,
            "editors": editors,
            "manager_profile": manager_profile
        }
        
    except HTTPException as e:
        logger.error(f"Service HTTPException: {e.detail}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error fetching manager dashboard data: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch manager dashboard data"
        )

@router.get("/dashboard-stream")
async def dashboard_event_stream(
    request: Request,
    current_user: User = Depends(get_current_user_from_token_param),  # ✅ Use token param auth
    db: AsyncSession = Depends(get_db)
):
    """
    Establishes an SSE connection to stream real-time dashboard updates.
    Uses token from query parameter since SSE doesn't support custom headers.
    """
    manager_id = str(current_user.user_id)
    
    # Create a new Queue for this manager client
    client_queue = asyncio.Queue()
    sse_clients.append(client_queue)
    
    logger.info(f"✅ New Manager SSE client connected for manager: {current_user.username} (ID: {manager_id})")

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    logger.info(f"Manager SSE client disconnected for {current_user.username}.")
                    break
                
                try:
                    # Wait for new messages from the queue
                    message = await asyncio.wait_for(client_queue.get(), timeout=30.0)
                    
                    # Format the SSE message properly
                    if isinstance(message, dict):
                        yield {
                            "event": message.get("event", "update"),
                            "data": message.get("data", "")
                        }
                    else:
                        yield {"data": str(message)}
                        
                except asyncio.TimeoutError:
                    # Send a keep-alive message to prevent connection from closing
                    yield {"event": "keep-alive", "data": "ping"}
        finally:
            # Clean up the queue when the client disconnects
            if client_queue in sse_clients:
                sse_clients.remove(client_queue)
                logger.info(f"Manager SSE client queue removed for {current_user.username}.")

    return EventSourceResponse(event_generator())

@router.post("/update-submission-status")
async def update_submission_status(
    submission_id: str,
    new_status: str,
    assigned_editor_id: Optional[str] = None,
    decline_reason: Optional[str] = None,
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Endpoint for an authenticated manager to change a submission's status.
    """
    manager_id = str(current_user.user_id)
    
    try:
        from components.managerDashboard.service import ManagerService
        
        logger.info(f"🎯 Manager {current_user.username} updating submission {submission_id} to status {new_status}")
        
        # Handle decline reason if provided
        if decline_reason and new_status == "declined":
            updated_submission = await ManagerService.update_submission_status_with_reason(
                db, submission_id, new_status, assigned_editor_id, manager_id, decline_reason
            )
        else:
            updated_submission = await ManagerService.update_submission_status(
                db, submission_id, new_status, assigned_editor_id, manager_id
            )
        
        logger.info(f"✅ Submission {submission_id} updated successfully by manager {current_user.username}")
        return {"message": "Submission updated successfully", "success": True}
        
    except ValueError as e:
        logger.error(f"❌ ValueError updating submission {submission_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to update submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update submission status"
        )

@router.get("/editor-workload")
async def get_editor_workload(
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Get editor workload information for the sidebar.
    """
    try:
        from components.managerDashboard.service import ManagerService
        
        logger.info(f"📊 Fetching editor workload for manager {current_user.username}")
        workload = await ManagerService.get_editor_workload(db)
        
        return {"workload": workload}
        
    except Exception as e:
        logger.error(f"Failed to get editor workload: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get editor workload"
        )

@router.get("/assignment-counts")
async def get_assignment_counts(
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Get assignment counts for dashboard statistics.
    """
    try:
        from components.managerDashboard.service import ManagerService
        
        logger.info(f"📊 Fetching assignment counts for manager {current_user.username}")
        counts = await ManagerService.get_assignment_counts(db)
        
        return counts
        
    except Exception as e:
        logger.error(f"Failed to get assignment counts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get assignment counts"
        )

@router.get("/profile")
async def get_manager_profile(
    current_user: User = Depends(require_manager_role)
):
    """
    Get the authenticated manager's profile information.
    """
    logger.info(f"👤 Fetching profile for manager {current_user.username}")
    
    profile = {
        "user_id": str(current_user.user_id),
        "full_name": current_user.full_name,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        "updated_at": current_user.updated_at.isoformat() if current_user.updated_at else None
    }
    
    return {"profile": profile}
