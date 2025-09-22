from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
from components.auth.models import User
from components.auth.dependencies import get_current_user, require_editor_role
from core.security import security
from typing import List, Optional
import asyncio
from sse_starlette.sse import EventSourceResponse
import logging
import json
from uuid import UUID

router = APIRouter(tags=["Editor Dashboard"])
logger = logging.getLogger(__name__)

# Global list to hold Editor SSE clients
editor_sse_clients: List[asyncio.Queue] = []

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

        # Check if user has editor privileges
        if not result.is_editor:
            logger.warning(f"Non-editor user attempted SSE access: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Editor privileges required"
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
async def get_editor_dashboard_data(
    current_user: User = Depends(require_editor_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Fetches all initial data for the authenticated editor's dashboard.
    """
    editor_id = str(current_user.user_id)
    logger.info(f"Fetching editor dashboard data for editor: {current_user.username} (ID: {editor_id})")
    
    from components.editorDashboard.service import EditorService
    
    try:
        # Get assignments for this editor
        assignments = await EditorService.get_editor_assignments(db, editor_id)
        logger.info(f"✅ Fetched {len(assignments)} assignments for editor {current_user.username}")
        
        # Get editor stats
        stats = await EditorService.get_editor_stats(db, editor_id)
        logger.info(f"✅ Fetched editor stats: {stats}")
        
        # Get editor profile info - use current_user data directly
        editor_profile = {
            "user_id": str(current_user.user_id),
            "full_name": current_user.full_name,
            "username": current_user.username,
            "email": current_user.email,
            "role": current_user.role.value,
            "is_verified": current_user.is_verified,
            "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        }
        
        logger.info(f"✅ Using authenticated user profile: {current_user.full_name}")
        
        return {
            "assignments": assignments,
            "stats": stats,
            "editor_profile": editor_profile
        }
        
    except HTTPException as e:
        logger.error(f"Service HTTPException: {e.detail}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error fetching editor dashboard data: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch editor dashboard data"
        )

@router.get("/dashboard-stream")
async def editor_dashboard_stream(
    request: Request,
    current_user: User = Depends(get_current_user_from_token_param),  # ✅ Use token param auth
    db: AsyncSession = Depends(get_db)
):
    """
    Establishes an SSE connection for real-time editor dashboard updates.
    Uses token from query parameter since SSE doesn't support custom headers.
    """
    editor_id = str(current_user.user_id)
    
    # Create a new Queue for this editor client
    client_queue = asyncio.Queue()
    editor_sse_clients.append(client_queue)
    
    logger.info(f"✅ New Editor SSE client connected for editor: {current_user.username} (ID: {editor_id})")

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    logger.info(f"Editor SSE client disconnected for {current_user.username}.")
                    break
                
                try:
                    # Wait for new messages from the queue
                    message = await asyncio.wait_for(client_queue.get(), timeout=30.0)
                    
                    # Filter messages for this specific editor
                    if isinstance(message, dict):
                        message_data = message.get("data")
                        if message_data:
                            try:
                                parsed_data = json.loads(message_data) if isinstance(message_data, str) else message_data
                                # Only send if message is for this editor
                                if parsed_data.get("assigned_editor_id") == editor_id:
                                    logger.info(f"📡 Sending editor update to {current_user.username}: {parsed_data.get('event', 'unknown')}")
                                    yield {
                                        "event": message.get("event", "update"),
                                        "data": message.get("data", "")
                                    }
                            except (json.JSONDecodeError, AttributeError):
                                # Send all non-filtered messages
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
            if client_queue in editor_sse_clients:
                editor_sse_clients.remove(client_queue)
                logger.info(f"Editor SSE client queue removed for {current_user.username}.")

    return EventSourceResponse(event_generator())

@router.post("/complete-assignment")
async def complete_assignment(
    assignment_id: str,
    completed_video_url: str,
    editor_notes: Optional[str] = None,
    current_user: User = Depends(require_editor_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Complete an assignment with the edited video URL.
    Uses authenticated user's ID.
    """
    editor_id = str(current_user.user_id)
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"🎯 Completing assignment {assignment_id} for editor {current_user.username}")
        
        # Verify assignment belongs to this editor
        assignments = await EditorService.get_editor_assignments(db, editor_id)
        assignment_exists = any(a["assignment_id"] == assignment_id for a in assignments)
        
        if not assignment_exists:
            logger.warning(f"❌ Assignment {assignment_id} not found for editor {current_user.username}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assignment not found or not assigned to this editor"
            )
        
        result = await EditorService.complete_assignment(
            db, assignment_id, completed_video_url, editor_notes
        )
        
        logger.info(f"✅ Assignment {assignment_id} completed successfully by {current_user.username}")
        return {"message": "Assignment completed successfully", "data": result, "success": True}
        
    except ValueError as e:
        logger.error(f"❌ ValueError completing assignment {assignment_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to complete assignment {assignment_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete assignment"
        )

@router.post("/update-notes")
async def update_editor_notes(
    assignment_id: str,
    editor_notes: str,
    current_user: User = Depends(require_editor_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Update editor notes for an assignment.
    Uses authenticated user's ID.
    """
    editor_id = str(current_user.user_id)
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"📝 Updating notes for assignment {assignment_id} by {current_user.username}")
        
        # Verify assignment belongs to this editor
        assignments = await EditorService.get_editor_assignments(db, editor_id)
        assignment_exists = any(a["assignment_id"] == assignment_id for a in assignments)
        
        if not assignment_exists:
            logger.warning(f"❌ Assignment {assignment_id} not found for editor {current_user.username}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assignment not found or not assigned to this editor"
            )
        
        result = await EditorService.update_editor_notes(db, assignment_id, editor_notes)
        
        logger.info(f"✅ Notes updated for assignment {assignment_id} by {current_user.username}")
        return {"message": "Editor notes updated successfully", "data": result, "success": True}
        
    except ValueError as e:
        logger.error(f"❌ ValueError updating notes for {assignment_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to update notes for assignment {assignment_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update editor notes"
        )

@router.get("/assignments/{assignment_id}")
async def get_assignment_details(
    assignment_id: str,
    current_user: User = Depends(require_editor_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific assignment.
    Uses authenticated user's ID.
    """
    editor_id = str(current_user.user_id)
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"📋 Fetching assignment details for {assignment_id} by {current_user.username}")
        
        assignments = await EditorService.get_editor_assignments(db, editor_id)
        assignment = next((a for a in assignments if a["assignment_id"] == assignment_id), None)
        
        if not assignment:
            logger.warning(f"❌ Assignment {assignment_id} not found for editor {current_user.username}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assignment not found or not assigned to this editor"
            )
        
        logger.info(f"✅ Found assignment details for {assignment_id}")
        return {"assignment": assignment}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"💥 Failed to get assignment details {assignment_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get assignment details"
        )

@router.get("/stats")
async def get_editor_stats(
    current_user: User = Depends(require_editor_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Get statistics for the authenticated editor.
    """
    editor_id = str(current_user.user_id)
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"📊 Fetching editor stats for {current_user.username}")
        stats = await EditorService.get_editor_stats(db, editor_id)
        
        logger.info(f"✅ Editor stats fetched for {current_user.username}: {stats}")
        return {"stats": stats}
        
    except Exception as e:
        logger.error(f"💥 Failed to get editor stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get editor stats"
        )

@router.get("/profile")
async def get_editor_profile(
    current_user: User = Depends(require_editor_role)
):
    """
    Get the authenticated editor's profile information.
    """
    logger.info(f"👤 Fetching profile for editor {current_user.username}")
    
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

# ✅ Function to broadcast updates to all editor SSE clients
async def broadcast_to_editor_clients(message: dict):
    """
    Broadcast a message to all connected editor SSE clients
    """
    if not editor_sse_clients:
        logger.info("No editor SSE clients to broadcast to")
        return
    
    logger.info(f"Broadcasting to {len(editor_sse_clients)} editor SSE clients")
    
    # Create a copy of the list to avoid modification during iteration
    clients_copy = editor_sse_clients.copy()
    
    for client_queue in clients_copy:
        try:
            # Non-blocking put with immediate timeout
            client_queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("Editor SSE client queue is full, removing client")
            if client_queue in editor_sse_clients:
                editor_sse_clients.remove(client_queue)
        except Exception as e:
            logger.error(f"Error broadcasting to editor SSE client: {e}")
            if client_queue in editor_sse_clients:
                editor_sse_clients.remove(client_queue)
