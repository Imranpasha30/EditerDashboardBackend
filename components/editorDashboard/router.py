from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
from components.auth.models import User
from typing import List, Optional
import asyncio
from sse_starlette.sse import EventSourceResponse
import logging
import json

router = APIRouter(tags=["Editor Dashboard"])
logger = logging.getLogger(__name__)

# Global list to hold Editor SSE clients
editor_sse_clients: List[asyncio.Queue] = []

# Default editor ID (temporary until auth is complete)
DEFAULT_EDITOR_ID = "5b6a490e-25df-4011-ae79-1a0dd4fb1fa4"

@router.get("/dashboard-data", response_model=None)
async def get_editor_dashboard_data(
    editor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Fetches all initial data for the editor dashboard.
    """
    current_editor_id = editor_id or DEFAULT_EDITOR_ID
    logger.info(f"Fetching editor dashboard data for editor: {current_editor_id}")
    
    from components.editorDashboard.service import EditorService
    
    try:
        # Get assignments for this editor
        assignments = await EditorService.get_editor_assignments(db, current_editor_id)
        logger.info(f"✅ Fetched {len(assignments)} assignments for editor")
        
        # Get editor stats
        stats = await EditorService.get_editor_stats(db, current_editor_id)
        logger.info(f"✅ Fetched editor stats: {stats}")
        
        # Get editor profile info
        editor_profile = await EditorService.get_editor_profile(db, current_editor_id)
        logger.info(f"✅ Fetched editor profile: {editor_profile.get('full_name', 'Unknown')}")
        
        return {
            "assignments": assignments,
            "stats": stats,
            "editor_profile": editor_profile
        }
        
    except HTTPException as e:
        # Re-raise HTTPExceptions from service layer
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
    editor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Establishes an SSE connection for real-time editor dashboard updates.
    """
    current_editor_id = editor_id or DEFAULT_EDITOR_ID
    
    # Create a new Queue for this editor client
    client_queue = asyncio.Queue()
    editor_sse_clients.append(client_queue)
    
    logger.info(f"New Editor SSE client connected for editor: {current_editor_id}")

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    logger.info("Editor SSE client disconnected.")
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
                                if parsed_data.get("assigned_editor_id") == current_editor_id:
                                    logger.info(f"📡 Sending editor update: {parsed_data.get('event', 'unknown')}")
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
                logger.info("Editor SSE client queue removed from active clients.")

    return EventSourceResponse(event_generator())

@router.post("/complete-assignment")
async def complete_assignment(
    assignment_id: str,
    completed_video_url: str,
    editor_notes: Optional[str] = None,
    editor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Complete an assignment with the edited video URL.
    """
    current_editor_id = editor_id or DEFAULT_EDITOR_ID
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"🎯 Completing assignment {assignment_id} for editor {current_editor_id}")
        
        # Verify assignment belongs to this editor
        assignments = await EditorService.get_editor_assignments(db, current_editor_id)
        assignment_exists = any(a["assignment_id"] == assignment_id for a in assignments)
        
        if not assignment_exists:
            logger.warning(f"❌ Assignment {assignment_id} not found for editor {current_editor_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assignment not found or not assigned to this editor"
            )
        
        result = await EditorService.complete_assignment(
            db, assignment_id, completed_video_url, editor_notes
        )
        
        logger.info(f"✅ Assignment {assignment_id} completed successfully")
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
    editor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Update editor notes for an assignment.
    """
    current_editor_id = editor_id or DEFAULT_EDITOR_ID
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"📝 Updating notes for assignment {assignment_id}")
        
        # Verify assignment belongs to this editor
        assignments = await EditorService.get_editor_assignments(db, current_editor_id)
        assignment_exists = any(a["assignment_id"] == assignment_id for a in assignments)
        
        if not assignment_exists:
            logger.warning(f"❌ Assignment {assignment_id} not found for editor {current_editor_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Assignment not found or not assigned to this editor"
            )
        
        result = await EditorService.update_editor_notes(db, assignment_id, editor_notes)
        
        logger.info(f"✅ Notes updated for assignment {assignment_id}")
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
    editor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific assignment.
    """
    current_editor_id = editor_id or DEFAULT_EDITOR_ID
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"📋 Fetching assignment details for {assignment_id}")
        
        assignments = await EditorService.get_editor_assignments(db, current_editor_id)
        assignment = next((a for a in assignments if a["assignment_id"] == assignment_id), None)
        
        if not assignment:
            logger.warning(f"❌ Assignment {assignment_id} not found for editor {current_editor_id}")
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
    editor_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get statistics for the current editor.
    """
    current_editor_id = editor_id or DEFAULT_EDITOR_ID
    
    try:
        from components.editorDashboard.service import EditorService
        
        logger.info(f"📊 Fetching editor stats for {current_editor_id}")
        stats = await EditorService.get_editor_stats(db, current_editor_id)
        
        logger.info(f"✅ Editor stats fetched: {stats}")
        return {"stats": stats}
        
    except Exception as e:
        logger.error(f"💥 Failed to get editor stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get editor stats"
        )
