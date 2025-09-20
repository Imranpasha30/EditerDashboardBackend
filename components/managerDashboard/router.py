# D:\EditerDashboard\components\managerDashboard\router.py

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
# Temporarily commented out authentication dependency
# from components.auth.dependencies import require_manager_role 
from components.auth.models import User
from components.submissions.models import VideoSubmission, SubmissionStatus
from typing import List
import asyncio
from sse_starlette.sse import EventSourceResponse
import logging
import json

router = APIRouter(tags=["Manager Dashboard"])
logger = logging.getLogger(__name__)

# Global list to hold SSE clients
sse_clients: List[asyncio.Queue] = []

@router.get("/dashboard-data", response_model=None)
async def get_initial_dashboard_data(
    # The dependency has been removed to allow unauthenticated access
    db: AsyncSession = Depends(get_db)
):
    """
    Fetches all initial data for the manager dashboard.
    """
    logger.info("Fetching initial dashboard data without authentication.")
    from components.managerDashboard.service import ManagerService
    submissions = await ManagerService.get_all_submissions(db)
    editors = await ManagerService.get_all_editors(db)
    
    return {
        "submissions": submissions,
        "editors": editors
    }

@router.get("/dashboard-stream")
async def dashboard_event_stream(
    request: Request,
    # The dependency has been removed to allow unauthenticated access
    db: AsyncSession = Depends(get_db)
):
    """
    Establishes an SSE connection to stream real-time dashboard updates.
    """
    # Create a new Queue for this client and add it to the global list
    client_queue = asyncio.Queue()
    sse_clients.append(client_queue)
    
    logger.info("New SSE client connected without authentication.")

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    logger.info("SSE client disconnected.")
                    break
                
                try:
                    # Wait for new messages from the queue
                    message = await asyncio.wait_for(client_queue.get(), timeout=30.0)
                    
                    # Format the SSE message properly
                    if isinstance(message, dict):
                        # Format: event: update\ndata: {json_data}\n\n
                        yield {
                            "event": message.get("event", "update"),
                            "data": message.get("data", "")
                        }
                    else:
                        # Fallback for string messages
                        yield {"data": str(message)}
                        
                except asyncio.TimeoutError:
                    # Send a keep-alive message to prevent connection from closing
                    yield {"event": "keep-alive", "data": "ping"}
        finally:
            # Clean up the queue when the client disconnects
            if client_queue in sse_clients:
                sse_clients.remove(client_queue)
                logger.info("SSE client queue removed from active clients.")

    return EventSourceResponse(event_generator())

@router.post("/update-submission-status")
async def update_submission(
    submission_id: str,
    new_status: str,
    assigned_editor_id: str = None,
    # The dependency has been removed to allow unauthenticated access
    db: AsyncSession = Depends(get_db)
):
    """
    Endpoint for a manager to change a submission's status.
    """
    try:
        from components.managerDashboard.service import ManagerService
        updated_submission = await ManagerService.update_submission_status(
            db, submission_id, new_status, assigned_editor_id
        )
        return {"message": "Submission updated successfully", "success": True}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Failed to update submission {submission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update submission status"
        )
