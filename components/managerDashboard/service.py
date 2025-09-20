# D:\EditerDashboard\components\managerDashboard\service.py

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update
from components.submissions.models import VideoSubmission, SubmissionStatus, Volunteer, VideoAssignment, AssignmentStatus
from components.auth.models import User, UserRole
from fastapi import HTTPException, status
from typing import List, Dict, Any, Optional
import logging
from uuid import UUID
import json
import asyncio

logger = logging.getLogger(__name__)

class ManagerService:

    @staticmethod
    async def get_all_submissions(db: AsyncSession) -> List[Dict[str, Any]]:
        """Fetch all video submissions with volunteer name and assignment info."""
        try:
            # Query with LEFT JOIN to get assignment info if exists
            result = await db.execute(
                select(
                    VideoSubmission.id,
                    VideoSubmission.volunteer_id,
                    Volunteer.first_name.label('volunteer_name'),
                    VideoSubmission.video_platform_url.label('video_url'),
                    VideoSubmission.status,
                    VideoSubmission.created_at.label('received_at'),
                    VideoAssignment.assigned_editor_id,
                    VideoAssignment.id.label('assignment_id'),
                    VideoAssignment.status.label('assignment_status'),
                    User.full_name.label('assigned_editor_name')
                )
                .join(Volunteer, VideoSubmission.volunteer_id == Volunteer.id)
                .outerjoin(VideoAssignment, VideoSubmission.id == VideoAssignment.video_submission_id)
                .outerjoin(User, VideoAssignment.assigned_editor_id == User.user_id)
                .order_by(VideoSubmission.created_at.desc())
            )
            
            submissions = result.mappings().all()
            return [
                {
                    "id": str(sub.id),
                    "volunteer_id": sub.volunteer_id,
                    "volunteer_name": sub.volunteer_name,
                    "video_url": sub.video_url,
                    "status": sub.status,
                    "received_at": sub.received_at,
                    "assigned_editor_id": str(sub.assigned_editor_id) if sub.assigned_editor_id else None,
                    "assigned_editor_name": sub.assigned_editor_name,
                    "assignment_id": str(sub.assignment_id) if sub.assignment_id else None,
                    "assignment_status": sub.assignment_status
                }
                for sub in submissions
            ]
        except Exception as e:
            logger.error(f"Error fetching submissions: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch submissions"
            )

    @staticmethod
    async def get_all_editors(db: AsyncSession) -> List[Dict[str, Any]]:
        """Fetch all users with the EDITOR role."""
        try:
            result = await db.execute(
                select(User.user_id, User.full_name, User.is_active)
                .where(User.role == UserRole.EDITOR, User.is_active == True)
                .order_by(User.full_name)
            )
            editors = result.mappings().all()
            return [
                {"id": str(editor.user_id), "name": editor.full_name} 
                for editor in editors
            ]
        except Exception as e:
            logger.error(f"Error fetching editors: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch editors"
            )

    @staticmethod
    async def update_submission_status(
        db: AsyncSession, 
        submission_id: str, 
        new_status: str, 
        assigned_editor_id: Optional[str] = None,
        manager_id: Optional[str] = None
    ):
        """Update a video submission's status and handle assignments."""
        try:
            submission_uuid = UUID(submission_id)

            # Get the current submission
            submission = await db.get(VideoSubmission, submission_uuid)
            if not submission:
                raise ValueError("Submission not found.")

            # Validate status transition
            valid_statuses = [s.value for s in SubmissionStatus]
            if new_status not in valid_statuses:
                raise ValueError(f"Invalid status: {new_status}")

            # Handle different status transitions
            if new_status == "ASSIGNED" and assigned_editor_id:
                # Create assignment when status is set to ASSIGNED
                await ManagerService._create_assignment(
                    db, submission_uuid, assigned_editor_id, manager_id
                )
            elif new_status in ["DECLINED", "ACCEPTED", "USED"]:
                # For other statuses, just update the submission
                pass
            
            # Update the submission status
            submission.status = new_status
            
            await db.commit()
            await db.refresh(submission)
            
            # The database trigger will handle the notification
            return submission
            
        except ValueError as e:
            await db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to update submission {submission_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update submission status"
            )

    @staticmethod
    async def _create_assignment(
        db: AsyncSession,
        submission_id: UUID,
        editor_id: str,
        manager_id: Optional[str] = None
    ):
        """Create a new video assignment."""
        try:
            # Use a default manager if not provided (for backward compatibility)
            if not manager_id:
                # Get the first available manager/admin
                result = await db.execute(
                    select(User.user_id)
                    .where(User.role.in_([UserRole.MANAGER, UserRole.ADMIN]), User.is_active == True)
                    .limit(1)
                )
                manager = result.scalar_one_or_none()
                if not manager:
                    raise ValueError("No active manager found to create assignment")
                manager_id = str(manager)

            # Check if assignment already exists
            existing_assignment = await db.execute(
                select(VideoAssignment)
                .where(
                    VideoAssignment.video_submission_id == submission_id,
                    VideoAssignment.status.in_([AssignmentStatus.IN_PROGRESS, AssignmentStatus.REVISION_NEEDED])
                )
            )
            if existing_assignment.scalar_one_or_none():
                raise ValueError("Assignment already exists for this submission")

            # Create new assignment
            assignment = VideoAssignment(
                video_submission_id=submission_id,
                assigned_editor_id=UUID(editor_id),
                assigned_manager_id=UUID(manager_id),
                status=AssignmentStatus.IN_PROGRESS
            )
            
            db.add(assignment)
            await db.flush()  # Flush to get the ID
            
            logger.info(f"Created assignment {assignment.id} for submission {submission_id}")
            return assignment
            
        except Exception as e:
            logger.error(f"Failed to create assignment: {e}")
            raise

    @staticmethod
    async def get_assignment_counts(db: AsyncSession) -> Dict[str, int]:
        """Get assignment counts for dashboard statistics."""
        try:
            # Get counts for different assignment statuses
            result = await db.execute(
                select(VideoAssignment.status, db.func.count(VideoAssignment.id))
                .group_by(VideoAssignment.status)
            )
            
            counts = dict(result.mappings().all())
            
            # Also get submission counts
            submission_result = await db.execute(
                select(VideoSubmission.status, db.func.count(VideoSubmission.id))
                .group_by(VideoSubmission.status)
            )
            
            submission_counts = dict(submission_result.mappings().all())
            
            return {
                "assignments": counts,
                "submissions": submission_counts
            }
            
        except Exception as e:
            logger.error(f"Error fetching assignment counts: {e}")
            return {"assignments": {}, "submissions": {}}

    @staticmethod
    async def get_editor_workload(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get workload information for all editors."""
        try:
            result = await db.execute(
                select(
                    User.user_id,
                    User.full_name,
                    db.func.count(VideoAssignment.id).label('active_assignments')
                )
                .outerjoin(
                    VideoAssignment,
                    db.and_(
                        VideoAssignment.assigned_editor_id == User.user_id,
                        VideoAssignment.status == AssignmentStatus.IN_PROGRESS
                    )
                )
                .where(User.role == UserRole.EDITOR, User.is_active == True)
                .group_by(User.user_id, User.full_name)
                .order_by(User.full_name)
            )
            
            workload = result.mappings().all()
            return [
                {
                    "id": str(editor.user_id),
                    "name": editor.full_name,
                    "assignedCount": editor.active_assignments
                }
                for editor in workload
            ]
            
        except Exception as e:
            logger.error(f"Error fetching editor workload: {e}")
            return []


async def listen_and_broadcast_updates(db_url: str):
    """
    Listens for PostgreSQL NOTIFY events and broadcasts them to SSE clients.
    """
    # Import inside function to avoid circular dependency
    from components.managerDashboard.router import sse_clients
    import asyncpg
    
    conn = None
    notification_queue = asyncio.Queue()
    
    def notification_handler(connection, pid, channel, payload):
        """Handle incoming notifications from PostgreSQL"""
        try:
            # Parse the JSON payload
            parsed_payload = json.loads(payload)
            logger.info(f"Received notification from PID {pid} on channel '{channel}': {parsed_payload}")
            
            # Create a properly formatted SSE message
            sse_message = {
                "event": "dashboard-update",
                "data": json.dumps(parsed_payload)
            }
            
            # Put the notification in the queue for processing
            try:
                notification_queue.put_nowait(sse_message)
            except asyncio.QueueFull:
                logger.warning("Notification queue is full, dropping notification")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse notification payload: {e}")
        except Exception as e:
            logger.error(f"Error handling notification: {e}")
    
    try:
        # Connect to PostgreSQL using asyncpg
        conn = await asyncpg.connect(db_url)
        
        # Add notification listeners for both channels
        await conn.add_listener('video_updates', notification_handler)
        await conn.add_listener('editor_updates', notification_handler)
        logger.info("Connected to PostgreSQL and listening for notifications on 'video_updates' and 'editor_updates' channels.")

        # Main loop to process notifications and broadcast to SSE clients
        while True:
            try:
                # Wait for notifications with a timeout to allow for graceful cancellation
                sse_message = await asyncio.wait_for(
                    notification_queue.get(), 
                    timeout=30.0
                )
                
                # Broadcast the message to all connected SSE clients
                clients_to_remove = []
                for client_queue in sse_clients:
                    try:
                        # Use put_nowait to avoid blocking
                        client_queue.put_nowait(sse_message)
                    except asyncio.QueueFull:
                        logger.warning("Client queue is full, skipping update for a client.")
                    except Exception as e:
                        logger.error(f"Error sending message to client: {e}")
                        clients_to_remove.append(client_queue)
                
                # Remove dead clients
                for client_queue in clients_to_remove:
                    if client_queue in sse_clients:
                        sse_clients.remove(client_queue)
                
                logger.info(f"Broadcasted update to {len(sse_clients)} SSE clients")
                        
            except asyncio.TimeoutError:
                # Timeout is expected - this allows for graceful cancellation
                continue
            except asyncio.CancelledError:
                logger.info("PostgreSQL listener task was cancelled")
                break
            except Exception as e:
                logger.error(f"Error processing notifications: {e}")
                # Wait a bit before retrying to avoid rapid loops
                await asyncio.sleep(5)
                
    except asyncio.CancelledError:
        logger.info("PostgreSQL listener shutdown requested")
    except Exception as e:
        logger.error(f"PostgreSQL listener failed: {e}")
    finally:
        if conn and not conn.is_closed():
            try:
                # Remove the listeners before closing the connection
                await conn.remove_listener('video_updates', notification_handler)
                await conn.remove_listener('editor_updates', notification_handler)
                await conn.close()
                logger.info("PostgreSQL connection closed")
            except Exception as e:
                logger.error(f"Error closing PostgreSQL connection: {e}")
