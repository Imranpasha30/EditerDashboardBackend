# D:\EditerDashboard\components\managerDashboard\service.py

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, func
from components.submissions.models import VideoSubmission, SubmissionStatus, Volunteer, VideoAssignment, AssignmentStatus
from components.auth.models import User, UserRole
from fastapi import HTTPException, status
from typing import List, Dict, Any, Optional
import logging
from uuid import UUID
import json
import asyncio
from datetime import datetime

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
                    VideoSubmission.decline_reason,
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
                    "status": sub.status.value if hasattr(sub.status, 'value') else sub.status,
                    "received_at": sub.received_at.isoformat() if sub.received_at else None,
                    "assigned_editor_id": str(sub.assigned_editor_id) if sub.assigned_editor_id else None,
                    "assigned_editor_name": sub.assigned_editor_name,
                    "assignment_id": str(sub.assignment_id) if sub.assignment_id else None,
                    "assignment_status": sub.assignment_status.value if sub.assignment_status and hasattr(sub.assignment_status, 'value') else sub.assignment_status,
                    "decline_reason": sub.decline_reason
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
            logger.info(f"=== UPDATE SUBMISSION STATUS START ===")
            logger.info(f"submission_id: {submission_id}")
            logger.info(f"new_status: {new_status}")
            logger.info(f"assigned_editor_id: {assigned_editor_id}")
            logger.info(f"manager_id: {manager_id}")
            
            # Validate UUID format
            try:
                submission_uuid = UUID(submission_id)
                logger.info(f"✓ Valid submission UUID: {submission_uuid}")
            except ValueError as e:
                logger.error(f"✗ Invalid submission ID format: {submission_id}")
                raise ValueError(f"Invalid submission ID format: {submission_id}")

            # Get the current submission
            submission = await db.get(VideoSubmission, submission_uuid)
            if not submission:
                logger.error(f"✗ Submission not found: {submission_id}")
                raise ValueError("Submission not found.")

            logger.info(f"✓ Found submission {submission_id}, current status: {submission.status}")

            # Validate status transition
            try:
                # Try to create SubmissionStatus enum from string
                status_enum = SubmissionStatus(new_status)
                logger.info(f"✓ Valid status enum: {status_enum}")
            except ValueError as e:
                valid_statuses = [s.value for s in SubmissionStatus]
                logger.error(f"✗ Invalid status '{new_status}'. Valid statuses: {valid_statuses}")
                raise ValueError(f"Invalid status '{new_status}'. Valid statuses: {valid_statuses}")

            old_status = submission.status
            logger.info(f"📋 Status transition: {old_status} -> {status_enum}")

            # Handle different status transitions
            if new_status == "assigned" and assigned_editor_id:
                logger.info(f"🎯 ASSIGNMENT BRANCH: Creating assignment for editor: {assigned_editor_id}")
                
                # IMPORTANT: Create assignment BEFORE updating status
                try:
                    assignment = await ManagerService._create_assignment(
                        db, submission_uuid, assigned_editor_id, manager_id
                    )
                    
                    if assignment:
                        logger.info(f"✅ Assignment created successfully: {assignment.id}")
                    else:
                        logger.warning("⚠️ Assignment creation returned None")
                        
                except Exception as assignment_error:
                    logger.error(f"❌ Assignment creation failed: {str(assignment_error)}", exc_info=True)
                    # Continue with status update even if assignment fails for debugging
                    
            elif new_status == "accepted":
                logger.info("✅ Status set to accepted - ready for assignment")
            elif new_status == "declined":
                logger.info("❌ Status set to declined")
            else:
                logger.info(f"ℹ️ Other status change: {new_status}")
            
            # Update the submission status
            logger.info(f"📝 Updating submission status to: {status_enum}")
            submission.status = status_enum
            submission.updated_at = datetime.utcnow()
            
            logger.info(f"💾 Committing status change for submission {submission_id}")
            await db.commit()
            await db.refresh(submission)
            
            logger.info(f"✅ Successfully updated submission {submission_id} from {old_status} to {new_status}")
            logger.info(f"=== UPDATE SUBMISSION STATUS END ===")
            
            # The database trigger will handle the notification
            return submission
            
        except ValueError as e:
            await db.rollback()
            logger.error(f"❌ ValueError updating submission {submission_id}: {str(e)}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"💥 Unexpected error updating submission {submission_id}: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to update submission status: {str(e)}"
            )

    @staticmethod
    async def update_submission_status_with_reason(
        db: AsyncSession, 
        submission_id: str, 
        new_status: str, 
        assigned_editor_id: Optional[str] = None,
        manager_id: Optional[str] = None,
        decline_reason: Optional[str] = None
    ):
        """Update a video submission's status with decline reason."""
        try:
            logger.info(f"=== UPDATE WITH REASON START ===")
            logger.info(f"submission_id: {submission_id}")
            logger.info(f"new_status: {new_status}")
            logger.info(f"decline_reason: {decline_reason}")
            
            try:
                submission_uuid = UUID(submission_id)
            except ValueError as e:
                logger.error(f"✗ Invalid submission ID format: {submission_id}")
                raise ValueError(f"Invalid submission ID format: {submission_id}")

            # Get the current submission
            submission = await db.get(VideoSubmission, submission_uuid)
            if not submission:
                logger.error(f"✗ Submission not found: {submission_id}")
                raise ValueError("Submission not found.")

            # Validate status transition
            try:
                status_enum = SubmissionStatus(new_status)
            except ValueError as e:
                valid_statuses = [s.value for s in SubmissionStatus]
                logger.error(f"✗ Invalid status '{new_status}'. Valid statuses: {valid_statuses}")
                raise ValueError(f"Invalid status '{new_status}'. Valid statuses: {valid_statuses}")

            old_status = submission.status
            
            # Update the submission status
            submission.status = status_enum
            submission.updated_at = datetime.utcnow()
            
            # Add decline reason if provided
            if decline_reason and new_status == "declined":
                submission.decline_reason = decline_reason
                logger.info(f"📝 Added decline reason: {decline_reason}")
            
            await db.commit()
            await db.refresh(submission)
            
            logger.info(f"✅ Successfully updated submission {submission_id} from {old_status} to {new_status} with reason: {decline_reason}")
            logger.info(f"=== UPDATE WITH REASON END ===")
            
            return submission
            
        except ValueError as e:
            await db.rollback()
            logger.error(f"❌ ValueError updating submission {submission_id}: {str(e)}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"💥 Unexpected error updating submission {submission_id}: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to update submission status: {str(e)}"
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
            logger.info(f"🔥 === CREATING ASSIGNMENT START ===")
            logger.info(f"📋 Parameters:")
            logger.info(f"   submission_id: {submission_id}")
            logger.info(f"   editor_id: {editor_id}")
            logger.info(f"   manager_id: {manager_id}")
            
            # Validate editor ID format
            try:
                editor_uuid = UUID(editor_id)
                logger.info(f"✅ Valid editor UUID: {editor_uuid}")
            except ValueError as e:
                logger.error(f"❌ Invalid editor ID format: {editor_id}")
                raise ValueError(f"Invalid editor ID format: {editor_id}")
            
            # Use default manager if not provided
            if not manager_id:
                logger.info("🔍 No manager ID provided, looking for default manager...")
                result = await db.execute(
                    select(User.user_id, User.full_name, User.role)
                    .where(User.role.in_([UserRole.MANAGER, UserRole.ADMIN]), User.is_active == True)
                    .limit(1)
                )
                manager_record = result.mappings().first()
                if not manager_record:
                    logger.error("❌ No active manager found to create assignment")
                    raise ValueError("No active manager found to create assignment")
                manager_id = str(manager_record.user_id)
                logger.info(f"✅ Found manager: {manager_record.full_name} ({manager_record.role}) - ID: {manager_id}")
            
            try:
                manager_uuid = UUID(manager_id)
                logger.info(f"✅ Valid manager UUID: {manager_uuid}")
            except ValueError as e:
                logger.error(f"❌ Invalid manager ID format: {manager_id}")
                raise ValueError(f"Invalid manager ID format: {manager_id}")

            # Verify editor exists and is active
            logger.info(f"🔍 Verifying editor exists and is active...")
            editor_result = await db.execute(
                select(User.user_id, User.full_name, User.role, User.is_active)
                .where(User.user_id == editor_uuid)
            )
            editor_record = editor_result.mappings().first()
            
            if not editor_record:
                logger.error(f"❌ Editor not found: {editor_id}")
                raise ValueError(f"Editor not found: {editor_id}")
                
            if not editor_record.is_active:
                logger.error(f"❌ Editor is inactive: {editor_record.full_name}")
                raise ValueError(f"Editor is inactive: {editor_record.full_name}")
                
            if editor_record.role != UserRole.EDITOR:
                logger.warning(f"⚠️ User is not an editor: {editor_record.full_name} (role: {editor_record.role})")
            
            logger.info(f"✅ Editor verified: {editor_record.full_name} ({editor_record.role}) - Active: {editor_record.is_active}")

            # Check if assignment already exists
            logger.info(f"🔍 Checking for existing assignments...")
            existing_result = await db.execute(
                select(VideoAssignment.id, VideoAssignment.status)
                .where(
                    VideoAssignment.video_submission_id == submission_id,
                    VideoAssignment.status.in_([AssignmentStatus.IN_PROGRESS, AssignmentStatus.REVISION_NEEDED])
                )
            )
            existing_records = existing_result.mappings().all()
            
            if existing_records:
                for record in existing_records:
                    logger.warning(f"⚠️ Existing assignment found: {record.id} (status: {record.status})")
                logger.info("⏭️ Skipping creation due to existing assignment")
                return existing_records[0]

            logger.info("✅ No existing assignments found, proceeding with creation")

            # Verify submission exists
            logger.info(f"🔍 Verifying submission exists...")
            submission_result = await db.execute(
                select(VideoSubmission.id, VideoSubmission.status)
                .where(VideoSubmission.id == submission_id)
            )
            submission_record = submission_result.mappings().first()
            
            if not submission_record:
                logger.error(f"❌ Submission not found: {submission_id}")
                raise ValueError(f"Submission not found: {submission_id}")
                
            logger.info(f"✅ Submission verified: {submission_record.id} (status: {submission_record.status})")

            # Create new assignment
            logger.info(f"🚀 Creating new assignment record...")
            assignment = VideoAssignment(
                video_submission_id=submission_id,
                assigned_editor_id=editor_uuid,
                assigned_manager_id=manager_uuid,
                status=AssignmentStatus.IN_PROGRESS,
                assigned_at=datetime.utcnow()
            )
            
            logger.info(f"📝 Assignment object created:")
            logger.info(f"   video_submission_id: {assignment.video_submission_id}")
            logger.info(f"   assigned_editor_id: {assignment.assigned_editor_id}")
            logger.info(f"   assigned_manager_id: {assignment.assigned_manager_id}")
            logger.info(f"   status: {assignment.status}")
            logger.info(f"   assigned_at: {assignment.assigned_at}")
            
            logger.info(f"➕ Adding assignment to session...")
            db.add(assignment)
            
            logger.info(f"💾 Flushing session to get ID...")
            await db.flush()  # Flush to get the ID
            
            logger.info(f"🎉 SUCCESS: Assignment created with ID: {assignment.id}")
            
            # Verify the assignment was actually created
            logger.info(f"🔍 Verifying assignment was created...")
            verify_result = await db.execute(
                select(VideoAssignment)
                .where(VideoAssignment.id == assignment.id)
            )
            verified_assignment = verify_result.scalar_one_or_none()
            
            if verified_assignment:
                logger.info(f"✅ Assignment verification successful: {verified_assignment.id}")
            else:
                logger.error(f"❌ Assignment verification failed - not found in database!")
            
            logger.info(f"🔥 === CREATING ASSIGNMENT END ===")
            return assignment
            
        except Exception as e:
            logger.error(f"💥 ASSIGNMENT CREATION FAILED: {str(e)}", exc_info=True)
            raise

    @staticmethod
    async def get_assignment_counts(db: AsyncSession) -> Dict[str, int]:
        """Get assignment counts for dashboard statistics."""
        try:
            logger.info("📊 Fetching assignment counts...")
            
            # Get counts for different assignment statuses
            assignment_result = await db.execute(
                select(VideoAssignment.status, func.count(VideoAssignment.id))
                .group_by(VideoAssignment.status)
            )
            
            assignment_counts = {str(row[0]): row[1] for row in assignment_result}
            logger.info(f"Assignment counts: {assignment_counts}")
            
            # Get submission counts
            submission_result = await db.execute(
                select(VideoSubmission.status, func.count(VideoSubmission.id))
                .group_by(VideoSubmission.status)
            )
            
            submission_counts = {str(row[0]): row[1] for row in submission_result}
            logger.info(f"Submission counts: {submission_counts}")
            
            return {
                "assignments": assignment_counts,
                "submissions": submission_counts
            }
            
        except Exception as e:
            logger.error(f"Error fetching assignment counts: {e}")
            return {"assignments": {}, "submissions": {}}

    @staticmethod
    async def get_editor_workload(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get workload information for all editors."""
        try:
            logger.info("📊 Fetching editor workload...")
            
            result = await db.execute(
                select(
                    User.user_id,
                    User.full_name,
                    func.count(VideoAssignment.id).label('active_assignments')
                )
                .outerjoin(
                    VideoAssignment,
                    (VideoAssignment.assigned_editor_id == User.user_id) &
                    (VideoAssignment.status == AssignmentStatus.IN_PROGRESS)
                )
                .where(User.role == UserRole.EDITOR, User.is_active == True)
                .group_by(User.user_id, User.full_name)
                .order_by(User.full_name)
            )
            
            workload = result.mappings().all()
            
            workload_list = [
                {
                    "id": str(editor.user_id),
                    "name": editor.full_name,
                    "assignedCount": editor.active_assignments
                }
                for editor in workload
            ]
            
            logger.info(f"Editor workload: {workload_list}")
            return workload_list
            
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
            logger.info(f"📡 Received notification from PID {pid} on channel '{channel}': {parsed_payload}")
            
            # Create a properly formatted SSE message
            sse_message = {
                "event": "dashboard-update",
                "data": json.dumps(parsed_payload)
            }
            
            # Put the notification in the queue for processing
            try:
                notification_queue.put_nowait(sse_message)
            except asyncio.QueueFull:
                logger.warning("⚠️ Notification queue is full, dropping notification")
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse notification payload: {e}")
        except Exception as e:
            logger.error(f"💥 Error handling notification: {e}")
    
    try:
        # Connect to PostgreSQL using asyncpg
        conn = await asyncpg.connect(db_url)
        
        # Add notification listeners for both channels
        await conn.add_listener('video_updates', notification_handler)
        await conn.add_listener('editor_updates', notification_handler)
        logger.info("🔗 Connected to PostgreSQL and listening for notifications on 'video_updates' and 'editor_updates' channels.")

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
                        logger.warning("⚠️ Client queue is full, skipping update for a client.")
                    except Exception as e:
                        logger.error(f"❌ Error sending message to client: {e}")
                        clients_to_remove.append(client_queue)
                
                # Remove dead clients
                for client_queue in clients_to_remove:
                    if client_queue in sse_clients:
                        sse_clients.remove(client_queue)
                
                logger.info(f"📡 Broadcasted update to {len(sse_clients)} SSE clients")
                        
            except asyncio.TimeoutError:
                # Timeout is expected - this allows for graceful cancellation
                continue
            except asyncio.CancelledError:
                logger.info("🔚 PostgreSQL listener task was cancelled")
                break
            except Exception as e:
                logger.error(f"💥 Error processing notifications: {e}")
                # Wait a bit before retrying to avoid rapid loops
                await asyncio.sleep(5)
                
    except asyncio.CancelledError:
        logger.info("🔚 PostgreSQL listener shutdown requested")
    except Exception as e:
        logger.error(f"💥 PostgreSQL listener failed: {e}")
    finally:
        if conn and not conn.is_closed():
            try:
                # Remove the listeners before closing the connection
                await conn.remove_listener('video_updates', notification_handler)
                await conn.remove_listener('editor_updates', notification_handler)
                await conn.close()
                logger.info("🔗 PostgreSQL connection closed")
            except Exception as e:
                logger.error(f"❌ Error closing PostgreSQL connection: {e}")
