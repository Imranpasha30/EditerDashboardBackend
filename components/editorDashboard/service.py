from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, and_
from components.submissions.models import VideoSubmission, SubmissionStatus, Volunteer, VideoAssignment, AssignmentStatus
from components.auth.models import User, UserRole
from fastapi import HTTPException, status
from typing import List, Dict, Any, Optional
import logging
from uuid import UUID
from datetime import datetime

logger = logging.getLogger(__name__)

class EditorService:
    
    @staticmethod
    async def get_editor_assignments(db: AsyncSession, editor_id: str) -> List[Dict[str, Any]]:
        """Fetch all assignments for a specific editor."""
        try:
            editor_uuid = UUID(editor_id)
            logger.info(f"Fetching assignments for editor: {editor_id}")
            
            result = await db.execute(
                select(
                    VideoAssignment.id.label('assignment_id'),
                    VideoAssignment.status.label('assignment_status'),
                    VideoAssignment.assigned_at,
                    VideoAssignment.completed_at,
                    VideoAssignment.completed_video_url,
                    VideoAssignment.editor_notes,
                    VideoAssignment.manager_notes,
                    VideoAssignment.assigned_manager_id,  # Add this line
                    VideoSubmission.id.label('submission_id'),
                    VideoSubmission.video_platform_url.label('video_url'),
                    VideoSubmission.status.label('submission_status'),
                    VideoSubmission.created_at.label('received_at'),
                    Volunteer.first_name.label('volunteer_name'),
                    User.full_name.label('manager_name')
                )
                .join(VideoSubmission, VideoAssignment.video_submission_id == VideoSubmission.id)
                .join(Volunteer, VideoSubmission.volunteer_id == Volunteer.id)
                .join(User, VideoAssignment.assigned_manager_id == User.user_id)
                .where(VideoAssignment.assigned_editor_id == editor_uuid)
                .order_by(VideoAssignment.assigned_at.desc())
            )
            
            assignments = result.mappings().all()
            return [
                {
                    "assignment_id": str(assignment.assignment_id),
                    "submission_id": str(assignment.submission_id),
                    "video_url": assignment.video_url,
                    "volunteer_name": assignment.volunteer_name,
                    "manager_name": assignment.manager_name,
                    "manager_id": str(assignment.assigned_manager_id),  # Add this line
                    "assignment_status": assignment.assignment_status.value if hasattr(assignment.assignment_status, 'value') else assignment.assignment_status,
                    "submission_status": assignment.submission_status.value if hasattr(assignment.submission_status, 'value') else assignment.submission_status,
                    "assigned_at": assignment.assigned_at.isoformat() if assignment.assigned_at else None,
                    "completed_at": assignment.completed_at.isoformat() if assignment.completed_at else None,
                    "completed_video_url": assignment.completed_video_url,
                    "editor_notes": assignment.editor_notes,
                    "manager_notes": assignment.manager_notes,
                    "received_at": assignment.received_at.isoformat() if assignment.received_at else None
                }
                for assignment in assignments
            ]

            
        except Exception as e:
            logger.error(f"Error fetching editor assignments: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch assignments"
            )
    
    @staticmethod
    @staticmethod
    async def complete_assignment(
        db: AsyncSession,
        assignment_id: str,
        completed_video_url: str,
        editor_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Complete an assignment with the edited video URL and send success notification."""
        try:
            logger.info(f"=== COMPLETING ASSIGNMENT START ===")
            logger.info(f"assignment_id: {assignment_id}")
            logger.info(f"completed_video_url: {completed_video_url}")
            logger.info(f"editor_notes: {editor_notes}")
            
            assignment_uuid = UUID(assignment_id)
            
            # Get the assignment with volunteer and submission information
            result = await db.execute(
                select(VideoAssignment, VideoSubmission, Volunteer)
                .join(VideoSubmission, VideoAssignment.video_submission_id == VideoSubmission.id)
                .join(Volunteer, VideoSubmission.volunteer_id == Volunteer.id)
                .where(VideoAssignment.id == assignment_uuid)
            )
            
            assignment_data = result.first()
            if not assignment_data:
                raise ValueError(f"Assignment not found: {assignment_id}")
            
            assignment, submission, volunteer = assignment_data
            
            logger.info(f"Found assignment: {assignment.id}")
            logger.info(f"Current assignment status: {assignment.status}")
            logger.info(f"Volunteer: {volunteer.first_name} (chat_id: {volunteer.id})")
            logger.info(f"Original video: {submission.video_platform_url}")
            
            # Update assignment status to COMPLETED
            assignment.status = AssignmentStatus.COMPLETED
            assignment.completed_video_url = completed_video_url
            assignment.editor_notes = editor_notes
            assignment.completed_at = datetime.utcnow()
            assignment.updated_at = datetime.utcnow()
            
            # Update submission status to USED
            submission.status = SubmissionStatus.USED
            submission.updated_at = datetime.utcnow()
            
            # Commit database changes first
            await db.commit()
            await db.refresh(assignment)
            await db.refresh(submission)
            
            logger.info(f"✅ Successfully completed assignment {assignment_id}")
            
            # Send success notification to volunteer
            notification_sent = False
            try:
                from core.telegram_service import TelegramService
                
                logger.info(f"🎉 Attempting to send completion notification to volunteer {volunteer.first_name}")
                
                notification_sent = await TelegramService.send_video_completion_notification(
                    chat_id=volunteer.id,  # volunteer.id is the chat_id
                    original_video_url=submission.video_platform_url,  # Their original video
                    completed_video_url=completed_video_url,  # Where it was published
                    volunteer_name=volunteer.first_name,
                    editor_notes=editor_notes
                )
                
                if notification_sent:
                    logger.info(f"✅ Completion notification sent successfully to {volunteer.first_name}")
                else:
                    logger.warning(f"⚠️ Failed to send completion notification to {volunteer.first_name}")
                    
            except Exception as telegram_error:
                logger.error(f"💥 Error sending Telegram completion notification: {str(telegram_error)}", exc_info=True)
                # Don't raise exception here - assignment completion should still succeed even if notification fails
            
            logger.info(f"=== COMPLETING ASSIGNMENT END ===")
            
            return {
                "assignment_id": str(assignment.id),
                "submission_id": str(submission.id),
                "assignment_status": assignment.status.value,
                "submission_status": submission.status.value,
                "completed_video_url": completed_video_url,
                "editor_notes": editor_notes,
                "completed_at": assignment.completed_at.isoformat() if assignment.completed_at else None,
                "volunteer_notified": notification_sent
            }
            
        except ValueError as e:
            await db.rollback()
            logger.error(f"❌ ValueError completing assignment: {str(e)}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"💥 Unexpected error completing assignment: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to complete assignment: {str(e)}"
            )

    
    @staticmethod
    async def update_editor_notes(
        db: AsyncSession,
        assignment_id: str,
        editor_notes: str
    ) -> Dict[str, Any]:
        """Update editor notes for an assignment."""
        try:
            assignment_uuid = UUID(assignment_id)
            
            assignment = await db.get(VideoAssignment, assignment_uuid)
            if not assignment:
                raise ValueError(f"Assignment not found: {assignment_id}")
            
            assignment.editor_notes = editor_notes
            assignment.updated_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(assignment)
            
            return {
                "assignment_id": str(assignment.id),
                "editor_notes": assignment.editor_notes,
                "updated_at": assignment.updated_at.isoformat()
            }
            
        except ValueError as e:
            await db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"Error updating editor notes: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update editor notes"
            )
    
    @staticmethod
    async def get_editor_stats(db: AsyncSession, editor_id: str) -> Dict[str, int]:
        """Get statistics for an editor."""
        try:
            editor_uuid = UUID(editor_id)
            
            # Count assignments by status
            result = await db.execute(
                select(VideoAssignment.status, VideoAssignment.id)
                .where(VideoAssignment.assigned_editor_id == editor_uuid)
            )
            
            assignments = result.all()
            stats = {
                "total_assignments": len(assignments),
                "in_progress": len([a for a in assignments if a.status == AssignmentStatus.IN_PROGRESS]),
                "completed": len([a for a in assignments if a.status == AssignmentStatus.COMPLETED]),
                "revision_needed": len([a for a in assignments if a.status == AssignmentStatus.REVISION_NEEDED])
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error fetching editor stats: {e}")
            return {"total_assignments": 0, "in_progress": 0, "completed": 0, "revision_needed": 0}

    @staticmethod
    async def get_editor_profile(db: AsyncSession, editor_id: str) -> Dict[str, Any]:
        """Get editor profile information."""
        try:
            editor_uuid = UUID(editor_id)
            logger.info(f"Fetching profile for editor: {editor_id}")
            
            result = await db.execute(
                select(User.user_id, User.full_name, User.email, User.username, User.role, User.is_active, User.created_at)
                .where(User.user_id == editor_uuid)
            )
            
            editor = result.mappings().first()
            if not editor:
                raise ValueError(f"Editor not found: {editor_id}")
            
            return {
                "editor_id": str(editor.user_id),
                "full_name": editor.full_name,
                "email": editor.email,
                "username": editor.username,
                "role": editor.role.value if hasattr(editor.role, 'value') else editor.role,
                "is_active": editor.is_active,
                "joined_at": editor.created_at.isoformat() if editor.created_at else None
            }
            
        except ValueError as e:
            logger.error(f"ValueError fetching editor profile: {str(e)}")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        except Exception as e:
            logger.error(f"Error fetching editor profile: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch editor profile"
            )

    @staticmethod
    async def request_revision(
        db: AsyncSession,
        assignment_id: str,
        revision_notes: str
    ) -> Dict[str, Any]:
        """Request revision for an assignment."""
        try:
            logger.info(f"=== REQUESTING REVISION START ===")
            logger.info(f"assignment_id: {assignment_id}")
            logger.info(f"revision_notes: {revision_notes}")
            
            assignment_uuid = UUID(assignment_id)
            
            # Get the assignment
            result = await db.execute(
                select(VideoAssignment, VideoSubmission)
                .join(VideoSubmission, VideoAssignment.video_submission_id == VideoSubmission.id)
                .where(VideoAssignment.id == assignment_uuid)
            )
            
            assignment_data = result.first()
            if not assignment_data:
                raise ValueError(f"Assignment not found: {assignment_id}")
            
            assignment, submission = assignment_data
            
            logger.info(f"Found assignment: {assignment.id}")
            logger.info(f"Current assignment status: {assignment.status}")
            
            # Update VideoAssignment to REVISION_NEEDED
            assignment.status = AssignmentStatus.REVISION_NEEDED
            assignment.revision_notes = revision_notes
            assignment.updated_at = datetime.utcnow()
            
            # Keep submission status as ASSIGNED (editor still has it)
            submission.updated_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(assignment)
            await db.refresh(submission)
            
            logger.info(f"✅ Successfully requested revision for assignment {assignment_id}")
            logger.info(f"Assignment status: {assignment.status}")
            logger.info(f"=== REQUESTING REVISION END ===")
            
            return {
                "assignment_id": str(assignment.id),
                "submission_id": str(submission.id),
                "assignment_status": assignment.status.value,
                "submission_status": submission.status.value,
                "revision_notes": assignment.revision_notes,
                "updated_at": assignment.updated_at.isoformat()
            }
            
        except ValueError as e:
            await db.rollback()
            logger.error(f"❌ ValueError requesting revision: {str(e)}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"💥 Unexpected error requesting revision: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to request revision: {str(e)}"
            )
