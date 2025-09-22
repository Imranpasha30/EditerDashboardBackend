from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc, and_, or_, text, case
from components.submissions.models import VideoSubmission, SubmissionStatus, Volunteer, VideoAssignment, AssignmentStatus
from components.auth.models import User, UserRole
from fastapi import HTTPException, status
from typing import List, Dict, Any, Optional
import logging
from uuid import UUID
from datetime import datetime, timedelta
import json
import secrets
import string

logger = logging.getLogger(__name__)

class AdminService:
    
    @staticmethod
    async def get_dashboard_overview(db: AsyncSession) -> Dict[str, Any]:
        """Get comprehensive dashboard overview for admin."""
        try:
            logger.info("Fetching admin dashboard overview")
            
            # Get basic stats
            total_submissions_result = await db.execute(select(func.count(VideoSubmission.id)))
            total_submissions = total_submissions_result.scalar()
            
            pending_submissions_result = await db.execute(
                select(func.count(VideoSubmission.id))
                .where(VideoSubmission.status == SubmissionStatus.PENDING_REVIEW)
            )
            pending_submissions = pending_submissions_result.scalar()
            
            total_users_result = await db.execute(
                select(func.count(User.user_id))
                .where(User.role.in_([UserRole.EDITOR, UserRole.MANAGER, UserRole.ADMIN]))
            )
            total_users = total_users_result.scalar()
            
            active_assignments_result = await db.execute(
                select(func.count(VideoAssignment.id))
                .where(VideoAssignment.status == AssignmentStatus.IN_PROGRESS)
            )
            active_assignments = active_assignments_result.scalar()
            
            total_volunteers_result = await db.execute(select(func.count(Volunteer.id)))
            total_volunteers = total_volunteers_result.scalar()
            
            # Get submissions this week
            week_start = datetime.utcnow().date() - timedelta(days=6)
            week_submissions_result = await db.execute(
                select(func.count(VideoSubmission.id))
                .where(func.date(VideoSubmission.created_at) >= week_start)
            )
            week_submissions = week_submissions_result.scalar()
            
            # Get completed assignments this week
            week_completed_result = await db.execute(
                select(func.count(VideoAssignment.id))
                .where(
                    VideoAssignment.status == AssignmentStatus.COMPLETED,
                    func.date(VideoAssignment.completed_at) >= week_start
                )
            )
            week_completed = week_completed_result.scalar()
            
            return {
                "total_submissions": total_submissions,
                "pending_submissions": pending_submissions,
                "total_users": total_users,
                "active_assignments": active_assignments,
                "total_volunteers": total_volunteers,
                "week_submissions": week_submissions,
                "week_completed": week_completed,
                "completion_rate": round((week_completed / week_submissions * 100) if week_submissions > 0 else 0, 1)
            }
            
        except Exception as e:
            logger.error(f"Error fetching dashboard overview: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch dashboard overview"
            )
    
    @staticmethod
    async def get_daily_submissions_data(db: AsyncSession, days: int = 7) -> List[Dict[str, Any]]:
        """Get daily submissions data for the last N days."""
        try:
            logger.info(f"Fetching daily submissions data for last {days} days")
            
            # Calculate date range
            end_date = datetime.utcnow().date()
            start_date = end_date - timedelta(days=days-1)
            
            # Query for daily submissions
            result = await db.execute(
                select(
                    func.date(VideoSubmission.created_at).label('date'),
                    func.count(VideoSubmission.id).label('submissions')
                )
                .where(
                    func.date(VideoSubmission.created_at) >= start_date,
                    func.date(VideoSubmission.created_at) <= end_date
                )
                .group_by(func.date(VideoSubmission.created_at))
                .order_by(func.date(VideoSubmission.created_at))
            )
            
            submissions_data = result.mappings().all()
            
            # Query for daily completions
            completion_result = await db.execute(
                select(
                    func.date(VideoAssignment.completed_at).label('date'),
                    func.count(VideoAssignment.id).label('completed')
                )
                .where(
                    VideoAssignment.status == AssignmentStatus.COMPLETED,
                    func.date(VideoAssignment.completed_at) >= start_date,
                    func.date(VideoAssignment.completed_at) <= end_date
                )
                .group_by(func.date(VideoAssignment.completed_at))
                .order_by(func.date(VideoAssignment.completed_at))
            )
            
            completions_data = {row.date: row.completed for row in completion_result.mappings()}
            
            # Create complete dataset with all days
            daily_data = []
            for i in range(days):
                current_date = start_date + timedelta(days=i)
                day_name = current_date.strftime('%a')  # Mon, Tue, etc.
                
                # Find submissions for this date
                submissions = 0
                for row in submissions_data:
                    if row.date == current_date:
                        submissions = row.submissions
                        break
                
                completed = completions_data.get(current_date, 0)
                
                daily_data.append({
                    "day": day_name,
                    "date": current_date.isoformat(),
                    "submissions": submissions,
                    "completed": completed
                })
            
            return daily_data
            
        except Exception as e:
            logger.error(f"Error fetching daily submissions data: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch daily submissions data"
            )
    
    @staticmethod
    async def get_editor_performance_data(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get editor performance data."""
        try:
            logger.info("Fetching editor performance data")
            
            result = await db.execute(
                select(
                    User.full_name,
                    func.count(
                        case(
                            (VideoAssignment.status == AssignmentStatus.COMPLETED, VideoAssignment.id),
                            else_=None
                        )
                    ).label('completed'),
                    func.count(
                        case(
                            (VideoAssignment.status == AssignmentStatus.IN_PROGRESS, VideoAssignment.id),
                            else_=None
                        )
                    ).label('in_progress'),
                    func.count(
                        case(
                            (VideoAssignment.status == AssignmentStatus.REVISION_NEEDED, VideoAssignment.id),
                            else_=None
                        )
                    ).label('revision_needed')
                )
                .outerjoin(VideoAssignment, VideoAssignment.assigned_editor_id == User.user_id)
                .where(User.role == UserRole.EDITOR, User.is_active == True)
                .group_by(User.user_id, User.full_name)
                .order_by(desc('completed'))
            )
            
            performance_data = result.mappings().all()
            
            return [
                {
                    "name": editor.full_name,
                    "completed": editor.completed,
                    "in_progress": editor.in_progress,
                    "revision_needed": editor.revision_needed
                }
                for editor in performance_data
            ]
            
        except Exception as e:
            logger.error(f"Error fetching editor performance data: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch editor performance data"
            )
    
    @staticmethod
    async def get_volunteer_performance_data(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get volunteer performance data."""
        try:
            logger.info("Fetching volunteer performance data")
            
            result = await db.execute(
                select(
                    Volunteer.first_name,
                    Volunteer.phone_number,
                    func.count(
                        case(
                            (VideoSubmission.status.in_([
                                SubmissionStatus.ACCEPTED, 
                                SubmissionStatus.ASSIGNED, 
                                SubmissionStatus.USED
                            ]), VideoSubmission.id),
                            else_=None
                        )
                    ).label('accepted'),
                    func.count(
                        case(
                            (VideoSubmission.status == SubmissionStatus.DECLINED, VideoSubmission.id),
                            else_=None
                        )
                    ).label('declined'),
                    func.count(VideoSubmission.id).label('total_submissions')
                )
                .join(VideoSubmission, VideoSubmission.volunteer_id == Volunteer.id)
                .group_by(Volunteer.id, Volunteer.first_name, Volunteer.phone_number)
                .having(func.count(VideoSubmission.id) > 0)  # Only volunteers with submissions
                .order_by(desc('accepted'))
                .limit(15)  # Top 15 volunteers
            )
            
            performance_data = result.mappings().all()
            
            return [
                {
                    "name": volunteer.first_name,
                    "phone": volunteer.phone_number,
                    "accepted": volunteer.accepted,
                    "declined": volunteer.declined,
                    "total": volunteer.total_submissions,
                    "success_rate": round((volunteer.accepted / volunteer.total_submissions * 100) if volunteer.total_submissions > 0 else 0, 1)
                }
                for volunteer in performance_data
            ]
            
        except Exception as e:
            logger.error(f"Error fetching volunteer performance data: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch volunteer performance data"
            )
    
    @staticmethod
    async def get_recent_submissions(db: AsyncSession, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent submissions for admin review."""
        try:
            logger.info(f"Fetching {limit} recent submissions")
            
            result = await db.execute(
                select(
                    VideoSubmission.id,
                    VideoSubmission.status,
                    VideoSubmission.created_at,
                    VideoSubmission.decline_reason,
                    VideoSubmission.video_platform_url,
                    Volunteer.first_name.label('volunteer_name'),
                    Volunteer.phone_number
                )
                .join(Volunteer, VideoSubmission.volunteer_id == Volunteer.id)
                .order_by(desc(VideoSubmission.created_at))
                .limit(limit)
            )
            
            submissions = result.mappings().all()
            
            return [
                {
                    "id": str(submission.id),
                    "volunteer_name": submission.volunteer_name,
                    "phone_number": submission.phone_number,
                    "status": submission.status.value if hasattr(submission.status, 'value') else submission.status,
                    "submitted_at": submission.created_at.isoformat() if submission.created_at else None,
                    "decline_reason": submission.decline_reason,
                    "video_url": submission.video_platform_url
                }
                for submission in submissions
            ]
            
        except Exception as e:
            logger.error(f"Error fetching recent submissions: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch recent submissions"
            )
    
    @staticmethod
    async def get_all_assignments(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all assignments with details."""
        try:
            logger.info("Fetching all assignments")
            
            result = await db.execute(
                select(
                    VideoAssignment.id,
                    VideoAssignment.status,
                    VideoAssignment.assigned_at,
                    VideoAssignment.completed_at,
                    VideoAssignment.completed_video_url,
                    VideoAssignment.editor_notes,
                    VideoAssignment.manager_notes,
                    VideoSubmission.id.label('submission_id'),
                    VideoSubmission.video_platform_url,
                    User.full_name.label('editor_name'),
                    Volunteer.first_name.label('volunteer_name'),
                    User.email.label('editor_email')
                )
                .join(VideoSubmission, VideoAssignment.video_submission_id == VideoSubmission.id)
                .join(User, VideoAssignment.assigned_editor_id == User.user_id)
                .join(Volunteer, VideoSubmission.volunteer_id == Volunteer.id)
                .order_by(desc(VideoAssignment.assigned_at))
            )
            
            assignments = result.mappings().all()
            
            return [
                {
                    "id": str(assignment.id),
                    "submission_id": str(assignment.submission_id),
                    "video_title": f"Video Report from {assignment.volunteer_name}",  # Generated title
                    "assigned_to": assignment.editor_name,
                    "editor_email": assignment.editor_email,
                    "reported_by": assignment.volunteer_name,
                    "status": assignment.status.value if hasattr(assignment.status, 'value') else assignment.status,
                    "assigned_at": assignment.assigned_at.isoformat() if assignment.assigned_at else None,
                    "completed_at": assignment.completed_at.isoformat() if assignment.completed_at else None,
                    "completed_video_url": assignment.completed_video_url,
                    "original_video_url": assignment.video_platform_url,
                    "editor_notes": assignment.editor_notes,
                    "manager_notes": assignment.manager_notes
                }
                for assignment in assignments
            ]
            
        except Exception as e:
            logger.error(f"Error fetching assignments: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch assignments"
            )
    
    @staticmethod
    async def get_all_users(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all users for management."""
        try:
            logger.info("Fetching all users for management")
            
            result = await db.execute(
                select(
                    User.user_id,
                    User.full_name,
                    User.email,
                    User.username,
                    User.role,
                    User.is_active,
                    User.is_verified,
                    User.created_at,
                    User.last_login,
                    User.updated_at
                )
                .order_by(User.created_at.desc())
            )
            
            users = result.mappings().all()
            
            return [
                {
                    "user_id": str(user.user_id),
                    "full_name": user.full_name,
                    "email": user.email,
                    "username": user.username,
                    "role": user.role.value if hasattr(user.role, 'value') else user.role,
                    "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "updated_at": user.updated_at.isoformat() if user.updated_at else None
                }
                for user in users
            ]
            
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch users"
            )
    
    @staticmethod
    async def update_user_role(db: AsyncSession, user_id: str, new_role: str) -> Dict[str, Any]:
        """Update user role."""
        try:
            user_uuid = UUID(user_id)
            
            # Validate role
            try:
                role_enum = UserRole(new_role.upper())  # Ensure uppercase
            except ValueError:
                raise ValueError(f"Invalid role: {new_role}. Valid roles: {[role.value for role in UserRole]}")
            
            user = await db.get(User, user_uuid)
            if not user:
                raise ValueError(f"User not found: {user_id}")
            
            old_role = user.role
            user.role = role_enum
            user.updated_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(user)
            
            logger.info(f"Updated user {user_id} role from {old_role} to {new_role}")
            
            return {
                "user_id": str(user.user_id),
                "full_name": user.full_name,
                "email": user.email,
                "old_role": old_role.value if hasattr(old_role, 'value') else old_role,
                "new_role": user.role.value,
                "updated_at": user.updated_at.isoformat()
            }
            
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"Error updating user role: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user role"
            )
    
    @staticmethod
    async def toggle_user_status(db: AsyncSession, user_id: str) -> Dict[str, Any]:
        """Toggle user active status."""
        try:
            user_uuid = UUID(user_id)
            
            user = await db.get(User, user_uuid)
            if not user:
                raise ValueError(f"User not found: {user_id}")
            
            old_status = user.is_active
            user.is_active = not user.is_active
            user.updated_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(user)
            
            logger.info(f"Toggled user {user_id} status from {old_status} to {user.is_active}")
            
            return {
                "user_id": str(user.user_id),
                "full_name": user.full_name,
                "email": user.email,
                "is_active": user.is_active,
                "old_status": old_status,
                "updated_at": user.updated_at.isoformat()
            }
            
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"Error toggling user status: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to toggle user status"
            )
    
    @staticmethod
    def generate_secure_password(length: int = 12) -> str:
        """Generate a secure random password."""
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    @staticmethod
    async def create_user(
        db: AsyncSession, 
        full_name: str, 
        email: str, 
        role: str,
        password: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new user."""
        try:
            # Validate role
            try:
                role_enum = UserRole(role.upper())  # Ensure uppercase
            except ValueError:
                raise ValueError(f"Invalid role: {role}. Valid roles: {[role.value for role in UserRole]}")
            
            # Check if email already exists
            existing_user = await db.execute(
                select(User).where(User.email == email)
            )
            if existing_user.scalar_one_or_none():
                raise ValueError(f"User with email {email} already exists")
            
            # Generate username from email
            username = email.split('@')[0]
            
            # Check if username exists and make unique
            username_check = await db.execute(
                select(User).where(User.username == username)
            )
            if username_check.scalar_one_or_none():
                username = f"{username}_{datetime.utcnow().microsecond}"
            
            # Generate secure password if not provided
            if not password:
                password = AdminService.generate_secure_password()
            
            # Create new user
            new_user = User(
                full_name=full_name,
                username=username,
                email=email,
                password=password,  # In production, hash this!
                role=role_enum,
                is_active=True,
                is_verified=True  # Auto-verify admin created users
            )
            
            db.add(new_user)
            await db.flush()
            await db.commit()
            await db.refresh(new_user)
            
            logger.info(f"Created new user: {new_user.email} with role {role}")
            
            return {
                "user_id": str(new_user.user_id),
                "full_name": new_user.full_name,
                "username": new_user.username,
                "email": new_user.email,
                "role": new_user.role.value,
                "is_active": new_user.is_active,
                "is_verified": new_user.is_verified,
                "created_at": new_user.created_at.isoformat(),
                "temporary_password": password  # Return for admin to share (remove in production)
            }
            
        except ValueError as e:
            await db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating user: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
    
    @staticmethod
    async def get_system_health(db: AsyncSession) -> Dict[str, Any]:
        """Get system health metrics."""
        try:
            logger.info("Fetching system health metrics")
            
            # Database connection test
            db_health = "healthy"
            try:
                await db.execute(select(func.now()))
            except Exception as e:
                db_health = f"unhealthy: {str(e)}"
                logger.error(f"Database health check failed: {e}")
            
            # Get processing stats
            processing_count = await db.execute(
                select(func.count(VideoSubmission.id))
                .where(VideoSubmission.status == SubmissionStatus.PROCESSING)
            )
            processing_submissions = processing_count.scalar()
            
            # Get stuck assignments (in progress for more than 24 hours)
            day_ago = datetime.utcnow() - timedelta(days=1)
            stuck_assignments = await db.execute(
                select(func.count(VideoAssignment.id))
                .where(
                    VideoAssignment.status == AssignmentStatus.IN_PROGRESS,
                    VideoAssignment.assigned_at < day_ago
                )
            )
            stuck_count = stuck_assignments.scalar()
            
            # Get active editors count
            active_editors = await db.execute(
                select(func.count(User.user_id))
                .where(
                    User.role == UserRole.EDITOR,
                    User.is_active == True
                )
            )
            active_editors_count = active_editors.scalar()
            
            return {
                "database_status": db_health,
                "processing_submissions": processing_submissions,
                "stuck_assignments": stuck_count,
                "active_editors": active_editors_count,
                "last_check": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error fetching system health: {e}")
            return {
                "database_status": f"error: {str(e)}",
                "processing_submissions": 0,
                "stuck_assignments": 0,
                "active_editors": 0,
                "last_check": datetime.utcnow().isoformat()
            }
    
    @staticmethod
    async def get_advanced_analytics(db: AsyncSession) -> Dict[str, Any]:
        """Get advanced analytics for admin dashboard."""
        try:
            logger.info("Fetching advanced analytics")
            
            # Hourly submission pattern (last 24 hours)
            hourly_result = await db.execute(
                select(
                    func.extract('hour', VideoSubmission.created_at).label('hour'),
                    func.count(VideoSubmission.id).label('count')
                )
                .where(VideoSubmission.created_at >= datetime.utcnow() - timedelta(days=1))
                .group_by(func.extract('hour', VideoSubmission.created_at))
                .order_by(func.extract('hour', VideoSubmission.created_at))
            )
            
            hourly_data = [
                {"hour": int(row.hour), "submissions": row.count}
                for row in hourly_result.mappings()
            ]
            
            # Average processing time
            processing_time_result = await db.execute(
                select(
                    func.avg(
                        func.extract('epoch', VideoAssignment.completed_at - VideoAssignment.assigned_at) / 3600
                    ).label('avg_hours')
                )
                .where(
                    VideoAssignment.status == AssignmentStatus.COMPLETED,
                    VideoAssignment.completed_at.is_not(None)
                )
            )
            
            avg_processing_hours = processing_time_result.scalar() or 0
            
            # Status distribution
            status_result = await db.execute(
                select(
                    VideoSubmission.status,
                    func.count(VideoSubmission.id).label('count')
                )
                .group_by(VideoSubmission.status)
            )
            
            status_distribution = {
                row.status.value if hasattr(row.status, 'value') else str(row.status): row.count
                for row in status_result.mappings()
            }
            
            return {
                "hourly_submissions": hourly_data,
                "avg_processing_hours": round(avg_processing_hours, 2),
                "status_distribution": status_distribution
            }
            
        except Exception as e:
            logger.error(f"Error fetching advanced analytics: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch advanced analytics"
            )
