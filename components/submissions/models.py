from sqlalchemy import Column, String, DateTime, Enum as SQLAlchemyEnum, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from core.base import Base 
import uuid
from datetime import datetime

# Import Python's native Enum with a clear alias
from enum import Enum as PythonEnum

# --- 1. Volunteer Model ---
class Volunteer(Base):
    __tablename__ = "volunteers"

    id = Column(String, primary_key=True, index=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    username = Column(String(50), nullable=True, index=True)
    phone_number = Column(String(20), unique=True, nullable=True, index=True)
    phone_verified= Column(Boolean ,default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Volunteer(id='{self.id}', username='{self.username}')>"


# --- 2. Video Submission Model ---

# CORRECTED: This class now inherits from Python's native Enum
class SubmissionStatus(str, PythonEnum):
    PROCESSING = "processing"
    PENDING_REVIEW = "pending_review"
    ACCEPTED = "accepted"
    ASSIGNED = "assigned"
    DECLINED = "declined"
    USED = "used"

class VideoSubmission(Base):
    __tablename__ = "video_submissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    volunteer_id = Column(String, ForeignKey("volunteers.id"), nullable=False, index=True)
    telegram_file_id = Column(String, nullable=False, unique=True, index=True)
    video_platform_url = Column(String, nullable=True)
    
    # CORRECTED: This now correctly uses SQLAlchemy's Enum to wrap the Python Enum
    status = Column(SQLAlchemyEnum(SubmissionStatus), default=SubmissionStatus.PROCESSING, nullable=False)
    
    assigned_editor_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True)
    decline_reason = Column(String, nullable=True)
    notification_sent=Column(Boolean,default=False)
    notification_sent_at=Column(DateTime,nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<VideoSubmission(id='{self.id}', volunteer_id='{self.volunteer_id}')>"


# --- 3. OTP Verification Model ---
class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    volunteer_id = Column(String, ForeignKey("volunteers.id"), nullable=False, index=True)
    otp_hash = Column(String(255), nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<OTPVerification(volunteer_id='{self.volunteer_id}', is_used={self.is_used})>"
