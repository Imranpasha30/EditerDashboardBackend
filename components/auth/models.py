from sqlalchemy import Column, String, Boolean, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from core.base import Base
import uuid
from datetime import datetime
from enum import Enum as PyEnum

class UserRole(PyEnum):
    USER = "USER"
    EDITOR = "EDITOR" 
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"
    NOT_SELECTED=" NOT_SELECTED"

class User(Base):
    __tablename__ = "users"

    # Primary identifier
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Basic information
    full_name = Column(String(100), nullable=False)
    username = Column(String(30), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    phone_number = Column(String(15), nullable=True)
    
    # Security
    password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.NOT_SELECTED, nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Activity tracking
    last_login = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}', role='{self.role.value}')>"
    
    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN
    
    @property
    def is_manager(self) -> bool:
        return self.role in [UserRole.MANAGER, UserRole.ADMIN]
    
    @property
    def is_editor(self) -> bool:
        return self.role in [UserRole.EDITOR, UserRole.MANAGER, UserRole.ADMIN]

# Supporting tables remain the same
class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    jti = Column(String(255), unique=True, nullable=False, index=True)
    token_type = Column(String(20), nullable=False)
    blacklisted_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(String(100), nullable=True)

    def __repr__(self):
        return f"<BlacklistedToken(jti='{self.jti}', token_type='{self.token_type}')>"

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=True)
    event_type = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(String(1000), nullable=True)
    severity = Column(String(20), default="info")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<SecurityEvent(event_type='{self.event_type}', user_id='{self.user_id}', severity='{self.severity}')>"

# Utility function
async def get_user_by_username(db, username: str):
    """Get user by username or email"""
    from sqlalchemy import select, or_
    result = await db.execute(
        select(User).where(
            or_(User.username == username, User.email == username)
        )
    )
    return result.scalar_one_or_none()
