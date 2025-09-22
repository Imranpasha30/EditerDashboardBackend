from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from uuid import UUID
from typing import Optional
from enum import Enum
import html
import re

# === Enums ===
class UserRole(str, Enum):
    USER = "USER"
    EDITOR = "EDITOR"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"
    NOT_SELECTED = "NOT_SELECTED"

# === Base Registration Schema ===
class UserCreateBase(BaseModel):
    """Base schema for user registration"""
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name of the user")
    username: str = Field(..., min_length=3, max_length=30, description="Unique username")
    email: EmailStr = Field(..., description="Valid email address")
    phone_number: Optional[str] = Field(None, pattern=r"^[+]?[0-9]{10,15}$", description="Phone number")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password")

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        # Sanitize input
        v = html.escape(v.strip())
        
        # Check format
        if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError('Username can only contain letters, numbers, dots, hyphens, and underscores')
        
        # Check for reserved usernames
        reserved = {'admin', 'root', 'api', 'www', 'mail', 'ftp', 'localhost', 'test', 'editor', 'manager'}
        if v.lower() in reserved:
            raise ValueError('This username is reserved')
            
        return v
    
    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        v = html.escape(v.strip())
        if not re.match(r"^[a-zA-Z\s'-]+$", v):
            raise ValueError('Full name can only contain letters, spaces, apostrophes, and hyphens')
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email_domain(cls, v):
        # Block temporary email domains
        blocked_domains = {
            'tempmail.com', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org'
        }
        domain = v.split('@')[1].lower()
        if domain in blocked_domains:
            raise ValueError('Temporary email addresses are not allowed')
        return v

# === Role-Specific Registration Schemas ===
class EditorCreate(UserCreateBase):
    """Schema for editor registration"""
    department: Optional[str] = Field(None, max_length=50, description="Department or team")
    specialization: Optional[str] = Field(None, max_length=100, description="Area of expertise")
    
    class Config:
        json_schema_extra = {
            "example": {
                "full_name": "John Smith",
                "username": "john_editor",
                "email": "john.smith@company.com",
                "phone_number": "+1234567890",
                "password": "SecurePass123!",
                "department": "Content Team",
                "specialization": "Technical Writing"
            }
        }

class ManagerCreate(UserCreateBase):
    """Schema for manager registration"""
    department: str = Field(..., max_length=50, description="Department managing")
    team_size: Optional[int] = Field(None, ge=1, le=1000, description="Size of team managing")
    experience_years: Optional[int] = Field(None, ge=0, le=50, description="Years of management experience")
    
    class Config:
        json_schema_extra = {
            "example": {
                "full_name": "Jane Manager",
                "username": "jane_manager",
                "email": "jane.manager@company.com",
                "phone_number": "+1234567890",
                "password": "SecurePass123!",
                "department": "Marketing",
                "team_size": 15,
                "experience_years": 8
            }
        }

# === Login Schemas ===
class UserLogin(BaseModel):
    """Base login schema"""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")
    remember_me: Optional[bool] = Field(False, description="Extended session duration")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_editor",
                "password": "SecurePass123!",
                "remember_me": False
            }
        }

class EditorLogin(UserLogin):
    """Editor-specific login (same as base but for clarity)"""
    pass

class ManagerLogin(UserLogin):
    """Manager-specific login (same as base but for clarity)"""
    pass

class AdminLogin(UserLogin):
    """Admin-specific login (same as base but for clarity)"""
    pass

# === Response Schemas ===
class UserResponse(BaseModel):
    """User response schema"""
    user_id: UUID
    full_name: str
    username: str
    email: EmailStr
    phone_number: Optional[str]
    role: UserRole
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "full_name": "John Smith",
                "username": "john_editor",
                "email": "john.smith@company.com",
                "phone_number": "+1234567890",
                "role": "EDITOR",
                "is_active": True,
                "is_verified": False,
                "last_login": None,
                "created_at": "2025-09-17T12:00:00",
                "updated_at": "2025-09-17T12:00:00"
            }
        }

class Token(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token expiration time in seconds")
    role: UserRole
    # user_id: str

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 43200,
                "role": "EDITOR",
                # "user_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }

# === Utility Schemas ===
class AvailabilityResponse(BaseModel):
    """Username/email availability check response"""
    available: bool
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "available": True,
                "message": "Username is available"
            }
        }

class MessageResponse(BaseModel):
    """Generic success/error message response"""
    message: str
    success: bool = True

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Operation completed successfully",
                "success": True
            }
        }

class ErrorResponse(BaseModel):
    """Error response schema"""
    error: str
    detail: Optional[str] = None
    status_code: int

    class Config:
        json_schema_extra = {
            "example": {
                "error": "Validation Error",
                "detail": "Invalid input provided",
                "status_code": 400
            }
        }

# === Role Check Schemas ===
class RoleCheckResponse(BaseModel):
    """Role verification response"""
    user_id: UUID
    role: UserRole
    permissions: list[str]
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "role": "EDITOR",
                "permissions": ["create_post", "edit_post", "view_analytics"],
                "message": "Access granted"
            }
        }
