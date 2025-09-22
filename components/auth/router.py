from fastapi import APIRouter, Body, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordRequestForm
from core.database import get_db
from components.auth.schemas import (
    EditorCreate, ManagerCreate, UserResponse, Token, MessageResponse,
    AvailabilityResponse, EditorLogin, ManagerLogin, AdminLogin, 
    RoleCheckResponse, UserLogin
)
from components.auth.service import AuthService
from components.auth.dependencies import (
    get_current_user, require_editor_role, require_manager_role, 
    require_admin_role, get_current_user_with_permissions,
    log_user_activity
)
from components.auth.models import User, UserRole
from core.security import is_password_strong
from slowapi import Limiter
from slowapi.util import get_remote_address
import logging
from datetime import datetime
from uuid import UUID
from sqlalchemy import or_
from pydantic import BaseModel, Field
from sqlalchemy import select, or_
from sqlalchemy.orm import relationship
from typing import Optional


class UserStatusUpdate(BaseModel):
    is_active: bool
    is_verified: bool

class UserUpdate(BaseModel):
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None

logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["Authentication"])

# === Username/Email Availability Checks ===

@router.get("/check-username/{username}", response_model=AvailabilityResponse)
@limiter.limit("10/minute")
async def check_username_availability(
    request: Request,
    username: str, 
    db: AsyncSession = Depends(get_db)
):
    """Check if username is available for registration"""
    if len(username) < 3 or len(username) > 30:
        return AvailabilityResponse(
            available=False,
            message="Username must be between 3 and 30 characters"
        )
    
    is_available = await AuthService.check_username_availability(username, db)
    
    return AvailabilityResponse(
        available=is_available,
        message="Username is available" if is_available else "Username is already taken"
    )

@router.get("/check-email/{email}", response_model=AvailabilityResponse)
@limiter.limit("10/minute")
async def check_email_availability(
    request: Request,
    email: str, 
    db: AsyncSession = Depends(get_db)
):
    """Check if email is available for registration"""
    try:
        from email_validator import validate_email, EmailNotValidError
        validate_email(email)
    except EmailNotValidError:
        return AvailabilityResponse(
            available=False,
            message="Invalid email format"
        )
    
    is_available = await AuthService.check_email_availability(email, db)
    
    return AvailabilityResponse(
        available=is_available,
        message="Email is available" if is_available else "Email is already registered"
    )

# === Role-Based Registration Endpoints ===

@router.post("/register/editor", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/hour")
async def register_editor(
    request: Request,
    editor_data: EditorCreate, 
    db: AsyncSession = Depends(get_db)
):
    """Register a new editor account"""
    new_editor = await AuthService.register_editor(editor_data, db, request)
    return new_editor

@router.post("/register/manager", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/hour")
async def register_manager(
    request: Request,
    manager_data: ManagerCreate, 
    db: AsyncSession = Depends(get_db)
):
    """Register a new manager account"""
    new_manager = await AuthService.register_manager(manager_data, db, request)
    return new_manager

# === Role-Based Login Endpoints ===

@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login_for_access_token(
    request: Request,
    credentials: UserLogin, 
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate any user and return a JWT token, but deny access
    if their role is 'NOT_SELECTED'.
    """
    # 1. Authenticate the user by checking their username and password
    user = await AuthService.authenticate_user(credentials, db, request)

    if user.role == UserRole.NOT_SELECTED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has not been approved by an administrator yet. Please wait."
        )

    # 3. If the check passes, proceed to create and return the token as before
    device_info = request.headers.get('user-agent', 'Unknown')
    ip_address = request.headers.get('x-forwarded-for', request.client.host if request.client else 'Unknown')
    
    token_data = await AuthService.create_token(
        user, db, credentials.remember_me, device_info, ip_address
    )
    
    return Token(**token_data)

@router.post("/login/manager", response_model=Token)
@limiter.limit("5/minute")
async def login_manager(
    request: Request,
    credentials: ManagerLogin, 
    db: AsyncSession = Depends(get_db)
):
    """Authenticate manager and return JWT token"""
    user = await AuthService.authenticate_manager(credentials, db, request)
    
    # Get device info
    device_info = request.headers.get('user-agent', 'Unknown')
    ip_address = request.headers.get('x-forwarded-for', request.client.host if request.client else None)
    
    token_data = await AuthService.create_token(
        user, db, credentials.remember_me, device_info, ip_address
    )
    
    return Token(**token_data)

@router.post("/login/admin", response_model=Token)
@limiter.limit("3/minute")  # Stricter rate limiting for admin
async def login_admin(
    request: Request,
    credentials: AdminLogin, 
    db: AsyncSession = Depends(get_db)
):
    """Authenticate admin and return JWT token"""
    user = await AuthService.authenticate_admin(credentials, db, request)
    
    # Get device info
    device_info = request.headers.get('user-agent', 'Unknown')
    ip_address = request.headers.get('x-forwarded-for', request.client.host if request.client else None)
    
    token_data = await AuthService.create_token(
        user, db, credentials.remember_me, device_info, ip_address
    )
    
    return Token(**token_data)

@router.post("/login/user", response_model=Token)
@limiter.limit("5/minute")
async def login_user(
    request: Request,
    credentials: UserLogin, 
    db: AsyncSession = Depends(get_db)
):
    """Authenticate regular user and return JWT token (if USER role exists)"""
    user = await AuthService.authenticate_user(credentials, db, request)
    
    # Get device info
    device_info = request.headers.get('user-agent', 'Unknown')
    ip_address = request.headers.get('x-forwarded-for', request.client.host if request.client else None)
    
    token_data = await AuthService.create_token(
        user, db, credentials.remember_me, device_info, ip_address
    )
    
    return Token(**token_data)

# === Form-Based Login for Swagger UI ===

@router.post("/login/form", response_model=Token)
@limiter.limit("5/minute")
async def login_form(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """Form-based login for Swagger UI documentation"""
    credentials = UserLogin(
        username=form_data.username,
        password=form_data.password
    )
    
    user = await AuthService.authenticate_user(credentials, db, request)
    
    device_info = request.headers.get('user-agent', 'Swagger UI')
    ip_address = request.headers.get('x-forwarded-for', request.client.host if request.client else None)
    
    token_data = await AuthService.create_token(
        user, db, False, device_info, ip_address
    )
    
    return Token(**token_data)

# === Token Management ===

@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout user by blacklisting access token"""
    
    # Get token from authorization header
    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        access_token = authorization.split(" ")[1]
        await AuthService.logout_user(current_user, access_token, db, request)
    
    return MessageResponse(
        message=f"Logged out successfully",
        success=True
    )

# === User Profile Endpoints ===

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current authenticated user's profile"""
    return current_user

@router.get("/me/permissions", response_model=RoleCheckResponse)
async def get_current_user_permissions(
    user_data: dict = Depends(get_current_user_with_permissions),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's role and permissions"""
    user = user_data["user"]
    permissions = user_data["permissions"]
    
    return RoleCheckResponse(
        user_id=user.user_id,
        role=user.role,
        permissions=permissions,
        message=f"User has {user.role.value} role with {len(permissions)} permissions"
    )

# === Role-Specific Profile Endpoints ===

@router.get("/editor/profile", response_model=UserResponse)
async def get_editor_profile(
    current_user: User = Depends(require_editor_role)
):
    """Get current editor's profile - requires editor privileges"""
    return current_user

@router.get("/manager/profile", response_model=UserResponse)
async def get_manager_profile(
    current_user: User = Depends(require_manager_role)
):
    """Get current manager's profile - requires manager privileges"""
    return current_user

@router.get("/admin/profile", response_model=UserResponse)
async def get_admin_profile(
    current_user: User = Depends(require_admin_role)
):
    """Get current admin's profile - requires admin privileges"""
    return current_user

# === Role Verification Endpoints ===

@router.get("/verify/editor", response_model=RoleCheckResponse)
async def verify_editor_access(
    current_user: User = Depends(require_editor_role),
    db: AsyncSession = Depends(get_db)
):
    """Verify user has editor access"""
    permissions = await AuthService.get_user_permissions(current_user)
    
    return RoleCheckResponse(
        user_id=current_user.user_id,
        role=current_user.role,
        permissions=permissions,
        message="Editor access verified"
    )

@router.get("/verify/manager", response_model=RoleCheckResponse)
async def verify_manager_access(
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """Verify user has manager access"""
    permissions = await AuthService.get_user_permissions(current_user)
    
    return RoleCheckResponse(
        user_id=current_user.user_id,
        role=current_user.role,
        permissions=permissions,
        message="Manager access verified"
    )

@router.get("/verify/admin", response_model=RoleCheckResponse)
async def verify_admin_access(
    current_user: User = Depends(require_admin_role),
    db: AsyncSession = Depends(get_db)
):
    """Verify user has admin access"""
    permissions = await AuthService.get_user_permissions(current_user)
    
    return RoleCheckResponse(
        user_id=current_user.user_id,
        role=current_user.role,
        permissions=permissions,
        message="Admin access verified"
    )

# === Admin Management Endpoints ===

@router.get("/admin/users", response_model=list[UserResponse])
async def list_all_users(
    current_user: User = Depends(require_admin_role),
    db: AsyncSession = Depends(get_db)
):
    """List all users - Admin only"""
    from sqlalchemy import select
    
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    
    return users

@router.put("/admin/users/{user_id}/role")
async def change_user_role(
    user_id: str,
    new_role: UserRole,
    current_user: User = Depends(require_admin_role),
    db: AsyncSession = Depends(get_db)
):
    """Change user role - Admin only"""
    from uuid import UUID
    
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    user = await db.get(User, user_uuid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    old_role = user.role
    user.role = new_role
    user.updated_at = datetime.utcnow()
    
    await db.commit()
    
    # Log role change
    await AuthService.log_security_event(
        event_type="role_changed",
        user_id=str(current_user.user_id),
        db=db,
        details={
            "target_user_id": str(user.user_id),
            "target_username": user.username,
            "old_role": old_role.value,
            "new_role": new_role.value,
            "changed_by": current_user.username
        },
        severity="warning"
    )
    
    return MessageResponse(
        message=f"User {user.username} role changed from {old_role.value} to {new_role.value}",
        success=True
    )

# === Health Check ===

@router.get("/health", response_model=MessageResponse)
async def auth_health_check():
    """Health check endpoint for authentication service"""
    return MessageResponse(
        message="Authentication service is healthy",
        success=True
    )

# === Test Endpoints (Remove in production) ===

@router.get("/test/roles")
async def test_role_access(
    current_user: User = Depends(get_current_user)
):
    """Test endpoint to check role access levels"""
    return {
        "username": current_user.username,
        "role": current_user.role.value,
        "is_editor": current_user.is_editor,
        "is_manager": current_user.is_manager,
        "is_admin": current_user.is_admin,
        "message": f"Hello {current_user.full_name}! You have {current_user.role.value} access."
    }

@router.get("/manager/team", response_model=list[UserResponse])
async def get_manager_team_list(
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a list of all users who are either pending approval (NOT_SELECTED)
    or are already part of the team (EDITOR).
    """
    # This query will now work because 'select' and 'or_' are imported
    stmt = select(User).where(
        or_(User.role == UserRole.NOT_SELECTED, User.role == UserRole.EDITOR)
    ).order_by(User.created_at.desc())
    
    result = await db.execute(stmt)
    users = result.scalars().all()
    return users


@router.put("/manager/users/{user_id}", response_model=MessageResponse)
async def update_user_details(
    user_id: UUID,
    update_data: UserUpdate,
    current_user: User = Depends(require_manager_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Update a user's role, active, or verified status.
    """
    user_to_update = await db.get(User, user_id)

    if not user_to_update:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Update fields only if they were provided in the request
    if update_data.role is not None:
        user_to_update.role = update_data.role
    if update_data.is_active is not None:
        user_to_update.is_active = update_data.is_active
    if update_data.is_verified is not None:
        user_to_update.is_verified = update_data.is_verified
    
    await db.commit()
    return MessageResponse(message=f"User {user_to_update.username} has been successfully updated.")

# Add this to your router.py file

@router.post("/validate-access", response_model=dict)
async def validate_route_access(
    request: Request,
    path_data: dict = Body(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Validate if current user has access to requested path
    This provides server-side route protection
    """
    requested_path = path_data.get("requested_path", "")
    
    # Define role-based path access rules
    path_permissions = {
        "/admin": ["ADMIN"],
        "/managerdashboard": ["MANAGER", "ADMIN"],
        "/editordashboard": ["EDITOR", "MANAGER", "ADMIN"],
        "/user": ["USER", "EDITOR", "MANAGER", "ADMIN"]
    }
    
    # Check if user has permission for requested path
    has_permission = False
    for path_prefix, allowed_roles in path_permissions.items():
        if requested_path.startswith(path_prefix):
            has_permission = current_user.role.value in allowed_roles
            break
    else:
        # Default: allow access to paths not specifically restricted
        has_permission = True
    
    # Log access attempt
    await AuthService.log_security_event(
        event_type="route_access_check",
        user_id=str(current_user.user_id),
        request=request,
        db=db,
        details={
            "requested_path": requested_path,
            "user_role": current_user.role.value,
            "permission_granted": has_permission
        },
        severity="info"
    )
    
    return {
        "valid": True,
        "has_permission": has_permission,
        "user": {
            "id": str(current_user.user_id),
            "username": current_user.username,
            "role": current_user.role.value
        }
    }
