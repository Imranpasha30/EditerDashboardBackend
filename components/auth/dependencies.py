from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
from core.security import security
from components.auth.models import User, UserRole, get_user_by_username
from components.auth.service import AuthService
from typing import Optional
from uuid import UUID
import logging

logger = logging.getLogger(__name__)

# OAuth2PasswordBearer for different login endpoints
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login/admin",  # Default to admin for Swagger UI
    scheme_name="JWT Authentication"
)

# === Base Authentication Dependencies ===

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    request: Request = None
) -> User:
    """
    Get current user from JWT token with comprehensive validation
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify and decode token with blacklist check
        payload = await security.verify_token(token, db=db, token_type="access")
        user_id: str = payload.get("user_id")
        
        if user_id is None:
            logger.error("No user_id in token payload")
            raise credentials_exception
            
        # Convert to UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            logger.error(f"Invalid UUID in token: {user_id}")
            raise credentials_exception
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise credentials_exception
    
    # Get user from database
    try:
        result = await db.get(User, user_uuid)
        if not result:
            logger.error(f"User not found with ID: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not result.is_active:
            logger.warning(f"Inactive user attempted access: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user account"
            )

        # Log access attempt for security monitoring
        if request:
            await AuthService.log_security_event(
                event_type="token_access",
                user_id=str(result.user_id),
                request=request,
                db=db,
                details={
                    "username": result.username,
                    "role": result.role.value,
                    "endpoint": str(request.url)
                },
                severity="info"
            )
            
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        raise credentials_exception

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (additional layer)"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )
    return current_user

async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current verified user"""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required"
        )
    return current_user

async def get_optional_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get current user optionally (for endpoints that work with or without auth)"""
    if not token:
        return None
    
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None

# === Role-Based Dependencies ===

async def require_editor_role(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to have EDITOR role or higher (EDITOR, MANAGER, ADMIN)
    """
    if not current_user.is_editor:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Editor privileges required"
        )
    return current_user

async def require_manager_role(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to have MANAGER role or higher (MANAGER, ADMIN)
    """
    if not current_user.is_manager:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Manager privileges required"
        )
    return current_user

async def require_admin_role(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to have ADMIN role
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# === Specific Role Dependencies (Exact Match) ===

async def require_exact_editor_role(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to have exactly EDITOR role (not manager or admin)
    """
    if current_user.role != UserRole.EDITOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is only for editors"
        )
    return current_user

async def require_exact_manager_role(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to have exactly MANAGER role (not admin)
    """
    if current_user.role != UserRole.MANAGER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is only for managers"
        )
    return current_user

# === Multiple Role Dependencies ===

async def require_editor_or_manager(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to be EDITOR, MANAGER, or ADMIN
    """
    if current_user.role not in [UserRole.EDITOR, UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Editor or Manager privileges required"
        )
    return current_user

async def require_manager_or_admin(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Require user to be MANAGER or ADMIN
    """
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Manager or Admin privileges required"
        )
    return current_user

# === Verified User Role Dependencies ===

async def require_verified_editor(
    current_user: User = Depends(require_editor_role)
) -> User:
    """
    Require verified user with editor privileges
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required for this action"
        )
    return current_user

async def require_verified_manager(
    current_user: User = Depends(require_manager_role)
) -> User:
    """
    Require verified user with manager privileges
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required for this action"
        )
    return current_user

async def require_verified_admin(
    current_user: User = Depends(require_admin_role)
) -> User:
    """
    Require verified user with admin privileges
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required for this action"
        )
    return current_user

# === Permission-Based Dependencies ===

def require_permission(permission: str):
    """
    Create a dependency that requires a specific permission
    """
    async def permission_checker(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        # Get user permissions
        user_permissions = await AuthService.get_user_permissions(current_user)
        
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        
        return current_user
    
    return permission_checker

# === Role Factory Dependencies ===

def require_any_role(*roles: UserRole):
    """
    Create a dependency that requires any of the specified roles
    """
    async def role_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        if current_user.role not in roles:
            role_names = [role.value for role in roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these roles required: {', '.join(role_names)}"
            )
        return current_user
    
    return role_checker

def require_minimum_role(minimum_role: UserRole):
    """
    Create a dependency that requires at least the specified role level
    """
    role_hierarchy = {
        UserRole.USER: 0,
        UserRole.EDITOR: 1,
        UserRole.MANAGER: 2,
        UserRole.ADMIN: 3
    }
    
    async def role_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        user_level = role_hierarchy.get(current_user.role, 0)
        required_level = role_hierarchy.get(minimum_role, 0)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Minimum role '{minimum_role.value}' required"
            )
        return current_user
    
    return role_checker

# === Utility Dependencies ===

async def get_current_user_with_permissions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    Get current user along with their permissions
    """
    permissions = await AuthService.get_user_permissions(current_user)
    
    return {
        "user": current_user,
        "permissions": permissions,
        "role_level": {
            UserRole.USER: 0,
            UserRole.EDITOR: 1,
            UserRole.MANAGER: 2,
            UserRole.ADMIN: 3
        }.get(current_user.role, 0)
    }

async def log_user_activity(
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency that logs user activity (for sensitive endpoints)
    """
    if request:
        await AuthService.log_security_event(
            event_type="sensitive_endpoint_access",
            user_id=str(current_user.user_id),
            request=request,
            db=db,
            details={
                "username": current_user.username,
                "role": current_user.role.value,
                "endpoint": str(request.url),
                "method": request.method
            },
            severity="info"
        )
    
    return current_user
