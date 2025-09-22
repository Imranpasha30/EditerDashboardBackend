from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, or_
from fastapi import HTTPException, status, Request
from components.auth.models import User, SecurityEvent, BlacklistedToken, get_user_by_username, UserRole
from components.auth.schemas import (
    EditorCreate, ManagerCreate, UserLogin, EditorLogin, ManagerLogin, AdminLogin
)
from core.security import security, is_password_strong
from core.config import settings
from datetime import datetime, timedelta
import logging
import uuid
import secrets
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class AuthService:
    """
    Comprehensive authentication service with role-based registration and login
    """

    # === User Registration Services ===

    @staticmethod
    async def register_editor(editor_data: EditorCreate, db: AsyncSession, request: Request = None) -> User:
        """Register a new editor with comprehensive validation"""
        
        # Check if user already exists
        await AuthService._check_user_exists(editor_data.username, editor_data.email, db, request)
        
        # Validate password strength
        await AuthService._validate_password_strength(editor_data.password)
        
        # Create new editor
        new_user = User(
            full_name=editor_data.full_name,
            username=editor_data.username,
            email=editor_data.email,
            phone_number=editor_data.phone_number,
            password=security.get_password_hash(editor_data.password),
            role=UserRole.NOT_SELECTED,  
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        # Log successful registration
        await AuthService.log_security_event(
            event_type="editor_registered",
            user_id=str(new_user.user_id),
            request=request,
            db=db,
            details={
                "username": new_user.username, 
                "email": new_user.email,
                "department": getattr(editor_data, 'department', None),
                "specialization": getattr(editor_data, 'specialization', None)
            }
        )
        
        logger.info(f"New editor registered: {new_user.username}")
        return new_user

    @staticmethod
    async def register_manager(manager_data: ManagerCreate, db: AsyncSession, request: Request = None) -> User:
        """Register a new manager with comprehensive validation"""
        
        # Check if user already exists
        await AuthService._check_user_exists(manager_data.username, manager_data.email, db, request)
        
        # Validate password strength
        await AuthService._validate_password_strength(manager_data.password)
        
        # Create new manager
        new_user = User(
            full_name=manager_data.full_name,
            username=manager_data.username,
            email=manager_data.email,
            phone_number=manager_data.phone_number,
            password=security.get_password_hash(manager_data.password),
            role=UserRole.MANAGER,  # Set role to MANAGER
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        # Log successful registration
        await AuthService.log_security_event(
            event_type="manager_registered",
            user_id=str(new_user.user_id),
            request=request,
            db=db,
            details={
                "username": new_user.username, 
                "email": new_user.email,
                "department": manager_data.department,
                "team_size": getattr(manager_data, 'team_size', None),
                "experience_years": getattr(manager_data, 'experience_years', None)
            }
        )
        
        logger.info(f"New manager registered: {new_user.username}")
        return new_user

    # === Authentication Services ===

    @staticmethod
    async def authenticate_user(
        credentials: UserLogin, 
        db: AsyncSession, 
        request: Request = None,
        required_role: Optional[UserRole] = None # This is used by other internal functions
    ) -> User:
        """
        Authenticate a user with comprehensive checks for active status, role, and verification.
        """
        
        user = await get_user_by_username(db, credentials.username)
        
        # 1. Check for basic credentials (user exists and password is correct)
        if not user or not security.verify_password(credentials.password, user.password):
            await AuthService._handle_failed_login(user, credentials.username, db, request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # 2. Check if the account has been deactivated
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="This account has been deactivated."
            )
        
        # --- THIS IS THE NEW, CRITICAL LOGIC ---

        # 3. Block any user whose role has not been assigned yet.
        if user.role == UserRole.NOT_SELECTED:
            await AuthService.log_security_event(
                event_type="login_attempt_pending_approval",
                user_id=str(user.user_id),
                request=request, db=db,
                details={"username": user.username}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account is pending approval from an administrator. Please wait."
            )
            
        # 4. For regular users (not Admins), check if they have been verified by an admin.
        if not user.is_verified and not user.is_admin:
            await AuthService.log_security_event(
                event_type="login_attempt_unverified",
                user_id=str(user.user_id),
                request=request, db=db,
                details={"username": user.username, "role": user.role.value}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account has not been verified by an administrator yet."
            )
            
        # --- END OF NEW LOGIC ---

        # This check is for internal use by functions like `authenticate_editor`
        if required_role and user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. {required_role.value} access required."
            )
        
        # If all checks pass, log the successful login and return the user object
        await AuthService._handle_successful_login(user, db, request)
        
        return user

    @staticmethod
    async def authenticate_editor(credentials: EditorLogin, db: AsyncSession, request: Request = None) -> User:
        """Authenticate editor with role validation"""
        user = await AuthService.authenticate_user(credentials, db, request)
        
        # Check if user has editor privileges (EDITOR, MANAGER, or ADMIN)
        if not user.is_editor:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Editor privileges required"
            )
        
        return user

    @staticmethod
    async def authenticate_manager(credentials: ManagerLogin, db: AsyncSession, request: Request = None) -> User:
        """Authenticate manager with role validation"""
        user = await AuthService.authenticate_user(credentials, db, request)
        
        # Check if user has manager privileges (MANAGER or ADMIN)
        if not user.is_manager:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Manager privileges required"
            )
        
        return user

    @staticmethod
    async def authenticate_admin(credentials: AdminLogin, db: AsyncSession, request: Request = None) -> User:
        """Authenticate admin with role validation"""
        user = await AuthService.authenticate_user(credentials, db, request)
        
        # Check if user has admin privileges
        if not user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        
        return user

    # === Token Management ===

    @staticmethod
    async def create_token(
        user: User, 
        db: AsyncSession, 
        remember_me: bool = False,
        device_info: str = None, 
        ip_address: str = None
    ) -> Dict[str, Any]:
        """Create access token with role-based claims"""
        
        # Determine token expiration
        if remember_me:
            expire_hours = settings.REMEMBER_ME_EXPIRE_DAYS * 24
        else:
            expire_hours = settings.ACCESS_TOKEN_EXPIRE_HOURS
        
        # Create token with user and role information
        access_token = security.create_access_token(
            data={
                "user_id": str(user.user_id),
                "username": user.username,
                "role": user.role.value,
                "full_name": user.full_name
            },
            expires_delta=timedelta(hours=expire_hours)
        )
        
        logger.info(f"Token created for {user.role.value}: {user.username}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expire_hours * 3600,  # Convert to seconds
            "role": user.role,
            "user_id": str(user.user_id)
        }

    @staticmethod
    async def logout_user(user: User, token: str, db: AsyncSession, request: Request = None) -> None:
        """Logout user by blacklisting token"""
        
        # Get JTI from token and blacklist it
        jti = security.get_token_jti(token)
        if jti:
            await security.blacklist_token(jti, "access", db, reason="user_logout")
        
        # Log logout event
        await AuthService.log_security_event(
            event_type="user_logout",
            user_id=str(user.user_id),
            request=request,
            db=db,
            details={
                "username": user.username,
                "role": user.role.value,
                "jti": jti
            }
        )

    # === Utility Methods ===

    @staticmethod
    async def check_username_availability(username: str, db: AsyncSession) -> bool:
        """Check if username is available"""
        result = await db.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none() is None

    @staticmethod
    async def check_email_availability(email: str, db: AsyncSession) -> bool:
        """Check if email is available"""
        result = await db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none() is None

    @staticmethod
    async def get_user_permissions(user: User) -> list[str]:
        """Get role-based permissions for user"""
        permissions = []
        
        # Base permissions for all users
        permissions.extend(["view_profile", "edit_profile"])
        
        # Editor permissions
        if user.is_editor:
            permissions.extend([
                "create_content", "edit_content", "delete_own_content",
                "view_analytics", "manage_media"
            ])
        
        # Manager permissions
        if user.is_manager:
            permissions.extend([
                "manage_editors", "view_all_content", "approve_content",
                "view_reports", "manage_categories"
            ])
        
        # Admin permissions
        if user.is_admin:
            permissions.extend([
                "manage_users", "system_settings", "view_security_logs",
                "manage_roles", "backup_data", "system_maintenance"
            ])
        
        return permissions

    # === Private Helper Methods ===

    @staticmethod
    async def _check_user_exists(username: str, email: str, db: AsyncSession, request: Request = None):
        """Check if user already exists"""
        result = await db.execute(select(User).where(
            or_(User.username == username, User.email == email)
        ))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            # Log security event
            await AuthService.log_security_event(
                event_type="registration_attempt_duplicate",
                request=request,
                db=db,
                details={
                    "attempted_username": username,
                    "attempted_email": email,
                    "existing_user_id": str(existing_user.user_id)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists"
            )

    @staticmethod
    async def _validate_password_strength(password: str):
        """Validate password strength"""
        is_strong, reason = is_password_strong(password)
        if not is_strong:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=reason
            )

    @staticmethod
    async def _check_account_locked(user: User, db: AsyncSession, request: Request):
        """Check if account is locked"""
        # Note: You might want to add locked_until field to User model
        # For now, we'll implement basic failed attempt tracking
        pass

    @staticmethod
    async def _handle_failed_login(user: Optional[User], attempted_username: str, db: AsyncSession, request: Request):
        """Handle failed login attempt"""
        await AuthService.log_security_event(
            event_type="login_failed",
            user_id=str(user.user_id) if user else None,
            request=request,
            db=db,
            details={"attempted_username": attempted_username}
        )

    @staticmethod
    async def _handle_successful_login(user: User, db: AsyncSession, request: Request):
        """Handle successful login"""
        user.last_login = datetime.utcnow()
        user.updated_at = datetime.utcnow()
        await db.commit()
        
        # Log successful login
        await AuthService.log_security_event(
            event_type="login_successful",
            user_id=str(user.user_id),
            request=request,
            db=db,
            details={
                "username": user.username,
                "role": user.role.value
            }
        )

    # === Security Event Logging ===

    @staticmethod
    async def log_security_event(
        event_type: str,
        user_id: str = None,
        request: Request = None,
        db: AsyncSession = None,
        details: Dict[str, Any] = None,
        severity: str = None
    ):
        """Log security events for monitoring and analysis"""
        if not db:
            return
            
        ip_address = None
        user_agent = None
        
        if request:
            # Get real IP address (considering proxy headers)
            ip_address = (
                request.headers.get('x-forwarded-for', '').split(',')[0].strip() or
                request.headers.get('x-real-ip') or
                request.client.host if request.client else None
            )
            user_agent = request.headers.get('user-agent')
        
        # Map event types to severity levels
        severity_map = {
            'login_failed': 'warning',
            'login_successful': 'info',
            'editor_registered': 'info',
            'manager_registered': 'info',
            'registration_attempt_duplicate': 'warning',
            'login_attempt_inactive_account': 'warning',
            'login_attempt_insufficient_role': 'warning',
            'user_logout': 'info',
            'account_locked': 'critical',
        }
        
        # Use provided severity or map from event type
        final_severity = severity or severity_map.get(event_type, 'info')
        
        # Convert details to JSON string
        details_str = str(details) if details else None
        
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details_str,
            severity=final_severity
        )
        
        db.add(event)
        try:
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to log security event: {str(e)}")
