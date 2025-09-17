from passlib.context import CryptContext
from passlib.hash import bcrypt
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from fastapi import HTTPException, status
import secrets
import re
import uuid
import logging
from core.config import settings

logger = logging.getLogger(__name__)

class SecurityManager:
    """
    Comprehensive security manager for JWT tokens, password hashing,
    and security validations with SQL injection prevention.
    Simplified for single-token authentication.
    """
    
    def __init__(self):
        # Initialize password context with multiple schemes for security
        self.pwd_context = CryptContext(
            schemes=["bcrypt", "pbkdf2_sha256"],
            deprecated="auto",
            bcrypt__rounds=settings.BCRYPT_ROUNDS
        )
        
        # Security patterns for validation
        self.password_patterns = {
            'length': rf'^.{{{settings.MIN_PASSWORD_LENGTH},{settings.MAX_PASSWORD_LENGTH}}}$',
            'uppercase': r'[A-Z]',
            'lowercase': r'[a-z]',
            'digit': r'\d',
            'special': r'[!@#$%^&*(),.?":{}|<>]'
        }
        
        # SQL injection patterns (for additional validation)
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)",
            r"['\"];?\s*--",
            r"['\"];\s*(SELECT|INSERT|UPDATE|DELETE)",
            r"\b(SCRIPT|JAVASCRIPT|VBSCRIPT|ONLOAD|ONERROR)\b",
        ]
    
    # === Password Security ===
    
    def get_password_hash(self, password: str) -> str:
        """Generate secure password hash with salt"""
        try:
            return self.pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Password hashing failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Password processing failed"
            )
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash with timing attack protection"""
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Password verification failed: {str(e)}")
            return False
    
    def is_password_strong(self, password: str) -> tuple[bool, str]:
        """
        Comprehensive password strength validation
        Returns: (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"
        
        # Length check
        if len(password) < settings.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters long"
        
        if len(password) > settings.MAX_PASSWORD_LENGTH:
            return False, f"Password cannot exceed {settings.MAX_PASSWORD_LENGTH} characters"
        
        # Character type requirements
        checks = [
            (self.password_patterns['uppercase'], "Password must contain at least one uppercase letter"),
            (self.password_patterns['lowercase'], "Password must contain at least one lowercase letter"),
            (self.password_patterns['digit'], "Password must contain at least one number"),
            (self.password_patterns['special'], "Password must contain at least one special character")
        ]
        
        for pattern, message in checks:
            if not re.search(pattern, password):
                return False, message
        
        # Common password patterns
        common_patterns = [
            (r'(.)\1{2,}', "Password cannot contain more than 2 consecutive identical characters"),
            (r'(012|123|234|345|456|567|678|789|890)', "Password cannot contain sequential numbers"),
            (r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', "Password cannot contain sequential letters"),
        ]
        
        for pattern, message in common_patterns:
            if re.search(pattern, password.lower()):
                return False, message
        
        # Check against common passwords
        common_passwords = [
            'password', '12345678', 'qwerty123', 'admin123', 'letmein',
            'welcome123', 'password123', 'admin', 'root', 'user'
        ]
        
        if password.lower() in common_passwords:
            return False, "Password is too common. Please choose a more unique password"
        
        return True, "Password is strong"
    
    # === JWT Token Management (Simplified) ===
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token with secure claims - Single token approach"""
        to_encode = data.copy()
        
        # Set expiration time (hours instead of minutes)
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=settings.ACCESS_TOKEN_EXPIRE_HOURS)
        
        # Add standard JWT claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "jti": str(uuid.uuid4()),  # JWT ID for token tracking/blacklisting
        })
        
        try:
            encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
            return encoded_jwt
        except Exception as e:
            logger.error(f"Token creation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token generation failed"
            )
    
    async def verify_token(
        self, 
        token: str, 
        db: Optional[AsyncSession] = None, 
        token_type: str = "access"
    ) -> Dict[str, Any]:
        """
        Verify JWT token with comprehensive validation and blacklist checking
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            # Decode token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            
            # Verify token type
            if payload.get("type") != token_type:
                logger.warning(f"Invalid token type. Expected: {token_type}, Got: {payload.get('type')}")
                raise credentials_exception
            
            # Check expiration
            exp = payload.get("exp")
            if exp is None:
                raise credentials_exception
            
            if datetime.utcnow() > datetime.fromtimestamp(exp):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            # Check token blacklist if database session provided
            jti = payload.get("jti")
            if jti and db:
                is_blacklisted = await self.is_token_blacklisted(jti, db)
                if is_blacklisted:
                    logger.warning(f"Blacklisted token attempted: {jti}")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked"
                    )
            
            return payload
            
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except JWTClaimsError:
            raise credentials_exception
        except JWTError as e:
            logger.error(f"JWT validation error: {str(e)}")
            raise credentials_exception
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise credentials_exception
    
    def get_token_jti(self, token: str) -> Optional[str]:
        """Extract JTI (JWT ID) from token without full validation"""
        try:
            # Decode without verification to get JTI
            unverified_payload = jwt.get_unverified_claims(token)
            return unverified_payload.get("jti")
        except Exception:
            return None
    
    # === Token Blacklisting ===
    
    async def blacklist_token(self, jti: str, token_type: str, db: AsyncSession, reason: str = "logout") -> None:
        """Add token to blacklist"""
        # Import here to avoid circular imports
        from components.auth.models import BlacklistedToken
        
        try:
            blacklisted_token = BlacklistedToken(
                jti=jti,
                token_type=token_type,
                blacklisted_at=datetime.utcnow(),
                reason=reason
            )
            
            db.add(blacklisted_token)
            await db.commit()
            
            logger.info(f"Token blacklisted: {jti} - Reason: {reason}")
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to blacklist token {jti}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token blacklisting failed"
            )
    
    async def is_token_blacklisted(self, jti: str, db: AsyncSession) -> bool:
        """Check if token is blacklisted"""
        from components.auth.models import BlacklistedToken
        
        try:
            result = await db.execute(
                select(BlacklistedToken).where(BlacklistedToken.jti == jti)
            )
            return result.scalar_one_or_none() is not None
        except Exception as e:
            logger.error(f"Error checking token blacklist: {str(e)}")
            return False  # Fail open for availability
    
    async def cleanup_expired_blacklisted_tokens(self, db: AsyncSession) -> int:
        """Clean up expired blacklisted tokens (scheduled task)"""
        from components.auth.models import BlacklistedToken
        
        try:
            # Delete tokens that have been blacklisted longer than token expiry time
            cutoff_time = datetime.utcnow() - timedelta(hours=settings.ACCESS_TOKEN_EXPIRE_HOURS * 2)
            
            result = await db.execute(
                delete(BlacklistedToken).where(
                    BlacklistedToken.blacklisted_at < cutoff_time
                )
            )
            
            deleted_count = result.rowcount
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired blacklisted tokens")
            return deleted_count
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error cleaning up blacklisted tokens: {str(e)}")
            return 0
    
    # === Input Sanitization & SQL Injection Prevention ===
    
    def sanitize_input(self, input_string: str, max_length: int = 1000) -> str:
        """
        Sanitize user input to prevent XSS and other injection attacks
        """
        if not input_string:
            return ""
        
        # Truncate if too long
        sanitized = input_string[:max_length]
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Strip whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    
    def check_sql_injection_patterns(self, input_string: str) -> bool:
        """
        Check input for potential SQL injection patterns
        Returns True if suspicious patterns are found
        """
        if not input_string:
            return False
        
        input_lower = input_string.lower()
        
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_lower, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {pattern}")
                return True
        
        return False
    
    def validate_and_sanitize_input(
        self, 
        input_string: str, 
        field_name: str = "input", 
        max_length: int = 1000,
        allow_html: bool = False
    ) -> str:
        """
        Comprehensive input validation and sanitization
        """
        if not input_string:
            return ""
        
        # Check for SQL injection patterns
        if self.check_sql_injection_patterns(input_string):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid characters detected in {field_name}"
            )
        
        # Sanitize input
        sanitized = self.sanitize_input(input_string, max_length)
        
        # HTML escaping if not allowed
        if not allow_html:
            import html
            sanitized = html.escape(sanitized)
        
        return sanitized
    
    # === Security Token Generation ===
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    def generate_otp(self, length: int = None) -> str:
        """Generate numeric OTP code"""
        if length is None:
            length = settings.OTP_LENGTH
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])

# Create global security instance
security = SecurityManager()

# Convenience functions for backward compatibility
def get_password_hash(password: str) -> str:
    return security.get_password_hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return security.verify_password(plain_password, hashed_password)

def is_password_strong(password: str) -> tuple[bool, str]:
    return security.is_password_strong(password)
