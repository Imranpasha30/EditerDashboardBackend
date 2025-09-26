from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import os
from typing import List, Any, Union
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
    # App settings
    Debug: bool = Field(default=False)
    Project_Name: str = Field(default="Editors Dashboard")
    version: str = Field(default="1.0.0")
    API_V1_STR: str = Field(default="/api/v1")
    
    # JWT Authentication
    SECRET_KEY: str = Field(default="your-secret-key")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_HOURS: int = Field(default=12)
    
    # Telegram bot token 
    TELEGRAM_BOT_TOKEN: str = Field(default="")
    
    # API VIDEO Key
    API_VIDEO_KEY: str = Field(default="")
    
    # Password Security
    BCRYPT_ROUNDS: int = Field(default=12)
    MIN_PASSWORD_LENGTH: int = Field(default=8)
    MAX_PASSWORD_LENGTH: int = Field(default=64)
    
    # Account Security & Lockout
    MAX_LOGIN_ATTEMPTS: int = Field(default=5)
    LOCKOUT_DURATION_MINUTES: int = Field(default=30)
    
    # OTP Configuration
    OTP_EXPIRE_MINUTES: int = Field(default=10)
    OTP_LENGTH: int = Field(default=6)
    MAX_OTP_ATTEMPTS: int = Field(default=3)
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60)
    AUTH_RATE_LIMIT_PER_MINUTE: int = Field(default=10)
    STRICT_RATE_LIMIT_PER_MINUTE: int = Field(default=3)
    
    # Environment Detection
    ENVIRONMENT: str = Field(default="development")
    
    # CORS & Network Security - NO DEFAULT VALUES, MUST BE PROVIDED VIA ENV
    ALLOWED_HOSTS: List[str]  # Required from environment
    ALLOWED_ORIGINS: List[str]  # Required from environment
    ALLOWED_ORIGIN_REGEX: str = Field(default="")
    
    # Database
    DATABASE_URL: str = Field(default="")
    DB_POOL_SIZE: int = Field(default=10)
    DB_MAX_OVERFLOW: int = Field(default=20)
    DB_POOL_TIMEOUT: int = Field(default=30)
    DB_POOL_CYCLE: int = Field(default=1800)  # in seconds
    
    # Session Security (for tracking active sessions)
    SESSION_EXPIRE_HOURS: int = Field(default=24)
    REMEMBER_ME_EXPIRE_DAYS: int = Field(default=30)
    
    # Security Headers
    SECURE_COOKIES: bool = Field(default=False)
    SECURE_SSL_REDIRECT: bool = Field(default=False)
    
    # Logging & Monitoring
    LOG_LEVEL: str = Field(default="INFO")
    ENABLE_SECURITY_LOGGING: bool = Field(default=True)
    
    @field_validator('Debug', 'SECURE_COOKIES', 'SECURE_SSL_REDIRECT', 'ENABLE_SECURITY_LOGGING', mode='before')
    @classmethod
    def parse_bool_from_env(cls, v):
        """Parse boolean values from environment variables"""
        if isinstance(v, str):
            return v.lower() in ('true', '1', 'yes', 'on')
        return v
    
    @field_validator('ALLOWED_HOSTS', 'ALLOWED_ORIGINS', mode='before')
    @classmethod
    def parse_list_from_env(cls, v):
        """Parse list values from environment variables"""
        if isinstance(v, str):
            # Handle JSON format: ["item1", "item2"]
            if v.startswith('[') and v.endswith(']'):
                import json
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    pass
            # Handle comma-separated format: item1,item2
            return [item.strip() for item in v.split(',') if item.strip()]
        return v
    
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == "development"
    
    def validate(self):
        """Validate critical security settings"""
        missing = []
        if not self.SECRET_KEY or self.SECRET_KEY == "your-secret-key":
            missing.append("SECRET_KEY must be set to a secure value")
        if not self.DATABASE_URL:
            missing.append("DATABASE_URL")
        if not self.ALLOWED_HOSTS:
            missing.append("ALLOWED_HOSTS must be provided")
        if not self.ALLOWED_ORIGINS:
            missing.append("ALLOWED_ORIGINS must be provided")
            
        if self.is_production:
            if len(self.SECRET_KEY) < 32:
                missing.append("SECRET_KEY must be at least 32 characters in production")
                
            if "*" in self.ALLOWED_ORIGINS:
                missing.append("ALLOWED_ORIGINS should not contain '*' in production")
                
            if "*" in self.ALLOWED_HOSTS:
                missing.append("ALLOWED_HOSTS should not contain '*' in production")
                
            if not self.SECURE_COOKIES:
                missing.append("SECURE_COOKIES should be True in production")
                
        if missing:
            raise RuntimeError(f"Missing or invalid security settings: {', '.join(missing)}")
    
    def get_database_url_with_pool_settings(self) -> str:
        """Get database URL with connection pooling parameters"""
        return self.DATABASE_URL

settings = Settings()
