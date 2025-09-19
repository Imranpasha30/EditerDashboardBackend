from pydantic import field_validator
from pydantic_settings import BaseSettings
import os
from typing import List,Any,Union
from dotenv import load_dotenv

#load environemnt variables from .env file
load_dotenv()


class Settings(BaseSettings):
    
    
    #App settings
    Debug: bool = os.getenv("DEBUG","FALSE").lower() == "true"
    Project_Name: str = "Editors Dashboard"
    version:str="1.0.0"
    API_V1_STR: str = "/api/v1"
    
    #JWT Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY","your-secret-key")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_HOURS : int = int(os.getenv("ACCESS_TOKEN_EXPIRE_HOURS","12"))
    
    #telegram bot token 
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN")
    
    
    # API VIDEO KEy
    API_VIDEO_KEY: str = os.getenv("API_VIDEO_KEY")
    
    
    
    
    #Password Security
    BCRYPT_ROUNDS: int=int(os.getenv("BCRYPT_ROUNDS","12"))
    MIN_PASSWORD_LENGTH: int = 8
    MAX_PASSWORD_LENGTH: int = 64
    
    
    
    #Account Security & Lockout
    MAX_LOGIN_ATTEMPTS:int=int(os.getenv("MAX_LOGIN_ATTEMPTS","5"))
    LOCKOUT_DURATION_MINUTES:int=int(os.getenv("LOCKOUT_DURATION_MINUTES","30"))
    
    
    # OTP Configuration
    OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
    OTP_LENGTH: int = 6
    MAX_OTP_ATTEMPTS: int = 3
    
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    AUTH_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("AUTH_RATE_LIMIT_PER_MINUTE", "10"))
    STRICT_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("STRICT_RATE_LIMIT_PER_MINUTE", "3"))
    
    
    
    
    
    #CORS & Network Security
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_ORIGINS: List[str] = ["*"]
    ALLOWED_ORIGIN_REGEX:str=os.getenv("ALLOWED_ORIGIN_REGEX","")   
    
    
    #Database
    DATABASE_URL:str=os.getenv("DATABASE_URL")
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "10"))
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    DB_POOL_CYCLE: int = int(os.getenv("DB_POOL_CYCLE", "1800"))  # in seconds
    
    # Session Security (for tracking active sessions)
    SESSION_EXPIRE_HOURS: int = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))
    REMEMBER_ME_EXPIRE_DAYS: int = int(os.getenv("REMEMBER_ME_EXPIRE_DAYS", "30"))
    
    
     # Security Headers
    SECURE_COOKIES: bool = os.getenv("SECURE_COOKIES", "FALSE").lower() == "true"
    SECURE_SSL_REDIRECT: bool = os.getenv("SECURE_SSL_REDIRECT", "FALSE").lower() == "true"
    
    # Environment Detection
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    
    
    # Logging & Monitoring
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    ENABLE_SECURITY_LOGGING: bool = os.getenv("ENABLE_SECURITY_LOGGING", "TRUE").lower() == "true"
    
    
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"
    
    
    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == "development"
    
    
    
    
    
    #TODO
    
    #Email (SMTP)
    #OTP Configuration
    #Security Configuration
    #Rate limiting
    
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"
    
    def validate(self):
        """Validate critical security settings"""
        missing = []
        if not self.SECRET_KEY or self.SECRET_KEY == "your-secret-key-change-this-in-production":
            missing.append("SECRET_KEY must be set to a secure value")
        if not self.DATABASE_URL:
            missing.append("DATABASE_URL")
        if self.is_production:
            if len(self.SECRET_KEY) < 32:
                missing.append("SECRET_KEY must be at least 32 characters in production")
                
            if "*" in self.ALLOWED_ORIGINS:
                missing.append("ALLOWED_ORIGINS should not contain '*' in production")
                
            if not self.SECURE_COOKIES:
                missing.append("SECURE_COOKIES should be True in production")
                
        if missing:
            raise RuntimeError(f"Missing or invalid security settings: {', '.join(missing)}")
    
    def get_database_url_with_pool_settings(self) -> str:
        """Get database URL with connection pooling parameters"""
        return self.DATABASE_URL
    
    
    
settings = Settings()

