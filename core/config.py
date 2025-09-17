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
    
    #allowence of requests
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_ORIGINS: List[str] = ["*"]   
    
    
    #Database
    DATABASE_URL:str=os.getenv("DATABASE_URL")
    
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
        missing = []
        if not self.SECRAT_KEY:
            missing.append("SECRET_KEY")
        if not self.DATABASE_URL:
            missing.append("DATABASE_URL")
        if missing:
            raise RuntimeError(f"Missing required settings: {', '.join(missing)}. ")
    
    
    
settings = Settings()

