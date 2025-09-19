import logging
from fastapi import FastAPI,Request
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse




#Import of application's components files
from components.auth import router as auth_router
from components.telegram import router as telegram_router



#Import of application's core files 
from core.config import settings ,Settings
from core.database import engine
from core.base import Base


#import of exception and response model
from core.exceptions import APIException
from core.response import IResponse




#configuring logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



async def api_exception_handler(request:Request,exc:APIException):
    """
    Global exception handler for custom APIException.
    Returend a standarized JSON error response.
    """
    
    return JSONResponse(
        status_code=exc.status_code,
        content=IResponse.error_response(message=exc.detail).dict()
    )



@asynccontextmanager
async def lifespan(app:FastAPI):
    """
    Handel startup and shutdown events for the Fastapi application.
    """
    
    logger.info("Application starting up...")
    
    
    yield  # the application runs here
    
    
    #on shutdown:dispose of the database engine connection pool
    
    logger.info("Application shutting down...")
    await engine.dispose()
    logger.info("Database connection pool closed.")



#--FastAPI Application Instance ----


app = FastAPI(
    title=settings.Project_Name,
    version=settings.version,
    debug=settings.Debug,
    lifespan=lifespan,
    exception_handlers={APIException:api_exception_handler}
)        



#--MiddleWare----
if settings.ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logger.info(f"CORS Middleware configured for origins: {settings.ALLOWED_ORIGINS}")

app.include_router(auth_router.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])

app.include_router(telegram_router.router, tags=["Telegram Webhook"])

@app.get("/",tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Editors Dashboard API"}