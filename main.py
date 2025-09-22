# D:\EditerDashboard\main.py

import asyncio
import logging
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import of application's components files
from components.auth import router as auth_router
from components.telegram import router as telegram_router
from components.managerDashboard.router import router as manager_router # Correct import

# Import of application's core files
from core.config import settings
from core.database import engine
from core.base import Base

# Import for the listener
from components.managerDashboard.service import listen_and_broadcast_updates

# Import of exception and response model
from core.exceptions import APIException
from core.response import IResponse

# Configuring logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def api_exception_handler(request: Request, exc: APIException):
    """
    Global exception handler for custom APIException.
    Returns a standardized JSON error response.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=IResponse.error_response(message=exc.detail).dict()
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handle startup and shutdown events for the FastAPI application.
    """
    logger.info("Application starting up...")
    
    # Start the PostgreSQL listener in the background
    listener_task = None
    try:
        # Convert SQLAlchemy URL format to asyncpg format
        asyncpg_url = settings.DATABASE_URL.replace('postgresql+asyncpg://', 'postgresql://')
        listener_task = asyncio.create_task(listen_and_broadcast_updates(asyncpg_url))
        logger.info("PostgreSQL listener task started.")
    except Exception as e:
        logger.error(f"Failed to start PostgreSQL listener: {e}")
        # Continue without the listener if it fails to start
    
    yield  # The application runs here
    
    # On shutdown: dispose of the database engine connection pool and cancel the listener task
    logger.info("Application shutting down...")
    
    # Cancel the listener task gracefully
    if listener_task and not listener_task.done():
        logger.info("Cancelling PostgreSQL listener task...")
        listener_task.cancel()
        try:
            # Wait for the task to be cancelled with a timeout
            await asyncio.wait_for(listener_task, timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("PostgreSQL listener task did not cancel within timeout")
        except asyncio.CancelledError:
            logger.info("PostgreSQL listener task cancelled successfully")
        except Exception as e:
            logger.error(f"Error during listener task cancellation: {e}")
    
    # Close database connections
    try:
        await engine.dispose()
        logger.info("Database connection pool closed.")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")

# -- FastAPI Application Instance ----
app = FastAPI(
    title=settings.Project_Name,
    version=settings.version,
    debug=settings.Debug,
    lifespan=lifespan,
    exception_handlers={APIException: api_exception_handler}
)

# -- Middleware ----
if settings.ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logger.info(f"CORS Middleware configured for origins: {settings.ALLOWED_ORIGINS}")

# -- Routers --
app.include_router(auth_router.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])
app.include_router(telegram_router.router, tags=["Telegram Webhook"])
app.include_router(manager_router, prefix="/api/v1/manager")

@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Editors Dashboard API"}
