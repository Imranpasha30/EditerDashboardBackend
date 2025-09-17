from sqlalchemy.ext.asyncio import create_async_engine,async_sessionmaker,AsyncSession
from sqlalchemy.orm import DeclarativeBase
from core.config import settings
import logging
from core.base import Base


logger =logging.getLogger(__name__)

#create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=50,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600,
    echo=settings.Debug,
)



#create session factory

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession
    
)


async def get_db():
    """Dependency to get DB session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()