"""
Database connection and session management using SQLAlchemy 2.0 async
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager

from config import settings
from models import Base


class DatabaseManager:
    """Database manager for async SQLAlchemy operations"""
    
    def __init__(self):
        # Create async engine with connection pooling
        engine_kwargs = {
            "echo": settings.database.echo,
        }
        
        # Add pool configuration if not using NullPool
        if not settings.debug:
            engine_kwargs.update({
                "pool_size": settings.database.pool_size,
                "max_overflow": settings.database.max_overflow,
            })
        else:
            engine_kwargs["poolclass"] = NullPool
            
        self.engine = create_async_engine(
            str(settings.database.url),
            **engine_kwargs
        )
        
        # Create session factory
        self.SessionLocal = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    
    async def create_tables(self):
        """Create all database tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def drop_tables(self):
        """Drop all database tables (for testing)"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    
    async def close(self):
        """Close database connections"""
        await self.engine.dispose()
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session with automatic cleanup"""
        async with self.SessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


# Global database manager instance
db_manager = DatabaseManager()


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI to get database session"""
    async with db_manager.get_session() as session:
        yield session


async def init_db():
    """Initialize database with tables and TimescaleDB hypertables"""
    await db_manager.create_tables()
    
    # Create TimescaleDB hypertable for scans (telemetry data)
    async with db_manager.get_session() as session:
        try:
            # Enable TimescaleDB extension
            await session.execute("CREATE EXTENSION IF NOT EXISTS timescaledb;")
            
            # Create hypertable for scans table
            await session.execute("""
                SELECT create_hypertable('scans', 'created_at', 
                    if_not_exists => TRUE,
                    chunk_time_interval => INTERVAL '1 day');
            """)
            
            # Add retention policy for scan data (keep 1 year)
            await session.execute("""
                SELECT add_retention_policy('scans', INTERVAL '1 year', 
                    if_not_exists => TRUE);
            """)
            
            await session.commit()
            print("TimescaleDB hypertables created successfully")
            
        except Exception as e:
            print(f"TimescaleDB setup warning: {e}")
            # Continue without TimescaleDB if not available
            await session.rollback()


async def close_db():
    """Close database connections"""
    await db_manager.close()
