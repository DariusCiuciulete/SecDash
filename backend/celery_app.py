"""
Celery worker configuration for backg    # Task timeouts and retries
    task_soft_time_limit=900,  # 15 minutes soft limit
    task_time_limit=1200,  # 20 minutes hard limitnd scan processing
"""
import os
import asyncio
from celery import Celery
from celery.signals import worker_ready
from kombu import Queue

from config import settings
from database import db_manager, init_db


# Create Celery app
celery_app = Celery(
    "secdash_worker",
    broker=str(settings.redis.broker_url),
    backend=str(settings.redis.result_backend),
    include=["workers.scan_worker"]  # Remove enrichment_worker for now
)

# Celery configuration
celery_app.conf.update(
    # Task routing
    task_routes={
        "workers.scan_worker.*": {"queue": "scans"},
    },
    
    # Queue configuration
    task_default_queue="default",
    task_queues=(
        Queue("default", routing_key="default"),
        Queue("scans", routing_key="scans"),
    ),
    
    # Task execution
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task timeouts and retries
    task_soft_time_limit=3600,  # 1 hour soft limit
    task_time_limit=3900,       # 1 hour 5 minutes hard limit
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    
    # Result backend settings
    result_expires=1800,  # Results expire after 30 minutes
    result_persistent=True,
    
    # Worker settings
    worker_disable_rate_limits=True,
    worker_pool_restarts=True,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Redis specific settings
    redis_socket_keepalive=True,
    redis_socket_keepalive_options={
        "TCP_KEEPINTVL": 1,
        "TCP_KEEPCNT": 3,
        "TCP_KEEPIDLE": 1,
    },
)


@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Initialize worker when ready"""
    print("Celery worker ready, initializing database...")
    # Run async database initialization in sync context
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(init_db())
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {e}")
    finally:
        loop.close()


# Health check task
@celery_app.task(name="health_check")
def health_check():
    """Simple health check task"""
    return {"status": "healthy", "worker": os.getenv("HOSTNAME", "unknown")}


if __name__ == "__main__":
    celery_app.start()
