import os
import multiprocessing
from app import logger

# Basic configuration
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
workers = 1
worker_class = "uvicorn.workers.UvicornWorker"

# Timeouts
timeout = 300
keepalive = 65
graceful_timeout = 120

# Request limits
max_requests = 1200
max_requests_jitter = 100

# Temporary directory
worker_tmp_dir = "/dev/shm"

# Performance
worker_connections = 1000
preload_app = True

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
capture_output = True

# Worker configuration
worker_exit = 'app:worker_exit'

def on_starting(server):
    """Server startup callback"""
    logger.info("Starting server...")

def on_exit(server):
    """Server shutdown callback"""
    logger.info("Shutting down server...")

def post_worker_init(worker):
    """Worker initialization callback"""
    logger.info(f"Initializing worker {worker.pid}")