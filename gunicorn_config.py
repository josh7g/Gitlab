import os

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

