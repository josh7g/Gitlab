# Import required modules
import os
import logging

# Number of worker processes for Render's free tier
workers = 2

# Worker class to use
worker_class = 'uvicorn.workers.UvicornWorker'

# Maximum number of requests a worker will process before restarting
max_requests = 500
max_requests_jitter = 25

# Memory limit hint (not enforced, just for reference)
max_worker_memory = 150 * 1024 * 1024

# Timeout settings
graceful_timeout = 120
timeout = 120

# Log configuration
loglevel = 'info'
accesslog = '-'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process name
proc_name = 'gitlab-scanner'

# Safe pre-fork hook that won't fail on Render
def pre_fork(server, worker):
    try:
        import resource
        # Try to get current limits
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        # Only set if new limit is lower than current
        if soft > max_worker_memory:
            resource.setrlimit(resource.RLIMIT_AS, (max_worker_memory, hard))
    except Exception as e:
        # Log but don't fail if we can't set limits
        logging.warning(f"Could not set memory limits: {e}")
    
    # Set nice value for CPU priority
    try:
        os.nice(10)
    except Exception:
        pass

# Keep-alive settings
keepalive = 2

# Worker connections
worker_connections = 100

# Thread configuration
threads = 2

# Memory optimization settings
preload_app = True

# Worker initialization hook
def on_starting(server):
    import gc
    gc.collect()

# Worker finalization hook
def worker_exit(server, worker):
    import gc
    gc.collect()

# Bind to the port Render provides
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"

# Reduce buffer size
backlog = 100

# Worker timeout
timeout = 300

# Prevent server from choking
max_requests = 500
max_requests_jitter = 25

# SSL Configuration (if needed)
ssl_version = 2