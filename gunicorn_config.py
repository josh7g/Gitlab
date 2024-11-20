import multiprocessing
import os

# Gunicorn config
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
log_level = "info"

# SSL config (if needed)
keyfile = os.getenv("SSL_KEYFILE", None)
certfile = os.getenv("SSL_CERTFILE", None)

# Logging
accesslog = "-"
errorlog = "-"