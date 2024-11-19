# For 512MB RAM, we should use minimal workers
workers = 1
worker_class = 'asyncio.Worker'
bind = "0.0.0.0:10000"
timeout = 120  # Increased timeout for slower operations
max_requests = 50  # Restart workers after 50 requests to free memory
worker_connections = 50  # Limit concurrent connections

# Memory management
worker_tmp_dir = '/dev/shm'  # Use RAM for temporary files