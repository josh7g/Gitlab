# Number of worker processes
workers = 2

# Worker class to use
worker_class = 'uvicorn.workers.UvicornWorker'

# Maximum number of requests a worker will process before restarting
max_requests = 1000
max_requests_jitter = 50

# Maximum memory (in bytes) that can be used by each worker (256MB)
max_worker_memory = 256 * 1024 * 1024

# Timeout settings
graceful_timeout = 30
timeout = 30

# Log configuration
loglevel = 'info'
accesslog = '-'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process name
proc_name = 'gitlab-scanner'

# Pre-fork hook for memory limits
def pre_fork(server, worker):
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (max_worker_memory, max_worker_memory))

# Keep-alive settings
keepalive = 5

# Worker connections
worker_connections = 1000

# Prevent worker timeout
timeout = 300

# Thread configuration
threads = 4

# Reduce worker spawning
max_requests = 1000
max_requests_jitter = 50