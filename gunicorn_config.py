workers = 1
worker_class = 'aiohttp.worker.GunicornWebWorker'
bind = "0.0.0.0:10000"
timeout = 120
max_requests = 50
worker_connections = 50
worker_tmp_dir = '/dev/shm'