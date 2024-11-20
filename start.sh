#!/bin/bash
export PYTHONPATH="${PYTHONPATH}:${PWD}"
export MAX_WORKERS=1
export WORKER_CLASS="uvicorn.workers.UvicornWorker"
export TIMEOUT=300
export KEEP_ALIVE=65
export MAX_REQUESTS=1200
export MAX_REQUESTS_JITTER=100
export GRACEFUL_TIMEOUT=120

exec gunicorn asgi_app:asgi_app \
    --bind "0.0.0.0:$PORT" \
    --workers $MAX_WORKERS \
    --worker-class $WORKER_CLASS \
    --timeout $TIMEOUT \
    --keep-alive $KEEP_ALIVE \
    --max-requests $MAX_REQUESTS \
    --max-requests-jitter $MAX_REQUESTS_JITTER \
    --graceful-timeout $GRACEFUL_TIMEOUT \
    --log-level info \
    --access-logfile - \
    --error-logfile - \
    --capture-output