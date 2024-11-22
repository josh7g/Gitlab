# asgi_app.py
import os
from dotenv import load_dotenv
from app import app as fastapi_app
import gc

# Load environment variables
load_dotenv()

# Enable garbage collection optimization
gc.enable()
gc.set_threshold(100, 5, 5)

# Configure memory optimization
import sys
if hasattr(sys, 'set_int_max_str_digits'):
    sys.set_int_max_str_digits(4300)

# Configure resource limits
def configure_resource_limits():
    import resource
    # Set soft limit to 150MB
    soft_limit = 150 * 1024 * 1024
    # Set hard limit to 200MB
    hard_limit = 200 * 1024 * 1024
    
    try:
        resource.setrlimit(resource.RLIMIT_AS, (soft_limit, hard_limit))
    except:
        pass  # Some systems don't allow setting resource limits

configure_resource_limits()

# This is the ASGI application
asgi_app = fastapi_app