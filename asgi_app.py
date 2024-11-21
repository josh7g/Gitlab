import os
from dotenv import load_dotenv
from app import app as fastapi_app

# Load environment variables
load_dotenv()

# This is the ASGI application
asgi_app = fastapi_app