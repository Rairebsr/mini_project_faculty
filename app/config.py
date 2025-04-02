import os
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

# Get MongoDB connection string from environment variables
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("SECRET_KEY")
if not MONGO_URI or not SECRET_KEY:
    raise ValueError("Environment variables MONGO_URI and SECRET_KEY must be set.")