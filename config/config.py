import os
from dotenv import load_dotenv

load_dotenv()  # Loads variables from .env
api_key = os.getenv("GEMINI_API_KEY")
