import os
from dotenv import load_dotenv

# Load .env from SSServer
load_dotenv(dotenv_path=os.path.join('SSServer', '.env'))

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    DATABASE_PATH = os.path.join(BASE_DIR, 'SSServer', 'storestash.db')
    FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL")
    SUPPORT_EMAIL_PASSWORD = os.getenv("SUPPORT_EMAIL_PASSWORD")
    SUPPORT_EMAIL_TO = os.getenv("SUPPORT_EMAIL_TO")