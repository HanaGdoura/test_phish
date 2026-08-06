import os
from datetime import timedelta

# Application configuration and environment-based settings.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "phishing.db")
SECRET_KEY = os.getenv("SECRET_KEY", "gophish-like-demo-secret")
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv("PERMANENT_SESSION_LIFETIME_MINUTES", "30")))
SESSION_REFRESH_EACH_REQUEST = True
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_FROM = os.getenv("SMTP_FROM", "simulator@example.com")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")
