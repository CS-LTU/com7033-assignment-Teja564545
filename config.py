# config.py
import os
from datetime import timedelta





class Config:
    # In real deployments, use an environment variable for the secret key
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production")

    # Main database: users (authentication)
    SQLALCHEMY_DATABASE_URI = "sqlite:///users.db"

    # Separate database for patient data
    SQLALCHEMY_BINDS = {
        "patients": "sqlite:///patients.db"
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF protection (Flask-WTF)
    WTF_CSRF_ENABLED = True

    # Secure session cookie configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # set True if using HTTPS
    API_TOKEN = "dev-api-token"
    # Logging
    LOG_FILE = "app.log"
