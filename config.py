import os

class Config:
    """Application configuration for FileGuard."""
    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Secret key for session management and CSRF protection
    # Prioritizes environment variable; falls back to cryptographically random key if unconfigured in production
    SECRET_KEY = os.environ.get('SECRET_KEY') or (
        os.urandom(24).hex() if os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER')
        else 'fileguard-secure-dev-key-change-in-production-2026'
    )
    
    # Database path (SQLite) - supports custom directory or Render persistent disk
    DATA_DIR = os.environ.get('FILEGUARD_DATA_DIR', os.path.join(BASE_DIR, 'data'))
    DATABASE_PATH = os.path.join(DATA_DIR, 'fileguard.db')
    
    # Upload limits (16 MB maximum file size to ensure safe, responsive analysis)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Temporary upload directory (files are safely analyzed and immediately purged/unlinked)
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'temp_uploads')
    
    # Allowed inspection modes
    ALLOWED_EXTENSIONS = None  # None means any extension can be analyzed (heuristic file triage)
    
    # Application details
    APP_NAME = "FileGuard"
    APP_VERSION = "1.0.0"
    ENVIRONMENT = os.environ.get('FLASK_ENV', 'production' if os.environ.get('RENDER') else 'development')

    # Hosting platform networking (Render, AWS, Heroku provide the PORT environment variable)
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '0.0.0.0' if os.environ.get('PORT') or os.environ.get('RENDER') else '127.0.0.1')

