import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    UPLOAD_FOLDER = 'uploaded_files'
    ALLOWED_EXTENSIONS = {'pdf'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    POLICY_INDEX_PATH = "policy_index.faiss"
    FRAMEWORK_INDEX_PATH = "framework_index.faiss"
    SEARCH_INDEX_PATH = "google_search.faiss"

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = "gpt-5"  # Updated to match original
    OPENAI_TEMPERATURE = 0.0
    OPENAI_MAX_TOKENS = 3000

    SEARCH_RESULTS_LIMIT = 5

    # Mail configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 25))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'False') == 'True'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False') == 'True'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@policylens.aphrc.org')
    
    # Password reset token expiry (24 hours)
    PASSWORD_RESET_TOKEN_EXPIRY = 86400  # seconds

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False