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
    OPENAI_MODEL = "gpt-4o"  # Updated to match original
    OPENAI_TEMPERATURE = 0.0
    OPENAI_MAX_TOKENS = 3000

    SEARCH_RESULTS_LIMIT = 5

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False