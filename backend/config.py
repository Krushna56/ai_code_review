# Production Configuration for Docker
import os
import logging
import tempfile
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directories
BASE_DIR = Path(__file__).parent

# Use system temp directory for uploads and processed files to prevent local storage fill-up
TEMP_BASE_DIR = Path(tempfile.gettempdir()) / 'ai_code_review'
UPLOAD_FOLDER = TEMP_BASE_DIR / 'uploads'
PROCESSED_FOLDER = TEMP_BASE_DIR / 'processed'

# Keep models and vector DB in permanent storage (they're reusable)
MODELS_DIR = BASE_DIR / 'models'
VECTOR_DB_DIR = BASE_DIR / 'vector_db'

# Create directories if they don't exist (parents=True creates parent dirs)
for directory in [UPLOAD_FOLDER, PROCESSED_FOLDER, MODELS_DIR, VECTOR_DB_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Authentication Configuration
_DEFAULT_SECRET_KEY = 'dev-secret-key-change-in-production'
SECRET_KEY = os.getenv('SECRET_KEY', _DEFAULT_SECRET_KEY)
if SECRET_KEY == _DEFAULT_SECRET_KEY:
    logging.warning(
        "SECURITY WARNING: SECRET_KEY is set to the insecure default value. "
        "Set the SECRET_KEY environment variable to a strong random value before deploying."
    )
DATABASE_URI = BASE_DIR / 'instance' / 'users.db'

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '900'))    # 15 minutes
JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', '604800'))  # 7 days

# GitHub OAuth Configuration
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID', '').strip()
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET', '').strip()
GITHUB_AUTHORIZATION_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_API_URL = 'https://api.github.com/user'

# LinkedIn OAuth Configuration
LINKEDIN_CLIENT_ID = os.getenv('LINKEDIN_CLIENT_ID', '').strip()
LINKEDIN_CLIENT_SECRET = os.getenv('LINKEDIN_CLIENT_SECRET', '').strip()
LINKEDIN_AUTHORIZATION_URL = 'https://www.linkedin.com/oauth/v2/authorization'
LINKEDIN_TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken'
LINKEDIN_API_URL = 'https://api.linkedin.com/v2/userinfo'  # OpenID Connect endpoint

# OAuth Redirect Base URL
# Set this in .env to your public app URL (e.g. https://yourapp.com)
# If not set, falls back to request.host_url (can cause mismatches behind proxies)
OAUTH_REDIRECT_BASE_URL = os.getenv('OAUTH_REDIRECT_BASE_URL', '').strip().rstrip('/')

# API Keys
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
MISTRAL_API_KEY = os.getenv('MISTRAL_API_KEY', '')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')

# LLM Configuration
# Deprecated: usage split into CHAT_PROVIDER and ANALYSIS_PROVIDER
LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'openai') 

CHAT_PROVIDER = os.getenv('CHAT_PROVIDER', 'gemini')
ANALYSIS_PROVIDER = os.getenv('ANALYSIS_PROVIDER', 'mistral')
ANALYSIS_FALLBACK_PROVIDER = os.getenv('ANALYSIS_FALLBACK_PROVIDER', 'anthropic')

LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-4-turbo-preview')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-1.5-pro')
LLM_TEMPERATURE = float(os.getenv('LLM_TEMPERATURE', '0.2'))
LLM_MAX_TOKENS = int(os.getenv('LLM_MAX_TOKENS', '2000'))

# Embedding Configuration
EMBEDDING_PROVIDER = os.getenv('EMBEDDING_PROVIDER', 'local')
OPENAI_EMBEDDING_MODEL = os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')
LOCAL_EMBEDDING_MODEL = os.getenv('LOCAL_EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
CODESTRAL_EMBED_MODEL = os.getenv('CODESTRAL_EMBED_MODEL', 'mistral-embed')

# Vector DB Configuration
VECTOR_DB_TYPE = os.getenv('VECTOR_DB_TYPE', 'qdrant')
FAISS_INDEX_PATH = VECTOR_DB_DIR / 'code_index.faiss'
FAISS_METADATA_PATH = VECTOR_DB_DIR / 'code_metadata.json'

# Qdrant Configuration
QDRANT_HOST = os.getenv('QDRANT_HOST', 'localhost')
QDRANT_PORT = int(os.getenv('QDRANT_PORT', '6333'))
QDRANT_COLLECTION = os.getenv('QDRANT_COLLECTION', 'code_chunks')
QDRANT_USE_MEMORY = os.getenv('QDRANT_USE_MEMORY', 'true').lower() == 'true'

VECTOR_SEARCH_K = int(os.getenv('VECTOR_SEARCH_K', '5'))

# ML Model Configuration
ML_MODEL_PATH = MODELS_DIR / 'risk_predictor.pkl'
CODE_SMELL_MODEL_PATH = MODELS_DIR / 'code_smell_classifier.pkl'
USE_PRETRAINED_MODELS = os.getenv('USE_PRETRAINED_MODELS', 'true').lower() == 'true'

# Deep Learning Configuration
DL_MODEL_NAME = os.getenv('DL_MODEL_NAME', 'microsoft/codebert-base')
DL_BATCH_SIZE = int(os.getenv('DL_BATCH_SIZE', '8'))
DL_MAX_LENGTH = int(os.getenv('DL_MAX_LENGTH', '512'))
USE_ONNX = os.getenv('USE_ONNX', 'false').lower() == 'true'

# Static Analysis Configuration
ENABLE_BANDIT = os.getenv('ENABLE_BANDIT', 'true').lower() == 'true'
ENABLE_SEMGREP = os.getenv('ENABLE_SEMGREP', 'true').lower() == 'true'
ENABLE_PYLINT = os.getenv('ENABLE_PYLINT', 'false').lower() == 'true'
ENABLE_RUFF = os.getenv('ENABLE_RUFF', 'true').lower() == 'true'

# Feature Flags
ENABLE_ML_ANALYSIS = os.getenv('ENABLE_ML_ANALYSIS', 'true').lower() == 'true'
ENABLE_DL_ANALYSIS = os.getenv('ENABLE_DL_ANALYSIS', 'false').lower() == 'true'
ENABLE_LLM_AGENTS = os.getenv('ENABLE_LLM_AGENTS', 'true').lower() == 'true'
ENABLE_SEMANTIC_SEARCH = os.getenv('ENABLE_SEMANTIC_SEARCH', 'true').lower() == 'true'

# Phase 4 & 5 Feature Flags
ENABLE_CVE_DETECTION = os.getenv('ENABLE_CVE_DETECTION', 'true').lower() == 'true'
ENABLE_SECURITY_REPORTING = os.getenv('ENABLE_SECURITY_REPORTING', 'true').lower() == 'true'

# CVE Detection Configuration
CVE_CACHE_DIR = VECTOR_DB_DIR / 'cve_cache'
CVE_CACHE_DIR.mkdir(exist_ok=True)

# Performance Configuration
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '4'))
CACHE_EMBEDDINGS = os.getenv('CACHE_EMBEDDINGS', 'true').lower() == 'true'
EMBEDDING_CACHE_DIR = VECTOR_DB_DIR / 'embedding_cache'
EMBEDDING_CACHE_DIR.mkdir(exist_ok=True)

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = BASE_DIR / 'app.log'

# Upload Configuration
MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 20 * 1024 * 1024 * 1024)) # 20GB default

# Temporary File Cleanup Configuration
# Files older than this will be deleted on app startup (in hours)
TEMP_FILE_RETENTION_HOURS = int(os.getenv('TEMP_FILE_RETENTION_HOURS', '24'))

# Supported file extensions
SUPPORTED_EXTENSIONS = ['.py', '.js', '.java', '.go', '.cpp', '.c', '.rb', '.php']

# File Filtering Configuration
# Ignored file patterns (case-insensitive matching)
IGNORED_FILE_PATTERNS = [
    'readme*',
    'license*',
    'changelog*',
    'contributing*',
    'code_of_conduct*',
    'authors*',
    'contributors*',
    'history*',
    'news*',
    'todo*',
    'makefile*',
    'dockerfile*',
    '.dockerignore',
    '.gitignore',
    '.gitattributes',
    'requirements*.txt',
    'package*.json',
    'yarn.lock',
    'poetry.lock',
    'pipfile*',
    'setup.py',
    'setup.cfg',
    'manifest.in',
    'pyproject.toml',
    'tox.ini',
    '.editorconfig',
    '.pylintrc',
    '.flake8',
    '.coveragerc',
]

# Ignored file extensions
IGNORED_EXTENSIONS = [
    '.json',
    '.md',
    '.txt',
    '.rst',
    '.pdf',
    '.doc',
    '.docx',
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.svg',
    '.ico',
    '.zip',
    '.tar',
    '.gz',
    '.bz2',
    '.7z',
    '.rar',
    '.lock',
    '.log',
    '.xml',
    '.yaml',
    '.yml',
    '.toml',
    '.ini',
    '.cfg',
    '.conf',
]

# Ignored directories
IGNORED_DIRECTORIES = [
    '.git',
    '.svn',
    '.hg',
    '__pycache__',
    'node_modules',
    'venv',
    'env',
    '.env',
    'virtualenv',
    '.venv',
    'dist',
    'build',
    'target',
    '.idea',
    '.vscode',
    '.vs',
    'bin',
    'obj',
    'out',
    'coverage',
    '.coverage',
    'htmlcov',
    '.pytest_cache',
    '.mypy_cache',
    '.tox',
    'eggs',
    '.eggs',
    '*.egg-info',
    'docs',
    'doc',
    'documentation',
    'test',
    'tests',
    '__tests__',
    'spec',
    'specs',
]

# Analysis thresholds
RISK_THRESHOLD_HIGH = float(os.getenv('RISK_THRESHOLD_HIGH', '0.7'))
RISK_THRESHOLD_MEDIUM = float(os.getenv('RISK_THRESHOLD_MEDIUM', '0.4'))
CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.6'))

# Security Q&A System Configuration
CVE_PROVIDER = os.getenv('CVE_PROVIDER', 'osv')
SNYK_API_KEY = os.getenv('SNYK_API_KEY', '')
CVE_CHECK_INTERVAL_HOURS = int(os.getenv('CVE_CHECK_INTERVAL_HOURS', '24'))

# Query System
QUERY_MAX_RESULTS = int(os.getenv('QUERY_MAX_RESULTS', '10'))
QUERY_MIN_SIMILARITY = float(os.getenv('QUERY_MIN_SIMILARITY', '0.5'))
QUERY_CONTEXT_CHUNKS = int(os.getenv('QUERY_CONTEXT_CHUNKS', '5'))

# Code Chunking
CHUNK_STRATEGY = os.getenv('CHUNK_STRATEGY', 'function')
MAX_CHUNK_SIZE = int(os.getenv('MAX_CHUNK_SIZE', '1000'))

# Git Webhook
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')
ENABLE_AUTO_REINDEX = os.getenv('ENABLE_AUTO_REINDEX', 'false').lower() == 'true'

# Chat Configuration
CHAT_MAX_HISTORY = int(os.getenv('CHAT_MAX_HISTORY', '50'))
CHAT_CONTEXT_WINDOW = int(os.getenv('CHAT_CONTEXT_WINDOW', '4000'))
CHAT_SESSION_TIMEOUT = int(os.getenv('CHAT_SESSION_TIMEOUT', '3600'))

# Streaming Configuration
ENABLE_STREAMING = os.getenv('ENABLE_STREAMING', 'true').lower() == 'true'
SSE_RETRY_TIMEOUT = int(os.getenv('SSE_RETRY_TIMEOUT', '3000'))
SSE_HEARTBEAT_INTERVAL = int(os.getenv('SSE_HEARTBEAT_INTERVAL', '30'))

# Production Settings
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
DEBUG = FLASK_ENV != 'production'
