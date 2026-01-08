import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directories
BASE_DIR = Path(__file__).parent
UPLOAD_FOLDER = BASE_DIR / 'uploads'
PROCESSED_FOLDER = BASE_DIR / 'processed'
MODELS_DIR = BASE_DIR / 'models'
VECTOR_DB_DIR = BASE_DIR / 'vector_db'

# Create directories if they don't exist
for directory in [UPLOAD_FOLDER, PROCESSED_FOLDER, MODELS_DIR, VECTOR_DB_DIR]:
    directory.mkdir(exist_ok=True)

# API Keys
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
MISTRAL_API_KEY = os.getenv('MISTRAL_API_KEY', '')

# LLM Configuration
LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'openai')  # 'openai', 'anthropic', or 'mistral'
LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-4-turbo-preview')  # 'claude-3-opus-20240229', 'codestral-latest', etc.
LLM_TEMPERATURE = float(os.getenv('LLM_TEMPERATURE', '0.2'))
LLM_MAX_TOKENS = int(os.getenv('LLM_MAX_TOKENS', '2000'))

# Embedding Configuration
EMBEDDING_PROVIDER = os.getenv('EMBEDDING_PROVIDER', 'local')  # 'openai', 'local', or 'codestral'
OPENAI_EMBEDDING_MODEL = os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')
LOCAL_EMBEDDING_MODEL = os.getenv('LOCAL_EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
CODESTRAL_EMBED_MODEL = os.getenv('CODESTRAL_EMBED_MODEL', 'mistral-embed')  # Codestral Embed

# Vector DB Configuration
VECTOR_DB_TYPE = os.getenv('VECTOR_DB_TYPE', 'qdrant')  # 'faiss' or 'qdrant'
FAISS_INDEX_PATH = VECTOR_DB_DIR / 'code_index.faiss'
FAISS_METADATA_PATH = VECTOR_DB_DIR / 'code_metadata.json'

# Qdrant Configuration
QDRANT_HOST = os.getenv('QDRANT_HOST', 'localhost')
QDRANT_PORT = int(os.getenv('QDRANT_PORT', '6333'))
QDRANT_COLLECTION = os.getenv('QDRANT_COLLECTION', 'code_chunks')
QDRANT_USE_MEMORY = os.getenv('QDRANT_USE_MEMORY', 'true').lower() == 'true'  # In-memory for development

VECTOR_SEARCH_K = int(os.getenv('VECTOR_SEARCH_K', '5'))

# ML Model Configuration
ML_MODEL_PATH = MODELS_DIR / 'risk_predictor.pkl'
CODE_SMELL_MODEL_PATH = MODELS_DIR / 'code_smell_classifier.pkl'
USE_PRETRAINED_MODELS = os.getenv('USE_PRETRAINED_MODELS', 'true').lower() == 'true'

# Deep Learning Configuration
DL_MODEL_NAME = os.getenv('DL_MODEL_NAME', 'microsoft/codebert-base')
DL_BATCH_SIZE = int(os.getenv('DL_BATCH_SIZE', '8'))  # CPU-optimized
DL_MAX_LENGTH = int(os.getenv('DL_MAX_LENGTH', '512'))
USE_ONNX = os.getenv('USE_ONNX', 'false').lower() == 'true'

# Static Analysis Configuration
ENABLE_BANDIT = os.getenv('ENABLE_BANDIT', 'true').lower() == 'true'
ENABLE_SEMGREP = os.getenv('ENABLE_SEMGREP', 'true').lower() == 'true'
ENABLE_PYLINT = os.getenv('ENABLE_PYLINT', 'false').lower() == 'true'
ENABLE_RUFF = os.getenv('ENABLE_RUFF', 'true').lower() == 'true'

# Feature Flags
ENABLE_ML_ANALYSIS = os.getenv('ENABLE_ML_ANALYSIS', 'true').lower() == 'true'
ENABLE_DL_ANALYSIS = os.getenv('ENABLE_DL_ANALYSIS', 'false').lower() == 'true'  # CPU intensive
ENABLE_LLM_AGENTS = os.getenv('ENABLE_LLM_AGENTS', 'true').lower() == 'true'
ENABLE_SEMANTIC_SEARCH = os.getenv('ENABLE_SEMANTIC_SEARCH', 'true').lower() == 'true'

# Performance Configuration
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '4'))
CACHE_EMBEDDINGS = os.getenv('CACHE_EMBEDDINGS', 'true').lower() == 'true'
EMBEDDING_CACHE_DIR = VECTOR_DB_DIR / 'embedding_cache'
EMBEDDING_CACHE_DIR.mkdir(exist_ok=True)

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = BASE_DIR / 'app.log'

# Supported file extensions
SUPPORTED_EXTENSIONS = ['.py', '.js', '.java', '.go', '.cpp', '.c', '.rb', '.php']

# Analysis thresholds
RISK_THRESHOLD_HIGH = float(os.getenv('RISK_THRESHOLD_HIGH', '0.7'))
RISK_THRESHOLD_MEDIUM = float(os.getenv('RISK_THRESHOLD_MEDIUM', '0.4'))
CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.6'))

# Security Q&A System Configuration
# CVE Tracking
CVE_PROVIDER = os.getenv('CVE_PROVIDER', 'osv')  # 'osv' or 'snyk'
SNYK_API_KEY = os.getenv('SNYK_API_KEY', '')
CVE_CHECK_INTERVAL_HOURS = int(os.getenv('CVE_CHECK_INTERVAL_HOURS', '24'))

# Query System
QUERY_MAX_RESULTS = int(os.getenv('QUERY_MAX_RESULTS', '10'))
QUERY_MIN_SIMILARITY = float(os.getenv('QUERY_MIN_SIMILARITY', '0.5'))
QUERY_CONTEXT_CHUNKS = int(os.getenv('QUERY_CONTEXT_CHUNKS', '5'))

# Code Chunking
CHUNK_STRATEGY = os.getenv('CHUNK_STRATEGY', 'function')  # 'function', 'class', or 'file'
MAX_CHUNK_SIZE = int(os.getenv('MAX_CHUNK_SIZE', '1000'))  # lines

# Git Webhook
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')
ENABLE_AUTO_REINDEX = os.getenv('ENABLE_AUTO_REINDEX', 'false').lower() == 'true'
