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

# LLM Configuration
LLM_PROVIDER = os.getenv('LLM_PROVIDER', 'openai')  # 'openai' or 'anthropic'
LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-4-turbo-preview')  # or 'claude-3-opus-20240229'
LLM_TEMPERATURE = float(os.getenv('LLM_TEMPERATURE', '0.2'))
LLM_MAX_TOKENS = int(os.getenv('LLM_MAX_TOKENS', '2000'))

# Embedding Configuration
EMBEDDING_PROVIDER = os.getenv('EMBEDDING_PROVIDER', 'local')  # 'openai' or 'local'
OPENAI_EMBEDDING_MODEL = os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')
LOCAL_EMBEDDING_MODEL = os.getenv('LOCAL_EMBEDDING_MODEL', 'all-MiniLM-L6-v2')

# Vector DB Configuration
FAISS_INDEX_PATH = VECTOR_DB_DIR / 'code_index.faiss'
FAISS_METADATA_PATH = VECTOR_DB_DIR / 'code_metadata.json'
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
