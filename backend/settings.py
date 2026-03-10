"""
Pydantic-based configuration management.

Provides type-safe, validated configuration using Pydantic dataclasses.
Replaces the old environment variable parsing with better validation and defaults.
"""

import os
from typing import Optional, List
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: Optional[str] = None
    pool_size: int = 10
    max_overflow: int = 20
    pool_recycle_seconds: int = 3600
    is_postgres: bool = False

    def __post_init__(self):
        if self.url is None:
            self.url = os.getenv(
                'DATABASE_URL',
                f"sqlite:///{Path(__file__).parent.parent / 'instance' / 'users.db'}"
            )
        
        # Auto-detect PostgreSQL
        if self.url and self.url.startswith('postgresql'):
            self.is_postgres = True
            # Handle old postgres:// format
            if self.url.startswith('postgres://'):
                self.url = self.url.replace('postgres://', 'postgresql://', 1)


@dataclass
class JWTConfig:
    """JWT authentication configuration"""
    secret_key: str = field(default_factory=lambda: os.getenv('JWT_SECRET_KEY', 'dev-secret'))
    access_token_expires_seconds: int = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '14400'))
    refresh_token_expires_seconds: int = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', '604800'))
    algorithm: str = 'HS256'


@dataclass
class OAuthConfig:
    """OAuth configuration"""
    github_client_id: str = os.getenv('GITHUB_CLIENT_ID', '')
    github_client_secret: str = os.getenv('GITHUB_CLIENT_SECRET', '')
    github_auth_url: str = 'https://github.com/login/oauth/authorize'
    github_token_url: str = 'https://github.com/login/oauth/access_token'
    github_api_url: str = 'https://api.github.com/user'
    
    linkedin_client_id: str = os.getenv('LINKEDIN_CLIENT_ID', '')
    linkedin_client_secret: str = os.getenv('LINKEDIN_CLIENT_SECRET', '')
    linkedin_auth_url: str = 'https://www.linkedin.com/oauth/v2/authorization'
    linkedin_token_url: str = 'https://www.linkedin.com/oauth/v2/accessToken'
    linkedin_api_url: str = 'https://api.linkedin.com/v2/userinfo'
    
    redirect_base_url: str = os.getenv('OAUTH_REDIRECT_BASE_URL', '')

    def validate(self):
        """Validate OAuth configuration"""
        if not self.github_client_id:
            print("WARNING: GitHub OAuth not configured (GITHUB_CLIENT_ID)")
        if not self.linkedin_client_id:
            print("WARNING: LinkedIn OAuth not configured (LINKEDIN_CLIENT_ID)")


@dataclass
class LLMConfig:
    """LLM provider configuration"""
    # API Keys
    openai_key: str = os.getenv('OPENAI_API_KEY', '')
    anthropic_key: str = os.getenv('ANTHROPIC_API_KEY', '')
    mistral_key: str = os.getenv('MISTRAL_API_KEY', '')
    gemini_key: str = os.getenv('GEMINI_API_KEY', '')
    
    # Providers
    primary_provider: str = os.getenv('LLM_PROVIDER', 'openai')
    chat_provider: str = os.getenv('CHAT_PROVIDER', 'gemini')
    analysis_provider: str = os.getenv('ANALYSIS_PROVIDER', 'mistral')
    fallback_provider: str = os.getenv('ANALYSIS_FALLBACK_PROVIDER', 'anthropic')
    
    # Models
    primary_model: str = os.getenv('LLM_MODEL', 'gpt-4-turbo-preview')
    gemini_model: str = os.getenv('GEMINI_MODEL', 'gemini-1.5-pro')
    
    # Parameters
    temperature: float = float(os.getenv('LLM_TEMPERATURE', '0.2'))
    max_tokens: int = int(os.getenv('LLM_MAX_TOKENS', '2000'))

    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for provider"""
        provider_lower = provider.lower()
        if provider_lower == 'openai':
            return self.openai_key
        elif provider_lower == 'anthropic':
            return self.anthropic_key
        elif provider_lower == 'mistral':
            return self.mistral_key
        elif provider_lower == 'gemini':
            return self.gemini_key
        return None


@dataclass
class EmbeddingConfig:
    """Code embedding configuration"""
    provider: str = os.getenv('EMBEDDING_PROVIDER', 'local')
    openai_model: str = os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')
    local_model: str = os.getenv('LOCAL_EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
    mistral_model: str = os.getenv('CODESTRAL_EMBED_MODEL', 'mistral-embed')
    
    # Caching
    cache_enabled: bool = os.getenv('CACHE_EMBEDDINGS', 'true').lower() == 'true'
    max_chunk_size: int = int(os.getenv('MAX_CHUNK_SIZE', '1000'))


@dataclass
class VectorDBConfig:
    """Vector database configuration"""
    db_type: str = os.getenv('VECTOR_DB_TYPE', 'qdrant')
    
    # Qdrant settings
    qdrant_host: str = os.getenv('QDRANT_HOST', 'localhost')
    qdrant_port: int = int(os.getenv('QDRANT_PORT', '6333'))
    qdrant_collection: str = os.getenv('QDRANT_COLLECTION', 'code_chunks')
    qdrant_use_memory: bool = os.getenv('QDRANT_USE_MEMORY', 'true').lower() == 'true'
    
    # Search settings
    search_k: int = int(os.getenv('VECTOR_SEARCH_K', '5'))


@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_key: str = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    session_cookie_secure: bool = os.getenv('FLASK_ENV', 'development') == 'production'
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = 'Lax'
    session_lifetime_seconds: int = 3600
    
    # CSRF
    csrf_enabled: bool = True
    csrf_token_length: int = 32
    csrf_timeout_hours: Optional[int] = None
    
    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_cleanup_interval_hours: int = 1

    def validate(self):
        """Validate security settings"""
        if self.secret_key == 'dev-secret-key-change-in-production':
            print("WARNING: SECRET_KEY is using default value. Set SECRET_KEY environment variable.")


@dataclass
class AnalysisConfig:
    """Code analysis configuration"""
    # Execution
    max_workers: int = int(os.getenv('MAX_WORKERS', '4'))
    
    # Feature flags
    enable_static_analysis: bool = os.getenv('ENABLE_STATIC_ANALYSIS', 'true').lower() == 'true'
    enable_embedding: bool = os.getenv('ENABLE_SEMANTIC_SEARCH', 'true').lower() == 'true'
    enable_llm_agents: bool = os.getenv('ENABLE_LLM_AGENTS', 'true').lower() == 'true'
    enable_cve_detection: bool = os.getenv('ENABLE_CVE_DETECTION', 'true').lower() == 'true'
    enable_security_reporting: bool = os.getenv('ENABLE_SECURITY_REPORTING', 'true').lower() == 'true'
    
    # Linters
    enable_bandit: bool = os.getenv('ENABLE_BANDIT', 'true').lower() == 'true'
    enable_semgrep: bool = os.getenv('ENABLE_SEMGREP', 'true').lower() == 'true'
    enable_ruff: bool = os.getenv('ENABLE_RUFF', 'true').lower() == 'true'
    enable_pylint: bool = os.getenv('ENABLE_PYLINT', 'false').lower() == 'true'
    
    # Thresholds
    risk_threshold_high: float = float(os.getenv('RISK_THRESHOLD_HIGH', '0.7'))
    risk_threshold_medium: float = float(os.getenv('RISK_THRESHOLD_MEDIUM', '0.4'))
    confidence_threshold: float = float(os.getenv('CONFIDENCE_THRESHOLD', '0.6'))


@dataclass
class FileHandlingConfig:
    """File upload and processing configuration"""
    max_upload_size_bytes: int = int(os.getenv('MAX_CONTENT_LENGTH', str(20 * 1024 * 1024 * 1024)))
    max_form_parts: int = 100000
    temp_retention_hours: int = int(os.getenv('TEMP_FILE_RETENTION_HOURS', '24'))
    
    # Supported extensions
    supported_extensions: List[str] = field(default_factory=lambda: [
        '.py', '.js', '.java', '.go', '.cpp', '.c', '.rb', '.php'
    ])


@dataclass
class Settings:
    """Complete application settings"""
    # Core
    flask_env: str = os.getenv('FLASK_ENV', 'development')
    debug: bool = False  # Set based on flask_env
    log_level: str = os.getenv('LOG_LEVEL', 'INFO')
    log_file: Optional[Path] = None
    
    # Components
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    jwt: JWTConfig = field(default_factory=JWTConfig)
    oauth: OAuthConfig = field(default_factory=OAuthConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    vector_db: VectorDBConfig = field(default_factory=VectorDBConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    file_handling: FileHandlingConfig = field(default_factory=FileHandlingConfig)

    def __post_init__(self):
        """Initialize and validate settings"""
        self.debug = self.flask_env != 'production'
        
        # Set log file path
        if not self.log_file:
            base_dir = Path(__file__).parent.parent
            self.log_file = base_dir / 'app.log'
        
        # Validate components
        self.security.validate()
        self.oauth.validate()

    @classmethod
    def from_env(cls) -> 'Settings':
        """Create settings from environment variables"""
        return cls()


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create global settings instance"""
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


def load_settings() -> Settings:
    """Load fresh settings from environment"""
    global _settings
    _settings = Settings.from_env()
    return _settings
