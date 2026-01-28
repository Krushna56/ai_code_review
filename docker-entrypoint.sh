#!/bin/bash
set -e

echo "=========================================="
echo "AI Code Review Platform - Starting..."
echo "=========================================="

# Wait for Qdrant to be ready if using Qdrant
if [ "$VECTOR_DB_TYPE" = "qdrant" ]; then
    echo "Waiting for Qdrant to be ready..."
    max_attempts=30
    attempt=0
    
    until curl -f http://${QDRANT_HOST:-qdrant}:${QDRANT_PORT:-6333}/health > /dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            echo "ERROR: Qdrant is not available after $max_attempts attempts"
            exit 1
        fi
        echo "Waiting for Qdrant... (attempt $attempt/$max_attempts)"
        sleep 2
    done
    echo "✓ Qdrant is ready!"
fi

# Validate required environment variables
echo "Validating environment configuration..."

if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" = "change-this-secret-key-in-production" ]; then
    echo "WARNING: SECRET_KEY is not set or using default value. Please set a secure SECRET_KEY in production!"
fi

# Check if at least one LLM API key is configured
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$MISTRAL_API_KEY" ]; then
    echo "WARNING: No LLM API keys configured. LLM-based features will be disabled."
    echo "Please set at least one of: OPENAI_API_KEY, ANTHROPIC_API_KEY, or MISTRAL_API_KEY"
fi

# Initialize database
echo "Initializing authentication database..."
python -c "from models.user import User; User.init_db(); print('✓ Database initialized')" || {
    echo "ERROR: Failed to initialize database"
    exit 1
}

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p uploads processed output reports vector_db instance models .cache
echo "✓ Directories created"

# Display configuration
echo ""
echo "=========================================="
echo "Configuration Summary:"
echo "=========================================="
echo "LLM Provider: ${LLM_PROVIDER:-openai}"
echo "LLM Model: ${LLM_MODEL:-gpt-4-turbo-preview}"
echo "Embedding Provider: ${EMBEDDING_PROVIDER:-local}"
echo "Vector DB Type: ${VECTOR_DB_TYPE:-qdrant}"
if [ "$VECTOR_DB_TYPE" = "qdrant" ]; then
    echo "Qdrant Host: ${QDRANT_HOST:-qdrant}:${QDRANT_PORT:-6333}"
fi
echo "ML Analysis: ${ENABLE_ML_ANALYSIS:-true}"
echo "LLM Agents: ${ENABLE_LLM_AGENTS:-true}"
echo "CVE Detection: ${ENABLE_CVE_DETECTION:-true}"
echo "=========================================="
echo ""

# Execute the main command
echo "Starting application..."
exec "$@"
