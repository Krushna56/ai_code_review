#!/usr/bin/env python3
"""
Production-ready entry point for AI Code Review Platform
Supports both development and production modes
"""
import os
import logging
from app import app
import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    # Determine if running in production
    is_production = config.FLASK_ENV == 'production'
    
    if is_production:
        logger.info("Starting AI Code Review Platform in PRODUCTION mode")
        logger.info(f"LLM Provider: {config.LLM_PROVIDER}")
        logger.info(f"Vector DB: {config.VECTOR_DB_TYPE}")
        
        # Production settings
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False,
            threaded=True
        )
    else:
        logger.info("Starting AI Code Review Platform in DEVELOPMENT mode")
        logger.warning("⚠️  Not suitable for production use!")
        
        # Development settings
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False  # Disabled to prevent issues with file uploads
        )
