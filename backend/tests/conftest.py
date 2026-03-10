"""
Pytest configuration and fixtures for the test suite.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock
from flask import Flask
import sys
import os

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['WTF_CSRF_ENABLED'] = False
    return app


@pytest.fixture
def client(app):
    """Create Flask test client"""
    return app.test_client()


@pytest.fixture
def temp_dir():
    """Create temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_code():
    """Sample Python code for testing"""
    return '''
def vulnerable_function(user_input):
    """Function with security issues"""
    import os
    # Security issue: command injection
    result = os.system(f"echo {user_input}")
    return result

def poorly_written_function(items):
    """Function with code quality issues"""
    result = []
    for i in range(len(items)):
        result.append(items[i] * 2)
    return result

class ExampleClass:
    """Class for testing semantic analysis"""
    
    def __init__(self):
        self.data = {}
    
    def process(self, x):
        # High complexity function
        if x > 0:
            if x > 10:
                if x > 100:
                    return "very large"
                return "large"
            return "small"
        return "negative"
'''


@pytest.fixture
def mock_llm_agent():
    """Mock LLM agent for testing"""
    agent = MagicMock()
    agent.analyze.return_value = {
        'issues': [
            {
                'severity': 'high',
                'type': 'security',
                'description': 'Command injection vulnerability',
                'line': 5
            }
        ]
    }
    return agent


@pytest.fixture
def mock_config():
    """Mock configuration for testing"""
    config = MagicMock()
    config.ENABLE_LLM_AGENTS = True
    config.ENABLE_SEMANTIC_SEARCH = True
    config.ENABLE_CVE_DETECTION = True
    config.MAX_CHUNK_SIZE = 500
    config.EMBEDDING_PROVIDER = 'local'
    config.LOG_LEVEL = 'INFO'
    config.FLASK_ENV = 'testing'
    return config


@pytest.fixture
def mock_embedder():
    """Mock code embedder for testing"""
    embedder = MagicMock()
    embedder.embed.return_value = __import__('numpy').array([0.1] * 384, dtype=__import__('numpy').float32)
    return embedder


# Test markers
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line("markers", "performance: Performance tests")
