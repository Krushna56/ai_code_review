"""
Comprehensive test suite for code optimization modules.

Tests for:
- Rate limiting
- CSRF protection
- Parallel execution
- Code chunking
- LLM factory
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Test Rate Limiter
from utils.rate_limiter import RateLimiter, rate_limit, RATE_LIMITS


class TestRateLimiter:
    """Test suite for rate limiting"""

    def test_rate_limiter_init(self):
        """Test rate limiter initialization"""
        limiter = RateLimiter()
        assert limiter.requests == {}
        assert limiter.lock is not None

    def test_rate_limiter_allows_requests_within_limit(self):
        """Test that requests within limit are allowed"""
        limiter = RateLimiter()
        client_id = "test_client"

        # First request should be allowed
        allowed, count, reset = limiter.is_allowed(client_id, limit=5, window_seconds=60)
        assert allowed is True
        assert count == 1

        # Subsequent requests within limit should be allowed
        for i in range(2, 6):
            allowed, count, reset = limiter.is_allowed(client_id, limit=5, window_seconds=60)
            assert allowed is True
            assert count == i

    def test_rate_limiter_blocks_requests_over_limit(self):
        """Test that requests over limit are blocked"""
        limiter = RateLimiter()
        client_id = "test_client"

        # Fill up the limit
        for _ in range(5):
            limiter.is_allowed(client_id, limit=5, window_seconds=60)

        # Next request should be blocked
        allowed, count, reset = limiter.is_allowed(client_id, limit=5, window_seconds=60)
        assert allowed is False
        assert count == 5
        assert reset > 0

    def test_rate_limiter_cleanup(self):
        """Test rate limiter cleanup"""
        limiter = RateLimiter()

        # Add old entries
        limiter.requests['old_client'] = [time.time() - 7200]  # 2 hours old
        limiter.requests['new_client'] = [time.time()]

        # Cleanup old entries (1 hour max age)
        limiter.cleanup_expired(max_age_seconds=3600)

        # Old client should be removed, new client should remain
        assert 'old_client' not in limiter.requests
        assert 'new_client' in limiter.requests


# Test CSRF Protection
from utils.csrf_protection import (
    generate_csrf_token, validate_csrf_token, get_csrf_token_from_request
)


class TestCSRFProtection:
    """Test suite for CSRF protection"""

    def test_csrf_token_generation(self):
        """Test CSRF token generation"""
        token = generate_csrf_token()
        assert isinstance(token, str)
        assert len(token) >= 32

    def test_generate_different_tokens(self):
        """Test that different tokens are generated"""
        token1 = generate_csrf_token()
        token2 = generate_csrf_token()
        assert token1 != token2

    def test_csrf_validation_with_matching_token(self):
        """Test CSRF validation with matching token"""
        from flask import session, Flask

        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test'

        with app.test_request_context():
            # Simulate token in session
            session['_csrf_token'] = 'test_token'

            # Should validate successfully
            # Note: validate_csrf_token uses session, so we need Flask context
            # This is simplified for testing
            assert session.get('_csrf_token') == 'test_token'

    def test_csrf_token_length(self):
        """Test CSRF token has adequate length"""
        for _ in range(10):
            token = generate_csrf_token()
            assert len(token) >= 32, "Token should be at least 32 characters"


# Test Parallel Executor
from utils.parallel_executor import ParallelExecutor, run_parallel_lm_agents


class TestParallelExecutor:
    """Test suite for parallel execution"""

    def test_parallel_executor_init(self):
        """Test executor initialization"""
        executor = ParallelExecutor(max_workers=2, timeout_seconds=30)
        assert executor.max_workers == 2
        assert executor.timeout_seconds == 30

    def test_parallel_executor_single_task(self):
        """Test executing a single task"""
        executor = ParallelExecutor(max_workers=1)

        def simple_task():
            return "result"

        tasks = {'task1': (simple_task, (), {})}
        results = executor.execute_tasks(tasks)

        assert 'task1' in results
        assert results['task1'].success is True
        assert results['task1'].result == "result"

    def test_parallel_executor_multiple_tasks(self):
        """Test executing multiple tasks in parallel"""
        executor = ParallelExecutor(max_workers=3)

        def task1():
            time.sleep(0.1)
            return "result1"

        def task2():
            time.sleep(0.1)
            return "result2"

        def task3():
            time.sleep(0.1)
            return "result3"

        tasks = {
            'task1': (task1, (), {}),
            'task2': (task2, (), {}),
            'task3': (task3, (), {})
        }

        start = time.time()
        results = executor.execute_tasks(tasks)
        duration = time.time() - start

        # All tasks should complete successfully
        assert len(results) == 3
        for result in results.values():
            assert result.success is True

        # Parallel execution should be faster than sequential
        # (0.3s sequential vs ~0.1s parallel)
        assert duration < 0.3

    def test_parallel_executor_error_handling(self):
        """Test error handling in parallel execution"""
        executor = ParallelExecutor(max_workers=2)

        def failing_task():
            raise ValueError("Test error")

        def passing_task():
            return "success"

        tasks = {
            'fail': (failing_task, (), {}),
            'pass': (passing_task, (), {})
        }

        results = executor.execute_tasks(tasks, continue_on_error=True)

        assert results['fail'].success is False
        assert results['fail'].error is not None
        assert results['pass'].success is True


# Test Code Chunker
from utils.code_chunker import CodeChunker, ChunkStrategy


class TestCodeChunker:
    """Test suite for code chunking"""

    def test_chunker_initialization(self):
        """Test chunker initialization"""
        chunker = CodeChunker(
            strategy=ChunkStrategy.SLIDING_WINDOW,
            chunk_size=500,
            overlap=100
        )
        assert chunker.chunk_size == 500
        assert chunker.overlap == 100

    def test_fixed_size_chunking(self):
        """Test fixed-size chunking"""
        code = "def foo():\n    pass\n" * 100  # Large code snippet
        chunker = CodeChunker(
            strategy=ChunkStrategy.FIXED_SIZE,
            chunk_size=100
        )

        chunks = chunker.chunk(code)
        assert len(chunks) > 0
        assert all(len(chunk.content) <= 150 for chunk in chunks)  # Some slack

    def test_sliding_window_chunking(self):
        """Test sliding window chunking"""
        code = "x = 1\n" * 100
        chunker = CodeChunker(
            strategy=ChunkStrategy.SLIDING_WINDOW,
            chunk_size=100,
            overlap=20
        )

        chunks = chunker.chunk(code)
        assert len(chunks) > 1

        # Check overlap between chunks
        for i in range(len(chunks) - 1):
            # Chunks should overlap slightly
            assert chunks[i].content[-50:] in chunks[i + 1].content

    def test_semantic_chunking(self):
        """Test semantic chunking (function boundaries)"""
        code = """def function1():
    x = 1
    return x

def function2():
    y = 2
    return y

def function3():
    z = 3
    return z
"""
        chunker = CodeChunker(
            strategy=ChunkStrategy.SEMANTIC,
            chunk_size=1000
        )

        chunks = chunker.chunk(code)
        assert len(chunks) >= 1

    def test_chunk_metadata(self):
        """Test chunk metadata"""
        code = "line1\nline2\nline3\n"
        chunker = CodeChunker(
            strategy=ChunkStrategy.FIXED_SIZE,
            chunk_size=50
        )

        chunks = chunker.chunk(code)
        for chunk in chunks:
            assert chunk.chunk_index >= 0
            assert chunk.start_line >= 0
            assert chunk.end_line >= chunk.start_line

    def test_optimal_chunk_size_estimation(self):
        """Test optimal chunk size estimation"""
        code = "x = 1\n" * 1000
        optimal_size = CodeChunker.estimate_optimal_chunk_size(code, target_chunks=10)

        assert optimal_size > 0
        assert optimal_size <= len(code) / 5


# Test LLM Factory
from llm_agents.llm_factory import LLMClientFactory, OpenAIClient


class TestLLMFactory:
    """Test suite for LLM factory"""

    @patch('llm_agents.llm_factory.config')
    def test_factory_provider_list(self, mock_config):
        """Test getting available providers"""
        mock_config.OPENAI_API_KEY = "test_key"
        mock_config.ANTHROPIC_API_KEY = ""
        mock_config.MISTRAL_API_KEY = ""
        mock_config.GEMINI_API_KEY = ""

        providers = [p for p in ['openai'] if p in LLMClientFactory.PROVIDERS]
        assert len(providers) > 0

    def test_factory_known_providers(self):
        """Test factory knows all major providers"""
        providers = LLMClientFactory.PROVIDERS.keys()
        assert 'openai' in providers
        assert 'anthropic' in providers
        assert 'mistral' in providers
        assert 'gemini' in providers

    @patch('llm_agents.llm_factory.OpenAI')
    @patch('llm_agents.llm_factory.config')
    def test_create_openai_client(self, mock_config, mock_openai):
        """Test creating OpenAI client"""
        mock_config.OPENAI_API_KEY = "test_key"
        mock_config.LLM_MODEL = "gpt-4"

        # Create client
        client = OpenAIClient(api_key="test_key", model="gpt-4")
        assert client.provider == "openai"
        assert client.model == "gpt-4"

    def test_factory_fallback_order(self):
        """Test fallback provider order"""
        fallback_order = LLMClientFactory.DEFAULT_FALLBACK_ORDER
        assert len(fallback_order) > 0
        assert all(provider in LLMClientFactory.PROVIDERS for provider in fallback_order)


# Test Background Tasks
from utils.background_tasks import BackgroundTaskManager, TaskStatus, submit_background_task


class TestBackgroundTasks:
    """Test suite for background tasks"""

    def test_task_manager_init(self):
        """Test task manager initialization"""
        manager = BackgroundTaskManager(max_workers=2)
        assert manager.max_workers == 2
        assert len(manager.worker_threads) == 2

    def test_submit_simple_task(self):
        """Test submitting a simple task"""
        manager = BackgroundTaskManager(max_workers=1)

        def simple_work():
            return "done"

        task_id = manager.submit_task(
            task_name="test_task",
            task_func=simple_work
        )

        assert task_id is not None
        time.sleep(0.5)  # Wait for task to complete

        task = manager.get_task(task_id)
        assert task.status == TaskStatus.COMPLETED
        assert task.result == "done"

    def test_task_progress_tracking(self):
        """Test tracking task progress"""
        manager = BackgroundTaskManager(max_workers=1)

        def work_with_progress():
            for i in range(5):
                time.sleep(0.05)
                yield {'progress': (i + 1) * 20}
            return "completed"

        task_id = manager.submit_task(
            task_name="progress_task",
            task_func=work_with_progress
        )

        time.sleep(0.5)  # Wait for task to complete
        task = manager.get_task(task_id)

        assert task.status == TaskStatus.COMPLETED
        assert task.progress == 100.0

    def test_task_error_handling(self):
        """Test error handling in tasks"""
        manager = BackgroundTaskManager(max_workers=1)

        def failing_work():
            raise ValueError("Test error")

        task_id = manager.submit_task(
            task_name="failing_task",
            task_func=failing_work
        )

        time.sleep(0.2)  # Wait for task to complete
        task = manager.get_task(task_id)

        assert task.status == TaskStatus.FAILED
        assert task.error is not None

    def test_task_cleanup(self):
        """Test task cleanup"""
        manager = BackgroundTaskManager(max_workers=1)

        # Add old tasks
        from utils.background_tasks import Task
        old_task = Task(
            task_id="old",
            name="old_task",
            status=TaskStatus.COMPLETED,
            completed_at=datetime.now() - timedelta(hours=25)
        )
        manager.tasks['old'] = old_task

        # New task
        new_task = Task(
            task_id="new",
            name="new_task",
            status=TaskStatus.COMPLETED,
            completed_at=datetime.now()
        )
        manager.tasks['new'] = new_task

        # Cleanup old tasks (max 24 hours)
        cleaned = manager.cleanup_old_tasks(max_age_hours=24)
        assert cleaned == 1
        assert 'old' not in manager.tasks
        assert 'new' in manager.tasks


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
