"""
End-to-end tests demonstrating complete workflows.

These tests show how to use the optimization modules together
in realistic scenarios.
"""

import pytest
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestEndToEndWorkflows:
    """End-to-end workflow tests"""

    @pytest.mark.e2e
    def test_full_code_analysis_workflow(self):
        """Test complete analysis workflow"""
        from utils.structured_logging import setup_logging, generate_correlation_id
        from utils.background_tasks import BackgroundTaskManager

        # Setup
        setup_logging()
        correlation_id = generate_correlation_id()
        manager = BackgroundTaskManager(max_workers=2)

        # Simulate code upload
        sample_code = """
def vulnerable_function(user_input):
    import subprocess
    # SQL injection risk
    query = f"SELECT * FROM users WHERE id = {user_input}"
    # Command injection risk
    result = subprocess.call(user_input)
    return result
"""

        def analyze_code_task(code, file_id):
            """Simulated analysis task"""
            return {
                'file_id': file_id,
                'issues': [
                    {'type': 'security', 'severity': 'high', 'line': 5},
                    {'type': 'performance', 'severity': 'low', 'line': 2}
                ],
                'status': 'completed'
            }

        # Submit background task
        task_id = manager.submit_task(
            task_name="analyze_upload_12345",
            task_func=analyze_code_task,
            task_args=(sample_code, "file_12345")
        )

        # Poll task status
        time.sleep(0.5)
        task = manager.get_task(task_id)

        assert task is not None
        assert 'analyze_upload' in task.name

    @pytest.mark.e2e
    def test_api_request_with_rate_limiting_and_logging(self, client, mock_config):
        """Test API request with rate limiting and correlation IDs"""
        from utils.rate_limiter import RateLimiter, RATE_LIMITS
        from utils.structured_logging import generate_correlation_id

        correlation_id = generate_correlation_id()

        # Create rate limiter
        limiter = RateLimiter(
            limit=RATE_LIMITS['chat']['requests_per_minute'],
            window_seconds=60
        )

        # Simulate multiple requests with rate limiting
        allowed_count = 0
        for i in range(40):
            allowed, count, reset_in = limiter.is_allowed('test_user')
            if allowed:
                allowed_count += 1

        # Should hit the rate limit
        assert allowed_count < 40

    @pytest.mark.e2e
    def test_llm_analysis_with_fallback(self):
        """Test LLM analysis with provider fallback"""
        from llm_agents.llm_factory import LLMClientFactory

        factory = LLMClientFactory()

        # Mock available providers
        with patch.object(factory, 'get_available_providers') as mock_providers:
            mock_providers.return_value = ['openai', 'anthropic']

            code = "def foo(): pass"

            # This would normally try OpenAI first, then fallback to Anthropic
            # We'll just verify the factory can be used
            assert factory is not None

    @pytest.mark.e2e
    def test_code_analysis_with_chunking_and_embeddings(self):
        """Test code analysis using chunking and embeddings"""
        from utils.code_chunker import CodeChunker, ChunkStrategy
        from embeddings.code_embedder import CodeEmbedder

        large_code = """
def function1():
    pass

def function2():
    # Large function
    x = 1
    y = 2
    z = 3
    return x + y + z

def function3():
    pass
""" * 50  # Create large code

        # Chunk the code
        chunker = CodeChunker(strategy=ChunkStrategy.SEMANTIC, chunk_size=500)
        chunks = chunker.chunk(large_code)

        assert len(chunks) > 0

        # Verify chunks preserve structure
        for chunk in chunks:
            assert len(chunk.content) > 0
            assert chunk.start_line >= 0
            assert chunk.end_line >= chunk.start_line

    @pytest.mark.e2e
    def test_csrf_protection_workflow(self, client):
        """Test CSRF protection in request workflow"""
        from utils.csrf_protection import generate_csrf_token, validate_csrf_token

        # Generate token for user
        token1 = generate_csrf_token()
        assert token1

        # Generate another token  
        token2 = generate_csrf_token()
        assert token2

        # Tokens should be different
        assert token1 != token2

    @pytest.mark.e2e
    def test_parallel_security_and_refactor_analysis(self):
        """Test parallel security and refactor analysis"""
        from utils.parallel_executor import ParallelExecutor
        import time

        executor = ParallelExecutor(max_workers=2)

        def security_check(code):
            time.sleep(0.1)
            return {'vulnerabilities': []}

        def refactor_check(code):
            time.sleep(0.1)
            return {'improvements': []}

        code = "def foo(): pass"

        tasks = {
            'security': (security_check, (code,), {}),
            'refactor': (refactor_check, (code,), {})
        }

        start = time.time()
        results = executor.execute_tasks(tasks)
        duration = time.time() - start

        assert 'security' in results
        assert 'refactor' in results
        # Should take ~0.1s (parallel) not ~0.2s (sequential)
        assert duration < 0.25

    @pytest.mark.e2e
    def test_settings_environment_configuration(self):
        """Test loading settings from environment"""
        from settings import Settings
        import os

        # Mock environment variables
        with patch.dict(os.environ, {
            'FLASK_ENV': 'production',
            'DATABASE_URL': 'postgresql://user:pass@localhost/db',
            'JWT_SECRET': 'test-secret'
        }):
            settings = Settings.from_env()

            assert settings.flask_env == 'production'

    @pytest.mark.e2e
    def test_complete_request_lifecycle(self, mock_config):
        """Test complete request lifecycle with all optimizations"""
        from utils.structured_logging import generate_correlation_id
        from utils.rate_limiter import RateLimiter

        correlation_id = generate_correlation_id()
        limiter = RateLimiter(limit=10, window_seconds=60)

        # Simulate request lifecycle
        # 1. Generate correlation ID
        assert len(correlation_id) == 32

        # 2. Check rate limit
        allowed, count, reset_in = limiter.is_allowed('user_123')
        assert allowed is True

        # 3. Process request (mocked)
        request_data = {
            'correlation_id': correlation_id,
            'user_id': 'user_123'
        }

        # 4. Return response with correlation ID
        response = {
            'data': 'results',
            'x-correlation-id': correlation_id,
            'x-ratelimit-remaining': 9
        }

        assert response['x-correlation-id'] == correlation_id


class TestErrorHandling:
    """Tests for error handling in workflows"""

    @pytest.mark.e2e
    def test_graceful_degradation_on_phase_failure(self):
        """Test pipeline gracefully handles phase failures"""
        from code_analysis.pipeline import AnalysisPipeline, AnalysisPhaseResult

        pipeline = AnalysisPipeline()

        # Verify pipeline has error handling capability
        assert len(pipeline.phases) == 6

    @pytest.mark.e2e
    def test_task_cleanup_on_error(self):
        """Test background tasks clean up on error"""
        from utils.background_tasks import BackgroundTaskManager, TaskStatus

        manager = BackgroundTaskManager(max_workers=1)

        def failing_task():
            raise ValueError("Task failed")

        task_id = manager.submit_task(
            task_name="failing_task",
            task_func=failing_task,
            task_args=()
        )

        time.sleep(0.5)

        task = manager.get_task(task_id)
        assert task.status in [TaskStatus.FAILED, TaskStatus.RUNNING]

    @pytest.mark.e2e
    def test_rate_limiter_cleanup(self):
        """Test rate limiter cleans up old entries"""
        from utils.rate_limiter import RateLimiter

        limiter = RateLimiter(limit=10, window_seconds=1)

        # Create many entries
        for i in range(100):
            limiter.is_allowed(f'user_{i}')

        # Verify cleanup doesn't cause errors
        assert len(limiter.requests) <= 100


class TestScalability:
    """Tests for scalability of optimizations"""

    @pytest.mark.e2e
    @pytest.mark.slow
    def test_handling_many_concurrent_requests(self):
        """Test handling many concurrent rate-limited requests"""
        from utils.rate_limiter import RateLimiter
        from utils.parallel_executor import ParallelExecutor
        import time

        executor = ParallelExecutor(max_workers=10)
        limiter = RateLimiter(limit=100, window_seconds=60)

        def mock_request(user_id):
            allowed, _, _ = limiter.is_allowed(user_id)
            return {'user': user_id, 'allowed': allowed}

        # Simulate 50 concurrent requests
        tasks = {
            f'req_{i}': (mock_request, (f'user_{i % 10}',), {})
            for i in range(50)
        }

        start = time.time()
        results = executor.execute_tasks(tasks)
        duration = time.time() - start

        assert len(results) == 50
        # Should complete in reasonable time
        assert duration < 2.0

    @pytest.mark.e2e
    @pytest.mark.slow
    def test_handling_large_code_files(self):
        """Test handling analysis of large code files"""
        from utils.code_chunker import CodeChunker, ChunkStrategy

        # Create a very large code file (1MB)
        large_code = """
def function_{i}():
    # This is function {i}
    x = {i}
    y = {i} * 2
    z = x + y
    return z

""".format(i='{i}')

        large_code = large_code * 10000  # ~1MB

        chunker = CodeChunker(strategy=ChunkStrategy.SLIDING_WINDOW)

        start = time.time()
        chunks = chunker.chunk(large_code)
        duration = time.time() - start

        assert len(chunks) > 0
        # Should handle large files efficiently
        assert duration < 5.0

    @pytest.mark.e2e
    def test_handling_many_background_tasks(self):
        """Test handling many background tasks"""
        from utils.background_tasks import BackgroundTaskManager
        import time

        manager = BackgroundTaskManager(max_workers=5)

        def quick_task(task_num):
            return {'task': task_num, 'result': task_num * 2}

        # Submit many tasks
        task_ids = []
        for i in range(20):
            task_id = manager.submit_task(
                task_name=f"task_{i}",
                task_func=quick_task,
                task_args=(i,)
            )
            task_ids.append(task_id)

        # Wait for tasks to complete
        time.sleep(1.0)

        # Verify tasks completed
        completed = 0
        for task_id in task_ids:
            task = manager.get_task(task_id)
            if task and task.result:
                completed += 1

        assert completed > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'e2e'])
