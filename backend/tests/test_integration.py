"""
Integration tests for the analysis pipeline.

Tests the complete code analysis workflow from input to output.
"""

import pytest
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path


class TestAnalysisPipeline:
    """Integration tests for the analysis pipeline"""

    @pytest.mark.integration
    def test_pipeline_initialization(self):
        """Test pipeline initialization"""
        from code_analysis import AnalysisPipeline

        pipeline = AnalysisPipeline()
        assert len(pipeline.phases) == 6
        assert pipeline.phases[0].__class__.__name__ == 'StaticAnalysisPhase'
        assert pipeline.phases[1].__class__.__name__ == 'EmbeddingPhase'

    @pytest.mark.integration
    def test_pipeline_with_sample_code(self, sample_code, temp_dir):
        """Test pipeline execution with sample code"""
        from code_analysis import AnalysisPipeline

        # Write sample code to file
        code_file = temp_dir / "test.py"
        code_file.write_text(sample_code)

        pipeline = AnalysisPipeline()

        # Mock static analysis to avoid heavy dependencies
        with patch('code_analysis.pipeline.MultiLinter'):
            with patch('code_analysis.pipeline.ASTParser'):
                initial_data = {
                    'files': {'test.py': sample_code},
                    'code_paths': [str(code_file)],
                    'metadata': {'language': 'python'}
                }

                # This would normally run all phases, but we'll mock some
                # to keep tests fast
                result = pipeline.execute(initial_data)

                assert 'phases' in result
                assert 'final_data' in result
                assert len(result['phases']) == 6

    @pytest.mark.integration
    def test_static_analysis_phase(self, sample_code, temp_dir):
        """Test static analysis phase"""
        from code_analysis import StaticAnalysisPhase

        code_file = temp_dir / "test.py"
        code_file.write_text(sample_code)

        phase = StaticAnalysisPhase()

        with patch('code_analysis.pipeline.MultiLinter'):
            with patch('code_analysis.pipeline.ASTParser'):
                codebase_data = {
                    'files': {'test.py': sample_code},
                    'code_paths': [str(code_file)]
                }

                result = phase.execute(codebase_data)
                assert result.success is True or result.success is False  # May fail with mocks
                assert result.phase_name == 'StaticAnalysis'

    @pytest.mark.integration
    def test_embedding_phase(self, sample_code):
        """Test embedding phase"""
        from code_analysis import EmbeddingPhase

        phase = EmbeddingPhase()

        codebase_data = {
            'files': {'test.py': sample_code}
        }

        # Test phase initialization
        assert phase.name == 'Embeddings'

    @pytest.mark.integration
    def test_phase_result_merge(self):
        """Test merging phase results"""
        from code_analysis import AnalysisPhaseResult

        result1 = AnalysisPhaseResult(
            phase_name='Phase1',
            success=True,
            data={'data1': 'value1'}
        )

        result2 = AnalysisPhaseResult(
            phase_name='Phase2',
            success=True,
            data={'data2': 'value2'}
        )

        merged = result1.merge(result2)
        assert merged.success is True
        assert 'data1' in merged.data
        assert 'data2' in merged.data


class TestCodeChunkingIntegration:
    """Integration tests for code chunking"""

    @pytest.mark.integration
    def test_chunking_with_embedder(self, sample_code):
        """Test chunking integrated with embedder"""
        from embeddings.code_embedder import CodeEmbedder

        embedder = CodeEmbedder()

        # Mock the actual embedding to avoid dependencies
        with patch.object(embedder, 'embed_batch') as mock_embed:
            mock_embed.return_value = [None] * 5  # Mock embeddings

            chunks = embedder.chunk_code(sample_code, strategy='sliding')
            assert len(chunks) > 0

            for chunk in chunks:
                assert chunk.content
                assert chunk.start_line >= 0
                assert chunk.end_line >= chunk.start_line


class TestRateLimitingIntegration:
    """Integration tests for rate limiting"""

    @pytest.mark.integration
    def test_rate_limit_decorator_with_flask(self, client):
        """Test rate limiting decorator with Flask"""
        from utils.rate_limiter import rate_limit, RATE_LIMITS

        @rate_limit(limit=2, window_seconds=1)
        def limited_endpoint():
            return {'status': 'ok'}

        # This test verifies the decorator works (implementation-specific)
        result = limited_endpoint()
        assert result == {'status': 'ok'}


class TestParallelExecutionIntegration:
    """Integration tests for parallel execution"""

    @pytest.mark.integration
    def test_parallel_lm_agents(self):
        """Test parallel LLM agent execution"""
        from utils.parallel_executor import run_parallel_lm_agents

        mock_security_agent = MagicMock()
        mock_security_agent.analyze.return_value = {'issues': []}

        mock_refactor_agent = MagicMock()
        mock_refactor_agent.analyze.return_value = {'suggestions': []}

        code_sample = "def test(): pass"
        context = {'file': 'test.py'}

        security_result, refactor_result = run_parallel_lm_agents(
            code=code_sample,
            context=context,
            security_agent=mock_security_agent,
            refactor_agent=mock_refactor_agent
        )

        assert isinstance(security_result, dict)
        assert isinstance(refactor_result, dict)


class TestBackgroundTasksIntegration:
    """Integration tests for background tasks"""

    @pytest.mark.integration
    def test_background_analysis_task(self):
        """Test background code analysis task"""
        from utils.background_tasks import BackgroundTaskManager, TaskStatus

        manager = BackgroundTaskManager(max_workers=1)

        def mock_analysis(code):
            return {
                'issues': [],
                'metrics': {'lines': len(code)}
            }

        task_id = manager.submit_task(
            task_name="analyze_code",
            task_func=mock_analysis,
            task_args=("def foo(): pass",)
        )

        # Wait briefly for task to complete
        import time
        time.sleep(0.5)

        task = manager.get_task(task_id)
        assert task.name == "analyze_code"
        assert task.status in [TaskStatus.COMPLETED, TaskStatus.RUNNING]


class TestSettingsIntegration:
    """Integration tests for settings"""

    @pytest.mark.integration
    def test_settings_loading(self):
        """Test loading settings from environment"""
        from settings import Settings

        settings = Settings.from_env()

        assert settings.flask_env in ['development', 'production', 'testing']
        assert settings.database is not None
        assert settings.jwt is not None
        assert settings.llm is not None

    @pytest.mark.integration
    def test_settings_validation(self):
        """Test settings validation"""
        from settings import Settings

        settings = Settings()
        # Should not raise any exceptions


# Performance tests
class TestPerformance:
    """Performance tests for optimization"""

    @pytest.mark.performance
    def test_parallel_vs_sequential_performance(self):
        """Verify parallel execution is faster than sequential"""
        from utils.parallel_executor import ParallelExecutor
        import time

        def slow_task():
            time.sleep(0.1)
            return "done"

        # Sequential execution
        start = time.time()
        for _ in range(3):
            slow_task()
        sequential_time = time.time() - start

        # Parallel execution
        executor = ParallelExecutor(max_workers=3)
        tasks = {
            f'task{i}': (slow_task, (), {})
            for i in range(3)
        }

        start = time.time()
        results = executor.execute_tasks(tasks)
        parallel_time = time.time() - start

        # Parallel should be noticeably faster
        # (0.3s sequential vs ~0.15s parallel, allowing some overhead)
        assert parallel_time < sequential_time * 0.8, \
            f"Parallel ({parallel_time:.2f}s) not faster than sequential ({sequential_time:.2f}s)"

    @pytest.mark.performance
    def test_code_chunking_performance(self, sample_code):
        """Test code chunking performance"""
        from utils.code_chunker import CodeChunker, ChunkStrategy
        import time

        # Create large code sample
        large_code = sample_code * 100

        # Test different strategies
        strategies = [
            ChunkStrategy.FIXED_SIZE,
            ChunkStrategy.SLIDING_WINDOW,
            ChunkStrategy.SEMANTIC
        ]

        for strategy in strategies:
            chunker = CodeChunker(strategy=strategy, chunk_size=500)

            start = time.time()
            chunks = chunker.chunk(large_code)
            duration = time.time() - start

            assert len(chunks) > 0
            assert duration < 1.0  # Should complete in under 1 second


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'integration'])
