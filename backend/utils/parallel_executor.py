"""
Parallel execution utilities for LLM agents and other async operations.

Provides thread-safe parallel execution with proper error handling and timeout support.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Callable, Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ParallelTaskResult:
    """Result of a parallel task execution"""
    task_name: str
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    duration_seconds: float = 0.0
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class ParallelExecutor:
    """Manages parallel execution of independent tasks with error handling"""

    def __init__(self, max_workers: int = 4, timeout_seconds: int = 60):
        """
        Initialize parallel executor.

        Args:
            max_workers: Maximum number of worker threads
            timeout_seconds: Timeout for each task in seconds
        """
        self.max_workers = max_workers
        self.timeout_seconds = timeout_seconds
        self.logger = logging.getLogger(__name__)

    def execute_tasks(
        self,
        tasks: Dict[str, Tuple[Callable, tuple, dict]],
        continue_on_error: bool = True
    ) -> Dict[str, ParallelTaskResult]:
        """
        Execute multiple tasks in parallel.

        Args:
            tasks: Dictionary mapping task_name -> (callable, args, kwargs)
            continue_on_error: Whether to continue if a task fails

        Returns:
            Dictionary mapping task_name -> ParallelTaskResult

        Example:
            tasks = {
                'security': (security_agent.analyze, (), {'code': code_snippet}),
                'refactor': (refactor_agent.analyze, (), {'code': code_snippet})
            }
            results = executor.execute_tasks(tasks)
        """
        results = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {}
            for task_name, (func, args, kwargs) in tasks.items():
                try:
                    future = executor.submit(func, *args, **kwargs)
                    future_to_task[future] = task_name
                except Exception as e:
                    self.logger.error(f"Failed to submit task '{task_name}': {e}")
                    results[task_name] = ParallelTaskResult(
                        task_name=task_name,
                        success=False,
                        error=e
                    )

            # Collect results
            for future in as_completed(future_to_task, timeout=self.timeout_seconds):
                task_name = future_to_task[future]
                start_time = datetime.now()

                try:
                    result = future.result(timeout=self.timeout_seconds)
                    duration = (datetime.now() - start_time).total_seconds()

                    results[task_name] = ParallelTaskResult(
                        task_name=task_name,
                        success=True,
                        result=result,
                        duration_seconds=duration
                    )
                    self.logger.info(
                        f"Task '{task_name}' completed successfully in {duration:.2f}s"
                    )

                except FuturesTimeoutError as e:
                    self.logger.error(f"Task '{task_name}' timed out after {self.timeout_seconds}s")
                    results[task_name] = ParallelTaskResult(
                        task_name=task_name,
                        success=False,
                        error=e,
                        duration_seconds=self.timeout_seconds
                    )
                    if not continue_on_error:
                        raise

                except Exception as e:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.logger.error(
                        f"Task '{task_name}' failed after {duration:.2f}s: {e}",
                        exc_info=True
                    )
                    results[task_name] = ParallelTaskResult(
                        task_name=task_name,
                        success=False,
                        error=e,
                        duration_seconds=duration
                    )
                    if not continue_on_error:
                        raise

        return results

    def execute_two_tasks(
        self,
        task1_name: str,
        task1_func: Callable,
        task1_args: tuple = (),
        task1_kwargs: dict = None,
        task2_name: str = None,
        task2_func: Callable = None,
        task2_args: tuple = (),
        task2_kwargs: dict = None,
        continue_on_error: bool = True
    ) -> Tuple[Any, Any]:
        """
        Convenience method for executing exactly two tasks in parallel.
        
        Returns results as tuple: (result1, result2)
        """
        if task1_kwargs is None:
            task1_kwargs = {}
        if task2_kwargs is None:
            task2_kwargs = {}

        tasks = {
            task1_name: (task1_func, task1_args, task1_kwargs),
            task2_name: (task2_func, task2_args, task2_kwargs)
        }

        results = self.execute_tasks(tasks, continue_on_error=continue_on_error)

        result1 = results[task1_name].result if results[task1_name].success else None
        result2 = results[task2_name].result if results[task2_name].success else None

        return result1, result2


# Global executor instance with configurable workers
_executor: Optional[ParallelExecutor] = None


def get_parallel_executor(max_workers: int = 4) -> ParallelExecutor:
    """Get or create the global parallel executor."""
    global _executor
    if _executor is None:
        _executor = ParallelExecutor(max_workers=max_workers)
    return _executor


def run_parallel_lm_agents(
    code: str,
    context: Dict[str, Any],
    security_agent,
    refactor_agent,
    timeout_seconds: int = 60
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Run security and refactor agents in parallel.

    Args:
        code: Code to analyze
        context: Additional context for analysis
        security_agent: Security reviewer agent
        refactor_agent: Refactor agent
        timeout_seconds: Timeout per task

    Returns:
        Tuple of (security_result, refactor_result)
    """
    executor = ParallelExecutor(max_workers=2, timeout_seconds=timeout_seconds)

    security_result, refactor_result = executor.execute_two_tasks(
        task1_name="security_review",
        task1_func=security_agent.analyze,
        task1_kwargs={'code': code, 'context': context},
        task2_name="refactoring",
        task2_func=refactor_agent.analyze,
        task2_kwargs={'code': code, 'context': context},
        continue_on_error=True
    )

    # Ensure we return dicts even on failure
    if security_result is None:
        security_result = {'error': 'Security review failed', 'issues': []}
    if refactor_result is None:
        refactor_result = {'error': 'Refactoring analysis failed', 'suggestions': []}

    return security_result, refactor_result
