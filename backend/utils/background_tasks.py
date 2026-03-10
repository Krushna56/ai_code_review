"""
Background task management for async operations.

Handles long-running tasks like file uploads, analysis, and report generation
without blocking the request-response cycle.
"""

import logging
import asyncio
import uuid
from typing import Dict, Any, Optional, Callable, Coroutine
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from threading import Thread
import queue

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Represents a background task"""
    task_id: str
    name: str
    status: TaskStatus = TaskStatus.PENDING
    progress: float = 0.0  # 0-100
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get task duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary"""
        return {
            'task_id': self.task_id,
            'name': self.name,
            'status': self.status.value,
            'progress': self.progress,
            'result': self.result,
            'error': self.error,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'metadata': self.metadata
        }


class BackgroundTaskManager:
    """Manages background task execution and tracking"""

    def __init__(self, max_workers: int = 4):
        """
        Initialize task manager.

        Args:
            max_workers: Maximum concurrent task workers
        """
        self.max_workers = max_workers
        self.tasks: Dict[str, Task] = {}
        self.task_queue: queue.Queue = queue.Queue()
        self.worker_threads = []

        # Start worker threads
        for i in range(max_workers):
            thread = Thread(target=self._worker_loop, daemon=True)
            thread.start()
            self.worker_threads.append(thread)

        logger.info(f"Background task manager started with {max_workers} workers")

    def _worker_loop(self):
        """Worker thread loop for processing tasks"""
        while True:
            try:
                task_id, task_func, task_args, task_kwargs = self.task_queue.get()

                if task_id is None:  # Shutdown signal
                    break

                task = self.tasks.get(task_id)
                if not task:
                    continue

                # Execute task
                try:
                    task.status = TaskStatus.RUNNING
                    task.started_at = datetime.now()

                    logger.info(f"Task {task_id} started: {task.name}")

                    # Run task function
                    result = task_func(*task_args, **task_kwargs)

                    # Handle generator-based progress updates
                    if hasattr(result, '__iter__') and not isinstance(result, (str, bytes)):
                        final_result = None
                        for item in result:
                            if isinstance(item, dict) and 'progress' in item:
                                task.progress = item['progress']
                                task.metadata.update(item)
                            else:
                                final_result = item
                        result = final_result

                    task.result = result
                    task.status = TaskStatus.COMPLETED
                    task.progress = 100.0

                    logger.info(
                        f"Task {task_id} completed in "
                        f"{task.duration_seconds:.2f}s: {task.name}"
                    )

                except Exception as e:
                    task.error = str(e)
                    task.status = TaskStatus.FAILED

                    logger.error(
                        f"Task {task_id} failed: {task.name}",
                        exc_info=True
                    )

                finally:
                    task.completed_at = datetime.now()

            except Exception as e:
                logger.error(f"Worker thread error: {e}", exc_info=True)

    def submit_task(self,
                   task_name: str,
                   task_func: Callable,
                   task_args: tuple = (),
                   task_kwargs: dict = None,
                   metadata: dict = None) -> str:
        """
        Submit a task for background execution.

        Args:
            task_name: Human-readable task name
            task_func: Callable to execute
            task_args: Positional arguments for task_func
            task_kwargs: Keyword arguments for task_func
            metadata: Additional metadata for task

        Returns:
            Task ID for tracking progress
        """
        task_id = str(uuid.uuid4())
        task_kwargs = task_kwargs or {}
        metadata = metadata or {}

        # Create and store task
        task = Task(
            task_id=task_id,
            name=task_name,
            metadata=metadata
        )
        self.tasks[task_id] = task

        # Queue task for execution
        self.task_queue.put((task_id, task_func, task_args, task_kwargs))

        logger.info(f"Task submitted: {task_id} ({task_name})")
        return task_id

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        return self.tasks.get(task_id)

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status as dictionary"""
        task = self.get_task(task_id)
        if task:
            return task.to_dict()
        return None

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task (running tasks cannot be cancelled)"""
        task = self.get_task(task_id)
        if task and task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now()
            logger.info(f"Task cancelled: {task_id}")
            return True
        return False

    def cleanup_old_tasks(self, max_age_hours: int = 24) -> int:
        """Remove old completed tasks to free memory"""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=max_age_hours)

        old_tasks = [
            task_id for task_id, task in self.tasks.items()
            if task.completed_at and task.completed_at < cutoff
        ]

        for task_id in old_tasks:
            del self.tasks[task_id]

        if old_tasks:
            logger.info(f"Cleaned up {len(old_tasks)} old tasks")

        return len(old_tasks)

    def shutdown(self):
        """Shutdown task manager and workers"""
        logger.info("Shutting down background task manager...")

        # Signal workers to stop
        for _ in range(self.max_workers):
            self.task_queue.put((None, None, (), {}))

        # Wait for workers to finish
        for thread in self.worker_threads:
            thread.join(timeout=5)

        logger.info("Background task manager shut down")


# Global task manager instance
_task_manager: Optional[BackgroundTaskManager] = None


def get_task_manager(max_workers: int = 4) -> BackgroundTaskManager:
    """Get or create the global task manager"""
    global _task_manager
    if _task_manager is None:
        _task_manager = BackgroundTaskManager(max_workers=max_workers)
    return _task_manager


def submit_background_task(
    task_name: str,
    task_func: Callable,
    task_args: tuple = (),
    task_kwargs: dict = None
) -> str:
    """
    Convenience function to submit a background task.

    Args:
        task_name: Human-readable task name
        task_func: Callable to execute
        task_args: Positional arguments
        task_kwargs: Keyword arguments

    Returns:
        Task ID for tracking
    """
    manager = get_task_manager()
    return manager.submit_task(
        task_name=task_name,
        task_func=task_func,
        task_args=task_args,
        task_kwargs=task_kwargs
    )
