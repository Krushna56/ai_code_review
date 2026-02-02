"""
Streaming Service

Handle Server-Sent Events (SSE) for real-time streaming of LLM responses and analysis progress.
"""

import json
import logging
import time
from typing import Generator, Dict, Any, Optional
from queue import Queue, Empty
import threading

logger = logging.getLogger(__name__)


class StreamingService:
    """Service for handling SSE streaming operations"""

    @staticmethod
    def format_sse(data: Dict[str, Any], event: Optional[str] = None) -> str:
        """
        Format data as Server-Sent Event

        Args:
            data: Data to send
            event: Optional event type

        Returns:
            Formatted SSE string
        """
        message = ""

        if event:
            message += f"event: {event}\n"

        message += f"data: {json.dumps(data)}\n\n"

        return message

    @staticmethod
    def stream_generator(
        generator: Generator,
        event_type: str = "message",
        heartbeat_interval: int = 30
    ) -> Generator[str, None, None]:
        """
        Convert a generator into SSE format with heartbeat

        Args:
            generator: Source generator
            event_type: SSE event type
            heartbeat_interval: Seconds between heartbeat messages

        Yields:
            SSE-formatted strings
        """
        last_heartbeat = time.time()

        try:
            for chunk in generator:
                # Send actual data
                yield StreamingService.format_sse(chunk, event_type)

                # Send heartbeat if needed
                if time.time() - last_heartbeat > heartbeat_interval:
                    yield StreamingService.format_sse(
                        {"type": "heartbeat", "timestamp": time.time()},
                        "heartbeat"
                    )
                    last_heartbeat = time.time()

            # Send completion event
            yield StreamingService.format_sse(
                {"type": "complete", "timestamp": time.time()},
                "complete"
            )

        except Exception as e:
            logger.error(f"Streaming error: {e}", exc_info=True)
            yield StreamingService.format_sse(
                {"type": "error", "error": str(e)},
                "error"
            )

    @staticmethod
    def stream_chat_response(chat_generator: Generator) -> Generator[str, None, None]:
        """
        Stream chat responses with proper SSE formatting

        Args:
            chat_generator: Generator from ChatEngine

        Yields:
            SSE-formatted chat chunks
        """
        for chunk in chat_generator:
            if chunk.get('type') == 'content':
                # Stream content chunks
                yield StreamingService.format_sse({
                    'type': 'content',
                    'content': chunk['content'],
                    'done': False
                }, 'message')

            elif chunk.get('type') == 'done':
                # Send completion
                yield StreamingService.format_sse({
                    'type': 'done',
                    'message_id': chunk.get('message_id'),
                    'tokens_used': chunk.get('tokens_used'),
                    'done': True
                }, 'complete')

            elif chunk.get('type') == 'error':
                # Send error
                yield StreamingService.format_sse({
                    'type': 'error',
                    'error': chunk.get('content'),
                    'done': True
                }, 'error')

    @staticmethod
    def stream_progress(
        total_steps: int,
        step_generator: Generator[Dict[str, Any], None, None]
    ) -> Generator[str, None, None]:
        """
        Stream analysis progress updates

        Args:
            total_steps: Total number of steps
            step_generator: Generator yielding progress updates

        Yields:
            SSE-formatted progress updates
        """
        current_step = 0

        for update in step_generator:
            current_step += 1
            progress = (current_step / total_steps) * 100

            yield StreamingService.format_sse({
                'step': current_step,
                'total_steps': total_steps,
                'progress': progress,
                'status': update.get('status', 'Processing...'),
                'data': update.get('data')
            }, 'progress')

        # Send completion
        yield StreamingService.format_sse({
            'step': total_steps,
            'total_steps': total_steps,
            'progress': 100,
            'status': 'Complete',
            'done': True
        }, 'complete')


class ProgressTracker:
    """Track and broadcast progress for long-running operations"""

    def __init__(self, total_steps: int):
        """
        Initialize progress tracker

        Args:
            total_steps: Total number of steps in the operation
        """
        self.total_steps = total_steps
        self.current_step = 0
        self.queue = Queue()
        self._lock = threading.Lock()

    def update(self, status: str, data: Optional[Dict[str, Any]] = None):
        """
        Update progress

        Args:
            status: Status message
            data: Optional additional data
        """
        with self._lock:
            self.current_step += 1

            update = {
                'step': self.current_step,
                'total_steps': self.total_steps,
                'progress': (self.current_step / self.total_steps) * 100,
                'status': status
            }

            if data:
                update['data'] = data

            self.queue.put(update)

    def get_updates(self) -> Generator[Dict[str, Any], None, None]:
        """
        Get progress updates as they arrive

        Yields:
            Progress update dictionaries
        """
        while self.current_step < self.total_steps:
            try:
                update = self.queue.get(timeout=1)
                yield update
            except Empty:
                continue

        # Get any remaining updates
        while not self.queue.empty():
            try:
                update = self.queue.get_nowait()
                yield update
            except Empty:
                break


def create_sse_response(generator: Generator, mimetype: str = 'text/event-stream'):
    """
    Create a Flask response for SSE

    Args:
        generator: Generator yielding SSE-formatted strings
        mimetype: MIME type for response

    Returns:
        Flask Response object
    """
    from flask import Response

    return Response(
        generator,
        mimetype=mimetype,
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # Disable nginx buffering
            'Connection': 'keep-alive'
        }
    )
