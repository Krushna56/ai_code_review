"""
Structured Logging utilities with request correlation IDs.

Provides request tracing, structured logging, and centralized logging configuration.
"""

import logging
import logging.handlers
import uuid
import json
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import config

# Correlation ID context variable for request tracing
_correlation_id: Optional[str] = None


def set_correlation_id(correlation_id: str):
    """Set correlation ID for current request"""
    global _correlation_id
    _correlation_id = correlation_id


def get_correlation_id() -> str:
    """Get correlation ID for current request"""
    return _correlation_id or str(uuid.uuid4())


def generate_correlation_id() -> str:
    """Generate a new correlation ID"""
    return str(uuid.uuid4())


class CorrelationIdFilter(logging.Filter):
    """Logging filter that adds correlation ID to all log records"""

    def filter(self, record):
        """Add correlation ID to log record"""
        record.correlation_id = get_correlation_id()
        record.timestamp = datetime.utcnow().isoformat()
        return True


class StructuredFormatter(logging.Formatter):
    """Formatter for structured JSON logging"""

    def format(self, record):
        """Format log record as structured JSON"""
        log_data = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'correlation_id': getattr(record, 'correlation_id', ''),
            'message': record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, 'extra'):
            log_data['extra'] = record.extra

        return json.dumps(log_data)


class TextFormatter(logging.Formatter):
    """Formatter for readable text logging"""

    FORMAT = (
        '%(asctime)s - %(correlation_id)s - %(name)s - '
        '%(levelname)s - %(message)s'
    )

    def __init__(self):
        super().__init__(fmt=self.FORMAT)
        self.default_time_format = '%Y-%m-%d %H:%M:%S'


def setup_logging(log_file: Optional[Path] = None,
                  json_format: bool = False,
                  level: str = 'INFO') -> None:
    """
    Configure structured logging for the application.

    Args:
        log_file: Optional file path for logging
        json_format: Whether to use JSON formatting
        level: Logging level
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add correlation ID filter to all loggers
    correlation_filter = CorrelationIdFilter()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, level.upper()))
    console_handler.addFilter(correlation_filter)

    if json_format:
        console_handler.setFormatter(StructuredFormatter())
    else:
        console_handler.setFormatter(TextFormatter())

    root_logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.addFilter(correlation_filter)

        if json_format:
            file_handler.setFormatter(StructuredFormatter())
        else:
            file_handler.setFormatter(TextFormatter())

        root_logger.addHandler(file_handler)

        logging.info(f"Logging configured: file={log_file}, json={json_format}")


class RequestLogger:
    """Helper for structured request logging"""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_request(self, method: str, path: str, user_id: Optional[str] = None,
                   ip_address: Optional[str] = None, **extras):
        """Log incoming request"""
        data = {
            'method': method,
            'path': path,
            'user_id': user_id,
            'ip_address': ip_address,
        }
        data.update(extras)

        self.logger.info("Request received", extra={'extra': data})

    def log_response(self, status_code: int, duration_ms: float,
                    user_id: Optional[str] = None, **extras):
        """Log outgoing response"""
        data = {
            'status_code': status_code,
            'duration_ms': duration_ms,
            'user_id': user_id,
        }
        data.update(extras)

        level = 'info' if 200 <= status_code < 400 else 'warning'
        getattr(self.logger, level)("Response sent", extra={'extra': data})

    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Log error with context"""
        data = {'error_type': type(error).__name__}
        if context:
            data.update(context)

        self.logger.error(str(error), extra={'extra': data}, exc_info=True)


def get_request_logger(name: str = __name__) -> RequestLogger:
    """Get a RequestLogger instance"""
    logger = logging.getLogger(name)
    return RequestLogger(logger)


# Flask integration
def setup_flask_logging(app):
    """Configure Flask app with structured logging"""
    from flask import request, g
    from datetime import datetime
    import time

    # Remove default Flask logger
    app.logger.handlers.clear()

    # Setup structured logging
    setup_logging(
        log_file=config.LOG_FILE,
        json_format=config.FLASK_ENV == 'production',
        level=config.LOG_LEVEL
    )

    app.logger = logging.getLogger('flask')

    @app.before_request
    def before_request():
        """Log before request"""
        g.start_time = time.time()
        correlation_id = request.headers.get('X-Correlation-ID') or generate_correlation_id()
        set_correlation_id(correlation_id)
        g.correlation_id = correlation_id

        request_logger = get_request_logger('flask.request')
        request_logger.log_request(
            method=request.method,
            path=request.path,
            user_id=getattr(request, 'user_id', None),
            ip_address=request.remote_addr
        )

    @app.after_request
    def after_request(response):
        """Log after request"""
        duration_ms = (time.time() - g.get('start_time', 0)) * 1000

        request_logger = get_request_logger('flask.response')
        request_logger.log_response(
            status_code=response.status_code,
            duration_ms=duration_ms,
            path=request.path,
            method=request.method
        )

        # Add correlation ID to response header
        response.headers['X-Correlation-ID'] = g.get('correlation_id', '')

        return response

    @app.errorhandler(Exception)
    def handle_error(error):
        """Log unhandled errors"""
        error_logger = get_request_logger('flask.error')
        error_logger.log_error(
            error,
            context={
                'path': request.path,
                'method': request.method,
                'ip_address': request.remote_addr
            }
        )

        # Return JSON error response
        from flask import jsonify
        response = jsonify({'error': str(error)})
        response.status_code = 500
        response.headers['X-Correlation-ID'] = g.get('correlation_id', '')
        return response

    logging.info("Flask logging configured")
