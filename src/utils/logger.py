"""Logging configuration for the PII classification agent."""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production use."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry['exception'] = self.formatException(record.exc_info)
        if hasattr(record, 'topic'):
            log_entry['topic'] = record.topic
        if hasattr(record, 'pii_type'):
            log_entry['pii_type'] = record.pii_type
        return json.dumps(log_entry)


def setup_logger(
    name: str = "pii_classifier",
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    console_output: bool = True,
    json_format: bool = False,
) -> logging.Logger:
    """
    Set up and configure the logger.

    Also configures the root 'src' logger so that all child loggers
    (src.agent, src.pii.detector, etc.) inherit the same level and handlers.

    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        console_output: Whether to output to console
        json_format: Use structured JSON format (recommended for production)

    Returns:
        Configured logger instance
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Choose formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    # Configure the named logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    # Also configure the 'src' logger so all src.* child loggers inherit settings
    src_logger = logging.getLogger('src')
    src_logger.setLevel(level)
    src_logger.handlers.clear()

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        src_logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        src_logger.addHandler(file_handler)

    # Prevent duplicate log messages by disabling propagation
    src_logger.propagate = False

    return logger
