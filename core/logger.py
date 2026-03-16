"""
Core Logger - Structured JSON Logging
======================================
Provides consistent, structured logging across all modules.
"""

import json
import logging
import traceback
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured, machine-parseable logs."""

    def format(self, record):
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[0] is not None:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Include extra fields
        for key in ("target", "action", "result", "agent", "scan_id", "round_id"):
            if hasattr(record, key):
                log_data[key] = getattr(record, key)

        return json.dumps(log_data)


def get_logger(name: str) -> logging.Logger:
    """
    Get a named logger configured through Django settings.

    Usage:
        from core.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Scan started", extra={"target": "192.168.1.1"})
    """
    return logging.getLogger(name)


class AgentLogger:
    """
    High-level logger for Red/Blue team agents.
    Automatically includes agent context in all logs.
    """

    def __init__(self, agent_name: str, agent_type: str):
        self.logger = get_logger(f"{agent_type}.{agent_name}")
        self.agent_name = agent_name
        self.agent_type = agent_type

    def _extra(self, **kwargs):
        base = {"agent": f"{self.agent_type}:{self.agent_name}"}
        base.update(kwargs)
        return base

    def action(self, action_name: str, target: str = "", details: str = "", **kwargs):
        self.logger.info(
            f"ACTION: {action_name} | {details}",
            extra=self._extra(action=action_name, target=target, **kwargs),
        )

    def result(self, action_name: str, success: bool, details: str = "", **kwargs):
        level = logging.INFO if success else logging.WARNING
        self.logger.log(
            level,
            f"RESULT: {action_name} -> {'SUCCESS' if success else 'FAILURE'} | {details}",
            extra=self._extra(action=action_name, result="success" if success else "failure", **kwargs),
        )

    def decision(self, decision: str, reasoning: str = "", confidence: float = 0.0, **kwargs):
        self.logger.info(
            f"DECISION: {decision} (confidence={confidence:.2f}) | {reasoning}",
            extra=self._extra(**kwargs),
        )

    def error(self, message: str, exc_info=None, **kwargs):
        self.logger.error(message, exc_info=exc_info, extra=self._extra(**kwargs))

    def warning(self, message: str, **kwargs):
        self.logger.warning(message, extra=self._extra(**kwargs))

    def info(self, message: str, **kwargs):
        self.logger.info(message, extra=self._extra(**kwargs))
