"""
Structured logging for Phish Raksha.

Replaces scattered print() calls with JSON log lines that carry a
correlation_id per scan, so the full trail for one scan (headers parse ->
DNS -> VirusTotal -> Gemini -> DB write) can be grepped/filtered as a unit
in whatever log store this eventually ships to (stdout today, Datadog /
CloudWatch / Loki later -- JSON lines work with all of them unchanged).
"""

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any, Optional

# Holds the current scan's correlation ID for the duration of one request.
_correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="-")


def new_correlation_id() -> str:
    """Generate and bind a new correlation ID to the current async context."""
    cid = uuid.uuid4().hex[:12]
    _correlation_id_ctx.set(cid)
    return cid


def get_correlation_id() -> str:
    return _correlation_id_ctx.get()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", "-"),
            "message": record.getMessage(),
        }
        # Allow extra structured fields via logger.info("msg", extra={"extra_fields": {...}})
        extra_fields = getattr(record, "extra_fields", None)
        if extra_fields:
            payload.update(extra_fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = get_correlation_id()
        return True


def setup_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(CorrelationFilter())
    root.addHandler(handler)

    # Quiet down noisy third-party loggers at INFO level
    for noisy in ("uvicorn.access", "pymongo", "motor"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class StageTimer:
    """
    Small helper to time named stages of a scan and collect them into a
    dict suitable for storing as `stage_latency_ms` on the scan document.

    Usage:
        timer = StageTimer()
        with timer.stage("dns_lookup"):
            ... do work ...
        timer.as_dict()  -> {"dns_lookup": 123.4, "total": 456.7}
    """

    def __init__(self) -> None:
        self._start = time.perf_counter()
        self._stages: dict[str, float] = {}

    class _StageCtx:
        def __init__(self, parent: "StageTimer", name: str) -> None:
            self.parent = parent
            self.name = name
            self.t0: Optional[float] = None

        def __enter__(self) -> "StageTimer._StageCtx":
            self.t0 = time.perf_counter()
            return self

        def __exit__(self, *exc: Any) -> None:
            elapsed_ms = (time.perf_counter() - self.t0) * 1000
            self.parent._stages[self.name] = round(elapsed_ms, 2)

    def stage(self, name: str) -> "StageTimer._StageCtx":
        return StageTimer._StageCtx(self, name)

    def as_dict(self) -> dict:
        total_ms = round((time.perf_counter() - self._start) * 1000, 2)
        return {**self._stages, "total": total_ms}
