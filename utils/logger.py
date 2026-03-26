"""
utils/logger.py
Structured JSON session logger.

Each attack session writes to logs/<timestamp>_<module>.jsonl
Every line is a valid JSON event:
  {"ts": 1710000000.0, "event": "start", "module": "syn_flood", "target": "..."}
  {"ts": 1710000001.0, "event": "metrics", "packets": 142000, "pps": 14200.0, ...}
  {"ts": 1710000030.0, "event": "stop", "summary": {...}}
"""

import json
import os
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


LOG_DIR = Path("logs")


class SessionLogger:
    """
    One instance per attack session. Thread-safe.
    Writes JSONL to logs/<iso_timestamp>_<module>.jsonl
    """

    def __init__(self, module: str, target: str, params: dict) -> None:
        self.module = module
        self.target = target
        self.params = params
        self.session_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self._lock = threading.Lock()

        LOG_DIR.mkdir(exist_ok=True)
        self._path = LOG_DIR / f"{self.session_id}_{module}.jsonl"
        self._fh = open(self._path, "a", buffering=1)  # Line-buffered

        self._write({
            "event":   "start",
            "module":  module,
            "target":  target,
            "params":  params,
        })

    def _write(self, data: dict) -> None:
        data["ts"] = time.time()
        with self._lock:
            self._fh.write(json.dumps(data) + "\n")

    def metrics(self, summary: dict) -> None:
        self._write({"event": "metrics", **summary})

    def note(self, message: str, **kwargs) -> None:
        self._write({"event": "note", "message": message, **kwargs})

    def error(self, message: str, **kwargs) -> None:
        self._write({"event": "error", "message": message, **kwargs})

    def stop(self, summary: dict) -> None:
        self._write({"event": "stop", "summary": summary})
        self._fh.flush()
        self._fh.close()

    @property
    def path(self) -> Path:
        return self._path


def get_logger(module: str, target: str, params: dict) -> SessionLogger:
    return SessionLogger(module, target, params)
