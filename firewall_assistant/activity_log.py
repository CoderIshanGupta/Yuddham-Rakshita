# firewall_assistant/activity_log.py

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
import datetime as _dt

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "activity.log"


def log_event(event_type: str, message: str, extra: Dict[str, Any] | None = None) -> None:
    """
    Append a log entry to logs/activity.log.
    Format per line could be JSON:
      {"timestamp": "...", "event_type": "...", "message": "...", "extra": {...}}
    """
    ...


def get_recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Read up to 'limit' most recent events from the log file and return as dicts.
    """
    ...