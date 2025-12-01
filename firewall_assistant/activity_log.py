# firewall_assistant/activity_log.py

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import datetime as _dt

# Base directory = repo root (same idea as in config.py)
ROOT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT_DIR / "logs"
LOG_FILE = LOG_DIR / "activity.log"


def _now_iso() -> str:
    """Return current UTC time as ISO string (seconds precision)."""
    return _dt.datetime.utcnow().isoformat(timespec="seconds")


def log_event(event_type: str, message: str, extra: Dict[str, Any] | None = None) -> None:
    """
    Append a log entry to logs/activity.log.
    Format per line (JSON):
      {"timestamp": "...", "event_type": "...", "message": "...", "extra": {...}}
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    entry = {
      "timestamp": _now_iso(),
      "event_type": event_type,
      "message": message,
      "extra": extra or {},
    }

    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        # Logging should never crash the app; just print a warning.
        print(f"[activity_log] Failed to write log entry: {exc}")


def get_recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Read up to 'limit' most recent events from the log file and return as dicts.
    If the file doesn't exist yet, return an empty list.
    """
    if not LOG_FILE.exists():
        return []

    events: List[Dict[str, Any]] = []

    try:
        with LOG_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as exc:
        print(f"[activity_log] Failed to read log file: {exc}")
        return []

    # Take last 'limit' lines
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
            events.append(evt)
        except json.JSONDecodeError:
            # Skip malformed lines
            continue

    return events


if __name__ == "__main__":
    # Simple self-test
    log_event("TEST", "This is a test event", {"foo": "bar"})
    recent = get_recent_events(limit=5)
    print("Recent events:")
    for e in recent:
        print(e)