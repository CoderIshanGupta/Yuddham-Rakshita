# firewall_assistant/models.py

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Literal, Optional

Action = Literal["allow", "block"]
Direction = Literal["in", "out", "both"]


@dataclass
class AppInfo:
    exe_path: str
    name: str
    tags: list[str] = field(default_factory=list)
    last_seen: Optional[str] = None
    pinned: bool = False


@dataclass
class AppRule:
    app_exe_path: str
    action: Action
    direction: Direction = "out"
    temporary_until: Optional[str] = None  # ISO timestamp or None


@dataclass
class ProfileConfig:
    name: str            # internal profile id, e.g. "normal"
    display_name: str    # e.g. "Normal"
    description: str
    default_action: Action
    app_rules: Dict[str, AppRule]  # key: exe_path


@dataclass
class FullConfig:
    version: int
    active_profile: str
    apps: Dict[str, AppInfo]               # key: exe_path
    profiles: Dict[str, ProfileConfig]     # key: profile name

  