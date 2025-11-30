# firewall_assistant/profiles.py

from __future__ import annotations
from .models import FullConfig, ProfileConfig, Action
from .config import load_config, save_config
from .firewall_win import sync_profile_to_windows_firewall


def get_active_profile(cfg: FullConfig) -> ProfileConfig:
    """
    Return the currently active ProfileConfig from FullConfig.
    """
    ...


def set_active_profile(cfg: FullConfig, profile_name: str) -> None:
    """
    Set cfg.active_profile to profile_name and persist config.
    Does NOT itself call Windows Firewall; UI or caller can decide when to sync.
    """
    ...


def apply_profile(profile_name: str) -> None:
    """
    High-level: load config, set active_profile, save config,
    and call sync_profile_to_windows_firewall(profile_name).
    UI should call this when user clicks a profile button.
    """
    ...


def set_app_action_in_profile(
    cfg: FullConfig,
    profile_name: str,
    exe_path: str,
    action: Action,
) -> None:
    """
    In the given profile, set app_rules[exe_path].action = action.
    If rule does not exist, create it. Caller should then save_config() and
    (optionally) sync to Windows Firewall.
    """
    ...