# firewall_assistant/profiles.py

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import datetime as _dt

from .models import FullConfig, ProfileConfig, Action, AppRule
from .config import load_config, save_config
from .firewall_win import sync_profile_to_windows_firewall
from .activity_log import log_event


def get_active_profile(cfg: FullConfig) -> ProfileConfig:
    """
    Return the currently active ProfileConfig from FullConfig.
    If cfg.active_profile is invalid, try to repair it.
    """
    if cfg.active_profile in cfg.profiles:
        return cfg.profiles[cfg.active_profile]

    # Attempt to repair
    if "normal" in cfg.profiles:
        cfg.active_profile = "normal"
    elif cfg.profiles:
        cfg.active_profile = next(iter(cfg.profiles))
    else:
        raise RuntimeError("No profiles available in config")

    save_config(cfg)
    return cfg.profiles[cfg.active_profile]


def set_active_profile(cfg: FullConfig, profile_name: str) -> None:
    """
    Set cfg.active_profile to profile_name and persist config.
    Does NOT itself call Windows Firewall; caller can decide when to sync.
    """
    if profile_name not in cfg.profiles:
        raise ValueError(f"Profile '{profile_name}' not found")

    cfg.active_profile = profile_name
    save_config(cfg)
    log_event(
        "ACTIVE_PROFILE_CHANGED",
        f"Active profile changed to '{profile_name}'",
        {"profile": profile_name},
    )


def apply_profile(profile_name: str) -> None:
    """
    High-level: load config, set active_profile, save config,
    and call sync_profile_to_windows_firewall(profile_name).

    UI or CLI should call this when the user selects a profile.
    """
    cfg = load_config()

    if profile_name not in cfg.profiles:
        raise ValueError(f"Profile '{profile_name}' not found")

    cfg.active_profile = profile_name
    save_config(cfg)

    log_event(
        "PROFILE_APPLIED",
        f"Profile '{profile_name}' applied",
        {"profile": profile_name},
    )

    # Enforce the profile via Windows Firewall
    sync_profile_to_windows_firewall(profile_name)


def set_app_action_in_profile(
    cfg: FullConfig,
    profile_name: str,
    exe_path: str,
    action: Action,
) -> None:
    """
    In the given profile, set app_rules[exe_path].action = action.
    If rule does not exist, create it with default direction='out'.

    Caller should then save_config(cfg) and (optionally) apply_profile(cfg.active_profile)
    to sync changes to Windows Firewall.
    """
    if profile_name not in cfg.profiles:
        raise ValueError(f"Profile '{profile_name}' not found")

    exe_path_resolved = str(Path(exe_path).resolve())
    profile = cfg.profiles[profile_name]

    rule = profile.app_rules.get(exe_path_resolved)
    if rule is None:
        rule = AppRule(
            app_exe_path=exe_path_resolved,
            action=action,
            direction="out",
            temporary_until=None,
        )
        profile.app_rules[exe_path_resolved] = rule
        change_type = "created"
    else:
        rule.action = action
        # When user explicitly sets rule, clear any previous temporary allowance
        rule.temporary_until = None
        change_type = "updated"

    log_event(
        "PROFILE_APP_RULE_CHANGED",
        f"Rule {change_type}: {action.upper()} {exe_path_resolved} in profile '{profile_name}'",
        {
            "profile": profile_name,
            "exe_path": exe_path_resolved,
            "action": action,
            "change_type": change_type,
        },
    )


# ---------------------------------------------------------------------------
# Temporary allow helper ("Why is this app not working?")
# ---------------------------------------------------------------------------

def set_temporary_allow_in_active_profile(
    exe_path: str,
    minutes: int = 60,
) -> None:
    """
    Mark a BLOCK rule for this app in the ACTIVE profile as temporarily allowed
    for 'minutes' minutes.

    Semantics:
      - The underlying rule.action remains "block".
      - temporary_until is set to now + minutes.
      - sync_profile_to_windows_firewall() treats this as ALLOW until expiry.
      - After expiry (next sync), it behaves as a normal block again.
    """
    cfg = load_config()
    profile = get_active_profile(cfg)
    exe_path_resolved = str(Path(exe_path).resolve())

    rule = profile.app_rules.get(exe_path_resolved)
    if rule is None or rule.action != "block":
        raise ValueError(
            f"App '{exe_path_resolved}' is not currently BLOCKED in active profile "
            f"'{profile.name}', so temporary allow does not apply."
        )

    until_dt = _dt.datetime.utcnow() + _dt.timedelta(minutes=minutes)
    until_str = until_dt.isoformat(timespec="seconds")
    rule.temporary_until = until_str
    save_config(cfg)

    log_event(
        "APP_TEMP_ALLOW_SET",
        f"Temporarily allowing {exe_path_resolved} in profile '{profile.name}'",
        {
            "profile": profile.name,
            "exe_path": exe_path_resolved,
            "temporary_until": until_str,
            "duration_minutes": minutes,
        },
    )

    # Re-apply profile so firewall immediately unblocks this app.
    sync_profile_to_windows_firewall(profile.name)


# ---------------------------------------------------------------------------
# "Why is this app not working?" backend helper
# ---------------------------------------------------------------------------

def explain_app_in_active_profile(exe_path: str) -> Dict[str, Any]:
    """
    Explain how the currently active profile treats the given exe_path.

    Returns a dict with keys:
      - exe_path
      - profile
      - profile_display_name
      - action           (effective: "allow" or "block", considering temporary_until)
      - direction        ("in", "out", "both") – if explicit rule, else "out"
      - temporary_until  (str or None, from the rule if any)
      - reason           (human-readable explanation)
    """
    cfg = load_config()
    profile = get_active_profile(cfg)
    exe_path_resolved = str(Path(exe_path).resolve())
    now = _dt.datetime.utcnow()

    explicit_rule = profile.app_rules.get(exe_path_resolved)

    if explicit_rule:
        effective_action: Action = explicit_rule.action
        direction = explicit_rule.direction
        temporary_until = explicit_rule.temporary_until
        temp_active = False

        # If there's a temporary_until on a BLOCK rule, and it's still in the future,
        # treat this as effectively ALLOW for now.
        if temporary_until and explicit_rule.action == "block":
            try:
                expiry = _dt.datetime.fromisoformat(temporary_until)
                if now < expiry:
                    effective_action = "allow"
                    temp_active = True
            except ValueError:
                # Ignore malformed timestamps; treat as normal block/allow
                pass

        if temp_active:
            reason = (
                f"This app would normally be BLOCKED by profile "
                f"'{profile.display_name}', but it is TEMPORARILY ALLOWED "
                f"until {temporary_until}."
            )
        else:
            reason = (
                f"Explicit rule in profile '{profile.display_name}': "
                f"{explicit_rule.action.upper()} ({explicit_rule.direction})"
            )

        explanation: Dict[str, Any] = {
            "exe_path": exe_path_resolved,
            "profile": profile.name,
            "profile_display_name": profile.display_name,
            "action": effective_action,
            "direction": direction,
            "temporary_until": temporary_until,
            "reason": reason,
        }
    else:
        # No explicit rule: fall back to default_action
        explanation = {
            "exe_path": exe_path_resolved,
            "profile": profile.name,
            "profile_display_name": profile.display_name,
            "action": profile.default_action,
            "direction": "out",
            "temporary_until": None,
            "reason": (
                f"No explicit rule in profile '{profile.display_name}'. "
                f"Using default_action='{profile.default_action}'."
            ),
        }

    # Log that someone asked for an explanation
    log_event(
        "APP_STATUS_EXPLAINED",
        f"Explained status for {exe_path_resolved} in profile '{profile.name}'",
        explanation,
    )

    return explanation


# ---------------------------------------------------------------------------
# Simple CLI for debug / manual testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Profile management / explanation test CLI (Member 1, Week 3)."
    )
    parser.add_argument(
        "profile",
        nargs="?",
        help="Profile name to apply (e.g. normal, public_wifi, focus). "
             "If omitted, no profile is changed.",
    )
    parser.add_argument(
        "--explain",
        metavar="EXE_PATH",
        help="Explain how the active profile treats this executable.",
    )
    parser.add_argument(
        "--temp-allow",
        metavar="EXE_PATH",
        help="Temporarily allow this executable for 60 minutes in the active profile.",
    )
    args = parser.parse_args()

    cfg = load_config()
    print("Existing profiles:", ", ".join(cfg.profiles.keys()))
    print("Active profile before:", cfg.active_profile)

    if args.profile:
        apply_profile(args.profile)
        cfg2 = load_config()
        print("Active profile after:", cfg2.active_profile)

    if args.explain:
        info = explain_app_in_active_profile(args.explain)
        print("\nExplanation:")
        for k, v in info.items():
            print(f"  {k}: {v}")

    if args.temp_allow:
        set_temporary_allow_in_active_profile(args.temp_allow, minutes=60)
        print(f"\nTemporary allow set for {args.temp_allow} in active profile.")