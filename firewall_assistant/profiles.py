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
# Helper for CLI: list rules for a profile
# ---------------------------------------------------------------------------

def _list_rules_for_profile(profile_name: str) -> None:
    """
    Print the rules (and effective status) for the given profile to stdout.
    Intended only for the __main__ CLI.
    """
    cfg = load_config()
    if profile_name not in cfg.profiles:
        print(f"Profile '{profile_name}' not found.")
        return

    profile = cfg.profiles[profile_name]
    now = _dt.datetime.utcnow()

    print(f"Profile: {profile.display_name} ({profile.name})")
    print(f"default_action = {profile.default_action}")
    print("Rules:")

    if not profile.app_rules:
        print("  (no explicit app rules)")
        return

    for exe_path, rule in profile.app_rules.items():
        eff_action: Action = rule.action
        temp_note = ""
        if rule.temporary_until and rule.action == "block":
            try:
                expiry = _dt.datetime.fromisoformat(rule.temporary_until)
                if now < expiry:
                    eff_action = "allow"
                    temp_note = f" (TEMP ALLOW until {rule.temporary_until})"
            except ValueError:
                pass

        print(f"  {exe_path}")
        print(f"    base_action   = {rule.action}")
        print(f"    direction     = {rule.direction}")
        print(f"    effective_act = {eff_action}{temp_note}")
        print(f"    temporary_until = {rule.temporary_until}")


# ---------------------------------------------------------------------------
# CLI for debug / manual testing (Week 4 backend tooling)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Profile management / explanation CLI for Firewall Assistant."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # apply PROFILE
    p_apply = subparsers.add_parser(
        "apply",
        help="Set active profile and sync Windows Firewall.",
    )
    p_apply.add_argument("profile", help="Profile name (e.g. normal, public_wifi, focus)")

    # explain EXE_PATH
    p_explain = subparsers.add_parser(
        "explain",
        help="Explain how the ACTIVE profile treats this executable.",
    )
    p_explain.add_argument("exe_path", help="Path to executable to explain")

    # temp-allow EXE_PATH [--minutes N]
    p_temp = subparsers.add_parser(
        "temp-allow",
        help="Temporarily allow a BLOCKED app in the ACTIVE profile.",
    )
    p_temp.add_argument("exe_path", help="Path to executable to temp-allow")
    p_temp.add_argument(
        "--minutes",
        type=int,
        default=60,
        help="Duration in minutes (default: 60)",
    )

    # list-rules PROFILE
    p_list = subparsers.add_parser(
        "list-rules",
        help="List all rules defined in a profile.",
    )
    p_list.add_argument("profile", help="Profile name")

    args = parser.parse_args()

    if args.command == "apply":
        print("Existing profiles:", ", ".join(load_config().profiles.keys()))
        apply_profile(args.profile)
        cfg2 = load_config()
        print("Active profile is now:", cfg2.active_profile)

    elif args.command == "explain":
        info = explain_app_in_active_profile(args.exe_path)
        print("Explanation:")
        for k, v in info.items():
            print(f"  {k}: {v}")

    elif args.command == "temp-allow":
        try:
            set_temporary_allow_in_active_profile(args.exe_path, minutes=args.minutes)
            print(f"Temporary allow set for {args.exe_path} in active profile for {args.minutes} minutes.")
        except Exception as exc:
            print(f"Error setting temporary allow: {exc}")

    elif args.command == "list-rules":
        _list_rules_for_profile(args.profile)