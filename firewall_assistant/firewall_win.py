# firewall_assistant/firewall_win.py

from __future__ import annotations

import argparse
import ctypes
import subprocess
from pathlib import Path
from typing import List, Literal, Optional
import datetime as _dt

from .activity_log import log_event

Direction = Literal["in", "out", "both"]

# Prefix for all rules created by our tool
FW_RULE_PREFIX = "FWAssist_"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """Return True if the current process has administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_netsh(args: List[str]) -> subprocess.CompletedProcess:
    """
    Run a 'netsh advfirewall firewall' command.

    Raises RuntimeError on non-zero exit code, with stderr/stdout included.
    """
    cmd = ["netsh", "advfirewall", "firewall"] + args

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        msg = stderr or stdout or "Unknown error from netsh"
        raise RuntimeError(
            f"netsh failed (code {result.returncode}): {' '.join(cmd)}\n{msg}"
        )

    return result


def _rule_names_for_exe(exe_path: str) -> list[str]:
    """
    Return the two possible FWAssist rule names for this exe:
      - FWAssist_BLOCK_OUT_<exe_name>
      - FWAssist_BLOCK_IN_<exe_name>
    """
    exe_name = Path(exe_path).name or exe_path
    return [
        f"{FW_RULE_PREFIX}BLOCK_OUT_{exe_name}",
        f"{FW_RULE_PREFIX}BLOCK_IN_{exe_name}",
    ]


def _list_all_fwassist_rule_names() -> list[str]:
    """
    Return all FWAssist_* rule names currently present in Windows Firewall.

    We do:
      - netsh advfirewall firewall show rule name=all
      - parse all 'Rule Name:' lines
      - keep only those starting with FW_RULE_PREFIX
    """
    try:
        result = _run_netsh(["show", "rule", "name=all"])
    except RuntimeError as e:
        msg = str(e)
        if "No rules match the specified criteria" in msg:
            return []
        raise

    stdout = result.stdout or ""
    lines = stdout.splitlines()

    names: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith("rule name:"):
            parts = s.split(":", 1)
            if len(parts) == 2:
                name = parts[1].strip()
                if name.startswith(FW_RULE_PREFIX):
                    names.append(name)

    # Deduplicate in case netsh outputs duplicates
    return sorted(set(names))


def _clear_all_fwassist_rules() -> None:
    """
    Delete all FWAssist_* rules globally.

    This is used when switching profiles so we don't leave stale rules
    from previous profiles.
    """
    names = _list_all_fwassist_rule_names()
    if not names:
        return

    for name in names:
        try:
            _run_netsh(["delete", "rule", f"name={name}"])
        except RuntimeError as e:
            msg = str(e)
            if "No rules match the specified criteria" in msg:
                continue
            else:
                raise

    # Log once after clearing
    log_event(
        "FWASSIST_RULES_CLEARED",
        f"Cleared {len(names)} FWAssist_* firewall rules",
        {"count": len(names), "rule_prefix": FW_RULE_PREFIX},
    )


# ---------------------------------------------------------------------------
# Core app-level rule operations
# ---------------------------------------------------------------------------

def block_app(path: str, direction: Direction = "out") -> None:
    """
    Block an application's network access in the given direction using
    Windows Firewall via netsh.
    """
    exe_path = str(Path(path).resolve())

    if "WindowsApps" in exe_path:
        print("[WARNING] This looks like a Microsoft Store/UWP app under WindowsApps.")
        print("         Current tool is focused on classic desktop .exe apps.")
        print("         Please test with something like C:\\Windows\\System32\\notepad.exe.")
        log_event(
            "APP_BLOCK_SKIPPED_WINDOWSAPPS",
            f"Skipped blocking UWP/Store app at {exe_path}",
            {"exe_path": exe_path},
        )
        return

    if direction == "both":
        block_app(exe_path, "in")
        block_app(exe_path, "out")
        return

    exe_name = Path(exe_path).name or exe_path
    rule_name = f"{FW_RULE_PREFIX}BLOCK_{direction.upper()}_{exe_name}"

    print(f"[INFO] Blocking app '{exe_path}' (direction={direction}) with rule '{rule_name}'")

    args = [
        "add",
        "rule",
        f"name={rule_name}",
        f"dir={direction}",
        "action=block",
        f"program={exe_path}",   # no inner quotes; subprocess handles spaces
        "enable=yes",
        "profile=any",           # Domain, Private, Public
    ]
    _run_netsh(args)
    print("[OK] Rule created.")

    # Log the change
    log_event(
        "APP_BLOCK_RULE_CREATED",
        f"Blocked {exe_path} ({direction})",
        {"exe_path": exe_path, "direction": direction, "rule_name": rule_name},
    )


def allow_app(path: str) -> None:
    """
    Allow an application's network access again by removing all FWAssist rules
    associated with that executable (by name pattern).
    """
    exe_path = str(Path(path).resolve())
    print(f"[INFO] Allowing app '{exe_path}' (removing FWAssist_* rules)")

    rule_names = _rule_names_for_exe(exe_path)

    removed_any = False
    actually_removed: list[str] = []
    for name in rule_names:
        try:
            _run_netsh(["delete", "rule", f"name={name}"])
            print(f"[OK] Deleted rule '{name}' (if it existed).")
            removed_any = True
            actually_removed.append(name)
        except RuntimeError as e:
            msg = str(e)
            if "No rules match the specified criteria" in msg:
                # Rule not present; ignore
                continue
            else:
                raise

    if not removed_any:
        print("[INFO] No FWAssist_* rules existed for this app. Nothing to remove.")
        log_event(
            "APP_ALLOW_NO_RULES",
            f"No FWAssist_* rules found to remove for {exe_path}",
            {"exe_path": exe_path},
        )
    else:
        log_event(
            "APP_RULES_REMOVED",
            f"Removed FWAssist rules for {exe_path}",
            {"exe_path": exe_path, "rules": actually_removed},
        )


def status_app(path: str) -> None:
    """
    Show FWAssist-related firewall rules that affect this executable.

    We only check for rules whose names follow our pattern:
      FWAssist_BLOCK_OUT_<exe_name>
      FWAssist_BLOCK_IN_<exe_name>
    """
    exe_path = str(Path(path).resolve())
    print(f"[INFO] Checking FWAssist rules for '{exe_path}'")

    rule_names = _rule_names_for_exe(exe_path)
    found_any = False

    for name in rule_names:
        try:
            result = _run_netsh(["show", "rule", f"name={name}"])
        except RuntimeError as e:
            msg = str(e)
            if "No rules match the specified criteria" in msg:
                # Rule not present
                continue
            else:
                raise

        stdout = (result.stdout or "").strip()
        if stdout:
            if not found_any:
                print("----- FWAssist rules for this app -----")
                found_any = True
            print(stdout)
            print("----------------------------------------")

    if not found_any:
        print("[INFO] No FWAssist_* rules found for this app.")


# ---------------------------------------------------------------------------
# Profile sync – aware of temporary_until
# ---------------------------------------------------------------------------

def sync_profile_to_windows_firewall(
    profile_name: str,
    cfg_path: Optional[str] = None,  # cfg_path unused; config module has global path
) -> None:
    """
    Enforce the given profile in Windows Firewall.

    Steps:
      1) Load config.json
      2) Clear all existing FWAssist_* rules
      3) For the selected profile:
           - For each app rule:
               * if action == "block": create a block rule (respecting direction),
                 UNLESS there is an active temporary_until, in which case allow.
               * if action == "allow": remove any FWAssist_* rules for that app
      4) If any temporary_until timestamps have expired or are invalid,
         clear them in config.
    """
    from .config import load_config, save_config

    cfg = load_config()

    if profile_name not in cfg.profiles:
        raise ValueError(f"Profile '{profile_name}' not found in config")

    profile = cfg.profiles[profile_name]

    print(f"[INFO] Syncing profile '{profile_name}' to Windows Firewall...")
    log_event(
        "PROFILE_SYNC_START",
        f"Syncing profile '{profile_name}' to Windows Firewall",
        {"profile": profile_name},
    )

    # 1) Clear all rules our tool has created before
    _clear_all_fwassist_rules()

    # 2) Apply rules for this profile
    now = _dt.datetime.utcnow()
    cfg_modified = False

    for exe_path, rule in profile.app_rules.items():
        exe_path_resolved = str(Path(exe_path).resolve())
        dir_value: Direction = rule.direction  # config parsing normalizes this

        # Determine effective action, considering temporary_until on block rules
        effective_action = rule.action
        temp_active = False

        if rule.temporary_until and rule.action == "block":
            try:
                expiry = _dt.datetime.fromisoformat(rule.temporary_until)
                if now < expiry:
                    # Temporarily allow: skip creating block rule
                    effective_action = "allow"
                    temp_active = True
                else:
                    # Temporary has expired; clear it
                    rule.temporary_until = None
                    cfg_modified = True
            except ValueError:
                # Invalid timestamp; clear it to avoid confusion
                rule.temporary_until = None
                cfg_modified = True

        if effective_action == "block":
            block_app(exe_path_resolved, direction=dir_value)
            log_event(
                "PROFILE_RULE_APPLIED",
                f"Profile '{profile_name}' blocking {exe_path_resolved} ({dir_value})",
                {
                    "profile": profile_name,
                    "exe_path": exe_path_resolved,
                    "action": "block",
                    "direction": dir_value,
                    "temporary_until": rule.temporary_until,
                },
            )
        elif effective_action == "allow":
            # This is either an explicit allow rule, or a temporary allow
            allow_app(exe_path_resolved)
            event_type = "PROFILE_RULE_APPLIED"
            message = f"Profile '{profile_name}' allowing {exe_path_resolved}"
            extra: dict = {
                "profile": profile_name,
                "exe_path": exe_path_resolved,
                "action": "allow",
                "base_action": rule.action,
                "temporary_until": rule.temporary_until,
            }
            if temp_active:
                event_type = "PROFILE_RULE_TEMP_ALLOW_IN_EFFECT"
                message = (
                    f"Profile '{profile_name}' TEMPORARILY ALLOWING "
                    f"{exe_path_resolved} until {rule.temporary_until}"
                )
            log_event(event_type, message, extra)
        else:
            # Should not happen (Action is Literal["allow","block"])
            continue

    # Save config if we modified any temporary_until (expired / invalid)
    if cfg_modified:
        save_config(cfg)

    print(f"[INFO] Profile '{profile_name}' sync complete.")
    log_event(
        "PROFILE_SYNC_DONE",
        f"Finished syncing profile '{profile_name}'",
        {"profile": profile_name},
    )


# ---------------------------------------------------------------------------
# CLI: python -m firewall_assistant.firewall_win ...
# ---------------------------------------------------------------------------

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Windows Firewall control per application (FWAssist).\n"
            "Run this as Administrator."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # block command
    p_block = subparsers.add_parser("block", help="Block an app's network access")
    p_block.add_argument("path", help="Full path to the EXE to block")
    p_block.add_argument(
        "--direction",
        choices=["in", "out", "both"],
        default="out",
        help="Direction to block (default: out)",
    )

    # allow command
    p_allow = subparsers.add_parser("allow", help="Allow an app's network access (remove FWAssist_* rules)")
    p_allow.add_argument("path", help="Full path to the EXE to allow (unblock)")

    # status command
    p_status = subparsers.add_parser("status", help="Show FWAssist rules affecting this app")
    p_status.add_argument("path", help="Full path to the EXE to check")

    args = parser.parse_args()

    if not is_admin():
        print("[WARNING] This process is NOT running as Administrator.")
        print("          Most firewall operations will FAIL.")
        print("          Please run your terminal as 'Run as administrator'.\n")

    try:
        if args.command == "block":
            block_app(args.path, direction=args.direction)
        elif args.command == "allow":
            allow_app(args.path)
        elif args.command == "status":
            status_app(args.path)
    except RuntimeError as e:
        print("[ERROR] Firewall operation failed:")
        print(e)


if __name__ == "__main__":
    _cli()