# firewall_assistant/firewall_win.py

from __future__ import annotations

import argparse
import ctypes
import subprocess
from pathlib import Path
from typing import List, Literal, Optional

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


# ---------------------------------------------------------------------------
# Core Week 1 functionality
# ---------------------------------------------------------------------------

def block_app(path: str, direction: Direction = "out") -> None:
    """
    Block an application's network access in the given direction using
    Windows Firewall via netsh.
    """
    exe_path = str(Path(path).resolve())

    if "WindowsApps" in exe_path:
        print("[WARNING] This looks like a Microsoft Store/UWP app under WindowsApps.")
        print("         Week 1 tool is focused on classic desktop .exe apps.")
        print("         Please test with something like C:\\Windows\\System32\\notepad.exe.")
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


def allow_app(path: str) -> None:
    """
    Allow an application's network access again by removing all FWAssist rules
    associated with that executable (by name pattern).
    """
    exe_path = str(Path(path).resolve())
    print(f"[INFO] Allowing app '{exe_path}' (removing FWAssist_* rules)")

    rule_names = _rule_names_for_exe(exe_path)

    removed_any = False
    for name in rule_names:
        try:
            _run_netsh(["delete", "rule", f"name={name}"])
            print(f"[OK] Deleted rule '{name}' (if it existed).")
            removed_any = True
        except RuntimeError as e:
            msg = str(e)
            if "No rules match the specified criteria" in msg:
                # Rule not present; ignore
                continue
            else:
                raise

    if not removed_any:
        print("[INFO] No FWAssist_* rules existed for this app. Nothing to remove.")


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
# Profile sync stub (Week 1)
# ---------------------------------------------------------------------------

def sync_profile_to_windows_firewall(
    profile_name: str,
    cfg_path: Optional[str] = None,
) -> None:
    """
    Week 1 stub.

    In later weeks, this will:
      - Load config (or use cfg_path)
      - Look at the profile's app_rules
      - Call block_app/allow_app as needed to enforce the profile.

    For now, it's a no-op (just prints) so that profiles.apply_profile()
    works without breaking imports.
    """
    msg = f"[stub] sync_profile_to_windows_firewall('{profile_name}'"
    if cfg_path is not None:
        msg += f", cfg_path='{cfg_path}'"
    msg += ") – not implemented yet"
    print(msg)


# ---------------------------------------------------------------------------
# CLI: python -m firewall_assistant.firewall_win ...
# ---------------------------------------------------------------------------

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Week 1 – Simple Windows Firewall control per application (FWAssist).\n"
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