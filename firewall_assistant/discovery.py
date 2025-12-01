# firewall_assistant/discovery.py

from __future__ import annotations

from pathlib import Path
from typing import List

import datetime as _dt

from .models import AppInfo, FullConfig

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]
    print("[discovery] WARNING: psutil is not installed. "
          "discover_active_apps() will return an empty list.")


def _now_iso() -> str:
    """Return current UTC time as ISO string (seconds precision)."""
    return _dt.datetime.utcnow().isoformat(timespec="seconds")


def discover_active_apps() -> List[AppInfo]:
    """
    Return a list of AppInfo for apps that currently have network activity
    (or had very recent activity).

    Implementation (Week 1):
      - Use psutil to get inet connections per process.
      - For each process with at least one inet connection, create an AppInfo.
      - De-duplicate by exe_path.
    """
    if psutil is None:
        return []

    apps_by_exe: dict[str, AppInfo] = {}
    now = _now_iso()

    try:
        # Iterate over all processes, asking only for basic info
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                conns = proc.connections(kind="inet")  # may raise AccessDenied/NoSuchProcess
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception as exc:
                print(f"[discovery] Error getting connections for pid={proc.pid}: {exc}")
                continue

            if not conns:
                # Skip processes that don't use the network at the moment
                continue

            raw_exe = proc.info.get("exe") or ""
            if not raw_exe:
                # Some system processes might not have a normal exe path
                continue

            exe_path = str(Path(raw_exe).resolve())
            name = proc.info.get("name") or Path(exe_path).name

            existing = apps_by_exe.get(exe_path)
            if existing is None:
                apps_by_exe[exe_path] = AppInfo(
                    exe_path=exe_path,
                    name=name,
                    tags=[],
                    last_seen=now,
                    pinned=False,
                )
            else:
                # If we've already seen this exe, just refresh last_seen
                existing.last_seen = now

    except Exception as exc:
        print(f"[discovery] Top-level error during discovery: {exc}")

    return list(apps_by_exe.values())


def merge_discovered_apps_into_config(cfg: FullConfig) -> None:
    """
    Take FullConfig, run discover_active_apps(), and:
      - Add any new exe_path to cfg.apps with basic info.
      - Update last_seen for known apps.

    Does NOT save to disk; caller must call save_config().
    """
    discovered = discover_active_apps()
    if not discovered:
        return

    for app in discovered:
        existing = cfg.apps.get(app.exe_path)

        if existing is None:
            # New app discovered: add as-is
            cfg.apps[app.exe_path] = app
        else:
            # Known app: update last_seen; keep existing custom name/tags/pinned
            existing.last_seen = app.last_seen or existing.last_seen
            # If the existing name is empty for some reason, fill it
            if not existing.name and app.name:
                existing.name = app.name


if __name__ == "__main__":
    # Simple self-test: discover and print apps
    apps = discover_active_apps()
    print(f"Discovered {len(apps)} active apps:")
    for a in apps:
        print(f"  {a.name} -> {a.exe_path} (last_seen={a.last_seen})")