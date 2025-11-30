# firewall_assistant/ui/main_window.py

from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from typing import List
from ..config import load_config, save_config
from ..profiles import apply_profile, set_app_action_in_profile
from ..discovery import discover_active_apps, merge_discovered_apps_into_config
from ..activity_log import get_recent_events, log_event
from ..models import FullConfig, AppInfo


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Assistant")
        self.cfg: FullConfig = load_config()

        # TODO: build UI widgets (profile buttons, app table, log panel)
        # and bind them to methods below.

    def refresh_apps(self):
        """
        Discover active apps, merge into cfg, save, and update UI list.
        """
        merge_discovered_apps_into_config(self.cfg)
        save_config(self.cfg)
        # TODO: update list widget

    def on_profile_selected(self, profile_name: str):
        """
        Called when user clicks a profile button.
        """
        apply_profile(profile_name)
        log_event("PROFILE_APPLIED", f"Applied profile {profile_name}", {"profile": profile_name})
        # TODO: update status in UI

    def on_app_toggle(self, exe_path: str, new_action: str, profile_name: str):
        """
        Called when user toggles an app allow/block in the UI.
        """
        set_app_action_in_profile(self.cfg, profile_name, exe_path, new_action)  # updates cfg
        save_config(self.cfg)
        # Optionally re-sync current profile to firewall:
        apply_profile(self.cfg.active_profile)
        log_event("APP_RULE_CHANGED", f"{new_action.upper()} for {exe_path}",
                  {"exe_path": exe_path, "profile": profile_name, "action": new_action})

    def refresh_logs(self):
        """
        Reload logs and show in UI.
        """
        events = get_recent_events(limit=100)
        # TODO: update log list widget with events


def run():
    app = MainWindow()
    app.mainloop()