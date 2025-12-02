# firewall_assistant/ui/main_window.py

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List

from ..config import load_config, save_config
from ..profiles import apply_profile, set_app_action_in_profile, get_active_profile
from ..discovery import merge_discovered_apps_into_config
from ..activity_log import get_recent_events, log_event
from ..models import FullConfig, AppInfo


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Firewall Assistant")
        self.geometry("900x600")

        # Load config and determine active profile
        self.cfg: FullConfig = load_config()
        self.current_profile_name: str = self.cfg.active_profile

        # Top-level layout frames
        self._build_layout()
        self._populate_profiles()
        self.refresh_apps_table()
        self.refresh_logs()

    # ------------------------------------------------------------------
    # Layout / UI construction
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        """Create all main frames and widgets."""
        # Root: use a vertical layout: profiles at top, then main content
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Profile bar at top
        self.profile_frame = ttk.Frame(self, padding=(10, 5))
        self.profile_frame.grid(row=0, column=0, sticky="ew")
        self.profile_frame.columnconfigure(0, weight=1)

        self.profile_buttons_frame = ttk.Frame(self.profile_frame)
        self.profile_buttons_frame.grid(row=0, column=0, sticky="w")

        self.active_profile_label = ttk.Label(self.profile_frame, text="")
        self.active_profile_label.grid(row=0, column=1, sticky="e", padx=(20, 0))

        # Main content: split into left (apps) and right (logs)
        self.main_frame = ttk.Frame(self, padding=10)
        self.main_frame.grid(row=1, column=0, sticky="nsew")
        self.main_frame.columnconfigure(0, weight=3)
        self.main_frame.columnconfigure(1, weight=2)
        self.main_frame.rowconfigure(0, weight=1)

        # Left: Apps panel
        self.apps_frame = ttk.LabelFrame(self.main_frame, text="Applications", padding=5)
        self.apps_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.apps_frame.rowconfigure(0, weight=1)
        self.apps_frame.columnconfigure(0, weight=1)

        self._build_apps_panel()

        # Right: Logs panel
        self.logs_frame = ttk.LabelFrame(self.main_frame, text="Activity Log", padding=5)
        self.logs_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.logs_frame.rowconfigure(0, weight=1)
        self.logs_frame.columnconfigure(0, weight=1)

        self._build_logs_panel()

    def _build_apps_panel(self) -> None:
        """Create the apps Treeview and its buttons."""
        # Treeview with scrollbars
        columns = ("name", "exe_path", "status")
        self.apps_tree = ttk.Treeview(
            self.apps_frame,
            columns=columns,
            show="headings",
            selectmode="extended",
        )
        self.apps_tree.heading("name", text="Name")
        self.apps_tree.heading("exe_path", text="Executable Path")
        self.apps_tree.heading("status", text="Status (for current profile)")

        self.apps_tree.column("name", width=160, anchor="w")
        self.apps_tree.column("exe_path", width=420, anchor="w")
        self.apps_tree.column("status", width=140, anchor="center")

        vsb = ttk.Scrollbar(self.apps_frame, orient="vertical", command=self.apps_tree.yview)
        hsb = ttk.Scrollbar(self.apps_frame, orient="horizontal", command=self.apps_tree.xview)
        self.apps_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.apps_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Buttons under the tree
        btn_frame = ttk.Frame(self.apps_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)

        self.refresh_apps_button = ttk.Button(
            btn_frame,
            text="Refresh Apps",
            command=self.refresh_apps,
        )
        self.refresh_apps_button.grid(row=0, column=0, sticky="ew", padx=2)

        self.allow_button = ttk.Button(
            btn_frame,
            text="Allow Selected",
            command=self.allow_selected_apps,
        )
        self.allow_button.grid(row=0, column=1, sticky="ew", padx=2)

        self.block_button = ttk.Button(
            btn_frame,
            text="Block Selected",
            command=self.block_selected_apps,
        )
        self.block_button.grid(row=0, column=2, sticky="ew", padx=2)

    def _build_logs_panel(self) -> None:
        """Create the logs listbox and refresh button."""
        self.logs_list = tk.Listbox(self.logs_frame, height=10)
        vsb = ttk.Scrollbar(self.logs_frame, orient="vertical", command=self.logs_list.yview)
        self.logs_list.config(yscrollcommand=vsb.set)

        self.logs_list.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self.logs_frame.rowconfigure(0, weight=1)
        self.logs_frame.columnconfigure(0, weight=1)

        btn_frame = ttk.Frame(self.logs_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        btn_frame.columnconfigure(0, weight=1)

        self.refresh_logs_button = ttk.Button(
            btn_frame,
            text="Refresh Log",
            command=self.refresh_logs,
        )
        self.refresh_logs_button.grid(row=0, column=0, sticky="ew")

    # ------------------------------------------------------------------
    # Profiles UI
    # ------------------------------------------------------------------

    def _populate_profiles(self) -> None:
        """Create profile buttons from cfg.profiles and update label."""
        # Clear existing buttons (if any)
        for child in self.profile_buttons_frame.winfo_children():
            child.destroy()

        self.profile_var = tk.StringVar(value=self.current_profile_name)

        col = 0
        for profile_name, profile in self.cfg.profiles.items():
            btn = ttk.Radiobutton(
                self.profile_buttons_frame,
                text=profile.display_name,
                value=profile_name,
                variable=self.profile_var,
                command=lambda p=profile_name: self.on_profile_selected(p),
            )
            btn.grid(row=0, column=col, padx=(0, 8))
            col += 1

        self._update_active_profile_label()

    def _update_active_profile_label(self) -> None:
        """Update the label that shows the currently active profile."""
        profile = self.cfg.profiles.get(self.current_profile_name)
        if profile:
            self.active_profile_label.config(
                text=f"Active profile: {profile.display_name} ({self.current_profile_name})"
            )
        else:
            self.active_profile_label.config(
                text=f"Active profile: {self.current_profile_name}"
            )

    def on_profile_selected(self, profile_name: str) -> None:
        """
        Called when user clicks a profile button.
        Applies the profile (updates Windows Firewall) and reloads config.
        """
        try:
            apply_profile(profile_name)
            # Reload config so self.cfg reflects any changes
            self.cfg = load_config()
            self.current_profile_name = self.cfg.active_profile
            self.profile_var.set(self.current_profile_name)
            self._update_active_profile_label()
            self.refresh_apps_table()

            log_event(
                "PROFILE_APPLIED",
                f"Applied profile '{profile_name}'",
                {"profile": profile_name},
            )
        except Exception as exc:
            print(f"[UI] Failed to apply profile '{profile_name}': {exc}")
            log_event(
                "ERROR",
                f"Failed to apply profile '{profile_name}'",
                {"profile": profile_name, "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Apps handling
    # ------------------------------------------------------------------

    def refresh_apps(self) -> None:
        """
        Discover active apps, merge into cfg, save, and update UI list.
        """
        merge_discovered_apps_into_config(self.cfg)
        save_config(self.cfg)
        self.refresh_apps_table()

        log_event("APPS_REFRESHED", "Discovered and merged active apps", {})

    def refresh_apps_table(self) -> None:
        """
        Rebuild the Treeview rows from cfg.apps for the current profile.
        """
        # Clear existing items
        for item in self.apps_tree.get_children():
            self.apps_tree.delete(item)

        # Determine active profile config
        profile = self.cfg.profiles.get(self.current_profile_name)
        if profile is None:
            # Fallback: try to restore active profile
            profile = get_active_profile(self.cfg)

        # Build rows
        # Sort by app name for nicer view
        apps_list: List[AppInfo] = sorted(
            self.cfg.apps.values(),
            key=lambda a: (a.name.lower(), a.exe_path.lower()),
        )

        for app in apps_list:
            exe_path = app.exe_path
            rule = profile.app_rules.get(exe_path)
            if rule is not None:
                status = rule.action  # "allow" or "block"
            else:
                # For now, unknown apps follow default_action in UI only.
                status = profile.default_action

            self.apps_tree.insert(
                "",
                "end",
                values=(app.name, exe_path, status.upper()),
            )

    def _change_selected_apps_action(self, action: str) -> None:
        """
        Helper to set allow/block for all selected apps in the current profile.
        """
        if self.current_profile_name not in self.cfg.profiles:
            print(f"[UI] Current profile '{self.current_profile_name}' not found")
            return

        selected = self.apps_tree.selection()
        if not selected:
            return

        profile_name = self.current_profile_name
        exe_paths_changed: List[str] = []

        for item_id in selected:
            values = self.apps_tree.item(item_id, "values")
            if len(values) < 2:
                continue
            exe_path = values[1]
            try:
                set_app_action_in_profile(self.cfg, profile_name, exe_path, action)  # type: ignore[arg-type]
                exe_paths_changed.append(exe_path)
            except Exception as exc:
                print(f"[UI] Failed to set {action} for {exe_path}: {exc}")

        if not exe_paths_changed:
            return

        # Persist and apply profile (updates Windows Firewall)
        save_config(self.cfg)
        try:
            apply_profile(profile_name)
        except Exception as exc:
            print(f"[UI] Failed to apply profile '{profile_name}' after app rule changes: {exc}")
            log_event(
                "ERROR",
                f"Failed to apply profile '{profile_name}' after app rule changes",
                {"profile": profile_name, "error": str(exc)},
            )

        # Refresh UI
        self.refresh_apps_table()

        log_event(
            "APP_RULE_CHANGED",
            f"Set {action.upper()} for {len(exe_paths_changed)} app(s) in profile '{profile_name}'",
            {"profile": profile_name, "action": action, "apps": exe_paths_changed},
        )

    def allow_selected_apps(self) -> None:
        """Allow selected apps (for current profile)."""
        self._change_selected_apps_action("allow")

    def block_selected_apps(self) -> None:
        """Block selected apps (for current profile)."""
        self._change_selected_apps_action("block")

    # ------------------------------------------------------------------
    # Logs handling
    # ------------------------------------------------------------------

    def refresh_logs(self) -> None:
        """
        Reload logs and show them in the listbox.
        """
        events = get_recent_events(limit=200)
        self.logs_list.delete(0, tk.END)

        for evt in events:
            ts = evt.get("timestamp", "")
            etype = evt.get("event_type", "")
            msg = evt.get("message", "")
            line = f"{ts} [{etype}] {msg}"
            self.logs_list.insert(tk.END, line)


def run() -> None:
    app = MainWindow()
    app.mainloop()