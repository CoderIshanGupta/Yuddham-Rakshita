# firewall_assistant/ui/main_window.py

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Optional
import datetime as _dt

from ..config import load_config, save_config
from ..profiles import (
    apply_profile,
    set_app_action_in_profile,
    get_active_profile,
    explain_app_in_active_profile,
    set_temporary_allow_in_active_profile,
)
from ..discovery import merge_discovered_apps_into_config
from ..activity_log import get_recent_events, log_event
from ..models import FullConfig, AppInfo
from ..firewall_win import is_admin  # for admin status indicator


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Firewall Assistant")
        self.geometry("900x600")

        # Load config and determine active profile
        self.cfg: FullConfig = load_config()
        self.current_profile_name: str = self.cfg.active_profile

        # Track last time "Refresh Apps" was called (for status bar)
        self.last_apps_refresh: Optional[str] = None

        # Check admin status once
        self.is_admin: bool = is_admin()

        # Top-level layout frames
        self._build_layout()
        self._populate_profiles()
        self.refresh_apps_table()
        self.refresh_logs()
        self._update_admin_status_label()
        self._update_status_bar()

    # ------------------------------------------------------------------
    # Layout / UI construction
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        """Create all main frames and widgets."""
        # Root: vertical layout: profiles at top, main content, then status bar
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)  # main_frame expands
        self.rowconfigure(2, weight=0)  # status bar

        # Profile bar at top
        self.profile_frame = ttk.Frame(self, padding=(10, 5))
        self.profile_frame.grid(row=0, column=0, sticky="ew")
        self.profile_frame.columnconfigure(0, weight=1)

        self.profile_buttons_frame = ttk.Frame(self.profile_frame)
        self.profile_buttons_frame.grid(row=0, column=0, sticky="w")

        self.active_profile_label = ttk.Label(self.profile_frame, text="")
        self.active_profile_label.grid(row=0, column=1, sticky="e", padx=(20, 0))

        # Admin status label (second row in profile frame)
        self.admin_status_label = ttk.Label(self.profile_frame, text="")
        self.admin_status_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

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

        # Status bar at the bottom
        self.status_bar = ttk.Label(self, text="", anchor="w", padding=(10, 2))
        self.status_bar.grid(row=2, column=0, sticky="ew")

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
        self.apps_tree.column("status", width=180, anchor="center")

        vsb = ttk.Scrollbar(self.apps_frame, orient="vertical", command=self.apps_tree.yview)
        hsb = ttk.Scrollbar(self.apps_frame, orient="horizontal", command=self.apps_tree.xview)
        self.apps_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.apps_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Update buttons when selection changes
        self.apps_tree.bind("<<TreeviewSelect>>", lambda e: self._update_buttons_state())

        # Buttons under the tree
        btn_frame = ttk.Frame(self.apps_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        for col in range(5):
            btn_frame.columnconfigure(col, weight=1)

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

        self.explain_button = ttk.Button(
            btn_frame,
            text="Why not working?",
            command=self.explain_selected_app,
        )
        self.explain_button.grid(row=0, column=3, sticky="ew", padx=2)

        self.temp_allow_button = ttk.Button(
            btn_frame,
            text="Temp Allow 1h",
            command=self.temp_allow_selected_app,
        )
        self.temp_allow_button.grid(row=0, column=4, sticky="ew", padx=2)

        # Initial button states (no selection yet)
        self._update_buttons_state()

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

    def _update_admin_status_label(self) -> None:
        """Show if we are running as Administrator or not."""
        if self.is_admin:
            self.admin_status_label.config(
                text="Running as Administrator – firewall changes should work.",
                foreground="green",
            )
        else:
            self.admin_status_label.config(
                text="Not running as Administrator – firewall changes may FAIL.",
                foreground="red",
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
            self._update_status_bar()

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

        # Record last refresh time for status bar
        self.last_apps_refresh = _dt.datetime.now().strftime("%H:%M:%S")
        self._update_status_bar()

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

        now = _dt.datetime.utcnow()

        # Build rows
        apps_list: List[AppInfo] = sorted(
            self.cfg.apps.values(),
            key=lambda a: (a.name.lower(), a.exe_path.lower()),
        )

        for app in apps_list:
            exe_path = app.exe_path
            rule = profile.app_rules.get(exe_path)
            status_display: str

            if rule is not None:
                status = rule.action
                temp_active = False

                if rule.temporary_until and rule.action == "block":
                    try:
                        expiry = _dt.datetime.fromisoformat(rule.temporary_until)
                        if now < expiry:
                            # Temporarily allowed
                            temp_active = True
                    except ValueError:
                        pass

                if temp_active:
                    status_display = "ALLOW (TEMP)"
                else:
                    status_display = status.upper()
            else:
                # No explicit rule; use default_action
                status_display = profile.default_action.upper()

            self.apps_tree.insert(
                "",
                "end",
                values=(app.name, exe_path, status_display),
            )

        # After repopulating, no app is selected by default
        self._update_buttons_state()
        self._update_status_bar()

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
    # Button state + status bar
    # ------------------------------------------------------------------

    def _update_buttons_state(self) -> None:
        """
        Enable/disable buttons based on current selection in the apps tree.
        - Allow/Block: enabled if ≥1 app selected.
        - Why not working? / Temp Allow 1h: enabled if exactly 1 app selected.
        """
        selected = self.apps_tree.selection()
        count = len(selected)

        has_any = count >= 1
        single = count == 1

        # Helper to set button state
        def set_btn_state(btn: ttk.Button, enabled: bool) -> None:
            if enabled:
                btn.state(["!disabled"])
            else:
                btn.state(["disabled"])

        set_btn_state(self.allow_button, has_any)
        set_btn_state(self.block_button, has_any)
        set_btn_state(self.explain_button, single)
        set_btn_state(self.temp_allow_button, single)

    def _update_status_bar(self) -> None:
        """
        Update the status bar with active profile, number of apps, and last refresh time.
        """
        active_profile = self.current_profile_name
        apps_count = len(self.cfg.apps)
        last_refresh = self.last_apps_refresh or "n/a"

        text = (
            f"Profile: {active_profile} | "
            f"Apps listed: {apps_count} | "
            f"Last Refresh Apps: {last_refresh}"
        )
        self.status_bar.config(text=text)

    # ------------------------------------------------------------------
    # "Why not working?" + temporary allow
    # ------------------------------------------------------------------

    def _get_single_selected_exe_path(self) -> str | None:
        selected = self.apps_tree.selection()
        if len(selected) != 1:
            messagebox.showinfo(
                "Select an app",
                "Please select exactly one application in the list.",
            )
            return None

        values = self.apps_tree.item(selected[0], "values")
        if len(values) < 2:
            return None
        return values[1]

    def explain_selected_app(self) -> None:
        exe_path = self._get_single_selected_exe_path()
        if not exe_path:
            return

        try:
            info = explain_app_in_active_profile(exe_path)
        except Exception as exc:
            print(f"[UI] Failed to explain app '{exe_path}': {exc}")
            messagebox.showerror(
                "Error",
                f"Could not determine why this app is not working:\n{exc}",
            )
            return

        action = info.get("action", "")
        direction = info.get("direction", "")
        profile_name = info.get("profile", "")
        profile_display = info.get("profile_display_name", profile_name)
        temporary_until = info.get("temporary_until")
        reason = info.get("reason", "")

        msg_lines = [
            f"Profile: {profile_display} ({profile_name})",
            f"Effective action: {action.upper()} ({direction})",
        ]
        if temporary_until:
            msg_lines.append(f"Temporary until: {temporary_until}")
        msg_lines.append("")
        msg_lines.append("Reason:")
        msg_lines.append(reason)

        messagebox.showinfo(
            "App network status",
            "\n".join(msg_lines),
        )

    def temp_allow_selected_app(self) -> None:
        exe_path = self._get_single_selected_exe_path()
        if not exe_path:
            return

        # Confirm with the user
        if messagebox.askyesno(
            "Temporarily allow for 1 hour",
            "This will temporarily ALLOW this app's internet access "
            "for 1 hour in the current profile.\n\n"
            "After that, it will be blocked again when the profile is re-applied.\n\n"
            "Continue?",
        ):
            try:
                set_temporary_allow_in_active_profile(exe_path, minutes=60)
            except ValueError as exc:
                messagebox.showinfo(
                    "Cannot temporarily allow",
                    str(exc),
                )
                return
            except Exception as exc:
                print(f"[UI] Failed to set temporary allow for '{exe_path}': {exc}")
                messagebox.showerror(
                    "Error",
                    f"Failed to set temporary allow:\n{exc}",
                )
                return

            # Refresh view to show ALLOW (TEMP)
            self.cfg = load_config()
            self.refresh_apps_table()

            messagebox.showinfo(
                "Temporary allow set",
                "This app is now temporarily allowed for 1 hour in the active profile.",
            )

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