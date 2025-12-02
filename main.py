# main.py

"""
Entry point for the Firewall Assistant GUI.

Run:
    python main.py

Note:
    For firewall operations to succeed, run your terminal as
    "Run as administrator" on Windows.
"""

from firewall_assistant.ui.main_window import run

if __name__ == "__main__":
    run()