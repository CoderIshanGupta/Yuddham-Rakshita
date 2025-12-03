# Firewall Assistant for Windows

A small GUI tool to control which Windows applications can access the internet, built on top of the built‑in Windows Firewall. Instead of ports and protocols, you get:
- Per‑app **Allow / Block** controls  
- Simple profiles (**Normal / Public Wi‑Fi / Focus**)  
- A **“Why is this app not working?”** explanation  
- **Temporary allow (1 hour)** for blocked apps  

> ⚠️ This tool **modifies Windows Firewall rules** and must be run as **Administrator**.

---

## Features

- **Per‑application control**
  - Shows apps (name + path) that have recent network activity.
  - Mark each app as *Allowed* or *Blocked* in the active profile.
  - Rules are enforced via Windows Firewall (`netsh advfirewall firewall`).
- **Profiles**
  - **Normal** – default everyday profile.
  - **Public Wi‑Fi** – intended for stricter rules on untrusted networks.
  - **Focus** – blocks distracting apps while working.
  - One‑click profile switching; firewall rules are re‑applied.
- **“Why is this app not working?”**
  - For a selected app, shows:
    - Which profile is active.
    - Whether the app is effectively **ALLOW** or **BLOCK**.
    - Whether this comes from the profile default or an explicit rule.
    - Any active **temporary allow** and its expiry time.
- **Temporary Allow (1 hour)**
  - For a blocked app, temporarily allow it for 60 minutes without changing permanent profile rules.
- **Activity log**
  - Logs actions (profile changes, rule changes, errors) to `logs/activity.log`.
  - Recent events visible in the UI.

---

## Tech Stack
- **OS**: Windows 10 / 11  
- **Language**: Python 3  
- **UI**: Tkinter (standard library)  
- **Firewall integration**: Windows Firewall via `netsh advfirewall`  
- **Process discovery**: [`psutil`](https://pypi.org/project/psutil/)  
- **Config / Data**: JSON (`config.json`), custom dataclasses  

---

## Project Structure
```text
firewall_assistant/
│
├─ main.py                      # Entry point for the GUI app
│
├─ firewall_assistant/
│  ├─ __init__.py
│  ├─ models.py                 # Dataclasses (AppInfo, AppRule, ProfileConfig, FullConfig)
│  ├─ config.py                 # Load/save config.json
│  ├─ firewall_win.py           # Windows Firewall wrapper (netsh)
│  ├─ discovery.py              # Find apps with active network connections
│  ├─ profiles.py               # Profile logic, per‑app rules, temp allow, explanation
│  ├─ activity_log.py           # Append/read logs/activity.log
│  └─ ui/
│     ├─ __init__.py
│     └─ main_window.py         # Tkinter GUI
│
├─ config.json                  # Auto‑created main configuration
└─ logs/
   └─ activity.log              # Auto‑created activity log

```
---
## Installation
### Requirements
* **Windows 10** or **Windows 11**
* **Python 3.9+** (**3.10+** recommended)
* `psutil` Python package

---

### Steps
```bash
git clone <REPO_URL>
cd <REPO_FOLDER>
python -m venv .venv
.venv\Scripts\activate
pip install psutil
```
> "Important: run commands from a terminal started with “Run as administrator” (right‑click on Command Prompt / PowerShell)."

### Usage
From the project root (where `main.py` is):
```bash
python main.py
```

In the GUI
- **Refresh Apps:** Detect apps with current network activity and add them to the list.
- **Allow Selected / Block Selected:** Select one or more apps and update their status for the active profile.
- **Profiles (top):** Switch between **Normal**, **Public Wi-Fi**, and **Focus**. Firewall rules are updated each time you change profile.
- **Why not working?:** Select exactly one app → shows an explanation of why it’s allowed or blocked.
- **Temp Allow 1h:** For a blocked app → temporarily allow it for 60 minutes in the active profile.
- **Activity Log (right side):** View recent profile changes, rule changes, and errors logged by the app.
---

## 📄 License
[MIT License](LICENSE)
