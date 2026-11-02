# 📡 Hotspot Zone – Captive Portal System

A complete captive portal and billing management system for Windows PC sharing internet via **Mobile Hotspot**. Built with Python, Flask, SQLite, and a MikroTik-style live interactive terminal dashboard using Rich.

---

## ✨ Features

- **MikroTik-style Interactive TUI**: Run everything in a single, flicker-free terminal dashboard.
- **DNS Redirection**: Pure-Python standard library UDP DNS spoofer intercepting client requests to portal host (`192.168.137.1`).
- **Windows Firewall Control**: Automatically blocks internet access for unapproved clients using native Windows `netsh advfirewall` commands.
- **Session & Billing Management**: Users select a duration package, pay via bKash/Nagad/Rocket, and submit their Transaction ID.
- **Approval Workflow**: Approve, reject, extend, or kick sessions directly from:
  - The live Terminal command line (`approve <id>`, `kick <id>`, `extend <id> <hours>`).
  - Web Admin Dashboard (`http://192.168.137.1:5000/admin`).
- **Automatic Expiry & Cutoff**: Monitors database timestamps and automatically disables internet access when time runs out.

---

## 📁 Repository Structure

```
├── run.py                 # All-in-one runner (DNS, Flask, Firewall monitor, and Rich TUI)
├── start_hotspot.bat      # One-click Admin launcher batch script
├── requirements.txt       # Dependencies
├── app.py                 # (Optional standalone) Flask server
├── dns_server.py          # (Optional standalone) DNS spoofer
├── network_manager.py     # (Optional standalone) Firewall session manager
├── templates/
│   ├── index.html         # Captive portal landing & payment page
│   ├── admin.html         # Web admin dashboard
│   ├── admin_login.html   # Admin login page
│   └── success.html       # Connection countdown & status
└── README.md
```

---

## 🚀 Quick Start (Windows)

### 1. Requirements & Installation
Ensure Python 3.10+ is installed. Clone this repository and install packages:

```bash
git clone <YOUR_REPO_URL>
cd "Hotspot Zone"
pip install -r requirements.txt
```

### 2. Enable Windows Mobile Hotspot
Go to: **Settings -> Network & Internet -> Mobile Hotspot -> Turn ON**.  
*(By default, Windows sets the hotspot gateway IP to `192.168.137.1`)*.

### 3. Run the System
Right-click on **`start_hotspot.bat`** and click **"Run as Administrator"**.

Alternatively, run via an elevated Command Prompt / PowerShell:
```cmd
python run.py
```

---

## ⌨️ Terminal Commands (In-Place)

While `run.py` is running, type commands into the terminal input box and press `Enter`:

| Command | Description | Example |
| :--- | :--- | :--- |
| `approve <id>` | Approves pending payment & unblocks internet for client | `approve 1` |
| `reject <id>` | Rejects pending payment transaction | `reject 2` |
| `kick <id>` | Immediately cuts off internet for active session | `kick 1` |
| `extend <id> <hours>` | Adds hours to an active session | `extend 1 2` |
| `sessions` | Lists all sessions in the database | `sessions` |
| `pending` | Lists all pending payments | `pending` |
| `quit` | Cleanly shuts down and removes all custom firewall rules | `quit` |

---

## 📱 Mobile Web Access

- **Client Portal**: `http://192.168.137.1:5000/` (Clients get redirected here automatically upon connecting to Wi-Fi)
- **Web Admin Panel**: `http://192.168.137.1:5000/admin`
  - **Username**: `admin`
  - **Password**: `admin1234` *(configurable inside `run.py`)*

---

## ⚙️ Configuration

In `run.py`, you can customize:
```python
PORTAL_IP      = "192.168.137.1"   # Hotspot IP
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234"       # Change this!
BKASH_NUMBER   = "01700-000000"    # Your merchant/personal bKash number
PLAN_PRICES    = {1: 10, 3: 25, 6: 45, 12: 80, 24: 140} # hours: BDT
```

---

## ⚠️ Notes & Disclaimer
- Must run as **Administrator** on Windows due to low-port binding (`UDP/53`) and Windows Firewall rule adjustments (`netsh`).
- Intended for personal hotspot sharing, local events, or learning environments.
