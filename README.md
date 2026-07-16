#                                 Certificate Manager                                                    

# Certificate Manager Tool

A Python-based automation tool for end-to-end SSL/TLS certificate lifecycle management — from generation to renewal and maintenance.

---

## Overview

The Certificate Manager Tool automates the full certificate management process so you never miss an expiry. It handles:

- Generating CSR (Certificate Signing Request) and key pairs
- Creating certificates based on user requirements
- Automatically renewing certificates before expiry
- Creating and managing keystores when necessary
- Triggering renewal automatically via scheduled scripts

For setup details, configuration help, or any queries — **contact Shankar N G**.

---

## Prerequisites

- **Python 3.13.7** is the version this application was built and tested with.
- If you are using a **different version of Python**, remove the version-specific suffixes present in the code where applicable.
- Ensure you have network access to the target certificate URLs.

---

## Installation & Setup

### Windows Server

```powershell
cd E:\PythonCertificates\CertificateManagerTool

python -m venv .venv

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

**Build the app package:**

```powershell
# If main.py uses a main() function:
Set-Content -Path app\main.py -Value "from main import main`nmain()"

# OR, if main.py runs directly without main():
Set-Content -Path app\main.py -Value "import main"

python -m zipapp app -o app.pyz
```

**Run the application:**

```powershell
python app.pyz
```

---

### Linux Server

```bash
cd ~/PythonCertificates/CertificateManagerTool

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

**Build the app package:**

```bash
# If main.py uses a main() function:
echo -e "from main import main\nmain()" > app/main.py

# OR, if main.py runs directly without main():
echo "import main" > app/main.py

python -m zipapp app -o app.pyz
```

**Run the application:**

```bash
python app.pyz
```

---

### Local Machine (VS Code)

```bash
cd ~/PythonCertificates/CertificateManagerTool

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

Run or debug directly through VS Code after activating the virtual environment.

---

## Automation Scripts

Automation scripts are included to **automatically trigger the application** when a certificate is nearing expiry. These can be scheduled to run periodically.

| Script | Platform | Scheduler |
|---|---|---|
| `certificatemanager.sh` | Linux | Cron Job |
| `certificatemanager.bat` | Windows | Task Scheduler |

### Scheduling on Linux (Cron)

```bash
crontab -e
```

Add a line such as:

```
0 8 * * * /path/to/certificatemanager.sh
```

This runs the script every day at 8:00 AM.

### Scheduling on Windows (Task Scheduler)

1. Open **Task Scheduler**
2. Create a new Basic Task
3. Set the trigger (e.g. daily)
4. Set the action to run `certificatemanager.bat`

> **Important:** Before running the scripts, read them carefully. Verify and update the **certificate threshold days** and **application paths** to match your environment.

---

##  Author

**Shankar N G**

For further details on setup, configuration, or usage — please contact Shankar directly.
