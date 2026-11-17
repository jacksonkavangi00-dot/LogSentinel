# LogSentinel

**Linux Security Monitoring and Incident Detection**

LogSentinel is a Python-based blue-team security monitoring application designed to detect suspicious authentication activity, account security changes, and potential Linux persistence modifications.

It combines authentication log monitoring, Linux Audit Framework (auditd) monitoring, SQLite incident storage, and a local web dashboard.

## Features

### Authentication Monitoring
- Detects failed SSH authentication attempts.
- Identifies successful SSH logins.
- Detects repeated authentication failures and potential brute-force activity.
- Identifies successful logins following repeated failures.
- Monitors selected sudo and account-management security events.

### Linux Audit Monitoring
- Monitors systemd service configuration changes.
- Monitors cron-related persistence locations.
- Detects SSH server configuration changes.
- Monitors `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow`.
- Records file operations, usernames, commands, and process information where available.

### Incident Management
- SQLite-based incident storage.
- Severity classification.
- Duplicate incident suppression.
- Historical incident records.

### Web Dashboard
- Incident statistics and severity summaries.
- Recent incident listings.
- CSV and JSON exports.
- Local dashboard at `http://127.0.0.1:8000`.

## Architecture

```text
Linux System
    |
    +---- Authentication Logs
    |          |
    |       monitor.py
    |          |
    +---- Linux Audit Framework
               |
          audit_monitor.py
               |
          Detection Engine
            analyzer.py
               |
           database.py
               |
           SQLite Database
               |
             app.py
               |
         Web Dashboard
               |
          CSV / JSON Export
```

## Technology Stack

- Python
- SQLite
- Linux Audit Framework (auditd)
- HTML and CSS
- Python HTTP server
- Fedora Linux

## Project Structure

```text
logsentinel/
├── analyzer.py
├── monitor.py
├── audit_monitor.py
├── database.py
├── reporter.py
├── app.py
├── run_logsentinel.sh
├── requirements.txt
├── data/
│   ├── bruteforce_test.log
│   └── sample_auth.log
├── reports/
└── README.md
```

## Installation

Tested on Fedora Linux.

Install Git, Python, and auditd. Ensure auditd is running and the required monitoring rules are configured.

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd logsentinel
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Make the launcher executable:

```bash
chmod +x run_logsentinel.sh
```

Start LogSentinel:

```bash
./run_logsentinel.sh
```

Open the dashboard:

`http://127.0.0.1:8000`

The launcher starts the authentication monitor, audit monitor, and dashboard together. Administrator privileges are requested for monitoring processes that require access to protected system logs.

## Testing

An example account-file monitoring test on an authorized test system:

```bash
sudo touch /etc/group
```

The audit monitor should detect the modification and save an incident.

Use the supplied sample authentication logs and controlled test events to validate authentication detections.

## Security Considerations

- Only monitor systems you own or are authorized to administer.
- Audit monitoring requires appropriate privileges.
- The dashboard is intended for local access.
- Do not publish databases, private logs, credentials, or sensitive system information.
- Review audit rules and log paths before deploying on another Linux distribution.

## Project Status

The core monitoring components, SQLite incident storage, unified launcher, and web dashboard have been implemented and tested on Fedora Linux.

Future improvements may include alert notifications, additional correlation rules, automated tests, and centralized log collection.

## Author

Developed as a hands-on Linux security monitoring and blue-team portfolio project.
