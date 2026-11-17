
import re
import json
import sys
from datetime import datetime
from collections import defaultdict, deque

from database import initialize_database, save_incidents


# ==========================================
# LOGSENTINEL - SECURITY LOG ANALYZER
# ==========================================

SSH_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
)

PAM_FAILED = re.compile(
    r"pam_unix\(([^)]+)\): authentication failure.*?user=(\S+)"
)

SSH_SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"
)

# Sudo activity
SUDO_FAILED = re.compile(
    r"sudo(?:\[\d+\])?:.*?pam_unix\(sudo:auth\): authentication failure.*?user=(\S+)"
)

SUDO_SUCCESS = re.compile(
    r"sudo(?:\[\d+\])?:\s+(\S+)\s*:\s+TTY=.*?;\s*PWD=.*?;\s*USER=(\S+)\s*;\s*COMMAND=(.+)"
)

# Linux account management
USER_CREATED = re.compile(
    r"(?:useradd|adduser)(?:\[\d+\])?:\s+new user:\s+name=(\S+?)(?:,|$)"
)

USER_DELETED = re.compile(
    r"userdel(?:\[\d+\])?:\s+delete user ['\"]?([^'\"\s]+)"
)

# Privileged group membership changes
USERMOD_PRIVILEGED_GROUP = re.compile(
    r"usermod(?:\[\d+\])?:\s+add ['\"]?(\S+?)['\"]?\s+to group ['\"]?(sudo|wheel)['\"]?",
    re.IGNORECASE
)

GPASSWD_PRIVILEGED_GROUP = re.compile(
    r"gpasswd(?:\[\d+\])?:\s+user\s+(\S+)\s+added by\s+(\S+)\s+to group\s+(sudo|wheel)",
    re.IGNORECASE
)

BRUTE_FORCE_THRESHOLD = 5
DETECTION_WINDOW_SECONDS = 300


# ==========================================
# TIMESTAMP PARSER
# ==========================================

def parse_timestamp(line):
    try:
        timestamp = line[:15].strip()

        return datetime.strptime(
            f"{datetime.now().year} {timestamp}",
            "%Y %b %d %H:%M:%S"
        )

    except ValueError:
        return None


# ==========================================
# PERSISTENT DETECTION STATE
# ==========================================

class LogSentinelAnalyzer:

    def __init__(self):
        self.failed_attempts = defaultdict(deque)
        self.alerted_sources = set()

    def remove_expired_attempts(self, source, current_time):
        attempts = self.failed_attempts[source]

        while attempts:
            age = (current_time - attempts[0]).total_seconds()

            if age > DETECTION_WINDOW_SECONDS:
                attempts.popleft()
            else:
                break

        if not attempts:
            self.alerted_sources.discard(source)

    def process_lines(self, lines):

        incidents = []

        for line in lines:

            timestamp = line[:15].strip()
            event_time = parse_timestamp(line)

            # ==================================
            # SSH FAILED LOGIN
            # ==================================

            ssh_failed = SSH_FAILED.search(line)

            if ssh_failed:

                username, ip = ssh_failed.groups()

                incidents.append({
                    "timestamp": timestamp,
                    "event": "SSH Failed Login",
                    "username": username,
                    "ip": ip,
                    "service": "SSH",
                    "severity": "LOW"
                })

                if event_time is None:
                    continue

                source = f"SSH:{ip}"

                self.failed_attempts[source].append(event_time)
                self.remove_expired_attempts(source, event_time)

                attempts = self.failed_attempts[source]

                if (
                    len(attempts) >= BRUTE_FORCE_THRESHOLD
                    and source not in self.alerted_sources
                ):

                    incidents.append({
                        "timestamp": timestamp,
                        "event": "Possible Brute Force",
                        "username": "Multiple",
                        "ip": ip,
                        "service": "SSH",
                        "attempts": len(attempts),
                        "severity": "HIGH"
                    })

                    self.alerted_sources.add(source)

                continue

            # ==================================
            # SSH SUCCESSFUL LOGIN
            # ==================================

            ssh_success = SSH_SUCCESS.search(line)

            if ssh_success:

                username, ip = ssh_success.groups()

                incidents.append({
                    "timestamp": timestamp,
                    "event": "SSH Successful Login",
                    "username": username,
                    "ip": ip,
                    "service": "SSH",
                    "severity": "INFO"
                })

                if event_time is None:
                    continue

                source = f"SSH:{ip}"

                self.remove_expired_attempts(source, event_time)
                attempts = self.failed_attempts[source]

                if len(attempts) >= BRUTE_FORCE_THRESHOLD:

                    incidents.append({
                        "timestamp": timestamp,
                        "event": "Successful Login After Repeated Failures",
                        "username": username,
                        "ip": ip,
                        "service": "SSH",
                        "attempts": len(attempts),
                        "severity": "HIGH"
                    })

                    attempts.clear()
                    self.alerted_sources.discard(source)

                continue

            # ==================================
            # FAILED SUDO AUTHENTICATION
            # ==================================

            sudo_failed = SUDO_FAILED.search(line)

            if sudo_failed:

                username = sudo_failed.group(1)

                incidents.append({
                    "timestamp": timestamp,
                    "event": "Failed Sudo Authentication",
                    "username": username,
                    "ip": None,
                    "service": "sudo",
                    "severity": "MEDIUM"
                })

                continue

            # ==================================
            # SUCCESSFUL SUDO COMMAND
            # ==================================

            sudo_success = SUDO_SUCCESS.search(line)

            if sudo_success:

                username, target_user, command = sudo_success.groups()

                incidents.append({
                    "timestamp": timestamp,
                    "event": "Sudo Command Executed",
                    "username": username,
                    "ip": None,
                    "service": f"sudo as {target_user}",
                    "severity": "MEDIUM"
                })

                continue

            # ==================================
            # NEW USER CREATED
            # ==================================

            user_created = USER_CREATED.search(line)

            if user_created:

                username = user_created.group(1)

                incidents.append({
                    "timestamp": timestamp,
                    "event": "New User Created",
                    "username": username,
                    "ip": None,
                    "service": "user management",
                    "severity": "HIGH"
                })

                continue

            # ==================================
            # USER DELETED
            # ==================================

            user_deleted = USER_DELETED.search(line)

            if user_deleted:

                username = user_deleted.group(1)

                incidents.append({
                    "timestamp": timestamp,
                    "event": "User Account Deleted",
                    "username": username,
                    "ip": None,
                    "service": "user management",
                    "severity": "MEDIUM"
                })

                continue

            # ==================================
            # USER ADDED TO SUDO OR WHEEL
            # ==================================

            usermod_match = USERMOD_PRIVILEGED_GROUP.search(line)
            gpasswd_match = GPASSWD_PRIVILEGED_GROUP.search(line)

            if usermod_match:

                username, group = usermod_match.groups()

                incidents.append({
                    "timestamp": timestamp,
                    "event": "User Added to Privileged Group",
                    "username": username,
                    "ip": None,
                    "service": f"group: {group}",
                    "severity": "HIGH"
                })

                continue

            if gpasswd_match:

                username, actor, group = gpasswd_match.groups()

                incidents.append({
                    "timestamp": timestamp,
                    "event": "User Added to Privileged Group",
                    "username": username,
                    "ip": None,
                    "service": f"group: {group}",
                    "severity": "HIGH"
                })

                continue

            # ==================================
            # GENERAL PAM AUTHENTICATION FAILURE
            # ==================================

            pam_failed = PAM_FAILED.search(line)

            if pam_failed:

                service, username = pam_failed.groups()

                incidents.append({
                    "timestamp": timestamp,
                    "event": "PAM Authentication Failure",
                    "username": username,
                    "ip": None,
                    "service": service,
                    "severity": "LOW"
                })

                if event_time is None:
                    continue

                source = f"PAM:{service}:{username}"

                self.failed_attempts[source].append(event_time)
                self.remove_expired_attempts(source, event_time)

                attempts = self.failed_attempts[source]

                if (
                    len(attempts) >= BRUTE_FORCE_THRESHOLD
                    and source not in self.alerted_sources
                ):

                    incidents.append({
                        "timestamp": timestamp,
                        "event": "Possible Brute Force",
                        "username": username,
                        "ip": None,
                        "service": service,
                        "attempts": len(attempts),
                        "severity": "HIGH"
                    })

                    self.alerted_sources.add(source)

                continue

        return incidents


# ==========================================
# FILE ANALYSIS - BACKWARD COMPATIBILITY
# ==========================================

def analyze_logs(log_file):

    analyzer = LogSentinelAnalyzer()

    with open(log_file, "r", errors="replace") as file:
        return analyzer.process_lines(file.readlines())


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    log_file = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/sample_auth.log"
    )

    try:

        print("\n================================")
        print("       LOGSENTINEL")
        print("  SECURITY LOG ANALYZER")
        print("================================")

        print(f"\nAnalyzing: {log_file}")

        results = analyze_logs(log_file)

        initialize_database()
        save_incidents(results)

        print(f"\nTotal incidents detected: {len(results)}")

        for incident in results:

            print("\n--------------------------------")
            print(f"Event:    {incident['event']}")
            print(f"Username: {incident['username']}")
            print(f"IP:       {incident['ip']}")
            print(f"Severity: {incident['severity']}")

            if "attempts" in incident:
                print(f"Attempts: {incident['attempts']}")

        with open("reports/incidents.json", "w") as report:
            json.dump(results, report, indent=4)

        print("\nJSON report saved successfully.")
        print("SQLite database updated successfully.")
        print("\n================================\n")

    except FileNotFoundError:
        print(f"\n[ERROR] File not found: {log_file}")

    except PermissionError:
        print(f"\n[ERROR] Permission denied: {log_file}")


if __name__ == "__main__":
    main()
