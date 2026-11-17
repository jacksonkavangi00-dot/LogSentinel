
import argparse
import os
import pwd
import re
import time
from datetime import datetime

from database import initialize_database, save_incidents


AUDIT_LOG = "/var/log/audit/audit.log"
POLL_INTERVAL = 0.2
EVENT_FLUSH_DELAY = 0.75

EVENT_RULES = {
    "logsentinel_systemd": {
        "event": "Systemd Persistence Configuration Changed",
        "targets": ["/etc/systemd/system"],
    },
    "logsentinel_cron": {
        "event": "Cron Persistence Configuration Changed",
        "targets": [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/crontab",
        ],
    },
    "logsentinel_ssh_config": {
        "event": "SSH Server Configuration Changed",
        "targets": ["/etc/ssh/sshd_config"],
    },
    "logsentinel_accounts": {
        "event": "Account Security Files Modified",
        "targets": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
        ],
    },
}

AUDIT_ID = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
AUDIT_KEY = re.compile(r'\bkey="?(logsentinel_[a-z_]+)"?')
PATH_NAME = re.compile(r'\bname="([^"]+)"')
PATH_TYPE = re.compile(r"\bnametype=(\w+)")
SUCCESS = re.compile(r"\bsuccess=(yes|no)")
SYSCALL = re.compile(r"\bSYSCALL=([A-Za-z0-9_]+)")
COMMAND = re.compile(r'\bcomm="([^"]+)"')
EXECUTABLE = re.compile(r'\bexe="([^"]+)"')
AUID_NAME = re.compile(r'\bAUID="([^"]+)"')
AUID_NUMBER = re.compile(r"\bauid=(\d+)")
PROCTITLE = re.compile(r"\bproctitle=([0-9A-Fa-f]+)")


def get_username(records):
    for line in records:
        match = AUID_NAME.search(line)

        if match:
            name = match.group(1)

            if name not in ("unset", "4294967295"):
                return name

        match = AUID_NUMBER.search(line)

        if match:
            uid = int(match.group(1))

            if uid == 4294967295:
                continue

            try:
                return pwd.getpwuid(uid).pw_name
            except KeyError:
                return str(uid)

    return "unknown"


def decode_command(records):
    for line in records:
        match = PROCTITLE.search(line)

        if match:
            try:
                decoded = bytes.fromhex(match.group(1))
                return decoded.replace(
                    b"\x00", b" "
                ).decode("utf-8", errors="replace").strip()
            except ValueError:
                pass

    return ""


def path_matches_target(path, target):
    if target in ("/etc/systemd/system", "/etc/cron.d",
                  "/etc/cron.daily"):
        return path == target or path.startswith(target + "/")

    return path == target


def get_operation(nametype):
    operations = {
        "CREATE": "CREATE",
        "DELETE": "DELETE",
        "NORMAL": "MODIFY",
        "RENAME": "RENAME",
    }

    return operations.get(nametype, "CHANGE")


def analyze_audit_event(records):
    if not records:
        return []

    event_key = None

    for line in records:
        match = AUDIT_KEY.search(line)

        if match:
            event_key = match.group(1)
            break

    if event_key not in EVENT_RULES:
        return []

    rule = EVENT_RULES[event_key]

    syscall_line = next(
        (line for line in records if line.startswith("type=SYSCALL")),
        None,
    )

    if not syscall_line:
        return []

    success_match = SUCCESS.search(syscall_line)

    if not success_match or success_match.group(1) != "yes":
        return []

    affected_paths = []

    for line in records:
        if not line.startswith("type=PATH"):
            continue

        name_match = PATH_NAME.search(line)
        type_match = PATH_TYPE.search(line)

        if not name_match:
            continue

        path = name_match.group(1)
        nametype = type_match.group(1) if type_match else "NORMAL"

        if nametype == "PARENT":
            continue

        if any(
            path_matches_target(path, target)
            for target in rule["targets"]
        ):
            affected_paths.append((path, nametype))

    if not affected_paths:
        return []

    timestamp_match = AUDIT_ID.search(records[0])

    if not timestamp_match:
        return []

    try:
        event_timestamp = datetime.fromtimestamp(
            float(timestamp_match.group(1))
        ).astimezone().isoformat(timespec="milliseconds")
    except (ValueError, OSError, OverflowError):
        return []

    username = get_username(records)

    syscall_match = SYSCALL.search(syscall_line)
    command_match = COMMAND.search(syscall_line)
    executable_match = EXECUTABLE.search(syscall_line)

    syscall = syscall_match.group(1) if syscall_match else "unknown"
    command = command_match.group(1) if command_match else "unknown"
    executable = (
        executable_match.group(1) if executable_match else "unknown"
    )

    process_title = decode_command(records)

    incidents = []

    for path, nametype in affected_paths:
        operation = get_operation(nametype)

        service_details = (
            f"{operation} {path}; "
            f"command={command}; "
            f"syscall={syscall}; "
            f"exe={executable}"
        )

        if process_title:
            service_details += f"; process={process_title}"

        incidents.append({
            "timestamp": event_timestamp,
            "event": rule["event"],
            "username": username,
            "ip": None,
            "service": service_details,
            "severity": "HIGH",
            "attempts": None,
        })

    return incidents


def process_event(records):
    incidents = analyze_audit_event(records)

    if not incidents:
        return

    print(
        f"\n[AUDIT DETECTION] "
        f"{len(incidents)} persistence/security change(s)",
        flush=True,
    )

    for incident in incidents:
        print(
            f"  [HIGH] {incident['event']} | "
            f"User: {incident['username']}",
            flush=True,
        )
        print(f"         {incident['service']}", flush=True)

    save_incidents(incidents)


def monitor_audit_log(start_from_beginning=False):
    if not os.path.exists(AUDIT_LOG):
        raise FileNotFoundError(f"Audit log not found: {AUDIT_LOG}")

    initialize_database()

    audit_file = open(
        AUDIT_LOG,
        "r",
        encoding="utf-8",
        errors="replace",
    )

    if not start_from_beginning:
        audit_file.seek(0, os.SEEK_END)
        print("[INFO] Starting at the end of the existing audit log.")
    else:
        print("[INFO] Reading the audit log from the beginning.")

    pending_event_id = None
    pending_records = []
    last_record_time = None

    print("\nLogSentinel Audit Monitor is running.")
    print(f"Monitoring: {AUDIT_LOG}")
    print("Watching systemd, cron, SSH and account security files.")
    print("Press Ctrl+C to stop.\n", flush=True)

    try:
        while True:
            line = audit_file.readline()

            if line:
                match = AUDIT_ID.search(line)

                if not match:
                    continue

                event_id = match.group(0)

                if (
                    pending_event_id is not None
                    and event_id != pending_event_id
                ):
                    process_event(pending_records)
                    pending_records = []

                pending_event_id = event_id
                pending_records.append(line.strip())
                last_record_time = time.monotonic()
                continue

            # Flush a completed audit event after its records go quiet.
            if (
                pending_records
                and last_record_time is not None
                and time.monotonic() - last_record_time >= EVENT_FLUSH_DELAY
            ):
                process_event(pending_records)
                pending_records = []
                pending_event_id = None
                last_record_time = None

            # Handle audit log rotation and truncation.
            try:
                current_stat = os.stat(AUDIT_LOG)
                open_stat = os.fstat(audit_file.fileno())

                rotated = current_stat.st_ino != open_stat.st_ino
                truncated = current_stat.st_size < audit_file.tell()

                if rotated or truncated:
                    if pending_records:
                        process_event(pending_records)

                    audit_file.close()
                    audit_file = open(
                        AUDIT_LOG,
                        "r",
                        encoding="utf-8",
                        errors="replace",
                    )

                    pending_event_id = None
                    pending_records = []
                    last_record_time = None

                    print(
                        "[INFO] Audit log rotated or truncated.",
                        flush=True,
                    )

            except FileNotFoundError:
                time.sleep(POLL_INTERVAL)
                continue

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[INFO] Stopping audit monitor.")

        if pending_records:
            process_event(pending_records)

    finally:
        audit_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LogSentinel Linux audit event monitor"
    )

    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Read the existing audit log from the beginning",
    )

    args = parser.parse_args()

    monitor_audit_log(
        start_from_beginning=args.from_start
    )
