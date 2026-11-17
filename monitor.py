
import argparse
import os
import time

from analyzer import LogSentinelAnalyzer
from database import initialize_database, save_incidents


POLL_INTERVAL = 2


def monitor_log(log_file, from_start=False):

    if not os.path.isfile(log_file):
        print(f"[ERROR] Log file not found: {log_file}")
        return

    initialize_database()

    analyzer = LogSentinelAnalyzer()

    try:
        stat = os.stat(log_file)
        previous_identity = (stat.st_dev, stat.st_ino)

        position = 0 if from_start else stat.st_size

        pending_text = ""

        print("\n========================================")
        print("       LOGSENTINEL REAL-TIME MONITOR")
        print("========================================")
        print(f"Monitoring: {os.path.abspath(log_file)}")
        print(f"Polling interval: {POLL_INTERVAL} seconds")

        if from_start:
            print("[MODE] Processing existing log contents.")
        else:
            print("[MODE] Waiting for new log entries.")

        print("[STATUS] Monitoring active. Press CTRL+C to stop.\n")

        while True:

            time.sleep(POLL_INTERVAL)

            try:
                current_stat = os.stat(log_file)

            except FileNotFoundError:
                print("[WARNING] Log file temporarily unavailable.")
                continue

            current_identity = (
                current_stat.st_dev,
                current_stat.st_ino
            )

            # Detect log rotation or file replacement.
            if current_identity != previous_identity:

                print("[WARNING] Log rotation detected.")

                previous_identity = current_identity
                position = 0
                pending_text = ""

            # Detect truncation.
            elif current_stat.st_size < position:

                print("[WARNING] Log truncation detected.")

                position = 0
                pending_text = ""

            if current_stat.st_size <= position:
                continue

            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as file:

                    file.seek(position)

                    new_content = file.read()

                    position = file.tell()

                if not new_content:
                    continue

                pending_text += new_content

                split_lines = pending_text.splitlines(keepends=True)

                complete_lines = []
                pending_text = ""

                for line in split_lines:

                    if line.endswith("\n") or line.endswith("\r"):
                        complete_lines.append(line)

                    else:
                        pending_text += line

                if not complete_lines:
                    continue

                print(
                    f"[MONITOR] Received {len(complete_lines)} "
                    "new log line(s)."
                )

                incidents = analyzer.process_lines(complete_lines)

                if incidents:

                    saved = save_incidents(incidents)

                    print(
                        f"[DETECTION] {len(incidents)} incident(s) "
                        f"detected; {saved} new incident(s) saved."
                    )

                    for incident in incidents:

                        print(
                            f"  [{incident['severity']}] "
                            f"{incident['event']} | "
                            f"User: {incident['username']} | "
                            f"IP: {incident['ip']}"
                        )

                else:
                    print("[MONITOR] No recognizable security events.")

            except OSError as error:
                print(f"[ERROR] Could not read log file: {error}")

    except KeyboardInterrupt:
        print("\n[MONITOR] Monitoring stopped by user.")

    except OSError as error:
        print(f"[ERROR] Monitoring failed: {error}")


def main():

    parser = argparse.ArgumentParser(
        description="LogSentinel real-time security log monitor"
    )

    parser.add_argument(
        "log_file",
        help="Log file to monitor"
    )

    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Process existing log entries before monitoring"
    )

    args = parser.parse_args()

    monitor_log(
        args.log_file,
        from_start=args.from_start
    )


if __name__ == "__main__":
    main()
