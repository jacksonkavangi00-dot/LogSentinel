
import csv
import os
from database import get_incidents

def export_csv():

    incidents = get_incidents()

    if not incidents:
        print("No incidents available for export.")
        return

    os.makedirs("reports", exist_ok=True)

    filename = "reports/incidents.csv"

    fields = [
        "id",
        "timestamp",
        "event",
        "username",
        "ip",
        "service",
        "severity",
        "attempts",
        "detected_at"
    ]

    with open(filename, "w", newline="") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(incidents)

    print("\nCSV report generated successfully!")
    print(f"Total records exported: {len(incidents)}")
    print(f"Location: {filename}")


if __name__ == "__main__":
    export_csv()
