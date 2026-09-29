import csv
from collections import defaultdict, deque
from datetime import datetime

LOG_FILE = "sample_logs.csv"

def load_logs(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def detect(logs):
    alerts = []
    failures = defaultdict(deque)

    for row in logs:
        ts = datetime.fromisoformat(row["timestamp"])
        key = (row["user"], row["src_ip"])

        if row["event"] == "login_failed":
            failures[key].append(ts)
            while failures[key] and (ts - failures[key][0]).total_seconds() > 120:
                failures[key].popleft()

            if len(failures[key]) >= 4:
                alerts.append({
                    "severity": "HIGH",
                    "rule": "Brute-force threshold",
                    "user": row["user"],
                    "src_ip": row["src_ip"],
                    "timestamp": row["timestamp"],
                    "reason": f"{len(failures[key])} failed logins within 120 seconds"
                })

        elif row["event"] == "login_success":
            recent = failures.get(key, deque())
            if len(recent) >= 3:
                alerts.append({
                    "severity": "CRITICAL",
                    "rule": "Success after repeated failures",
                    "user": row["user"],
                    "src_ip": row["src_ip"],
                    "timestamp": row["timestamp"],
                    "reason": f"Successful login after {len(recent)} recent failures"
                })

            if ts.hour < 6 or ts.hour >= 22:
                alerts.append({
                    "severity": "MEDIUM",
                    "rule": "Off-hours privileged/authentication activity",
                    "user": row["user"],
                    "src_ip": row["src_ip"],
                    "timestamp": row["timestamp"],
                    "reason": f"Successful authentication at {ts.strftime('%H:%M')}"
                })

        elif row["event"] == "process_start" and row["process"].lower() == "powershell.exe":
            alerts.append({
                "severity": "MEDIUM",
                "rule": "PowerShell execution",
                "user": row["user"],
                "src_ip": row["src_ip"],
                "timestamp": row["timestamp"],
                "reason": f"PowerShell started on {row['host']}"
            })

    return alerts

if __name__ == "__main__":
    alerts = detect(load_logs(LOG_FILE))
    print("Mini SOC Investigation Lab")
    print("=" * 28)
    for a in alerts:
        print(f"[{a['severity']}] {a['rule']} | {a['user']} | {a['src_ip']} | {a['reason']}")
    print(f"\nTotal alerts: {len(alerts)}")
