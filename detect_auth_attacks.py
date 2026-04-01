import re
from collections import defaultdict

log_file = "/var/log/auth.log"

failed_logins = defaultdict(int)
successful_logins = []

with open(log_file, "r") as file:
    for line in file:
        # Detect failed logins
        if "Failed password" in line:
            match = re.search(r'from ([\d\.:]+)', line)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1

        # Detect successful logins
        if "Accepted password" in line:
            match = re.search(r'from ([\d\.:]+)', line)
            if match:
                ip = match.group(1)
                successful_logins.append(ip)

# Detection threshold
THRESHOLD = 5

print("=== Brute Force Detection ===")
for ip, count in failed_logins.items():
    if count >= THRESHOLD:
        print(f"[ALERT] Possible brute force from {ip} ({count} failed attempts)")

print("\n=== Successful Logins ===")
for ip in successful_logins:
    print(f"[INFO] Successful login from {ip}")
