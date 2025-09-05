import json
import os
from datetime import datetime

LOG_FILE = "logs.json"

def log_attack(user_id, attack_type, status):
    log_entry = {
        "user_id": user_id,
        "attack": attack_type,
        "status": status,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    print(f"[AI Detection] Logged attack: {log_entry}")

# Example detections
log_attack("User123", "DDoS", "Detected")
log_attack("User456", "SQL Injection", "Detected")
