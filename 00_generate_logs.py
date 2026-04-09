# Databricks notebook source
# MAGIC %md
# MAGIC # Firewall Log Generator
# MAGIC Generates synthetic JSON firewall logs into a Unity Catalog volume.
# MAGIC 95% ALLOW (noise), 5% DENY/THREAT (signals).
# MAGIC Run this notebook on a schedule or ad-hoc to populate the volume before/during the DLT pipeline.

# COMMAND ----------

import json
import random
import uuid
from datetime import datetime, timedelta

# COMMAND ----------

# Configuration — see DEPLOY.md to change for your workspace
CATALOG = "lr_serverless_aws_us_catalog"
SCHEMA = "secops_demo"
VOLUME = "raw_logs"
VOLUME_PATH = f"/Volumes/{CATALOG}/{SCHEMA}/{VOLUME}"
NUM_BATCHES = 10
RECORDS_PER_BATCH = 500

# COMMAND ----------

INTERNAL_IPS = [f"10.0.{random.randint(1,50)}.{random.randint(1,254)}" for _ in range(200)]
EXTERNAL_IPS = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(500)]

THREAT_IPS = [
    "185.220.101.34", "45.155.205.233", "192.241.220.183",
    "89.248.167.131", "5.188.206.22", "194.26.29.113",
    "103.75.201.4", "162.247.74.74", "198.98.56.189",
    "91.240.118.172"
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
THREAT_PORTS = [22, 23, 445, 3389, 1433, 3306, 8080, 4444, 5555]
NORMAL_PORTS = [80, 443, 8443, 53, 123, 993, 587, 636]
THREAT_TYPES = [
    "PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "DATA_EXFIL",
    "MALWARE_DOWNLOAD", "DNS_TUNNEL", "LATERAL_MOVEMENT", "CREDENTIAL_STUFFING"
]
FIREWALL_NAMES = ["fw-edge-01", "fw-edge-02", "fw-core-01", "fw-dmz-01"]
ZONES = {"src": ["TRUST", "DMZ", "GUEST"], "dst": ["UNTRUST", "DMZ", "SERVERS"]}

# COMMAND ----------

def generate_log_record(timestamp):
    roll = random.random()

    if roll < 0.95:
        action = "ALLOW"
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        dst_port = random.choice(NORMAL_PORTS)
        threat_type = None
        severity = "INFO"
        bytes_sent = random.randint(64, 15000)
        bytes_recv = random.randint(64, 50000)
    elif roll < 0.975:
        action = "DENY"
        src_ip = random.choice(EXTERNAL_IPS + THREAT_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        dst_port = random.choice(THREAT_PORTS + NORMAL_PORTS)
        threat_type = None
        severity = "WARNING"
        bytes_sent = random.randint(40, 2000)
        bytes_recv = 0
    else:
        action = "THREAT"
        src_ip = random.choice(THREAT_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        dst_port = random.choice(THREAT_PORTS)
        threat_type = random.choice(THREAT_TYPES)
        severity = random.choice(["HIGH", "CRITICAL"])
        bytes_sent = random.randint(100, 100000)
        bytes_recv = random.randint(0, 50000)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp.isoformat() + "Z",
        "firewall": random.choice(FIREWALL_NAMES),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": random.choice(PROTOCOLS),
        "action": action,
        "threat_type": threat_type,
        "severity": severity,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "src_zone": random.choice(ZONES["src"]),
        "dst_zone": random.choice(ZONES["dst"]),
        "session_duration_ms": random.randint(10, 300000),
        "rule_name": f"rule-{random.randint(1,500):04d}"
    }

# COMMAND ----------

base_time = datetime.utcnow() - timedelta(hours=2)
total_records = 0
total_threats = 0
total_denies = 0

for batch in range(NUM_BATCHES):
    records = []
    for i in range(RECORDS_PER_BATCH):
        ts = base_time + timedelta(seconds=random.uniform(0, 7200))
        record = generate_log_record(ts)
        records.append(record)
        if record["action"] == "THREAT":
            total_threats += 1
        elif record["action"] == "DENY":
            total_denies += 1
        total_records += 1

    filename = f"{VOLUME_PATH}/firewall_batch_{batch:04d}_{uuid.uuid4().hex[:8]}.json"
    content = "\n".join(json.dumps(r) for r in records)
    dbutils.fs.put(filename, content, overwrite=True)
    print(f"Wrote batch {batch}: {len(records)} records -> {filename}")

print(f"\nTotal: {total_records} records | {total_threats} THREAT | {total_denies} DENY | {total_records - total_threats - total_denies} ALLOW")
