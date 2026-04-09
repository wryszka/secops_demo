# Databricks notebook source
# MAGIC %md
# MAGIC # RAG-Grounded Triage — SOC Runbook via Vector Search
# MAGIC The AI triage agent grounds its recommendations in **your company's actual
# MAGIC Incident Response Runbook** using Retrieval-Augmented Generation.
# MAGIC
# MAGIC This notebook creates the runbook content, chunks it into a Delta table,
# MAGIC and creates a Vector Search index with managed embeddings (GTE-Large).
# MAGIC
# MAGIC ---
# MAGIC **About this demo:** This is not a Databricks product. It is a working demonstration built on the Databricks platform
# MAGIC using Vector Search, Foundation Model APIs, and Unity Catalog. The SOC runbook content is illustrative and should not
# MAGIC be relied upon for actual incident response. Source code: [github.com/wryszka/secops_demo](https://github.com/wryszka/secops_demo)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Create the SOC Runbook as structured data
# MAGIC In production this would be ingested from a PDF/Confluence page. For the demo
# MAGIC we create it directly as a Delta table with section-level chunks.

# COMMAND ----------

CATALOG = "lr_serverless_aws_us_catalog"
SCHEMA = "secops_demo"

runbook_sections = [
    {
        "section_id": "1.1",
        "title": "Incident Classification",
        "content": "All security incidents must be classified within 15 minutes of detection. Use the following severity matrix: P1 (Critical) — active data exfiltration, ransomware execution, or domain admin compromise. P2 (High) — successful brute force, lateral movement detected, or C2 beacon confirmed. P3 (Medium) — port scanning from known threat IPs, repeated failed logins, or policy violations. P4 (Low) — single blocked connection attempts, informational alerts. Escalation: P1 requires immediate CISO notification and War Room activation. P2 requires SOC Lead notification within 30 minutes."
    },
    {
        "section_id": "2.1",
        "title": "Brute Force / Credential Stuffing Response",
        "content": "When repeated SSH or RDP failures are detected from a single source IP: (1) Immediately block the source IP on the perimeter firewall using the Palo Alto CLI: 'set address BLOCKED_<IP> ip-netmask <IP>/32' followed by adding it to the Block-Inbound address group. (2) Check if any authentication succeeded from that IP in the last 24 hours — if yes, treat as P1 compromise and force password reset for all affected accounts. (3) Isolate any endpoint that accepted a connection from the source IP using CrowdStrike: 'falconctl -s --cid=<CID> --rfm=true'. (4) Preserve forensic evidence by taking a memory dump before reimaging. (5) File a threat intelligence report with the IP, timestamps, and targeted accounts."
    },
    {
        "section_id": "2.2",
        "title": "C2 Beacon / Command and Control Response",
        "content": "When a C2 beacon is confirmed: (1) DO NOT alert the attacker — do not block the C2 domain immediately. (2) Identify all hosts communicating with the C2 infrastructure by querying DNS logs and firewall session data for the last 30 days. (3) Map the blast radius: which accounts, systems, and data stores were accessible from compromised hosts? (4) Coordinate with Legal before taking containment action if the attacker may have accessed PII or regulated data. (5) Execute containment in a single coordinated action: simultaneously isolate all affected hosts, block all C2 indicators (IPs, domains, JA3 hashes) at the perimeter, and revoke all credentials used from compromised hosts. (6) Deploy network forensics capture on the C2 communication channel before blocking to collect IOCs."
    },
    {
        "section_id": "2.3",
        "title": "Data Exfiltration Response",
        "content": "When data exfiltration is detected (large outbound transfers, DNS tunneling, or unusual upload patterns): (1) Immediately rate-limit the source host's outbound bandwidth to 1 Mbps to slow exfiltration without alerting the attacker that you've detected them. (2) Capture and log all traffic from the affected host using a SPAN port or network TAP. (3) Identify what data is being exfiltrated by examining the destination, protocol, and volume. (4) Notify the Data Protection Officer within 1 hour if PII or regulated data may be involved — GDPR requires 72-hour breach notification. (5) Block the exfiltration channel only after evidence preservation is complete. (6) Conduct a full review of the compromised account's access history for the last 90 days."
    },
    {
        "section_id": "2.4",
        "title": "Port Scanning / Reconnaissance Response",
        "content": "When port scanning is detected from an external IP: (1) Verify the source is not an authorized penetration test — check the approved pentest schedule in ServiceNow. (2) If unauthorized, add the source IP to the 24-hour temporary block list on the perimeter firewall. (3) Review which ports responded — any unexpected open ports indicate a misconfiguration that must be remediated immediately regardless of the scan source. (4) If the scanning IP is from a known threat intelligence feed (e.g., Tor exit node, known botnet), escalate to P3 and add to the permanent block list. (5) Check if the same IP appears in the low_cost_archive — previous ALLOW traffic from a now-scanning IP may indicate prior reconnaissance."
    },
    {
        "section_id": "2.5",
        "title": "Malware Download / Execution Response",
        "content": "When a malware download or execution is detected: (1) Immediately isolate the host from the network using CrowdStrike host isolation or by disabling the network adapter via EDR. (2) Do NOT power off the host — volatile memory may contain decryption keys or C2 configuration. (3) Capture a memory dump using WinPMEM or similar tool. (4) Submit the malware sample to the internal sandbox and to VirusTotal (if not sensitive). (5) Check if the download URL or hash appears on other hosts — use the endpoint_logs table and ai_query() to classify similar commands across the fleet. (6) If ransomware: immediately disconnect all network shares, check backup integrity, and activate the Business Continuity Plan."
    },
    {
        "section_id": "2.6",
        "title": "Lateral Movement Response",
        "content": "When lateral movement is detected (pass-the-hash, RDP pivoting, WMI/PSExec execution): (1) Map the full attack path: source host -> compromised credential -> target hosts. Query both firewall logs and endpoint_logs to build the timeline. (2) Disable the compromised account(s) immediately in Active Directory. (3) Isolate all hosts in the attack chain, not just the latest target. (4) Check for persistence mechanisms on each compromised host: scheduled tasks, new services, registry run keys, WMI subscriptions. (5) Reset the Kerberos KRBTGT password twice if domain admin credentials were compromised (Golden Ticket mitigation). (6) Deploy enhanced monitoring on all hosts that were accessible from the compromised accounts for the next 30 days."
    },
    {
        "section_id": "3.1",
        "title": "Evidence Preservation Requirements",
        "content": "Before any remediation action, the following evidence MUST be preserved: (1) Full packet capture of the incident timeframe (minimum: 1 hour before first indicator to current time). (2) Memory dump of all affected hosts. (3) Disk image or forensic triage package from the initial infection vector. (4) All relevant log sources: firewall, DNS, proxy, EDR, authentication, cloud audit trails. (5) Screenshots of any attacker-created artifacts (files, scheduled tasks, registry keys). Chain of custody must be maintained — all evidence must be hashed (SHA-256) and logged in the Evidence Tracker. Do not modify, delete, or reimage any affected system until evidence preservation is confirmed by the Forensics Lead."
    },
    {
        "section_id": "4.1",
        "title": "Notification Matrix",
        "content": "P1 incidents: CISO (immediate), Legal (within 1 hour), CEO (within 2 hours if data breach confirmed), affected business unit leaders (within 4 hours), cyber insurance carrier (within 24 hours). P2 incidents: SOC Lead (within 30 minutes), CISO (within 2 hours), affected system owners (within 4 hours). P3/P4 incidents: SOC Lead (next daily standup), included in weekly security report. All external notifications (regulators, customers, law enforcement) require Legal approval. GDPR-relevant breaches: DPO within 1 hour, supervisory authority within 72 hours, affected individuals without undue delay if high risk."
    },
    {
        "section_id": "5.1",
        "title": "Firewall Block Procedures",
        "content": "Palo Alto: To block an IP, use the CLI: 'set address BLOCK_<IP> ip-netmask <IP>/32', then 'set address-group Blocked-IPs static BLOCK_<IP>', then 'commit'. To verify: 'show address BLOCK_<IP>'. For emergency blocks during P1 incidents, use the 'Emergency-Block' policy which is pre-positioned at the top of the security rulebase. Google SecOps SOAR: To trigger an automated block, POST to the webhook endpoint with payload: {\"action\": \"block_ip\", \"ip\": \"<IP>\", \"duration\": \"24h\", \"reason\": \"<incident-id>\", \"source\": \"soc-analyst\"}. For DNS blocks, update the sinkhole list via the DNS Security profile."
    }
]

# COMMAND ----------

from pyspark.sql import Row

rows = [Row(
    section_id=s["section_id"],
    title=s["title"],
    content=s["content"]
) for s in runbook_sections]

df = spark.createDataFrame(rows)
df.write.mode("overwrite").saveAsTable(f"{CATALOG}.{SCHEMA}.soc_runbook_chunks")
print(f"Created {CATALOG}.{SCHEMA}.soc_runbook_chunks with {len(rows)} sections")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Enable Change Data Feed and create Vector Search Index
# MAGIC Vector Search with **managed embeddings** — Databricks automatically computes
# MAGIC embeddings using GTE-Large, no manual embedding step needed. The index accepts
# MAGIC plain-text queries and handles vectorization internally.

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE lr_serverless_aws_us_catalog.secops_demo.soc_runbook_chunks
# MAGIC SET TBLPROPERTIES (delta.enableChangeDataFeed = true);

# COMMAND ----------

import requests, time

VS_ENDPOINT = "ka-04bfe483-vs-endpoint"
INDEX_NAME = f"{CATALOG}.{SCHEMA}.soc_runbook_vs_index"
SOURCE_TABLE = f"{CATALOG}.{SCHEMA}.soc_runbook_chunks"

host = spark.conf.get("spark.databricks.workspaceUrl")
token = dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiToken().get()
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Delete existing index if present
requests.delete(f"https://{host}/api/2.0/vector-search/indexes/{INDEX_NAME}", headers=headers)
time.sleep(5)

# Create Delta Sync index with managed embeddings (GTE-Large)
resp = requests.post(
    f"https://{host}/api/2.0/vector-search/indexes",
    headers=headers,
    json={
        "name": INDEX_NAME,
        "endpoint_name": VS_ENDPOINT,
        "primary_key": "section_id",
        "index_type": "DELTA_SYNC",
        "delta_sync_index_spec": {
            "source_table": SOURCE_TABLE,
            "embedding_source_columns": [
                {"name": "content", "embedding_model_endpoint_name": "databricks-gte-large-en"}
            ],
            "pipeline_type": "TRIGGERED",
            "columns_to_sync": ["section_id", "title", "content"],
        },
    },
)
print(f"Create index response: {resp.status_code}")
print(resp.json())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Test a RAG query
# MAGIC Search the runbook for "SSH brute force" and see what comes back.

# COMMAND ----------

import json

# Wait for index to be ready (may take a minute on first sync)
print("Waiting for index to sync...")
for i in range(12):
    status_resp = requests.get(
        f"https://{host}/api/2.0/vector-search/indexes/{INDEX_NAME}",
        headers=headers,
    )
    status = status_resp.json().get("status", {}).get("ready", False)
    if status:
        print("Index is ready!")
        break
    time.sleep(10)
    print(f"  ...waiting ({(i+1)*10}s)")

# Test RAG query
resp = requests.post(
    f"https://{host}/api/2.0/vector-search/indexes/{INDEX_NAME}/query",
    headers=headers,
    json={
        "columns": ["section_id", "title", "content"],
        "query_text": "SSH brute force repeated login failures",
        "num_results": 2,
    },
)
results = resp.json()
for r in results.get("result", {}).get("data_array", []):
    print(f"[{r[0]}] {r[1]}")
    print(f"  {r[2][:150]}...")
    print()
