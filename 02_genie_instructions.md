# Genie Space Setup — SecOps Data Lakehouse

Step-by-step instructions to create a Genie Space for natural language querying.
Default catalog below is `lr_serverless_aws_us_catalog` — replace with yours (see DEPLOY.md).

---

## Tables to Add

### 1. `<catalog>.secops_demo.low_cost_archive`

ALLOWED firewall traffic — 95% of logs, routed to cheap cold storage. Use for threat hunting.

| Column | Type | Description |
|--------|------|-------------|
| `event_id` | STRING | Unique event identifier |
| `timestamp` | TIMESTAMP | When the event occurred |
| `src_ip` | STRING | Source IP address |
| `dst_ip` | STRING | Destination IP address |
| `src_port` | INT | Source port |
| `dst_port` | INT | Destination port |
| `protocol` | STRING | TCP, UDP, or ICMP |
| `action` | STRING | Always ALLOW in this table |
| `bytes_sent` | BIGINT | Bytes sent |
| `bytes_recv` | BIGINT | Bytes received |
| `firewall` | STRING | Firewall device (fw-edge-01, fw-edge-02, fw-core-01, fw-dmz-01) |
| `src_zone` | STRING | Source zone (TRUST, DMZ, GUEST) |
| `dst_zone` | STRING | Destination zone (UNTRUST, DMZ, SERVERS) |
| `session_duration_ms` | BIGINT | Session duration in ms |
| `rule_name` | STRING | Firewall rule that matched |

### 2. `<catalog>.secops_demo.high_value_siem_feed`

DENIED and THREAT events — 5% of logs, routed to hot SIEM tier. Same columns as above, plus:

| Column | Type | Description |
|--------|------|-------------|
| `action` | STRING | DENY or THREAT |
| `threat_type` | STRING | PORT_SCAN, BRUTE_FORCE, C2_BEACON, DATA_EXFIL, MALWARE_DOWNLOAD, DNS_TUNNEL, LATERAL_MOVEMENT, CREDENTIAL_STUFFING (NULL for DENY) |
| `severity` | STRING | WARNING (DENY), HIGH or CRITICAL (THREAT) |

### 3. `system.access.audit` (optional — requires account admin grant)

Workspace audit logs for insider threat detection and compliance monitoring.

---

## Setup Steps

1. Open workspace > **Genie** (left sidebar, under AI/BI) > **New Genie Space**
2. Configure:
   - **Name:** `SecOps Threat Intelligence`
   - **Description:** Search firewall logs, investigate threats, and monitor security posture.
   - **SQL Warehouse:** Select your serverless warehouse
   - **Tables:** Add the tables listed above

3. Paste into **General Instructions:**

```
You are a SOC analyst assistant. You help operators investigate firewall logs,
hunt for threats, and analyze security posture.

Key context:
- low_cost_archive: 95% of traffic (ALLOW) — cold search tier
- high_value_siem_feed: 5% of traffic (DENY/THREAT) — hot SIEM tier
- system.access.audit: workspace audit logs

When analyzing threats, consider:
- Source/destination IP patterns
- Port scanning (many distinct dst_ports from one src_ip)
- Threat types: PORT_SCAN, BRUTE_FORCE, C2_BEACON, DATA_EXFIL, MALWARE_DOWNLOAD, DNS_TUNNEL, LATERAL_MOVEMENT, CREDENTIAL_STUFFING
- Time-based patterns (bursts of activity)
- Data exfiltration indicators (high bytes_sent from internal IPs)

Format numbers with commas. Use severity levels when summarizing.
```

4. Add **Sample Questions:**
   - "How many total events are in the archive vs the SIEM feed?"
   - "Show me all THREAT events with severity CRITICAL"
   - "Which source IPs have the most DENY events? Top 10."
   - "Find all traffic from IP 185.220.101.34 across both tables"
   - "What types of threats have been detected? Count by threat_type."
   - "Show port scanning activity — IPs hitting more than 5 distinct ports"
   - "Total bytes sent by each threat source IP"
   - "Which firewalls see the most threat activity?"
   - "Show workspace login events from the last 7 days"
   - "Which users performed the most data exports this week?"

---

## Demo Talk Track

> "This is where the real magic happens for your analysts. Instead of writing SQL,
> they ask questions in plain English. Watch — 'Show me all critical threats from
> external IPs in the last hour' — Genie writes the SQL, runs it, returns results
> instantly. And that query just hit the cold archive at Delta Lake pricing, not
> Chronicle pricing. Same investigative capability, fraction of the cost."
