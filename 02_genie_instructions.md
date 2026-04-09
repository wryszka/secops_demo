# Genie Space Setup — SecOps Data Lakehouse

This document provides step-by-step instructions to create a Databricks Genie Space
for natural language querying of the Security Data Lakehouse tables.

---

## Prerequisites

- Workspace: Your Databricks workspace URL
- Catalog: `YOUR_CATALOG` (replace with the catalog you configured in DEPLOY.md Step 1)
- Schema: `secops_demo`
- SQL Warehouse: Any serverless or pro warehouse you have CAN_USE access to

---

## Tables to Add

Add the following tables to the Genie Space:

### 1. `YOUR_CATALOG.secops_demo.low_cost_archive`

**Description for Genie:** This table contains ALLOWED firewall traffic — the 95% of logs that are normal/benign and routed to cheap cold storage. Use this for threat hunting and retroactive investigation.

**Key Columns:**
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
| `bytes_sent` | BIGINT | Bytes sent in this session |
| `bytes_recv` | BIGINT | Bytes received in this session |
| `firewall` | STRING | Firewall device name (fw-edge-01, fw-edge-02, fw-core-01, fw-dmz-01) |
| `src_zone` | STRING | Source network zone (TRUST, DMZ, GUEST) |
| `dst_zone` | STRING | Destination network zone (UNTRUST, DMZ, SERVERS) |
| `session_duration_ms` | BIGINT | Session duration in milliseconds |
| `rule_name` | STRING | Firewall rule that matched |

### 2. `YOUR_CATALOG.secops_demo.high_value_siem_feed`

**Description for Genie:** This table contains DENIED and THREAT firewall events — the 5% of logs that are suspicious or malicious, routed to the hot SIEM tier for immediate investigation.

**Key Columns:**
Same as above, plus:
| Column | Type | Description |
|--------|------|-------------|
| `action` | STRING | DENY or THREAT |
| `threat_type` | STRING | Type of threat: PORT_SCAN, BRUTE_FORCE, C2_BEACON, DATA_EXFIL, MALWARE_DOWNLOAD, DNS_TUNNEL, LATERAL_MOVEMENT, CREDENTIAL_STUFFING (NULL for DENY) |
| `severity` | STRING | WARNING (for DENY), HIGH or CRITICAL (for THREAT) |

### 3. `system.access.audit` (optional — requires permissions)

**Description for Genie:** Databricks workspace audit logs showing user logins, API calls, data access, and admin actions. Use this for insider threat detection and compliance monitoring.

**Key Columns:**
| Column | Type | Description |
|--------|------|-------------|
| `event_date` | DATE | Date of the event |
| `event_time` | TIMESTAMP | Exact timestamp |
| `user_identity.email` | STRING | User who performed the action |
| `action_name` | STRING | The action performed (login, read, write, etc.) |
| `service_name` | STRING | Databricks service (clusters, sql, workspace, etc.) |
| `source_ip_address` | STRING | IP address of the client |
| `request_params` | MAP | Additional request parameters |

---

## Genie Space Configuration

### Step 1: Navigate to Genie

1. Open the Databricks workspace
2. Click **Genie** in the left sidebar (under "AI/BI")
3. Click **New Genie Space**

### Step 2: Configure the Space

- **Name:** `SecOps Threat Intelligence`
- **Description:** Natural language interface for querying the Security Data Lakehouse. Search firewall logs, investigate threats, and monitor workspace security posture.
- **SQL Warehouse:** Select the serverless warehouse
- **Tables:** Add the three tables listed above

### Step 3: Add General Instructions

Paste this into the **General Instructions** field:

```
You are a Security Operations Center (SOC) analyst assistant. You help operators investigate
firewall logs, hunt for threats, and analyze security posture.

Key context:
- The low_cost_archive table contains 95% of traffic (ALLOW actions) — this is the "cold search" tier
- The high_value_siem_feed table contains 5% of traffic (DENY and THREAT actions) — this is the "hot SIEM" tier
- The system.access.audit table contains Databricks workspace audit logs

When analyzing threats, always consider:
- Source and destination IP patterns
- Port scanning behavior (many distinct dst_ports from one src_ip)
- Known threat types: PORT_SCAN, BRUTE_FORCE, C2_BEACON, DATA_EXFIL, MALWARE_DOWNLOAD, DNS_TUNNEL, LATERAL_MOVEMENT, CREDENTIAL_STUFFING
- Time-based patterns (bursts of activity)
- Data exfiltration indicators (high bytes_sent from internal IPs)

Always format numbers with commas for readability. Use severity levels when summarizing threat data.
```

### Step 4: Add Sample Questions

Add these as **Sample Questions** in the Genie Space:

1. **"How many total events are in the archive vs the SIEM feed?"**
   - Tests: basic counts across both tables, proves the 95/5 split

2. **"Show me all THREAT events with severity CRITICAL in the last hour"**
   - Tests: filtering on high_value_siem_feed, time-based queries

3. **"Which source IPs have the most DENY events? Show the top 10."**
   - Tests: aggregation and ranking on the SIEM feed

4. **"Find all traffic from IP 185.220.101.34 across both tables"**
   - Tests: cross-table search, known threat IP investigation

5. **"What types of threats have been detected? Show count by threat_type."**
   - Tests: group-by on threat_type enum values

6. **"Show port scanning activity — IPs that connected to more than 5 distinct destination ports"**
   - Tests: complex aggregation for threat detection pattern

7. **"What is the total data volume (bytes) sent by each threat source IP?"**
   - Tests: aggregation on bytes_sent, potential data exfil detection

8. **"Which firewalls are seeing the most threat activity?"**
   - Tests: aggregation by firewall device name

9. **"Show workspace login events from the last 7 days"**
   - Tests: system.access.audit query for compliance

10. **"Which users have performed the most data export operations this week?"**
    - Tests: audit log query for insider threat detection

---

## Demo Talk Track for Genie

> "This is where the real magic happens for your security analysts. Instead of writing SQL
> or learning a new query language, they just ask questions in plain English.
>
> Watch — I'll type 'Show me all critical threats from external IPs in the last hour'
> and Genie writes the SQL, runs it against our Delta Lake tables, and returns the results
> instantly. Your analysts can investigate threats without waiting for the SIEM team to
> build custom dashboards.
>
> And here's the cost story — that same query just searched through the cold archive tier
> at Delta Lake pricing, not Chronicle pricing. You're getting the same investigative
> capability at a fraction of the cost."
