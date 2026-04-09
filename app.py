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
        st.error(f"SQL Error: {err.message if err else 'Unknown'}")
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
st.caption("Databricks Security Data Lakehouse — Smart Routing | Cold Search | AI Triage")

tab_about, tab_metrics, tab_hunt, tab_triage, tab_posture = st.tabs([
    "About",
    "Metrics Dashboard",
    "Threat Hunt Search",
    "AI Triage Agent",
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
- **Metrics Dashboard** — Volume of data routed to cold archive vs. hot SIEM,
  proving the 95/5 cost-savings split
- **Threat Hunt Search** — Instant, serverless search on the cold-storage archive
  at a fraction of Chronicle pricing
""")
    with col2:
        st.markdown("""
- **AI Triage Agent** — Foundation Model API + RAG-grounded runbook analysis
  with copy-paste remediation payloads
- **System Posture** — Out-of-the-box workspace audit dashboards
  from `system.access.audit`
""")

    st.divider()

    st.markdown("**Databricks services demonstrated:** Declarative Pipelines (DLT), "
                "Auto Loader, Unity Catalog, Serverless SQL, Foundation Model APIs, "
                "Vector Search, Databricks Apps")


# ===========================================================================
# TAB 1: Metrics Dashboard
# ===========================================================================
with tab_metrics:
    st.header("Data Routing Metrics")
    st.markdown("Proving the **cost-savings thesis**: only ~5% of traffic needs expensive SIEM processing.")

    col1, col2, col3 = st.columns(3)

    df_archive = run_sql(f"SELECT COUNT(*) as cnt FROM {CATALOG}.{SCHEMA}.low_cost_archive")
    df_siem = run_sql(f"SELECT COUNT(*) as cnt FROM {CATALOG}.{SCHEMA}.high_value_siem_feed")
    df_raw = run_sql(f"SELECT COUNT(*) as cnt FROM {CATALOG}.{SCHEMA}.raw_firewall_logs")

    archive_count = int(df_archive["cnt"].iloc[0]) if not df_archive.empty else 0
    siem_count = int(df_siem["cnt"].iloc[0]) if not df_siem.empty else 0
    raw_count = int(df_raw["cnt"].iloc[0]) if not df_raw.empty else 0

    with col1:
        st.metric("Total Ingested Logs", f"{raw_count:,}")
    with col2:
        st.metric("Low-Cost Archive (ALLOW)", f"{archive_count:,}", help="95% of traffic — cheap storage")
    with col3:
        st.metric("SIEM Feed (DENY/THREAT)", f"{siem_count:,}", help="5% of traffic — high-value alerts")

    st.divider()
    st.subheader("Cost Projection")
    col_a, col_b, col_c = st.columns(3)

    total_tb = 35
    pct_archive = archive_count / max(raw_count, 1)
    pct_siem = siem_count / max(raw_count, 1)

    chronicle_cost = total_tb * 1000 * 15
    dbx_archive_cost = total_tb * 1000 * pct_archive * 0.023
    dbx_siem_cost = total_tb * 1000 * pct_siem * 5
    dbx_total = dbx_archive_cost + dbx_siem_cost

    with col_a:
        st.metric("Google SecOps (Chronicle)", f"${chronicle_cost:,.0f}/mo", help="All 35TB at hot-tier SIEM pricing")
    with col_b:
        st.metric("Databricks Smart Routing", f"${dbx_total:,.0f}/mo", help="Archive tier + hot SIEM only for threats")
    with col_c:
        savings = chronicle_cost - dbx_total
        st.metric("Monthly Savings", f"${savings:,.0f}/mo", delta=f"{savings/max(chronicle_cost,1)*100:.0f}% reduction")

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
    st.header("Threat Hunt — Cold Storage Search")
    st.markdown("Search the **low-cost archive** (95% of all traffic) for any IP. "
                "Powered by Databricks Serverless SQL — sub-second queries on Delta Lake.")

    search_ip = st.text_input("Enter IP address to search:", placeholder="e.g., 10.0.12.45")

    if search_ip:
        st.info(f"Searching `{CATALOG}.{SCHEMA}.low_cost_archive` for IP: **{search_ip}**")
        df_results = run_sql(f"""
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port,
                   protocol, action, bytes_sent, bytes_recv,
                   firewall, src_zone, dst_zone
            FROM {CATALOG}.{SCHEMA}.low_cost_archive
            WHERE src_ip = '{search_ip}' OR dst_ip = '{search_ip}'
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        if not df_results.empty:
            st.success(f"Found **{len(df_results)}** records (showing up to 200)")
            st.dataframe(df_results, use_container_width=True, height=400)

            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Unique Destination Ports", df_results["dst_port"].nunique())
            with c2:
                st.metric("Total Bytes Sent", f"{df_results['bytes_sent'].astype(int).sum():,}")
            with c3:
                st.metric("Protocols Used", df_results["protocol"].nunique())
        else:
            st.warning("No records found for this IP in the archive.")


# ===========================================================================
# TAB 3: AI Triage Agent (with RAG Runbook + Remediation)
# ===========================================================================
with tab_triage:
    st.header("AI Triage Agent")
    st.markdown("Select a flagged IP from the **high-value SIEM feed**. "
                "The AI agent analyzes logs, consults the **SOC Runbook** via RAG, "
                "and generates **actionable remediation payloads**.")

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

                    # --- Collect threat types for this IP ---
                    threat_types_str = ", ".join(
                        df_ip_logs["threat_type"].dropna().unique().tolist()
                    )

                    # --- RAG: Search the SOC Runbook ---
                    runbook_context = ""
                    with st.spinner("Searching SOC Runbook..."):
                        search_query = f"{threat_types_str} {selected_ip} response procedure"
                        runbook_context = search_runbook(search_query)

                    # --- AI Triage with runbook grounding ---
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

                    # --- Show runbook context used ---
                    if runbook_context and "unavailable" not in runbook_context.lower():
                        with st.expander("SOC Runbook Sections Retrieved (RAG)"):
                            st.markdown(runbook_context)

                    # --- Store triage in session for remediation button ---
                    st.session_state["last_triage"] = triage
                    st.session_state["last_triage_ip"] = selected_ip
                    st.session_state["last_threat_types"] = threat_types_str
                else:
                    st.warning("No logs found for this IP.")

        # --- Remediation Payload Generator ---
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
# TAB 4: System Posture
# ===========================================================================
with tab_posture:
    st.header("Workspace Security Posture")
    st.markdown("Querying `system.access.audit` for workspace login activity and data access patterns.")

    st.subheader("Recent Workspace Logins")
    df_logins = run_sql("""
        SELECT event_date, user_identity.email as user_email,
               source_ip_address, action_name, service_name
        FROM system.access.audit
        WHERE action_name IN ('login', 'tokenLogin', 'oidcLogin', 'samlLogin')
          AND event_date >= DATEADD(DAY, -7, CURRENT_DATE())
        ORDER BY event_date DESC
        LIMIT 50
    """)
    if not df_logins.empty:
        st.dataframe(df_logins, use_container_width=True)
    else:
        st.info("No recent login events found or insufficient permissions on system.access.audit.")

    st.divider()
    st.subheader("Large Data Downloads (Last 7 Days)")
    df_downloads = run_sql("""
        SELECT event_date, user_identity.email as user_email,
               action_name, request_params.path as resource_path,
               source_ip_address
        FROM system.access.audit
        WHERE action_name IN ('downloadLargeResult', 'downloadQueryResult', 'export')
          AND event_date >= DATEADD(DAY, -7, CURRENT_DATE())
        ORDER BY event_date DESC
        LIMIT 50
    """)
    if not df_downloads.empty:
        st.dataframe(df_downloads, use_container_width=True)
    else:
        st.info("No large download events found in the last 7 days.")

    st.divider()
    st.subheader("Service Usage by Action")
    df_actions = run_sql("""
        SELECT service_name, action_name, COUNT(*) as event_count
        FROM system.access.audit
        WHERE event_date >= DATEADD(DAY, -7, CURRENT_DATE())
        GROUP BY service_name, action_name
        ORDER BY event_count DESC
        LIMIT 30
    """)
    if not df_actions.empty:
        df_actions["event_count"] = df_actions["event_count"].astype(int)
        st.dataframe(df_actions, use_container_width=True)
    else:
        st.info("No audit data available.")

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
    1. Raw JSON logs land in UC Volume
    2. DLT Auto Loader ingests continuously
    3. Smart Router splits traffic:
       - 95% ALLOW -> cold archive ($0.02/GB)
       - 5% DENY/THREAT -> hot SIEM ($5/GB)
    4. Serverless SQL enables instant search
    5. Foundation Model API powers AI triage
    6. Vector Search grounds recommendations in SOC Runbook
    """)
    st.markdown("---")
    st.caption("This is a demo, not a Databricks product. "
               "Data is synthetic. Provided as-is for "
               "demonstration purposes. "
               "[Source code](https://github.com/wryszka/secops_demo)")
