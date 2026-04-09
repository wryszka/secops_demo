# Databricks notebook source
# MAGIC %md
# MAGIC # SecOps Data Lakehouse — Demo Overview
# MAGIC
# MAGIC **Business context:** A client is spending $525K/month sending all 35TB of firewall logs to
# MAGIC Google SecOps (Chronicle) at hot-tier SIEM pricing. Most of that data is noise — 95% is routine
# MAGIC ALLOW traffic that never triggers an alert. This demo shows how **Databricks becomes the single
# MAGIC source of truth** for all security data, with only the 5% that needs active SOAR orchestration
# MAGIC forwarded to Chronicle.
# MAGIC
# MAGIC ---
# MAGIC **About this demo:** This is not a Databricks product. It is a working demonstration built on the
# MAGIC Databricks platform using Declarative Pipelines, Unity Catalog, Foundation Model APIs, Vector Search,
# MAGIC and Databricks Apps. All processes are real and running. The data is synthetic.
# MAGIC Source code: [github.com/wryszka/secops_demo](https://github.com/wryszka/secops_demo)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Architecture
# MAGIC
# MAGIC ![SecOps Data Lakehouse Architecture](./architecture.png)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Databricks Services Used
# MAGIC
# MAGIC | Service | Role in this demo |
# MAGIC |---------|-------------------|
# MAGIC | **Unity Catalog** | Governance layer — all tables, volumes, and indexes in one schema (`secops_demo`) |
# MAGIC | **Unity Catalog Volumes** | Landing zone for raw JSON firewall logs |
# MAGIC | **Declarative Pipelines (DLT)** | Ingests logs via Auto Loader, classifies and routes to two Delta tables |
# MAGIC | **Auto Loader** | Schema inference and incremental file ingestion from the volume |
# MAGIC | **Delta Lake** | Columnar storage for all firewall data — `low_cost_archive` and `high_value_siem_feed` |
# MAGIC | **Serverless SQL Warehouse** | On-demand queries across all tables — powers the app and threat hunt |
# MAGIC | **Foundation Model API** | LLM calls for AI triage, remediation generation, and `ai_query()` SQL classification |
# MAGIC | **`ai_query()` SQL Function** | Runs Foundation Models inline in SQL — no Python needed |
# MAGIC | **Vector Search** | Managed embeddings (GTE-Large) over SOC Runbook for RAG-grounded triage |
# MAGIC | **Databricks Apps** | Hosts the Streamlit Operator View — deployed and managed by the platform |
# MAGIC | **System Tables** | `system.access.audit` provides workspace security posture out of the box |

# COMMAND ----------

# MAGIC %md
# MAGIC ## Notebooks
# MAGIC
# MAGIC Run these in order. Each is self-contained and idempotent.
# MAGIC
# MAGIC | # | Notebook | What it does | Creates |
# MAGIC |---|----------|-------------|---------|
# MAGIC | 0 | `00_overview` | This notebook — architecture and orientation | — |
# MAGIC | 0 | `00_generate_logs` | Generates 5,000 synthetic firewall logs (95% ALLOW, 5% DENY/THREAT) and writes them as newline-delimited JSON to a UC Volume | JSON files in `raw_logs` volume |
# MAGIC | 1 | `01_dlt_router` | DLT pipeline notebook — Auto Loader reads the JSON, classifies by `action` field, routes to two Silver tables | `raw_firewall_logs`, `low_cost_archive`, `high_value_siem_feed` |
# MAGIC | 3 | `03_ai_query_sql` | Creates `endpoint_logs` with realistic EDR telemetry (obfuscated PowerShell, certutil abuse, credential dumping). Demonstrates `ai_query()` for inline MALICIOUS/BENIGN classification and MITRE ATT&CK mapping — all in SQL | `endpoint_logs` |
# MAGIC | 4 | `04_rag_runbook` | Creates a 10-section SOC Runbook as a Delta table, enables CDF, and builds a Vector Search index with managed GTE-Large embeddings. Tests RAG retrieval. | `soc_runbook_chunks`, `soc_runbook_vs_index` |

# COMMAND ----------

# MAGIC %md
# MAGIC ## Operator View App (Streamlit)
# MAGIC
# MAGIC The app is deployed via **Databricks Apps** and has 7 tabs:
# MAGIC
# MAGIC | Tab | What it shows | Databricks services |
# MAGIC |-----|-------------|---------------------|
# MAGIC | **About** | Demo disclaimer, overview, OK button | Databricks Apps |
# MAGIC | **Metrics Dashboard** | Ingestion volume, 95/5 routing split, cost comparison (Chronicle vs Databricks) | Serverless SQL, Delta Lake |
# MAGIC | **Threat Hunt Search** | Multi-field search (IP, port, protocol, firewall, zone) across the cold archive | Serverless SQL, Delta Lake |
# MAGIC | **AI Triage Agent** | Select a threat IP → RAG-grounded triage summary → remediation payloads | Serverless SQL, Vector Search, Foundation Model API |
# MAGIC | **AI SQL Classification** | `ai_query()` classifies endpoint commands as MALICIOUS/BENIGN + MITRE ATT&CK | Serverless SQL, Foundation Model API, `ai_query()` |
# MAGIC | **SOC Runbook (RAG)** | Natural language search across incident response procedures | Vector Search (GTE-Large) |
# MAGIC | **System Posture** | Workspace logins, data downloads, service activity from `system.access.audit` | Serverless SQL, System Tables |

# COMMAND ----------

# MAGIC %md
# MAGIC ## Data Flow
# MAGIC
# MAGIC ```
# MAGIC Firewall JSON  ──►  UC Volume  ──►  DLT Auto Loader  ──►  raw_firewall_logs (Bronze)
# MAGIC                                                                    │
# MAGIC                                          ┌─────────────────────────┼──────────────────────┐
# MAGIC                                          ▼                                                ▼
# MAGIC                                 low_cost_archive (Silver)                   high_value_siem_feed (Silver)
# MAGIC                                 95% ALLOW — stays in Delta Lake             5% DENY/THREAT
# MAGIC                                 Searchable at $0.023/GB                     Forwarded to Google SecOps
# MAGIC                                          │                                                │
# MAGIC                                          ▼                                                ▼
# MAGIC                                 Threat Hunt Search                          AI Triage Agent
# MAGIC                                 (Serverless SQL)                            (Foundation Model API
# MAGIC                                                                              + Vector Search RAG)
# MAGIC                                                                                           │
# MAGIC                                                                                           ▼
# MAGIC                                                                              Remediation Payloads
# MAGIC                                                                              (Palo Alto, SOAR, CrowdStrike)
# MAGIC ```
# MAGIC
# MAGIC **Parallel paths:**
# MAGIC - `endpoint_logs` → `ai_query()` → MALICIOUS/BENIGN classification (AI SQL tab)
# MAGIC - `soc_runbook_chunks` → Vector Search → RAG grounding for triage (SOC Runbook tab)
# MAGIC - `system.access.audit` → Serverless SQL → workspace posture (System Posture tab)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Schema: `secops_demo`
# MAGIC
# MAGIC All assets live in a single schema under your workspace catalog.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT table_name, table_type, comment
# MAGIC FROM system.information_schema.tables
# MAGIC WHERE table_schema = 'secops_demo'
# MAGIC   AND table_catalog = 'lr_serverless_aws_us_catalog'
# MAGIC ORDER BY table_name;
