# SecOps Data Lakehouse Demo — Deployment Guide

Deploy this demo on any Databricks workspace with Unity Catalog. This guide covers
permissions, catalog setup, and step-by-step deployment commands.

---

## Architecture Overview

```
Raw JSON Logs ──▶ UC Volume ──▶ DLT Auto Loader ──▶ Smart Router
                                                       │
                              ┌─────────────────────────┼──────────────────┐
                              ▼                                            ▼
                     low_cost_archive (95%)                    high_value_siem_feed (5%)
                     ALLOW — cold storage                     DENY/THREAT — hot SIEM
                     $0.02/GB                                 $5/GB
                              │                                            │
                              └──────────────┬─────────────────────────────┘
                                             ▼
                                   Streamlit Operator View
                                   (Metrics | Search | AI Triage | Posture)
```

**Business context:** Client spending too much on Google SecOps (Chronicle) for 35TB of
chatty firewall logs. Databricks acts as a smart routing layer — only 5% of traffic needs
expensive SIEM processing, saving ~90% on log management costs.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Databricks CLI** | v0.200+ installed and authenticated (`databricks auth login`) |
| **Workspace** | Any Databricks workspace with Unity Catalog enabled |
| **Cloud** | AWS, Azure, or GCP (serverless compute required) |
| **Python** | 3.10+ (for local development only) |

---

## Required Permissions

You (or the workspace admin) need the following permissions. If you don't have them,
ask your admin to grant them or point you to a catalog you can use.

### For the deploying user

| Permission | Where | Why | How to check |
|------------|-------|-----|--------------|
| **USE CATALOG** | On your target catalog | Access the catalog | `SHOW CATALOGS` — if your catalog appears, you have it |
| **CREATE SCHEMA** | On your target catalog | Create the `secops_demo` schema | Ask admin or try: `CREATE SCHEMA <catalog>.test_schema` then drop it |
| **CREATE TABLE** | On the schema (auto-granted if you create it) | DLT creates tables here | Granted automatically to schema creator |
| **CREATE VOLUME** | On the schema | Store raw JSON log files | Granted automatically to schema creator |
| **CAN MANAGE** or **CAN USE** | On a SQL Warehouse | Run queries from the app | Check SQL Warehouses page in workspace UI |
| **CAN MANAGE** or **CAN USE** | On a serverless DLT pipeline | Run the DLT pipeline | Auto-granted to creator |
| **Can create Databricks Apps** | Workspace-level | Deploy the Streamlit app | Check Settings > Workspace > Databricks Apps |
| **CAN QUERY** | On Foundation Model serving endpoint | AI Triage tab uses LLM | Enabled by default on pay-per-token endpoints |

### For system.access.audit (System Posture tab — optional)

| Permission | Details |
|------------|---------|
| **SELECT on system.access.audit** | Account admin must grant this. The tab degrades gracefully if unavailable. |

> **No audit access?** The System Posture tab will show "No data available" messages.
> The other three tabs work independently.

### For the App's service principal (auto-created)

When you create a Databricks App, it gets its own service principal. You must grant it:

| Permission | SQL Command |
|------------|-------------|
| USE CATALOG | `GRANT USE CATALOG ON CATALOG <catalog> TO \`<app-sp-uuid>\`` |
| USE SCHEMA | `GRANT USE SCHEMA ON SCHEMA <catalog>.secops_demo TO \`<app-sp-uuid>\`` |
| SELECT | `GRANT SELECT ON SCHEMA <catalog>.secops_demo TO \`<app-sp-uuid>\`` |

The `<app-sp-uuid>` is the `service_principal_client_id` returned by `databricks apps create`.
See Step 5 below for the exact commands.

---

## Step 1: Identify Your Catalog

**This is the most important step.** Not every user can create catalogs. Most workspaces
have one or more pre-provisioned catalogs.

### Option A: You already know your catalog
Use it. Common patterns:
- `main` (default on many workspaces)
- `<workspace_name>_catalog` (FEVM-style)
- `dev_catalog`, `sandbox`, `shared_catalog`

### Option B: Find your available catalogs
```bash
# List catalogs you have access to
databricks api post /api/2.0/sql/statements \
  --json '{"warehouse_id":"<WAREHOUSE_ID>","statement":"SHOW CATALOGS","wait_timeout":"30s"}'
```

### Option C: Ask your workspace admin
If `SHOW CATALOGS` returns nothing useful, ask your admin:
> "Which Unity Catalog should I use? I need CREATE SCHEMA permission on it."

### Option D: You are the admin and want to create a dedicated catalog
```sql
CREATE CATALOG IF NOT EXISTS secops_catalog
COMMENT 'Security Data Lakehouse demo';
```

### Once you have your catalog name

Run a global find-and-replace across all files:

| File | Find | Replace with |
|------|------|-------------|
| `00_setup.sql` | `YOUR_CATALOG` | Your catalog name |
| `00_generate_logs.py` | `YOUR_CATALOG` | Your catalog name |
| `01_dlt_router.py` | `YOUR_CATALOG` | Your catalog name |
| `app.yaml` | `YOUR_CATALOG` | Your catalog name |
| `02_genie_instructions.md` | `YOUR_CATALOG` | Your catalog name |

Or use sed:
```bash
# From the secops_demo/ directory — replaces in ALL files at once
sed -i '' 's/YOUR_CATALOG/my_actual_catalog/g' 00_setup.sql 00_generate_logs.py 01_dlt_router.py app.yaml 02_genie_instructions.md
```

---

## Step 2: Identify Your SQL Warehouse

You need a SQL Warehouse ID. The app and setup scripts use it for queries.

```bash
# List warehouses
databricks warehouses list
```

This returns something like:
```
ID                Name       Size      State
ab79eced8207d29b  warehouse  2X-Small  STOPPED
```

Copy the **ID** column value. Then replace in these files:

| File | Find | Replace with |
|------|------|-------------|
| `app.yaml` | `YOUR_WAREHOUSE_ID` (appears twice) | Your warehouse ID |

> **No warehouse?** Ask your admin to create one, or use a serverless SQL warehouse.
> You need at least CAN_USE permission on it.

---

## Step 3: Create the Schema

Run the setup SQL. Each statement must be executed individually via the API
(the SQL statements API does not support multi-statement batches).

```bash
WAREHOUSE_ID="<your-warehouse-id>"

# Set catalog context
databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"USE CATALOG <your-catalog>\",\"wait_timeout\":\"30s\"}"

# Create schema
databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"CREATE SCHEMA IF NOT EXISTS secops_demo COMMENT 'Security Data Lakehouse demo'\",\"wait_timeout\":\"30s\"}"

# Clean up any previous tables
for tbl in raw_firewall_logs low_cost_archive high_value_siem_feed; do
  databricks api post /api/2.0/sql/statements \
    --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"DROP TABLE IF EXISTS secops_demo.$tbl\",\"wait_timeout\":\"30s\"}"
done

# Create volume for raw log files
databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"CREATE VOLUME IF NOT EXISTS secops_demo.raw_logs\",\"wait_timeout\":\"30s\"}"
```

### Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `INSUFFICIENT_PRIVILEGES` on CREATE SCHEMA | You lack CREATE SCHEMA on the catalog | Ask admin to grant it, or use a catalog where you have it |
| `CATALOG_NOT_FOUND` | Catalog name is wrong | Re-check with `SHOW CATALOGS` |
| `SCHEMA_ALREADY_EXISTS` | Previous run — this is fine | `IF NOT EXISTS` handles it |

---

## Step 4: Upload Notebooks & Generate Data

```bash
# Create workspace directory
databricks workspace mkdirs /Users/$(databricks current-user me | jq -r .userName)/secops_demo

# Upload notebooks
USERNAME=$(databricks current-user me | jq -r .userName)

databricks workspace import /Users/$USERNAME/secops_demo/00_generate_logs \
  --file 00_generate_logs.py --format SOURCE --language PYTHON --overwrite

databricks workspace import /Users/$USERNAME/secops_demo/01_dlt_router \
  --file 01_dlt_router.py --format SOURCE --language PYTHON --overwrite
```

### Run the log generator

```bash
# Create a one-time serverless job
JOB_ID=$(databricks jobs create --json "{
  \"name\": \"secops_demo_log_generator\",
  \"tasks\": [{
    \"task_key\": \"generate_logs\",
    \"notebook_task\": {
      \"notebook_path\": \"/Users/$USERNAME/secops_demo/00_generate_logs\"
    },
    \"environment_key\": \"default\"
  }],
  \"environments\": [{
    \"environment_key\": \"default\",
    \"spec\": {\"client\": \"1\"}
  }]
}" | jq -r .job_id)

echo "Job created: $JOB_ID"

# Run it (synchronous — waits for completion)
databricks jobs run-now $JOB_ID
```

This generates 5,000 synthetic firewall logs (95% ALLOW, 5% DENY/THREAT) into the
UC volume at `/Volumes/<catalog>/secops_demo/raw_logs/`.

---

## Step 5: Create & Start the DLT Pipeline

```bash
USERNAME=$(databricks current-user me | jq -r .userName)

PIPELINE_ID=$(databricks pipelines create --json "{
  \"name\": \"secops_smart_router\",
  \"serverless\": true,
  \"catalog\": \"<your-catalog>\",
  \"target\": \"secops_demo\",
  \"continuous\": false,
  \"development\": true,
  \"libraries\": [{
    \"notebook\": {
      \"path\": \"/Users/$USERNAME/secops_demo/01_dlt_router\"
    }
  }],
  \"channel\": \"CURRENT\"
}" | jq -r .pipeline_id)

echo "Pipeline created: $PIPELINE_ID"

# Trigger the pipeline
databricks pipelines start-update $PIPELINE_ID --full-refresh

# Monitor progress
databricks pipelines get $PIPELINE_ID | jq '{state, latest_update: .latest_updates[0].state}'
```

Wait until `latest_update` shows `COMPLETED`. This typically takes 2-3 minutes on serverless.

### Verify data

```bash
WAREHOUSE_ID="<your-warehouse-id>"
for tbl in raw_firewall_logs low_cost_archive high_value_siem_feed; do
  echo -n "$tbl: "
  databricks api post /api/2.0/sql/statements \
    --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"SELECT COUNT(*) FROM <your-catalog>.secops_demo.$tbl\",\"wait_timeout\":\"30s\"}" \
    | jq -r '.result.data_array[0][0]'
done
```

Expected output:
```
raw_firewall_logs: 5000
low_cost_archive: ~4750
high_value_siem_feed: ~250
```

---

## Step 6: Deploy the Streamlit App

### 6a. Create the app

```bash
APP_NAME="secops-operator-view"

databricks apps create --json "{
  \"name\": \"$APP_NAME\",
  \"description\": \"SecOps Operator View - Security Data Lakehouse Demo\"
}"
```

Save the output — you need:
- `service_principal_client_id` (UUID) — for granting data access
- `url` — the app URL

### 6b. Grant the app's service principal access to your data

```bash
SP_UUID="<service_principal_client_id from step 6a>"
WAREHOUSE_ID="<your-warehouse-id>"

# Grant catalog access
databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"GRANT USE CATALOG ON CATALOG <your-catalog> TO \\\`$SP_UUID\\\`\",\"wait_timeout\":\"30s\"}"

# Grant schema access
databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"GRANT USE SCHEMA ON SCHEMA <your-catalog>.secops_demo TO \\\`$SP_UUID\\\`\",\"wait_timeout\":\"30s\"}"

# Grant read access to all tables in the schema
databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"GRANT SELECT ON SCHEMA <your-catalog>.secops_demo TO \\\`$SP_UUID\\\`\",\"wait_timeout\":\"30s\"}"
```

### 6c. Upload app source & deploy

```bash
USERNAME=$(databricks current-user me | jq -r .userName)

# Create workspace directory for app files
databricks workspace mkdirs /Users/$USERNAME/secops_demo/app

# Upload all app files
for f in app.py app.yaml requirements.txt; do
  databricks workspace import /Users/$USERNAME/secops_demo/app/$f \
    --file $f --format AUTO --overwrite
done

# Deploy
databricks apps deploy $APP_NAME \
  --source-code-path /Workspace/Users/$USERNAME/secops_demo/app \
  --no-wait
```

### 6d. Check deployment status

```bash
databricks apps get $APP_NAME | jq '{
  app_status: .app_status.state,
  compute_status: .compute_status.state,
  deployment: .active_deployment.status.state,
  url: .url
}'
```

Wait until `app_status` is `RUNNING` and `deployment` is `SUCCEEDED` (typically 2-5 minutes).

### Foundation Model API (AI Triage tab)

The app defaults to `databricks-meta-llama-3-3-70b-instruct`. This is a pay-per-token
endpoint available on most workspaces. If your workspace uses a different model:

1. Check available endpoints: `databricks serving-endpoints list`
2. Update `SECOPS_LLM_ENDPOINT` in `app.yaml` to match your endpoint name

> **No Foundation Model access?** The AI Triage tab will show an error when you click
> "Run AI Triage". All other tabs work independently.

---

## Step 7: Genie Space (Manual — UI Only)

Genie Spaces cannot be created via CLI. Follow the instructions in
`02_genie_instructions.md` to create one through the workspace UI.

---

## Quick Reference: All Values to Configure

| Placeholder | Where it appears | What to set it to |
|-------------|------------------|-------------------|
| `YOUR_CATALOG` | `00_setup.sql`, `00_generate_logs.py`, `01_dlt_router.py`, `app.yaml`, `02_genie_instructions.md` | Your Unity Catalog name |
| `YOUR_WAREHOUSE_ID` | `app.yaml` (2 places) | Your SQL Warehouse ID |

### One-liner to configure everything

```bash
CATALOG="my_catalog"
WAREHOUSE_ID="abc123def456"

sed -i '' "s/YOUR_CATALOG/$CATALOG/g" 00_setup.sql 00_generate_logs.py 01_dlt_router.py app.yaml 02_genie_instructions.md
sed -i '' "s/YOUR_WAREHOUSE_ID/$WAREHOUSE_ID/g" app.yaml
```

---

## Tear Down

To remove all demo assets from the workspace:

```bash
WAREHOUSE_ID="<your-warehouse-id>"

# Delete the app
databricks apps delete secops-operator-view

# Delete the DLT pipeline
databricks pipelines delete <pipeline-id>

# Delete the job
databricks jobs delete <job-id>

# Drop all tables and the schema
for stmt in \
  "DROP TABLE IF EXISTS <your-catalog>.secops_demo.raw_firewall_logs" \
  "DROP TABLE IF EXISTS <your-catalog>.secops_demo.low_cost_archive" \
  "DROP TABLE IF EXISTS <your-catalog>.secops_demo.high_value_siem_feed" \
  "DROP VOLUME IF EXISTS <your-catalog>.secops_demo.raw_logs" \
  "DROP SCHEMA IF EXISTS <your-catalog>.secops_demo CASCADE"
do
  databricks api post /api/2.0/sql/statements \
    --json "{\"warehouse_id\":\"$WAREHOUSE_ID\",\"statement\":\"$stmt\",\"wait_timeout\":\"30s\"}"
done

# Remove workspace notebooks
databricks workspace delete /Users/$(databricks current-user me | jq -r .userName)/secops_demo --recursive
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `CATALOG_NOT_FOUND` | Wrong catalog name | Run `SHOW CATALOGS` and verify |
| `INSUFFICIENT_PRIVILEGES` on CREATE SCHEMA | No CREATE SCHEMA grant | Ask admin: `GRANT CREATE SCHEMA ON CATALOG <cat> TO <user>` |
| `INSUFFICIENT_PRIVILEGES` on CREATE VOLUME | No CREATE VOLUME grant | Ask admin: `GRANT CREATE VOLUME ON SCHEMA <cat>.secops_demo TO <user>` |
| DLT pipeline fails with `UC_COMMAND_NOT_SUPPORTED` | Unsupported function on serverless | Check DLT notebook doesn't use `input_file_name()` (already removed) |
| App shows "SQL Error" on all tabs | Warehouse ID wrong or SP not granted | Verify `DATABRICKS_WAREHOUSE_ID` in `app.yaml` and re-run SP grants |
| AI Triage returns "LLM Error" | Foundation Model endpoint not available | Check `databricks serving-endpoints list` for available LLM endpoints |
| System Posture tab shows "No data" | No access to `system.access.audit` | Normal — requires account admin grant. Other tabs still work. |
| App deployment stuck in `IN_PROGRESS` | Compute is provisioning | Wait 5 minutes. Check: `databricks apps get <name>` |
| `PRINCIPAL_DOES_NOT_EXIST` when granting SP access | Using display name instead of UUID | Use the `service_principal_client_id` (UUID format) from `databricks apps create` |

---

## File Inventory

| File | Purpose | Runs where |
|------|---------|-----------|
| `00_setup.sql` | Schema, table cleanup, volume creation | SQL Warehouse (via CLI) |
| `00_generate_logs.py` | Synthetic firewall log generator | Serverless job (notebook) |
| `01_dlt_router.py` | DLT pipeline: Auto Loader + smart routing | Serverless DLT |
| `app.py` | Streamlit Operator View (4 tabs) | Databricks Apps |
| `app.yaml` | App configuration, env vars, resources | Databricks Apps |
| `requirements.txt` | Python dependencies for the app | Databricks Apps |
| `02_genie_instructions.md` | Manual Genie Space setup guide | Human (UI) |
| `DEPLOY.md` | This file | Human (reference) |
