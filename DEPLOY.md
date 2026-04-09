# SecOps Data Lakehouse Demo — Deployment Guide

```
Raw JSON Logs -> UC Volume -> DLT Auto Loader -> Smart Router
                                                     |
                              +----------------------+-------------------+
                              v                                          v
                     low_cost_archive (95%)                high_value_siem_feed (5%)
                     ALLOW — cold storage                  DENY/THREAT — hot SIEM
                              |                                          |
                              +-------------------+----------------------+
                                                  v
                                        Streamlit Operator View
                                  (Metrics | Search | AI Triage | Posture)
```

**Business context:** Client spending too much on Google SecOps (Chronicle) for 35TB of
chatty logs. Databricks acts as a smart routing layer — only 5% of traffic needs expensive
SIEM processing, saving ~90% on log management costs.

---

## Defaults (works as-is on the author's workspace)

| Setting | Default value |
|---------|---------------|
| Workspace | `fevm-lr-serverless-aws-us.cloud.databricks.com` |
| Catalog | `lr_serverless_aws_us_catalog` |
| Schema | `secops_demo` |
| SQL Warehouse | `ab79eced8207d29b` |
| LLM Endpoint | `databricks-meta-llama-3-3-70b-instruct` |

---

## Deploying on a Different Workspace

### What you need to change

There are **two values** to replace. Every file that needs editing is listed below.

#### 1. Catalog name

> **Not everyone can create catalogs.** Most workspaces have pre-provisioned catalogs.
> Run `SHOW CATALOGS` on your SQL warehouse to see what's available. If you don't see
> one you can use, ask your workspace admin: *"Which Unity Catalog should I use?
> I need CREATE SCHEMA permission on it."*

| File | Line | Change `lr_serverless_aws_us_catalog` to your catalog |
|------|------|-------------------------------------------------------|
| `00_setup.sql` | `USE CATALOG ...` |
| `00_generate_logs.py` | `CATALOG = "..."` |
| `01_dlt_router.py` | `CATALOG = "..."` |
| `app.yaml` | `value:` under `SECOPS_CATALOG` |

The `app.py` reads the catalog from the `SECOPS_CATALOG` env var set in `app.yaml`,
so you only need to change it in `app.yaml`. The hardcoded default in `app.py` is a
fallback for local development.

#### 2. SQL Warehouse ID

Run `databricks warehouses list` to find your warehouse ID.

| File | Line | Change `ab79eced8207d29b` to your warehouse ID |
|------|------|------------------------------------------------|
| `app.yaml` | `value:` under `DATABRICKS_WAREHOUSE_ID` |
| `app.yaml` | `id:` under `resources > sql_warehouse` |

#### One-liner

```bash
OLD_CATALOG="lr_serverless_aws_us_catalog"
OLD_WH="ab79eced8207d29b"
NEW_CATALOG="my_catalog"
NEW_WH="my_warehouse_id"

sed -i '' "s/$OLD_CATALOG/$NEW_CATALOG/g" 00_setup.sql 00_generate_logs.py 01_dlt_router.py app.yaml app.py
sed -i '' "s/$OLD_WH/$NEW_WH/g" app.yaml app.py
```

#### LLM Endpoint (optional)

The default `databricks-meta-llama-3-3-70b-instruct` is a pay-per-token endpoint
available on most workspaces. If yours differs, update `SECOPS_LLM_ENDPOINT` in
`app.yaml`. Run `databricks serving-endpoints list` to check. The AI Triage tab
degrades gracefully if the endpoint is unavailable.

---

## Required Permissions

### For the deploying user

| Permission | On what | Why | How to check |
|------------|---------|-----|--------------|
| USE CATALOG | Your catalog | Access it | `SHOW CATALOGS` — if it appears, you have it |
| CREATE SCHEMA | Your catalog | Create `secops_demo` | Try it; ask admin if it fails |
| CREATE TABLE | The schema | DLT creates tables | Auto-granted to schema creator |
| CREATE VOLUME | The schema | Store raw JSON logs | Auto-granted to schema creator |
| CAN USE | A SQL Warehouse | Run queries | SQL Warehouses page in UI |
| Can create Apps | Workspace-level | Deploy Streamlit app | Settings > Workspace > Databricks Apps |
| CAN QUERY | Foundation Model endpoint | AI Triage | Default on pay-per-token endpoints |

### For `system.access.audit` (System Posture tab — optional)

Account admin must grant `SELECT ON system.access.audit`. If unavailable, the tab
shows "No data available" — other tabs work independently.

### For the App's service principal

When you run `databricks apps create`, the output includes a `service_principal_client_id`
(a UUID). Grant it access to your data:

```sql
GRANT USE CATALOG ON CATALOG <catalog> TO `<sp-uuid>`;
GRANT USE SCHEMA ON SCHEMA <catalog>.secops_demo TO `<sp-uuid>`;
GRANT SELECT ON SCHEMA <catalog>.secops_demo TO `<sp-uuid>`;
```

Run these via the SQL statements API or a SQL editor. Use the UUID, not the display name.

---

## Deployment Steps

### 1. Create schema

```bash
WH="<warehouse-id>"

databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WH\",\"statement\":\"USE CATALOG <catalog>\",\"wait_timeout\":\"30s\"}"

databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WH\",\"statement\":\"CREATE SCHEMA IF NOT EXISTS secops_demo\",\"wait_timeout\":\"30s\"}"

databricks api post /api/2.0/sql/statements \
  --json "{\"warehouse_id\":\"$WH\",\"statement\":\"CREATE VOLUME IF NOT EXISTS secops_demo.raw_logs\",\"wait_timeout\":\"30s\"}"
```

### 2. Upload notebooks and generate data

```bash
USER=$(databricks current-user me | jq -r .userName)

databricks workspace mkdirs /Users/$USER/secops_demo

databricks workspace import /Users/$USER/secops_demo/00_generate_logs \
  --file 00_generate_logs.py --format SOURCE --language PYTHON --overwrite

databricks workspace import /Users/$USER/secops_demo/01_dlt_router \
  --file 01_dlt_router.py --format SOURCE --language PYTHON --overwrite

JOB_ID=$(databricks jobs create --json "{
  \"name\": \"secops_demo_log_generator\",
  \"tasks\": [{
    \"task_key\": \"generate_logs\",
    \"notebook_task\": {\"notebook_path\": \"/Users/$USER/secops_demo/00_generate_logs\"},
    \"environment_key\": \"default\"
  }],
  \"environments\": [{\"environment_key\": \"default\", \"spec\": {\"client\": \"1\"}}]
}" | jq -r .job_id)

databricks jobs run-now $JOB_ID
```

### 3. Create and run DLT pipeline

```bash
PIPELINE_ID=$(databricks pipelines create --json "{
  \"name\": \"secops_smart_router\",
  \"serverless\": true,
  \"catalog\": \"<catalog>\",
  \"target\": \"secops_demo\",
  \"continuous\": false,
  \"development\": true,
  \"libraries\": [{\"notebook\": {\"path\": \"/Users/$USER/secops_demo/01_dlt_router\"}}],
  \"channel\": \"CURRENT\"
}" | jq -r .pipeline_id)

databricks pipelines start-update $PIPELINE_ID --full-refresh
```

Wait 2-3 minutes, then verify:

```bash
for tbl in raw_firewall_logs low_cost_archive high_value_siem_feed; do
  echo -n "$tbl: "
  databricks api post /api/2.0/sql/statements \
    --json "{\"warehouse_id\":\"$WH\",\"statement\":\"SELECT COUNT(*) FROM <catalog>.secops_demo.$tbl\",\"wait_timeout\":\"30s\"}" \
    | jq -r '.result.data_array[0][0]'
done
# Expected: ~5000, ~4750, ~250
```

### 4. Deploy the Streamlit app

```bash
APP_NAME="secops-operator-view"

# Create app (save the service_principal_client_id from the output)
databricks apps create --json "{\"name\":\"$APP_NAME\",\"description\":\"SecOps Operator View\"}"

# Grant SP access (see "Required Permissions" above)
SP_UUID="<service_principal_client_id>"
# ... run GRANT statements ...

# Upload source files
databricks workspace mkdirs /Users/$USER/secops_demo/app
for f in app.py app.yaml requirements.txt; do
  databricks workspace import /Users/$USER/secops_demo/app/$f --file $f --format AUTO --overwrite
done

# Deploy (port must be 8000 — Databricks Apps routes traffic there)
databricks apps deploy $APP_NAME \
  --source-code-path /Workspace/Users/$USER/secops_demo/app --no-wait
```

Check status: `databricks apps get $APP_NAME`

### 5. Genie Space (manual)

See `02_genie_instructions.md` — Genie Spaces require UI setup.

---

## Tear Down

```bash
databricks apps delete secops-operator-view
databricks pipelines delete <pipeline-id>
databricks jobs delete <job-id>

WH="<warehouse-id>"
for stmt in \
  "DROP SCHEMA IF EXISTS <catalog>.secops_demo CASCADE"; do
  databricks api post /api/2.0/sql/statements \
    --json "{\"warehouse_id\":\"$WH\",\"statement\":\"$stmt\",\"wait_timeout\":\"30s\"}"
done

databricks workspace delete /Users/$USER/secops_demo --recursive
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `CATALOG_NOT_FOUND` | Run `SHOW CATALOGS` and verify your catalog name |
| `INSUFFICIENT_PRIVILEGES` on CREATE SCHEMA | Ask admin: `GRANT CREATE SCHEMA ON CATALOG <cat> TO <user>` |
| DLT fails with `UC_COMMAND_NOT_SUPPORTED` | Don't use `input_file_name()` on serverless (already removed) |
| App returns 502 Bad Gateway | Streamlit must bind to port **8000** (not 8501) — check `app.yaml` |
| App shows "SQL Error" on all tabs | Wrong warehouse ID or SP not granted access |
| AI Triage returns "LLM Error" | Check `databricks serving-endpoints list` for available models |
| System Posture shows "No data" | Normal without `system.access.audit` access; other tabs work |
| `PRINCIPAL_DOES_NOT_EXIST` on SP grant | Use the UUID from `service_principal_client_id`, not the display name |

---

## Files

| File | Purpose | Runs on |
|------|---------|---------|
| `00_setup.sql` | Schema + volume creation | SQL Warehouse via CLI |
| `00_generate_logs.py` | Synthetic log generator (5k records) | Serverless notebook job |
| `01_dlt_router.py` | DLT: Auto Loader + smart routing | Serverless DLT |
| `app.py` | Streamlit Operator View (4 tabs) | Databricks Apps |
| `app.yaml` | App config, env vars, warehouse resource | Databricks Apps |
| `requirements.txt` | Python dependencies | Databricks Apps |
| `02_genie_instructions.md` | Genie Space setup (manual) | Human (UI) |
