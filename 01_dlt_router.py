# Databricks notebook source
# MAGIC %md
# MAGIC # SecOps DLT Smart Router
# MAGIC Delta Live Tables pipeline that reads raw firewall JSON logs from a Unity Catalog volume
# MAGIC via Auto Loader and routes them:
# MAGIC - **ALLOW** -> `low_cost_archive` (cheap cold storage, 95% of traffic)
# MAGIC - **DENY / THREAT** -> `high_value_siem_feed` (hot tier for investigation, 5% of traffic)
# MAGIC
# MAGIC This proves the Databricks cost-savings thesis: only 5% of data needs expensive SIEM processing.

# COMMAND ----------

import dlt
from pyspark.sql.functions import col, current_timestamp

# COMMAND ----------

# ┌─────────────────────────────────────────────────────────────────────────┐
# │  CONFIGURE THIS: Set CATALOG to the Unity Catalog you have access to. │
# │  See DEPLOY.md "Step 1: Identify Your Catalog" for help.              │
# └─────────────────────────────────────────────────────────────────────────┘
CATALOG = "YOUR_CATALOG"        # <-- REPLACE with your catalog name
SCHEMA = "secops_demo"
VOLUME_PATH = f"/Volumes/{CATALOG}/{SCHEMA}/raw_logs"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Bronze: Ingest raw JSON with Auto Loader

# COMMAND ----------

@dlt.table(
    name="raw_firewall_logs",
    comment="Raw firewall logs ingested from JSON via Auto Loader",
    table_properties={"quality": "bronze"}
)
def raw_firewall_logs():
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.inferColumnTypes", "true")
        .load(VOLUME_PATH)
        .withColumn("_ingested_at", current_timestamp())
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Silver: Route ALLOW to Low-Cost Archive

# COMMAND ----------

@dlt.table(
    name="low_cost_archive",
    comment="95% of traffic - ALLOW logs routed to low-cost storage tier",
    table_properties={"quality": "silver"}
)
def low_cost_archive():
    return (
        dlt.read_stream("raw_firewall_logs")
        .filter(col("action") == "ALLOW")
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Silver: Route DENY/THREAT to High-Value SIEM Feed

# COMMAND ----------

@dlt.table(
    name="high_value_siem_feed",
    comment="5% of traffic - DENY and THREAT logs routed to hot SIEM tier for investigation",
    table_properties={"quality": "silver"}
)
def high_value_siem_feed():
    return (
        dlt.read_stream("raw_firewall_logs")
        .filter(col("action").isin("DENY", "THREAT"))
    )
