# Databricks notebook source
# MAGIC %md
# MAGIC # SecOps DLT Smart Router
# MAGIC Reads raw firewall JSON logs from a UC volume via Auto Loader and routes them:
# MAGIC - **ALLOW** -> `low_cost_archive` (cheap cold storage, 95% of traffic)
# MAGIC - **DENY / THREAT** -> `high_value_siem_feed` (hot tier for investigation, 5% of traffic)
# MAGIC
# MAGIC ---
# MAGIC **About this demo:** This is not a Databricks product. It is a working demonstration built on the Databricks platform
# MAGIC using Declarative Pipelines, Unity Catalog, Foundation Model APIs, Vector Search, and Databricks Apps. All processes
# MAGIC are real and running. The data is synthetic. Source code: [github.com/wryszka/secops_demo](https://github.com/wryszka/secops_demo)

# COMMAND ----------

import dlt
from pyspark.sql.functions import col, current_timestamp

# COMMAND ----------

# Configuration — see DEPLOY.md to change for your workspace
CATALOG = "lr_serverless_aws_us_catalog"
SCHEMA = "secops_demo"
VOLUME_PATH = f"/Volumes/{CATALOG}/{SCHEMA}/raw_logs"

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

@dlt.table(
    name="high_value_siem_feed",
    comment="5% of traffic - DENY/THREAT logs routed to hot SIEM tier",
    table_properties={"quality": "silver"}
)
def high_value_siem_feed():
    return (
        dlt.read_stream("raw_firewall_logs")
        .filter(col("action").isin("DENY", "THREAT"))
    )
