-- SecOps Data Lakehouse Demo - Schema Setup
-- Default catalog: lr_serverless_aws_us_catalog (see DEPLOY.md to change)

USE CATALOG lr_serverless_aws_us_catalog;

CREATE SCHEMA IF NOT EXISTS secops_demo
COMMENT 'Security Data Lakehouse demo - smart routing, cold search, AI triage';

DROP TABLE IF EXISTS secops_demo.raw_firewall_logs;
DROP TABLE IF EXISTS secops_demo.low_cost_archive;
DROP TABLE IF EXISTS secops_demo.high_value_siem_feed;

CREATE VOLUME IF NOT EXISTS secops_demo.raw_logs;
