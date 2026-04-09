-- SecOps Data Lakehouse Demo - Schema Setup
--
-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  CONFIGURE THIS: Set YOUR_CATALOG to the Unity Catalog you have       │
-- │  access to. See DEPLOY.md "Step 1: Identify Your Catalog" for help.   │
-- └─────────────────────────────────────────────────────────────────────────┘
-- Replace YOUR_CATALOG below with your actual catalog name.
-- Example: main, my_workspace_catalog, dev_catalog, etc.

USE CATALOG YOUR_CATALOG;

-- Create schema (requires CREATE SCHEMA privilege on the catalog)
CREATE SCHEMA IF NOT EXISTS secops_demo
COMMENT 'Security Data Lakehouse demo - smart routing, cold search, AI triage';

-- Drop existing tables from previous runs (safe to run on first deploy)
DROP TABLE IF EXISTS secops_demo.raw_firewall_logs;
DROP TABLE IF EXISTS secops_demo.low_cost_archive;
DROP TABLE IF EXISTS secops_demo.high_value_siem_feed;

-- Create volume for raw JSON log ingestion (requires CREATE VOLUME privilege)
CREATE VOLUME IF NOT EXISTS secops_demo.raw_logs;
