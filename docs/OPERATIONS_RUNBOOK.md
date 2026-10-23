# Operations & Support Runbook
**App:** `TA-splunk_to_fusion`  
**System:** Splunk Enterprise Security 8 → CrowdStrike Falcon (Fusion SOAR, Next-Gen SIEM, Cases, and IOCs)  
**Audience:** SOC Analysts, Support Engineers (Tier 1–3), and Splunk Platform Administrators  

This runbook explains how to monitor `TA-splunk_to_fusion`, what each health alert means, and the exact steps to fix common issues—even if you are new to Splunk or CrowdStrike.

---

## 1. Quick Architecture & Log Reference

Before troubleshooting, it helps to know how data flows and where logs live:

1. **Where Findings Start:** Either an analyst clicks **Send to CrowdStrike Fusion** in the ES 8 Analyst Queue, or a scheduled correlation search triggers `bin/send_to_fusion.py`.
2. **How Credentials & Tenants Are Handled:** `send_to_fusion.py` forwards the event to a local background service (`bin/s2f_broker.py` at `/services/ta_s2f/broker`). The broker resolves the target CrowdStrike tenant (`default` from `[settings]`, or `[cid:<name>]`), reads the encrypted CrowdStrike API keys from Splunk's password store, caches a 30-minute OAuth2 token in memory, and calls CrowdStrike.
3. **Where Logs Are Written:** Every attempt is logged to `$SPLUNK_HOME/var/log/splunk/send_to_fusion.log` and indexed into Splunk's `_internal` index.
4. **How to Search Logs in Splunk:** Open the Splunk Search bar and run the included macro (including the backticks `` ` ``):
   ```spl
   `s2f_logs`
   ```
   *(Under the hood, `` `s2f_logs` `` expands to `index=_internal (sourcetype="send_to_fusion" OR sourcetype="modular_alerts:send_to_fusion" OR source="*send_to_fusion.log")`).*

### Key Fields in `` `s2f_logs` ``

| Field Name | Example Value | What It Tells You |
|---|---|---|
| `status` | `success`, `failure`, or `skipped` | Whether the action succeeded, failed, or was skipped (for example, when an IOC field was empty on that event). |
| `action` | `execute_workflow`, `send_hec`, `create_case`, `save_ioc`, `alert_action_complete` | Which step of the delivery process wrote the log line. |
| `delivery_method` | `fusion_workflow`, `ngsiem_hec`, `both`, `none` | Which primary delivery mode was selected on the alert action. |
| `event_id` | `12345@@notable@@es` | The unique ID of the Splunk ES Finding. |
| `rule_name` | `Suspicious PowerShell Execution` | The name of the Splunk ES detection rule that generated the Finding. |
| `exec_id` | `a1b2c3d4...` | The unique Execution ID returned by CrowdStrike Fusion SOAR when a workflow starts. |
| `case_id` | `case-123...` | The CrowdStrike Case ID when `create_case=always` is enabled. |
| `ioc_type` / `ioc_value` | `ipv4` / `10.0.0.1` | The indicator type and value saved when `ioc_action` is `detect` or `prevent`. |
| `status_code` | `401`, `403`, `429`, `503` | The HTTP status code returned by CrowdStrike or the corporate proxy when an error occurs. |
| `error_msg` | `CrowdStrike API error 401: Unauthorized` | The human-readable error reason. |
| `duration_ms` | `340` | How long the API request took in milliseconds. |

---

## 2. Built-in Dashboards

Open **Apps > Splunk to CrowdStrike Fusion** in Splunk Web to access three views:

1. **CrowdStrike Fusion - Operational Overview (`fusion_overview`):**
   - **What it shows:** Total dispatches, Success Rate %, Failed Dispatches, Average API Latency (ms), top triggering ES detection rules, and a table of recent CrowdStrike Execution IDs (across workflows, HEC, cases, and IOCs).
   - **When to use it:** Daily health checks or verifying that a specific ES Finding was delivered to CrowdStrike.
2. **CrowdStrike Fusion - System Health & Diagnostics (`fusion_health`):**
   - **What it shows:** Failures broken down into four buckets: **Authentication Errors (401/403)**, **Rate Limit Events (429)**, **Proxy / TLS Interception Errors**, and **Server / Gateway Errors (5xx)**, followed by a searchable raw error log table.
   - **When to use it:** Whenever `Failed Dispatches` is greater than 0 or a health alert fires.
3. **Configuration (`fusion_setup`):**
   - **What it shows:** Tenant (`CID`) selector, CrowdStrike API credentials, default workflow, HEC URL/token, and proxy/CA settings, plus the **Test CrowdStrike Connection** button.

---

## 3. Alert Response Procedures

*(Note: Ensure the health alert saved searches in `Settings > Searches, reports, and alerts` are enabled after onboarding).*

### Alert 1: `Fusion - Authentication Failure Alert`
- **Severity:** Critical (Priority 1 — Events for the affected tenant cannot be delivered while authentication is failing)
- **Condition:** CrowdStrike API returns HTTP `401` or `403` ("Invalid client" or "Access denied").
- **Probable Causes:**
  1. The CrowdStrike API Client Secret has expired or was regenerated in the Falcon Console.
  2. The API Client ID or Falcon Cloud Region in `local/ta_splunk_to_fusion.conf` is misconfigured for the target tenant (`default` or `[cid:<name>]`).
  3. (For `403 Forbidden`) The API client lacks required scopes (`Workflows: Read & Write`, or `Cases` / `IOCs` scopes if the rule creates cases or saves IOCs).
- **Triage & Remediation:**
  1. Check the raw error in Splunk:
     ```spl
     `s2f_logs` status=failure (status_code=401 OR status_code=403 OR "Invalid client")
     | table _time, host, action, rule_name, status_code, error_msg, _raw
     ```
  2. Log into the CrowdStrike Falcon Console and verify the API Client ID and its active scopes under **Support and resources > API clients and keys**.
  3. Open **Apps > Splunk to CrowdStrike Fusion > Configuration**, select the affected **CrowdStrike Tenant (CID)** from the dropdown, paste the valid **OAuth2 API Client Secret**, click **Save Configuration**, and click **Test CrowdStrike Connection**.

---

### Alert 2: `Fusion - Proxy or TLS Failure Alert`
- **Severity:** High (Priority 2)
- **Condition:** Outbound connections fail due to proxy authentication (`407`), connection refusal, or SSL certificate validation failures (`SSLError`, `CERTIFICATE_VERIFY_FAILED`).
- **Probable Causes:**
  1. Corporate proxy is down, misrouted, or requires updated proxy credentials.
  2. Enterprise Root/Intermediate CA certificate expired or was rotated on the proxy without updating the app's `certs/` folder.
- **Triage & Remediation:**
  1. Determine the exact failure mode:
     ```spl
     `s2f_logs` status=failure ("SSLError" OR "certificate" OR "Proxy" OR "407")
     | table _time, host, error_msg, _raw
     ```
  2. **If TLS/SSLError:** Follow [SOP-S2F-001 (CA Certificate Management)](./PROCEDURE_CERTIFICATE_UPDATE.md) to update `certs/corp_ca.pem`.
  3. **If 407 Proxy Authentication Required:** Verify the **HTTP/HTTPS Proxy URL** under **Advanced** in **Apps > Splunk to CrowdStrike Fusion > Configuration** (e.g., `http://user:pass@proxy.example.com:8080` or store an authenticated `proxy_url` entry in `storage/passwords`).

---

### Alert 3: `Fusion - High Failure Rate Alert`
- **Severity:** High (Priority 2)
- **Condition:** More than 10% of transmissions (`execute_workflow`, `send_hec`, `create_case`, or `save_ioc`) fail within a 15-minute window (minimum 5 events).
- **Probable Causes:**
  1. Temporary CrowdStrike cloud service degradation (HTTP 502/503/504).
  2. The target Fusion workflow was deleted, disabled, or renamed in CrowdStrike (`HTTP 400`).
  3. An alert action enabled `create_case` or `ioc_action` on an API client that does not have Cases or IOC scopes (`HTTP 403`).
- **Triage & Remediation:**
  1. Identify failing rules, actions, and status codes:
     ```spl
     `s2f_logs` status=failure
     | stats count by action, status_code, rule_name, error_msg
     ```
  2. Check CrowdStrike Cloud Status (`status.crowdstrike.com`) for service incidents.
  3. If `status_code=400` on `action=execute_workflow`: Verify in the Falcon Console that the on-demand workflow is **Enabled** and its Name or Definition ID matches the Splunk configuration.

---

## 4. Error Code Reference & Recovery Matrix

| HTTP Code / Error | Plain-English Meaning | Action / Recovery |
|---|---|---|
| **`No workflow ID or name specified`** | `delivery_method` is `fusion_workflow` or `both`, but neither the alert action nor the tenant config has a workflow specified. | Set **Default Fusion Workflow** on the Configuration page, or set **Delivery Method** to `None (Case/IOC only)` if only creating cases/IOCs. |
| **400 Bad Request** | Invalid payload schema, disabled workflow, or non-existent workflow definition. | Verify that the workflow name or definition ID matches an active, **Enabled** on-demand workflow in Falcon. |
| **401 Unauthorized** | Invalid API client credentials or expired token. | Handled automatically with one token refresh retry. If persistent, update Client Secret on Configuration page for that tenant. |
| **403 Forbidden** | CrowdStrike API client lacks required scopes, or Splunk user lacks `s2f_send` / `s2f_admin`. | In Falcon Console, ensure `Workflows: Write` (plus Cases/IOCs scopes if used). In Splunk, check role capabilities in `authorize.conf`. |
| **404 Not Found** | Target URL or endpoint does not exist. | Check `falcon_cloud` (`eu-1`, `us-1`, etc.) or `ngsiem_hec_url`. |
| **407 Proxy Auth** | Proxy rejected connection due to missing/invalid credentials. | Update `proxy_url` under **Advanced** on the Configuration page or in `storage/passwords`. |
| **429 Too Many Requests** | Rate limit exceeded. | Handled automatically by exponential backoff (`Retry-After`). If persistent, investigate burst volume on noisy detections. |
| **500 / 502 / 503 / 504** | CrowdStrike backend or gateway outage. | Handled automatically by retry logic. Check CrowdStrike status portal. |
| **SSLError** | Proxy TLS re-signing certificate untrusted. | Update enterprise public CA cert in `certs/` as per [SOP-S2F-001](./PROCEDURE_CERTIFICATE_UPDATE.md). |
| **`status=skipped action=save_ioc`** | `ioc_action` was enabled, but none of the fields listed in `ioc_fields` had valid indicator values on that Finding. | Informational warning—verify the field names in `ioc_fields` match the fields output by your detection search. |

---

## 5. Helpful Support Searches

### Check Recent Dispatches Across Search Head Cluster
```spl
`s2f_logs` (action=execute_workflow OR action=send_hec OR action=create_case OR action=save_ioc)
| table _time, host, action, status, event_id, rule_name, exec_id, case_id, ioc_value, duration_ms
| sort - _time
```

### Correlate ES Findings with CrowdStrike Dispatch Status
```spl
`s2f_notable_index`
| fields event_id, rule_name, urgency, user, src, dest
| join type=left event_id [
    search `s2f_logs` (action=execute_workflow OR action=send_hec OR action=create_case OR action=save_ioc)
    | rename exec_id as cs_execution_id, status as cs_status
    | fields event_id, cs_execution_id, cs_status
]
| table event_id, rule_name, urgency, cs_status, cs_execution_id
```
