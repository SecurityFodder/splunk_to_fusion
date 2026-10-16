# Operations & Support Runbook
**App:** TA-splunk_to_fusion  
**System:** Splunk Enterprise Security 8 → CrowdStrike Falcon Fusion SOAR & Next-Gen SIEM  
**Audience:** Tier 2 / Tier 3 SOC Support, Splunk Platform Operations  

---

## 1. System Overview & Views

The app provides three views accessible from **Apps > Splunk to CrowdStrike Fusion**:

1. **CrowdStrike Fusion - Operational Overview (`fusion_overview`):**
   - **Key Metrics:** Total dispatches, success rate %, failure count, and average API latency (ms).
   - **Usage:** Monitor daily dispatch volume, trends by ES detection rule, and individual CrowdStrike execution IDs.
2. **CrowdStrike Fusion - System Health & Diagnostics (`fusion_health`):**
   - **Key Metrics:** Breakdown of errors by category (Auth 401/403, Rate Limiting 429, Proxy/TLS, Server 5xx).
   - **Usage:** Investigate failures, view raw error traces, and monitor proxy/CA health.
3. **Configuration (`fusion_setup`):**
   - **Usage:** Update API credentials, proxy settings, or workflow defaults and run **Test CrowdStrike Connection**.

---

## 2. Alert Response Procedures

*(Note: Ensure the health alert saved searches in `Settings > Searches, reports, and alerts` are enabled after onboarding).*

### Alert 1: `Fusion - Authentication Failure Alert`
- **Severity:** Critical (Priority 1)
- **Condition:** CrowdStrike API returns HTTP `401` or `403` ("Invalid client" or "Access denied").
- **Probable Causes:**
  1. The CrowdStrike API Client Secret has expired or was regenerated in the Falcon Console.
  2. The API Client ID in `local/ta_splunk_to_fusion.conf` is misconfigured.
  3. The API client lacks the `Workflows: Read & Write` scope.
- **Triage & Remediation:**
  1. Check raw error in Splunk:
     ```spl
     `s2f_logs` status=failure (status_code=401 OR status_code=403)
     | table _time, status_code, error_msg, _raw
     ```
  2. Log into the CrowdStrike Falcon Console and verify the API Client ID and its active scopes under **Support and resources > API clients and keys**.
  3. Open **Apps > Splunk to CrowdStrike Fusion > Configuration**, paste the new **OAuth2 API Client Secret**, click **Save Configuration**, and click **Test CrowdStrike Connection**.

---

### Alert 2: `Fusion - Proxy or TLS Failure Alert`
- **Severity:** High (Priority 2)
- **Condition:** Outbound connections fail due to proxy authentication (`407`), connection refusal, or SSL certificate validation failures (`SSLError`, `CERTIFICATE_VERIFY_FAILED`).
- **Probable Causes:**
  1. Corporate proxy is down, misrouted, or requires updated proxy credentials.
  2. Enterprise Root/Intermediate CA certificate expired or was rotated on the proxy without updating the app's `certs/` folder.
- **Triage & Remediation:**
  1. Determine exact failure mode:
     ```spl
     `s2f_logs` status=failure ("SSLError" OR "certificate" OR "Proxy" OR "407")
     | table _time, host, error_msg, _raw
     ```
  2. **If TLS/SSLError:** Follow [SOP-S2F-001 (CA Certificate Management)](./PROCEDURE_CERTIFICATE_UPDATE.md) to update `certs/corp_ca.pem`.
  3. **If 407 Proxy Authentication Required:** Verify the **HTTP/HTTPS Proxy URL** in **Apps > Splunk to CrowdStrike Fusion > Configuration** (or store an authenticated `proxy_url` entry in `storage/passwords`).

---

### Alert 3: `Fusion - High Failure Rate Alert`
- **Severity:** High (Priority 2)
- **Condition:** More than 10% of transmissions fail within a 15-minute window (minimum 5 events).
- **Probable Causes:**
  1. Temporary CrowdStrike cloud service degradation (HTTP 502/503/504).
  2. The target Fusion workflow was deleted, disabled, or renamed in CrowdStrike.
- **Triage & Remediation:**
  1. Identify failing rules and status codes:
     ```spl
     `s2f_logs` status=failure
     | stats count by status_code, rule_name, error_msg
     ```
  2. Check CrowdStrike Cloud Status (`status.crowdstrike.com`) for service incidents.
  3. If status code is `400`: Verify in the Falcon Console that the on-demand workflow is enabled and its Name or Definition ID matches the Splunk configuration.

---

## 3. Error Code Reference & Recovery Matrix

| HTTP Code / Error | Meaning | Action / Recovery |
|---|---|---|
| **400 Bad Request** | Invalid payload schema or non-existent workflow definition. | Verify that the workflow name or definition ID matches an active on-demand workflow in Falcon. |
| **401 Unauthorized** | Invalid API client credentials or expired token. | Handled automatically with one token refresh retry. If persistent, update Client Secret on Configuration page. |
| **403 Forbidden** | API client lacks required permissions, or Splunk user lacks `s2f_send` / `s2f_admin`. | In Falcon Console, ensure `Workflows: Read & Write` scopes. In Splunk, check role capabilities in `authorize.conf`. |
| **404 Not Found** | Target URL or endpoint does not exist. | Check `falcon_cloud` (`eu-1`, `us-1`, etc.) or `ngsiem_hec_url`. |
| **407 Proxy Auth** | Proxy rejected connection due to missing/invalid credentials. | Update `proxy_url` on the Configuration page or in `storage/passwords`. |
| **429 Too Many Requests** | Rate limit exceeded. | Handled automatically by exponential backoff (`Retry-After`). If persistent, investigate burst volume. |
| **500 / 502 / 503 / 504** | CrowdStrike backend or gateway outage. | Handled automatically by retry logic. Check CrowdStrike status portal. |
| **SSLError** | Proxy TLS re-signing certificate untrusted. | Update enterprise public CA cert in `certs/` as per SOP-S2F-001. |

---

## 4. Helpful Support Searches

### Check Recent Dispatches Across Search Head Cluster
```spl
`s2f_logs` action=execute_workflow
| table _time, host, status, event_id, rule_name, exec_id, duration_ms
| sort - _time
```

### Correlate ES Findings with Fusion Dispatch Status
```spl
`s2f_notable_index`
| fields event_id, rule_name, urgency, user, src, dest
| join type=left event_id [
    search `s2f_logs` action=execute_workflow
    | rename exec_id as cs_execution_id, status as cs_status
    | fields event_id, cs_execution_id, cs_status
]
| table event_id, rule_name, urgency, cs_status, cs_execution_id
```
