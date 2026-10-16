# Procedure: Automating Notable Event Dispatch in Splunk ES 8
**App:** TA-splunk_to_fusion  
**Audience:** Detection Engineers, Security Content Developers, SOC Lead Analysts  

---

## 1. Overview
In addition to ad-hoc manual execution by analysts in the Mission Control Analyst Queue, `TA-splunk_to_fusion` supports automated dispatch of notable events into CrowdStrike Fusion SOAR and Next-Gen SIEM using two methods:

1. **Method A (Direct Detection Attachment):** Attach the Adaptive Response Action directly to a specific ES 8 Correlation Search / Detection.
2. **Method B (Policy-Based Scheduled Search):** Enable the included `Fusion - Auto Forward High and Critical Notables` saved search (or create custom policy searches) over the `` `s2f_notable_index` `` macro.

---

## 2. Method A: Attaching to an ES 8 Correlation Search

Use this method when you want a specific detection (e.g., "Ransomware Behavior Detected" or "Domain Controller DCSync") to always trigger an immediate CrowdStrike workflow.

### Step-by-Step Instructions:
1. In Splunk Enterprise Security, go to **Configure > Content > Content Management** (or **Security Content > Detections** in ES 8).
2. Locate the detection rule you wish to automate and click on its name to edit.
3. Scroll down to the **Adaptive Response Actions** section.
4. Click **Add Action** and select **Send to CrowdStrike Fusion**.
5. Configure the parameters:
   - **Delivery Method:** `fusion_workflow` (default), `ngsiem_hec`, or `both`.
   - **Workflow Override:** (Optional) Enter the specific Workflow Name or 32-character Definition ID to execute for this rule.
   - **Analyst Comment:** (Optional) Enter context such as `Automated escalation triggered by correlation search`.
6. Click **Save**.
7. Every time this detection fires and generates a notable event, Splunk ES will automatically invoke the action, cache OAuth2 tokens via `s2f_broker.py`, and write the CrowdStrike execution ID note back to the ES 8 finding.

---

## 3. Method B: Policy-Based Automated Forwarding via Saved Search

Use this method when you want centralized governance over what gets forwarded to CrowdStrike after notable events are indexed, without editing individual correlation searches.

### Enabling the Built-In Policy Search:
1. In Splunk Web, navigate to **Settings > Searches, reports, and alerts**.
2. Filter by App: **Splunk to CrowdStrike Fusion (`TA-splunk_to_fusion`)**.
3. Locate **`Fusion - Auto Forward High and Critical Notables`**:
   ```spl
   `s2f_notable_index` urgency IN ("high", "critical")
   | search NOT [ search `s2f_logs` status=success (action=execute_workflow OR action=send_hec) | fields event_id ]
   | table _time, event_id, rule_id, rule_name, urgency, severity, security_domain, status_label, owner, src, dest, user
   ```
4. Click **Edit > Edit Schedule**, check **Schedule Alert**, and click **Save** (or click **Edit > Enable**).

### Why this is safe:
- **Multi-Layer Deduplication:**
  1. The subsearch excludes any `event_id` already logged as `status=success` in `` `s2f_logs` ``.
  2. CrowdStrike's `/workflows/entities/execute/v1` endpoint receives `?key=<event_id>` for server-side idempotency.
- **Batch `results_file` Support:** When multiple findings match in a single 5-minute window, `send_to_fusion.py` reads all rows from Splunk's `.csv.gz` `results_file` and dispatches each finding cleanly.

---

## 4. Payload Schema & Field Mapping for Fusion Workflows

When `send_to_fusion` dispatches an event, it maps standard ES fields at the top level and places all additional non-internal fields (`not k.startswith("_")`) into `details`:

```json
{
  "event_id": "12345@@notable@@es",
  "rule_name": "Suspicious PowerShell Execution",
  "urgency": "high",
  "severity": "critical",
  "security_domain": "endpoint",
  "status": "New",
  "owner": "unassigned",
  "src": "workstation-01.corp",
  "dest": "fileserver-02.corp",
  "user": "victim_user",
  "analyst_comment": "Auto-forwarded by Fusion saved search",
  "details": {
    "process": "powershell.exe -enc ...",
    "parent_process": "cmd.exe",
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "risk_score": "85"
  }
}
```
