# Procedure: Automating Notable Event Dispatch in Splunk ES 8
**App:** `TA-splunk_to_fusion`  
**Audience:** Detection Engineers, Security Content Developers, SOC Analysts, and Splunk Administrators  

In addition to ad-hoc manual execution by analysts in the Mission Control Analyst Queue, `TA-splunk_to_fusion` supports automated dispatch of notable events (findings) into CrowdStrike using two methods:

| Feature | Method A: Direct Detection Attachment | Method B: Policy-Based Scheduled Search |
|---|---|---|
| **How it works** | Attach the **Send to CrowdStrike Fusion** Adaptive Response action directly to an ES 8 Correlation Search / Detection. | Enable the included `Fusion - Auto Forward High and Critical Notables` saved search (or create custom policy searches) over `` `s2f_notable_index` ``. |
| **Speed** | **Immediate** — Fires as soon as the detection generates a Finding. | **Near real-time** — Runs on a 5-minute cron schedule (`*/5 * * * *`). |
| **Per-Rule Customization** | Configure a specific tenant (`cid`), workflow override, Case creation (`create_case`), or IOC saving (`ioc_action` / `ioc_fields`) per detection rule. | Applies one uniform action configuration to all matching High/Critical Findings. |

---

## 1. Method A: Attaching to an ES 8 Correlation Search

Use this method when you want a specific detection (e.g., *Ransomware Behavior Detected* or *Domain Controller DCSync*) to immediately trigger a CrowdStrike workflow, open a Falcon Case, or block IOCs.

### Step-by-Step Instructions
1. In Splunk Enterprise Security, go to **Configure > Content > Content Management** (or **Security Content > Detections** in ES 8).
2. Locate the detection rule you wish to automate and click on its name to edit.
3. Scroll down to the **Adaptive Response Actions** section.
4. Click **Add Action** and select **Send to CrowdStrike Fusion**.
5. Configure the parameters for this rule:
   - **CID / Tenant (`cid`):** *(Optional)* Leave blank to use the `default` tenant (`[settings]`), or enter the name of a `[cid:<name>]` tenant configured on the Configuration page.
   - **Delivery Method (`delivery_method`):**
     - `CrowdStrike Fusion SOAR Workflow` (`fusion_workflow`) — Triggers an on-demand workflow.
     - `CrowdStrike Next-Gen SIEM HEC` (`ngsiem_hec`) — Sends the raw Finding JSON to NG-SIEM HEC.
     - `Both (Workflow + NG-SIEM HEC)` (`both`) — Sends to both destinations.
     - `None (Case/IOC only)` (`none`) — Skips workflow and HEC execution (useful when you only want this rule to open a Falcon Case or save IOCs).
   - **Workflow Override (`workflow`):** *(Optional)* Enter a specific Workflow Name or 32-character Definition ID for this rule, or leave blank to use the tenant's `default_workflow`.
   - **Create Case (`create_case`):** Choose `Always` (`always`) to automatically open a CrowdStrike Falcon Case for each Finding, or `None` (`none`).
   - **Case Name (`case_name`) & Case Tags (`case_tags`):** *(Optional)* Custom name (defaults to `rule_name`) and comma-separated tags (defaults to `splunk, notable`).
   - **IOC Action (`ioc_action`):** Choose `Detect` (`detect` — alert only), `Prevent` (`prevent` — block indicator across endpoints), or `None` (`none`).
   - **IOC Fields (`ioc_fields`):** Comma-separated list of fields from the search result whose values should be saved as IOCs (for example: `sha256, src_ip, dest_ip, domain`).
     - *How IOC type detection works:* You do not need to specify indicator types manually. The add-on inspects each field's value and automatically classifies it as `ipv4`, `ipv6`, `sha256` (64 hex chars), `sha1` (40 hex chars), `md5` (32 hex chars), or `domain` (up to 10 indicators per Finding). Values that are empty or do not match a valid indicator format are safely skipped.
   - **Analyst Comment (`comment`):** *(Optional)* Enter context such as `Automated escalation triggered by correlation search`.
6. Click **Save**.
7. Every time this detection fires and generates a notable event, Splunk ES will automatically invoke the action through `s2f_broker.py` and write the confirmation note back to the ES 8 finding.

---

## 2. Method B: Policy-Based Automated Forwarding via Saved Search

Use this method when you want centralized governance over what gets forwarded to CrowdStrike after notable events are indexed, without editing individual correlation searches.

### Enabling the Built-In Policy Search
1. In Splunk Web, navigate to **Settings > Searches, reports, and alerts**.
2. Filter by App: **Splunk to CrowdStrike Fusion (`TA-splunk_to_fusion`)**.
3. Locate **`Fusion - Auto Forward High and Critical Notables`**:
   ```spl
   `s2f_notable_index` urgency IN ("high", "critical")
   | search NOT [ search `s2f_logs` status=success (action=execute_workflow OR action=send_hec OR action=create_case OR action=save_ioc) | fields event_id ]
   | table _time, event_id, rule_id, rule_name, urgency, severity, security_domain, status_label, owner, src, dest, user
   ```
4. Click **Edit > Edit Schedule**, check **Schedule Alert**, and click **Save** (or click **Edit > Enable**).

### Why This Is Safe
- **Multi-Layer Deduplication:**
  1. The subsearch excludes any `event_id` already logged as `status=success` in `` `s2f_logs` `` across workflow, HEC, case, or IOC actions.
  2. CrowdStrike's `/workflows/entities/execute/v1` endpoint receives `?key=<event_id>` for server-side idempotency.
- **Batch `results_file` Support:** When multiple findings match in a single 5-minute window, `send_to_fusion.py` reads all rows from Splunk's `.csv.gz` `results_file` and dispatches each finding cleanly while reusing the cached OAuth2 token.

---

## 3. Payload Schema & Field Mapping Reference

When `send_to_fusion` dispatches an event, it maps standard ES fields at the top level (automatically falling back from `src_ip` → `src`, `dest_ip` → `dest`, `src_user` → `user`, and `search_name` → `rule_name`) and places all additional non-internal fields (`not k.startswith("_")`) into `details`:

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

If an event contains unusually large fields causing the JSON payload to exceed **240 KB**, `CrowdStrikeClient` preserves all top-level fields and replaces `details` with `{"truncated": true, "notice": "Event details exceeded 240KB limit."}` so CrowdStrike's 256 KB API limit never rejects the alert.
