# TA-splunk_to_fusion
**Splunk Enterprise Security 8 → CrowdStrike Falcon Integration Add-on**

`TA-splunk_to_fusion` is a lightweight Splunk Add-on (Technical Add-on / TA) that forwards security alerts from **Splunk Enterprise Security (ES 8)** to **CrowdStrike Falcon**. From a single alert action, it can:
- Trigger automated response playbooks in **CrowdStrike Falcon Fusion SOAR**,
- Forward raw alert JSON to **CrowdStrike Next-Gen SIEM** over HTTP Event Collector (HEC),
- Open **Falcon Cases** (with custom names and tags), and
- Save **Indicators of Compromise (IOCs)** extracted from event fields in `detect` or `prevent` mode.

A single Splunk deployment can route findings to **multiple CrowdStrike tenants (CIDs)**.

---

## Core Concepts & Terminology

If you are new to Splunk Enterprise Security or CrowdStrike Falcon, here is how the key terms in this repository map to each platform:

| Term | Platform | What It Means |
|---|---|---|
| **Technical Add-on (`TA`)** | Splunk | A packaged Splunk app that adds backend integrations, scripts, and alert actions. |
| **Notable Event / Finding** | Splunk ES | A high-priority security alert created when a Splunk detection rule (correlation search) matches suspicious activity. Called a *Notable Event* in classic ES and a *Finding* in ES 8 Mission Control. |
| **Adaptive Response Action** | Splunk ES | A manual button (in the ES Analyst Queue) or automated trigger (on a correlation search) that runs an external integration on a Finding. |
| **Search Head & Deployer** | Splunk | **Search Heads** run searches and host the Splunk Web UI. In a **Search Head Cluster (SHC)**, multiple Search Heads share the load, and a **Deployer** server pushes apps to all cluster members at once. |
| **Macro (`` `s2f_logs` ``)** | Splunk | A reusable search shortcut in Splunk. Typing `` `s2f_logs` `` in the search bar expands to search all internal logs written by this add-on. |
| **CID (Customer ID / Tenant)** | CrowdStrike | A distinct CrowdStrike Falcon environment/account. This add-on supports a primary `default` tenant (`[settings]`) plus any number of named `[cid:<name>]` tenants. |
| **Falcon Fusion SOAR** | CrowdStrike | CrowdStrike's built-in orchestration engine. It executes automated **Workflows** (playbooks) when triggered via API. |
| **Next-Gen SIEM HEC** | CrowdStrike | **HTTP Event Collector (HEC)** is an HTTPS ingestion endpoint in CrowdStrike that accepts raw JSON events (`Bearer <token>`) for log search and correlation. |
| **Falcon Cases & IOCs** | CrowdStrike | **Cases** track investigations in Falcon; **Custom IOCs** tell Falcon to `detect` (alert on) or `prevent` (block) specific SHA256/SHA1/MD5 hashes, IPv4/IPv6 addresses, or domains across endpoints. |
| **SSL Inspection & CA Bundle** | Network | Corporate proxies often decrypt and re-sign outbound HTTPS traffic using an internal Certificate Authority (CA). Placing your company's public `.pem`/`.crt` certificate in `certs/` allows Python to verify the proxy's TLS certificate. |

---

## End-to-End Request Flow

When an analyst runs **Send to CrowdStrike Fusion** (or a correlation search triggers it automatically):

1. **Trigger (`bin/send_to_fusion.py`):** Splunk invokes `send_to_fusion.py` and passes the Finding fields on `stdin` (and/or a compressed `.csv.gz` `results_file` for batch searches).
2. **Security Broker (`bin/s2f_broker.py`):** The script forwards the request to the local persistent REST endpoint (`/services/ta_s2f/broker`). Because the broker runs under `splunkd` with `passSystemAuth = true`, standard SOC analysts only need the `s2f_send` capability—they never need direct read access (`list_storage_passwords`) to Splunk's password store.
3. **CrowdStrike Client (`bin/crowdstrike.py`):** The broker resolves the target tenant (`default` or `[cid:<name>]`), decrypts the stored OAuth2 Client Secret, caches the 30-minute OAuth2 bearer token in memory, and executes the requested actions (Fusion workflow, NG-SIEM HEC, Case creation, and/or IOC saving).
4. **ES 8 Note Write-Back:** Once CrowdStrike responds, the add-on writes a summary note (including the Workflow Execution ID, Case ID, or saved IOCs) directly back onto the Finding in Splunk ES 8.

---

## Features
- **ES 8 Analyst Queue & Adaptive Response Support:** Includes Common Action Model (`param._cam`) metadata to run ad-hoc from the Mission Control / Analyst Queue UI or attach directly to correlation searches.
- **Least-Privilege Security Broker (`s2f_broker.py`):** Persistent REST handler using `passSystemAuth = true` and custom capabilities (`s2f_send`, `s2f_admin`). Analysts can trigger dispatches without needing `list_storage_passwords`, and OAuth2 bearer tokens are cached in memory across executions.
- **Built-in Splunk Web Configuration UI (`fusion_setup`):** Manage multiple CIDs with a tenant dropdown, Falcon Cloud region, Client ID/Secret, default workflow, NG-SIEM HEC, proxy, and CA bundle directly in Splunk Web, with a **Test CrowdStrike Connection** button that returns clear, credential-safe diagnostic messages.
- **Operational Dashboards & Monitoring:** Classic SimpleXML v1.1 dashboards (`fusion_overview` and `fusion_health`) powered by the `` `s2f_logs` `` macro.
- **Proactive Health Alerts & Policy Forwarding:** Pre-configured saved searches in `default/savedsearches.conf` for failure rate (>10%), auth errors (401/403), proxy/TLS failures, daily summaries, and policy-based auto-forwarding of High/Critical notables.
- **Multiple CrowdStrike CIDs (Tenants):** Configure one `[cid:<name>]` stanza per tenant, each with its own client ID/secret, workflow, HEC endpoint, proxy, and CA bundle. Admins manage them from the setup page; analysts cannot save configuration.
- **Multiple Delivery Modes:** Choose `fusion_workflow`, `ngsiem_hec`, `both`, or `none`, with non-mutating payload size capping (240 KB for workflows) and automatic workflow `definition_id` vs `name` detection.
- **Falcon Cases & IOC Management (per alert action):** Optionally create a CrowdStrike case (custom name and tags) or save IOCs from comma-separated result fields in either `detect` or `prevent` mode (auto-inferring `ipv4`, `ipv6`, `sha256`, `sha1`, `md5`, or `domain` from each value).
- **Corporate Proxy & SSL Inspection:** Supports authenticated HTTP proxies (with encrypted proxy passwords) and enterprise TLS 1.2+ interception (auto-loads `.pem`/`.crt` files from `certs/`).
- **Resilient ES 8 Write-Back:** Automatically writes the CrowdStrike execution note back to ES 8 Findings/Investigations REST endpoints (`/public/v2/findings/{id}/notes`) with seamless fallback to `/services/notable_update`.
- **Zero External Dependencies:** Pure Python 3.9+ standard library implementation.

---

## Documentation & SOPs
- **[Tutorial: End-to-End Setup & Onboarding Guide](TUTORIAL_SETUP.md)** — Step-by-step instructions from creating a CrowdStrike API client to verifying your first Finding dispatch.
- **[Procedure: Automating Notable Event Dispatch in ES 8](PROCEDURE_AUTOMATION_ES8.md)** — How to attach this action to correlation searches, configure Cases/IOCs, or enable policy-based auto-forwarding.
- **[Operations & Support Runbook (Alerts & Troubleshooting)](OPERATIONS_RUNBOOK.md)** — How to read the dashboards, respond to health alerts, and troubleshoot HTTP/TLS errors.
- **[SOP: Corporate CA Certificate Management & Rotation](PROCEDURE_CERTIFICATE_UPDATE.md)** — How to install, verify, and rotate corporate proxy SSL certificates without downtime.

---

## Directory Structure

```text
TA-splunk_to_fusion/
├── README/
│   ├── alert_actions.conf.spec          # Spec file for modular alert parameters
│   └── ta_splunk_to_fusion.conf.spec    # Spec file for app configuration
├── appserver/static/
│   ├── alerticon.png                    # Adaptive Response action icon
│   └── s2f_setup.js                     # Setup page controller for s2f_broker
├── bin/
│   ├── crowdstrike.py                   # Pure stdlib CrowdStrike OAuth2, Fusion, Case, IOC & HEC client
│   ├── send_to_fusion.py                # Modular Alert / Adaptive Response entrypoint
│   └── s2f_broker.py                    # Persistent REST handler (passSystemAuth=true)
├── certs/
│   └── README.txt                       # Place enterprise public CA certificates (.pem/.crt) here
├── default/
│   ├── alert_actions.conf               # Alert action declaration & ES 8 _cam metadata
│   ├── app.conf                         # App metadata & setup_view declaration
│   ├── authorize.conf                   # Least-privilege s2f_send / s2f_admin capabilities
│   ├── macros.conf                      # s2f_logs and s2f_notable_index macros
│   ├── props.conf                       # KV_MODE=auto extraction for logs
│   ├── restmap.conf                     # /services/ta_s2f/broker endpoint mapping
│   ├── savedsearches.conf               # Health alerts & policy forwarding saved searches
│   ├── server.conf                      # Search Head Cluster replication rules
│   ├── ta_splunk_to_fusion.conf         # Default app settings
│   ├── web.conf                         # Exposes the broker endpoint through Splunk Web
│   └── data/ui/
│       ├── alerts/
│       │   └── send_to_fusion.html      # Modal UI for Analyst Queue & correlation search action
│       ├── nav/
│       │   └── default.xml              # App navigation bar
│       └── views/
│           ├── fusion_overview.xml      # Operational statistics & metrics dashboard
│           ├── fusion_health.xml        # System health & proxy diagnostics dashboard
│           └── fusion_setup.xml         # Configuration & credential setup dashboard
├── docs/
│   ├── TUTORIAL_SETUP.md                # Full onboarding tutorial
│   ├── PROCEDURE_CERTIFICATE_UPDATE.md  # CA certificate rotation procedure
│   ├── OPERATIONS_RUNBOOK.md            # Triage and alarm response runbook
│   └── PROCEDURE_AUTOMATION_ES8.md      # Correlation search & saved search automation guide
├── metadata/
│   └── default.meta                     # System export for alert_actions & macros
├── static/
│   ├── appIcon.png                      # App icon (36x36)
│   ├── appIcon_2x.png                   # App icon (72x72)
│   ├── appLogo.png                      # App logo (160x40)
│   └── appLogo_2x.png                   # App logo (320x80)
├── tests/
│   ├── test_alert_action.py             # Unit, broker, write-back & AppInspect structure tests
│   └── test_crowdstrike.py              # Unit tests for CrowdStrike client
└── README.md
```

---

## Installation & Deployment

### 1. Packaging for Splunk / AppInspect
To build a clean `.tar.gz` / `.spl` package (excluding development/test files), run `make package` or:
```bash
tar -czf TA-splunk_to_fusion-1.0.0.tar.gz \
  --exclude='.git*' --exclude='.agents*' --exclude='AGENTS.md' \
  --exclude='tests' --exclude='__pycache__' --exclude='*.pyc' \
  -C .. TA-splunk_to_fusion
```

### 2. Standalone Search Head Deployment
1. Extract `TA-splunk_to_fusion` into `$SPLUNK_HOME/etc/apps/TA-splunk_to_fusion/`.
2. If your network uses an SSL-inspecting proxy, copy your enterprise public CA `.pem` or `.crt` file into `$SPLUNK_HOME/etc/apps/TA-splunk_to_fusion/certs/`.
3. Restart Splunk (`$SPLUNK_HOME/bin/splunk restart`).

### 3. Search Head Cluster (SHC) Deployment
In a clustered environment, always deploy from the **Search Head Deployer** (never directly on individual Search Head members):
1. Extract `TA-splunk_to_fusion` to the Deployer's app repository:
   ```bash
   $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/
   ```
2. If your network uses an SSL-inspecting proxy, copy the enterprise public CA certificates (PEM format) into:
   ```bash
   $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   ```
3. Push the cluster bundle to the Search Head Cluster members:
   ```bash
   $SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://<sh_member>:8089
   ```

---

## Configuration

### Option 1: Via Splunk Web Setup UI (Recommended)
1. In Splunk Web, open **Apps > Splunk to CrowdStrike Fusion > Configuration**.
2. Pick a tenant from the dropdown (`default` for the primary tenant), or choose **+ New tenant...** to add one.
3. Enter the **Falcon Cloud Region**, **OAuth2 API Client ID**, **OAuth2 API Client Secret**, and **Default Fusion Workflow**.
4. *(Optional)* Enter the **NG-SIEM HEC URL** and **HEC Token**. Expand **Advanced** for the **HTTP/HTTPS Proxy URL** and **Custom CA Bundle Path**.
5. Click **Save Configuration**. Secrets are encrypted in `storage/passwords`.
6. Click **Test CrowdStrike Connection** to verify OAuth2 authentication.
7. Repeat steps 2–6 for each additional tenant.

Case creation and IOC saving are configured on each alert action, not on the Configuration page.

Only users with `s2f_admin` (or `admin_all_objects`) can save configuration.

### Option 2: Via Configuration Files & REST API
In Splunk, never edit files in `default/` directly (upgrades overwrite `default/`). Instead, create `local/ta_splunk_to_fusion.conf`:
```ini
[settings]
falcon_cloud = eu-1
client_id = your_falcon_client_id
default_workflow = Incident_Intake_Workflow
ngsiem_hec_url = https://your-id.ingest.eu-1.crowdstrike.com/services/collector
proxy_url = http://proxy.example.com:8080

# Additional tenant, referenced by the alert action cid parameter
[cid:tenant-a]
falcon_cloud = us-1
client_id = your_other_client_id
default_workflow = Incident_Intake_Workflow
```
And store encrypted secrets via the Configuration page or `storage/passwords` (realm `ta_splunk_to_fusion`):
- Client Secret username: `<client_id>` (one entry per CID)
- NG-SIEM HEC Token username: `hec_token:<cid>` (one entry per CID; `hec_token` still works for the default)
- Authenticated Proxy URL username (optional): `proxy_url`

Set the alert action's `cid` parameter to the tenant label (e.g. `tenant-a`). Leave it empty for the `[settings]` default.

### Setting reference

| Setting | Default | Meaning |
|---------|---------|---------|
| `falcon_cloud` | `eu-1` | Falcon API region or base URL: `us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2`. |
| `client_id` | empty | OAuth2 client ID. The secret is stored under this ID. |
| `default_workflow` | empty | Fusion workflow definition ID or name. |
| `ngsiem_hec_url` | empty | CrowdStrike NG-SIEM HEC collector URL; required for `ngsiem_hec` or `both`. |
| `proxy_url` | empty | Optional corporate proxy URL. |
| `ca_bundle_path` | empty | Optional CA bundle; empty loads `certs/*.pem` and `certs/*.crt`. |

### Alert action parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `cid` | empty | Tenant label matching a `[cid:<name>]` stanza. Empty uses `[settings]`. |
| `delivery_method` | `fusion_workflow` | `fusion_workflow`, `ngsiem_hec`, `both`, or `none`. |
| `workflow` | empty | Workflow definition ID or name override. Empty uses `default_workflow`. |
| `create_case` | `none` | `none` or `always`. `always` opens a CrowdStrike case per notable. |
| `case_name` | empty | Case name. Empty uses the notable's rule name. |
| `case_tags` | empty | Comma-separated case tags. Empty uses `splunk, notable`. |
| `ioc_action` | `none` | `none`, `detect`, or `prevent`. |
| `ioc_fields` | empty | Comma-separated result fields whose values become IOCs (up to 10 per finding). Empty disables IOC saving. |
| `comment` | empty | Optional context included in the case or workflow payload. |

---

## Enabling Health Alerts & Automated Forwarding
For Splunk AppInspect compliance, all saved searches in `default/savedsearches.conf` ship with `disabled = 1` and `enableSched = 0`. Enable them under **Settings > Searches, reports, and alerts**, filtering by `TA-splunk_to_fusion`.

| Saved search | What it does | Default schedule |
|--------------|--------------|------------------|
| `Fusion - Authentication Failure Alert` | Fires on 401/403 or invalid-client responses. | Every 15 minutes |
| `Fusion - Proxy or TLS Failure Alert` | Fires on proxy, TLS, certificate, or 407 errors. | Every 15 minutes |
| `Fusion - High Failure Rate Alert` | Fires when more than 10% of dispatches fail (minimum 5 events). | Every 15 minutes |
| `Fusion - Daily Operational Summary` | Reports daily volume, success rate, and latency by delivery method. | Daily at 07:00 |
| `Fusion - Auto Forward High and Critical Notables` | Optional. Sends new High/Critical ES notables to CrowdStrike and skips ones already delivered. | Every 5 minutes |

---

## Troubleshooting & Verification

### Splunk Logs
All execution logs are captured by the `` `s2f_logs` `` macro (`sourcetype="send_to_fusion"` and `sourcetype="modular_alerts:send_to_fusion"`):
```spl
`s2f_logs`
```

### Unit & Structural Tests
```bash
python3 -B -m unittest discover -s tests -v
```
