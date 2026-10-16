# TA-splunk_to_fusion
**Splunk Enterprise Security 8 → CrowdStrike Falcon Fusion SOAR & Next-Gen SIEM Add-on**

A lightweight, high-performance Splunk Add-on designed to send Splunk ES 8 notable events (findings) to **CrowdStrike Falcon Fusion SOAR** (to trigger on-demand workflows) and/or **CrowdStrike Next-Gen SIEM** (via HEC).

---

## Features
- **ES 8 Analyst Queue & Adaptive Response Support:** Includes Common Action Model (`param._cam`) metadata to run ad-hoc from the Mission Control / Analyst Queue UI or attach directly to correlation searches.
- **Least-Privilege Security Broker (`s2f_broker.py`):** Persistent REST handler using `passSystemAuth = true` and custom capabilities (`s2f_send`, `s2f_admin`). Analysts can trigger dispatches without needing `list_storage_passwords`, and OAuth2 bearer tokens are cached in memory across executions.
- **Built-in Splunk Web Configuration UI (`fusion_setup`):** Configure Falcon Cloud region, Client ID/Secret, Default Workflow, Corporate Proxy credentials, CA bundle path, and NG-SIEM HEC tokens directly in Splunk Web with a **Test CrowdStrike Connection** button.
- **Operational Dashboards & Monitoring:** Classic SimpleXML v1.1 dashboards (`fusion_overview` and `fusion_health`) powered by the `` `s2f_logs` `` macro.
- **Proactive Health Alerts & Policy Forwarding:** Pre-configured saved searches in `default/savedsearches.conf` for failure rate (>10%), auth errors (401/403), proxy/TLS failures, daily summaries, and policy-based auto-forwarding of High/Critical notables.
- **Dual Delivery Modes:** Choose `fusion_workflow`, `ngsiem_hec`, or `both`, with non-mutating payload size capping (240 KB for workflows, 512 KB for HEC) and automatic workflow `definition_id` vs `name` detection.
- **Corporate Proxy & SSL Inspection:** Supports authenticated HTTP proxies (with encrypted proxy passwords) and enterprise TLS 1.2+ interception (auto-loads `.pem`/`.crt` files from `certs/`).
- **Resilient ES 8 Write-Back:** Automatically writes the CrowdStrike execution ID note back to ES 8 Findings/Investigations REST endpoints (`/public/v2/findings/{id}/notes`) with seamless fallback to `/services/notable_update`.
- **Zero External Dependencies:** Pure Python 3.9+ standard library implementation.

---

## Documentation & SOPs
- [Tutorial: End-to-End Setup & Onboarding Guide](docs/TUTORIAL_SETUP.md)
- [SOP: Corporate CA Certificate Management & Rotation](docs/PROCEDURE_CERTIFICATE_UPDATE.md)
- [Operations & Support Runbook (Alerts & Troubleshooting)](docs/OPERATIONS_RUNBOOK.md)
- [Procedure: Automating Notable Event Dispatch in ES 8](docs/PROCEDURE_AUTOMATION_ES8.md)

### Building Documentation with MkDocs
To preview the documentation site locally:
```bash
pip install mkdocs mkdocs-material
mkdocs serve
```
To build static HTML:
```bash
mkdocs build --strict
```

---

## Directory Structure

```text
TA-splunk_to_fusion/
├── README/
│   ├── alert_actions.conf.spec          # Spec file for modular alert parameters
│   └── ta_splunk_to_fusion.conf.spec # Spec file for app configuration
├── appserver/static/
│   ├── alerticon.png                    # Adaptive Response action icon
│   └── s2f_setup.js                     # Setup page controller for s2f_broker
├── bin/
│   ├── crowdstrike.py                   # Pure stdlib CrowdStrike OAuth2, Fusion & HEC client
│   ├── send_to_fusion.py           # Modular Alert / Adaptive Response entrypoint
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
│   ├── ta_splunk_to_fusion.conf    # Default app settings
│   └── data/ui/
│       ├── alerts/
│       │   └── send_to_fusion.html # Modal UI for Analyst Queue action
│       ├── nav/
│       │   └── default.xml              # App navigation bar
│       └── views/
│           ├── fusion_overview.xml # Operational statistics & metrics dashboard
│           ├── fusion_health.xml   # System health & proxy diagnostics dashboard
│           └── fusion_setup.xml    # Configuration & credential setup dashboard
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
To build a clean `.tar.gz` / `.spl` package (excluding development/test files):
```bash
tar -czf TA-splunk_to_fusion-1.0.0.tar.gz \
  --exclude='.git*' --exclude='.agents*' --exclude='AGENTS.md' \
  --exclude='tests' --exclude='__pycache__' --exclude='*.pyc' \
  -C .. TA-splunk_to_fusion
```

### 2. Search Head Cluster (SHC) Deployment
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
   splunk apply shcluster-bundle -target https://<sh_member>:8089
   ```

---

## Configuration

### Option 1: Via Splunk Web Setup UI (Recommended)
1. In Splunk Web, open **Apps > Splunk to CrowdStrike Fusion > Configuration**.
2. Enter your **Falcon Cloud Region**, **OAuth2 API Client ID**, **OAuth2 API Client Secret**, and **Default Fusion Workflow** (Definition ID or Workflow Name).
3. *(Optional)* Enter your **NG-SIEM HEC URL** and **HEC Token**, and/or your **HTTP/HTTPS Proxy URL**, **Proxy Username**, **Proxy Password**, and **Custom CA Bundle Path**.
4. Click **Save Configuration** (secrets are encrypted in `storage/passwords` and replicated across SHC members).
5. Click **Test CrowdStrike Connection** to verify OAuth2 authentication through your proxy and TLS certificates.

### Option 2: Via Configuration Files & REST API
Create `local/ta_splunk_to_fusion.conf`:
```ini
[settings]
falcon_cloud = eu-1
client_id = your_falcon_client_id
default_workflow = Incident_Intake_Workflow
delivery_method = fusion_workflow
ngsiem_hec_url = https://your-id.ingest.eu-1.crowdstrike.com/services/collector
ngsiem_hec_auth_scheme = Bearer
proxy_url = http://proxy.example.com:8080
```
And store encrypted secrets via the Configuration page or `storage/passwords` (realm `ta_splunk_to_fusion`):
- Client Secret username: `<your_falcon_client_id>` (or `client_secret`)
- NG-SIEM HEC Token username: `hec_token`
- Authenticated Proxy URL username (optional): `proxy_url`

---

## Enabling Health Alerts & Automated Forwarding
For Splunk AppInspect compliance, all saved searches in `default/savedsearches.conf` ship with `disabled = 1` and `enableSched = 0`. After configuring credentials, go to **Settings > Searches, reports, and alerts** (filtering by `TA-splunk_to_fusion`) and enable:
- `Fusion - Authentication Failure Alert`
- `Fusion - Proxy or TLS Failure Alert`
- `Fusion - High Failure Rate Alert`
- `Fusion - Daily Operational Summary`
- *(Optional)* `Fusion - Auto Forward High and Critical Notables`

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
