# Tutorial: End-to-End Setup & Onboarding Guide
**TA-splunk_to_fusion: Splunk Enterprise Security 8 → CrowdStrike Falcon Integration**

This guide walks you through setting up `TA-splunk_to_fusion` from start to finish. No prior expertise in Splunk or CrowdStrike is required—each step explains both *what* to click and *why* it matters.

---

## Prerequisites
Before starting, check that you have:
1. **CrowdStrike Falcon Console Access:** An administrator account able to create API clients (**Support and resources > API clients and keys**) and Fusion SOAR workflows (**Fusion SOAR > Workflows**).
2. **Splunk Server Access:** Command-line access to your Splunk **Search Head Deployer** (if running a Search Head Cluster) or standalone **Search Head** to install the app directory.
3. **Splunk Web Access:** A Splunk user account with the `admin`, `sc_admin`, or `ess_admin` role.
4. *(If your network uses a proxy)* Your corporate proxy URL (e.g., `http://proxy.example.com:8080`) and the proxy's public Root/Intermediate CA certificate file (`.pem` or `.crt`).

---

## Step 1: Configure CrowdStrike Falcon

Splunk needs an **API Client** (machine credentials using OAuth2) in CrowdStrike, plus an **On-Demand Fusion Workflow** (if you plan to trigger SOAR playbooks).

### 1.1 Determine Your CrowdStrike Cloud Region
Check the URL you use when logging into the CrowdStrike Falcon Console in your browser:

| Browser Login URL | API Base URL | Region Value to Select in Splunk |
|---|---|---|
| `https://falcon.eu-1.crowdstrike.com` | `https://api.eu-1.crowdstrike.com` | `eu-1` |
| `https://falcon.crowdstrike.com` | `https://api.crowdstrike.com` | `us-1` |
| `https://falcon.us-2.crowdstrike.com` | `https://api.us-2.crowdstrike.com` | `us-2` |
| `https://falcon.laggar.gcw.crowdstrike.com` | `https://api.laggar.gcw.crowdstrike.com` | `us-gov-1` |

### 1.2 Create the OAuth2 API Client
1. Log in to the CrowdStrike Falcon Console.
2. In the left navigation menu, go to **Support and resources > API clients and keys**.
3. Click **Create API client**.
4. Configure the client details:
   - **Client Name:** `Splunk_ES_to_Fusion_Connector`
   - **Description:** `Integration with Splunk ES 8 for SOAR workflows, NG-SIEM, Cases, and IOCs.`
5. Under **API Scopes**, grant the scopes that match the features you will use:
   - **Workflows:** `Read` and `Write` *(Required to execute on-demand Fusion SOAR workflows)*.
   - **Cases / Next-Gen SIEM:** `Write` *(Required if alert actions create Falcon Cases)*.
   - **IOC Management (IOCs):** `Read` and `Write` *(Required if alert actions save custom IOCs in `detect` or `prevent` mode)*.
   - **Incidents / Alerts:** `Read` and `Write` *(Optional, if your workflow updates incidents/alerts)*.
6. Click **Create**.
7. **Save Your Credentials Immediately:** Copy and securely save the **32-character Client ID** and **Client Secret**. CrowdStrike only shows the Client Secret once.

### 1.3 Create the On-Demand Fusion Workflow
1. In the Falcon Console, navigate to **Next-Gen SIEM / Fusion SOAR > Workflows**.
2. Click **Create workflow** and select **Trigger: On demand** (meaning the workflow runs when triggered by an API call).
3. Define a JSON request schema matching the finding payload sent by `TA-splunk_to_fusion`:
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
     "user": "alice",
     "analyst_comment": "Escalated from Splunk ES",
     "details": {
       "src_ip": "10.0.0.1",
       "dest_ip": "10.0.0.2"
     }
   }
   ```
4. Add your desired workflow actions (e.g., **Create Case / Incident**, enrichment lookups, or endpoint containment).
5. Save and switch the workflow to **Enabled / On**.
   > **Important:** If the workflow is left in Draft/Disabled state, CrowdStrike will reject dispatches with `HTTP 400 Bad Request`.
6. Record either the **32-character Workflow Definition ID** or the **Workflow Name** (the app automatically detects whether you provide an ID or Name).

---

## Step 2: Deploying the App to Splunk

### Option A: Deploy to a Search Head Cluster (SHC)
In a clustered environment, always place the app on the **Search Head Deployer**, which pushes it to all Search Heads:
1. On your Search Head Deployer, place the app directory into:
   ```bash
   $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion
   ```
2. If your corporate proxy performs SSL inspection, copy the Enterprise Root and Intermediate CA certificates (PEM `.pem` or `.crt` format) into:
   ```bash
   $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/
   ```
3. Push the configuration bundle to all Search Heads:
   ```bash
   $SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://<sh_member>:8089
   ```

### Option B: Deploy to a Standalone Search Head
1. Extract `TA-splunk_to_fusion` into `$SPLUNK_HOME/etc/apps/TA-splunk_to_fusion/`.
2. Copy any corporate proxy `.pem`/`.crt` certificates into `$SPLUNK_HOME/etc/apps/TA-splunk_to_fusion/certs/`.
3. Restart Splunk (`$SPLUNK_HOME/bin/splunk restart`).

---

## Step 3: Configuring the App in Splunk Web

### 3.1 Use the Built-in Configuration Page (Recommended)
1. Log in to Splunk Web as an administrator (`admin`, `sc_admin`, or `ess_admin`).
2. Open **Apps > Splunk to CrowdStrike Fusion** and click **Configuration** in the top navigation bar.
3. Under **Tenant**, pick `default` for your primary CrowdStrike tenant, or select **+ New tenant...** to configure an additional CrowdStrike CID (e.g., `tenant-a`).
4. Fill in the settings:
   - **Falcon Cloud Region:** Select your region from Step 1.1 (e.g., `eu-1`).
   - **OAuth2 API Client ID:** Paste the 32-character Client ID from Step 1.2.
   - **OAuth2 API Client Secret:** Paste the Client Secret from Step 1.2.
   - **Default Fusion Workflow:** Enter the Workflow Definition ID or Name from Step 1.3.
   - **NG-SIEM HEC URL / HEC Token:** *(Optional)* Enter these only if you also forward findings to CrowdStrike Next-Gen SIEM over HEC.
   - **Advanced (Proxy & Custom CA):** *(Optional)* Expand **Proxy & custom CA** if outbound connections use a corporate HTTP/HTTPS proxy. Leave **Custom CA Bundle Path** blank if you placed your `.pem` certificate in the `certs/` folder.
5. Click **Save Configuration**.
   - Non-secret settings are saved to `local/ta_splunk_to_fusion.conf` (`[settings]` for `default`, or `[cid:<name>]` for additional tenants) and replicated across Search Head Cluster members.
   - Secrets (`client_secret`, `hec_token`) are stored encrypted in `storage/passwords` under realm `ta_splunk_to_fusion`.
6. Click **Test CrowdStrike Connection** and confirm the green banner:
   `Successfully authenticated with CrowdStrike (eu-1).`
   *(If there is an issue with the Client ID length, region, proxy, or CA certificate, the banner will explain the exact cause without exposing your secret).*

> **Note:** Case creation (`create_case`) and IOC saving (`ioc_action`, `ioc_fields`) are configured per detection rule / alert action, not on the global Configuration page.

### 3.2 Enable Operational Monitoring Alerts
By default, all scheduled searches ship disabled (`disabled = 1`) for Splunk AppInspect compliance. To turn them on:
1. In Splunk Web, navigate to **Settings > Searches, reports, and alerts**.
2. Filter by App: **Splunk to CrowdStrike Fusion (`TA-splunk_to_fusion`)** and Owner: **All**.
3. Click **Edit > Enable** on the four operational monitoring searches:
   - `Fusion - Authentication Failure Alert`
   - `Fusion - Proxy or TLS Failure Alert`
   - `Fusion - High Failure Rate Alert`
   - `Fusion - Daily Operational Summary`

---

## Step 4: Role Permissions & Least Privilege
By default (`default/authorize.conf`), the app grants:
- `s2f_send` capability to `role_ess_analyst`, `role_ess_admin`, `role_admin`, and `role_sc_admin`.
- `s2f_admin` capability to `role_ess_admin`, `role_admin`, and `role_sc_admin`.

Analysts with `s2f_send` can trigger **Send to CrowdStrike Fusion** from the ES 8 Analyst Queue without needing `list_storage_passwords`; the local persistent broker (`bin/s2f_broker.py`) reads the encrypted credentials using `system_authtoken`. Only administrators with `s2f_admin` (or `admin_all_objects`) can save changes or test connections on the Configuration page.

---

## Step 5: Verification & First Test

1. In Splunk Enterprise Security, navigate to **Mission Control > Analyst Queue** (or **Incident Review**).
2. Expand any finding, click the actions menu (`...`), and select **Run adaptive response actions**.
3. Select **Send to CrowdStrike Fusion**.
4. In the modal dialog:
   - Leave **CID / Tenant** blank (to use `default`) or enter your custom tenant name.
   - Keep **Delivery Method** set to `CrowdStrike Fusion SOAR Workflow`.
   - Optionally set **Create Case** to `Always` or enter **IOC Fields** (such as `sha256, src_ip`).
   - Enter an **Analyst Comment** (`Testing initial onboarding from Analyst Queue`) and click **Run**.
5. Verify results:
   - **In Splunk ES Finding Notes:** Refresh the finding; a note appears:
     `Sent to CrowdStrike: CrowdStrike Fusion workflow triggered successfully (Execution ID: ...)`
   - **In CrowdStrike Falcon:** Open **Fusion SOAR > Workflow Activity** (and **Cases** / **IOC Management**, if enabled) and confirm the execution arrived.
   - **In Splunk Dashboards:** Open **Apps > Splunk to CrowdStrike Fusion > Operational Overview** to view the dispatch metrics and execution ID.
