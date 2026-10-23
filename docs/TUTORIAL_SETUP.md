# Tutorial: End-to-End Setup & Onboarding Guide
**TA-splunk_to_fusion: Splunk Enterprise Security 8 → CrowdStrike Fusion SOAR**

This tutorial walks through the complete process of setting up CrowdStrike Falcon, deploying `TA-splunk_to_fusion` to Splunk Enterprise Security 8, configuring encrypted credentials via the built-in Setup UI, and verifying end-to-end incident creation and note write-back.

---

## Prerequisites
- Administrative access to the **CrowdStrike Falcon Console**.
- Administrator access (`admin` or `ess_admin` role) to the **Splunk Search Head Deployer** or standalone Search Head.
- Basic familiarity with Splunk Enterprise Security (ES 8.x Mission Control / Analyst Queue).

---

## Step 1: CrowdStrike Falcon Console Configuration

### 1.1 Create the API Client
1. Log in to the CrowdStrike Falcon Console (`https://falcon.crowdstrike.com` or `https://falcon.eu-1.crowdstrike.com`).
2. Navigate to **Support and resources > API clients and keys**.
3. Click **Create API client**.
4. Configure the client details:
   - **Client Name:** `Splunk_ES_to_Fusion_Connector`
   - **Description:** `Integration with Splunk ES 8 for incident triage and SOAR automations.`
5. Grant the following API Scopes:
   - **Workflows:** `Read` and `Write` (Required to execute on-demand workflows)
   - **Incidents / Alerts:** `Read` and `Write` (Optional, if your workflow updates incidents/alerts)
6. Click **Create**.
7. **Important:** Copy and securely save the **Client ID** and **Client Secret**.

### 1.2 Create the On-Demand Fusion Workflow
1. In the Falcon Console, navigate to **Next-Gen SIEM / Fusion SOAR > Workflows**.
2. Click **Create workflow** and select **Trigger: On demand**.
3. Define a JSON schema matching the finding payload sent by `TA-splunk_to_fusion`:
   - `event_id` (String, Required)
   - `rule_name` (String)
   - `urgency` (String)
   - `severity` (String)
   - `security_domain` (String)
   - `status` (String)
   - `owner` (String)
   - `src` (String)
   - `dest` (String)
   - `user` (String)
   - `analyst_comment` (String)
   - `details` (Object)
4. Add your desired workflow actions (e.g., **Create Case / Incident**, enrichment lookups, or endpoint containment).
5. Save and **Enable** the workflow.
6. Record either the **32-character Workflow Definition ID** or the **Workflow Name** (the app automatically detects whether you provide an ID or Name).

---

## Step 2: Deploying the App to Splunk

### 2.1 Deploy to Search Head Cluster (SHC)
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
   splunk apply shcluster-bundle -target https://<sh_member>:8089
   ```

---

## Step 3: Configuring the App in Splunk Web

### 3.1 Use the Built-in Configuration Page (Recommended)
1. Log in to Splunk Web as an administrator (`admin` or `ess_admin`).
2. Open **Apps > Splunk to CrowdStrike Fusion** and click **Configuration** in the top navigation bar.
3. Pick a tenant from the dropdown (`default` for the primary tenant), or choose **+ New tenant...** to add one.
4. Fill in the settings:
   - **Falcon Cloud Region:** Select your region (e.g., `eu-1`).
   - **OAuth2 API Client ID:** Paste the Client ID from Step 1.1.
   - **OAuth2 API Client Secret:** Paste the Client Secret from Step 1.1.
   - **Default Fusion Workflow:** Enter the Workflow Definition ID or Name from Step 1.2.
   - **NG-SIEM HEC URL / HEC Token:** Optional, only if you deliver to Next-Gen SIEM.
   - **Advanced:** Optional **HTTP/HTTPS Proxy URL** and **Custom CA Bundle Path**.
5. Click **Save Configuration**.
   - Non-secret settings are saved to `local/ta_splunk_to_fusion.conf`.
   - Secrets (`client_secret`, `hec_token`) are stored encrypted in `storage/passwords` under realm `ta_splunk_to_fusion` and automatically replicated across Search Head Cluster members.
6. Click **Test CrowdStrike Connection** and confirm the green banner:
   `Successfully authenticated with CrowdStrike (eu-1).`

Case creation and IOC saving are configured on each alert action, not on this page.

### 3.2 Enable Operational Monitoring Alerts
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

Analysts with `s2f_send` can trigger **Send to CrowdStrike Fusion** from the ES 8 Analyst Queue without needing `list_storage_passwords`; the local persistent broker (`bin/s2f_broker.py`) reads the encrypted credentials using `system_authtoken`.

---

## Step 5: Verification & First Test

1. In Splunk Enterprise Security, navigate to **Mission Control > Analyst Queue** (or Incident Review).
2. Expand any finding, click the actions menu (`...`), and select **Run adaptive response actions**.
3. Select **Send to CrowdStrike Fusion**.
4. Enter an optional comment (`Testing initial onboarding from Analyst Queue`) and click **Run**.
5. Verify results:
   - **In Splunk ES Finding Notes:** Refresh the finding; a note appears:
     `Sent to CrowdStrike: CrowdStrike Fusion workflow triggered successfully (Execution ID: ...)`
   - **In CrowdStrike Falcon:** Open **Fusion SOAR > Workflow Activity** and confirm the workflow ran.
   - **In Splunk Dashboards:** Open **Apps > Splunk to CrowdStrike Fusion > Operational Overview** to view the dispatch metrics and execution ID.
