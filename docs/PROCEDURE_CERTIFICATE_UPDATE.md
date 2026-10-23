# Standard Operating Procedure (SOP): Corporate CA Certificate Management
**Document ID:** SOP-S2F-001  
**Target Audience:** Splunk Platform Administrators, Network Security Engineers, and Support Engineers  
**App:** `TA-splunk_to_fusion`

---

## 1. Background: Why Are Corporate CA Certificates Needed?
When Splunk connects to CrowdStrike (`https://api.<region>.crowdstrike.com`), the traffic is encrypted using HTTPS (TLS).

In many enterprise networks, outbound internet traffic passes through a **corporate SSL-inspecting proxy**. To scan outbound traffic for security compliance, the proxy intercepts the HTTPS connection and dynamically re-signs the certificate using your organization's internal **Certificate Authority (CA)**.

By default, Python only trusts public internet CAs and will block a proxy-re-signed connection with `SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]` because it does not recognize your internal corporate CA. Placing your organization's public Root and Intermediate CA certificates (`.pem` or `.crt` files) into this add-on's `certs/` folder tells Python to trust your corporate proxy while keeping full TLS 1.2+ verification enabled.

> **Important Security Note:** Never place **private keys** into `certs/`. Only public Root and Intermediate CA certificates belong in this folder.

---

## 2. Requirements & Standards
- **Security Standard:** Certificate verification must **never** be disabled (`verify_mode = CERT_NONE` is strictly prohibited for external traffic). Minimum protocol version `TLSv1.2` is enforced.
- **Format:** Certificates must be Base64-encoded ASCII X.509 format (**PEM format** with extension `.pem` or `.crt`, beginning with `-----BEGIN CERTIFICATE-----`).
- **Scope:** Includes all active Enterprise Root CAs and any issuing Intermediate CAs.

---

## 3. Step-by-Step Certificate Installation / Rotation

### Step 3.1: Obtain and Validate the Current Enterprise Public CA Bundle
1. Export the active enterprise Root CA and Intermediate CA public certificates from your internal PKI repository or proxy team.
   - *If your certificate is in binary `.der` or `.cer` format, convert it to text PEM format first:*
     ```bash
     openssl x509 -inform DER -in corp_ca.cer -out corp_ca.pem
     ```
2. If multiple certificates exist, combine them into a single bundle file (e.g., `corp_ca_bundle.pem`):
   ```bash
   cat corp_root_ca.pem corp_intermediate_ca.pem > corp_ca_bundle.pem
   ```
3. Validate certificate format and expiry date (`Not After`) using OpenSSL:
   ```bash
   openssl x509 -in corp_ca_bundle.pem -text -noout | grep -E "Issuer:|Subject:|Not After"
   ```

### Step 3.2: Place Certificate in the Add-on's `certs/` Directory
1. Log in to the Splunk Search Head Deployer (or standalone Search Head).
2. Copy the updated certificate bundle into the app's `certs/` directory:
   ```bash
   cp /path/to/corp_ca_bundle.pem $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   chmod 644 $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   ```
   *(Note: `CrowdStrikeClient` automatically discovers and loads all `.pem` and `.crt` files in `certs/` in alphabetical order when `ca_bundle_path` is left empty. If an explicit `ca_bundle_path` is configured in `ta_splunk_to_fusion.conf`, ensure that file path exists on disk, as the client fails closed with `CrowdStrikeError` if a configured `ca_bundle_path` is missing).*

### Step 3.3: Deploy to Search Head Cluster (SHC)
Push the updated cluster bundle to all Search Head Cluster members:
```bash
$SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://<sh_member>:8089
```

---

## 4. Verification & Health Check

### 4.1 Run Connection Test in Splunk Web
1. Open **Apps > Splunk to CrowdStrike Fusion > Configuration**.
2. Click **Test CrowdStrike Connection** and verify authentication succeeds with the green confirmation banner.

### 4.2 Check App Internal Logs
Run the following search in Splunk to confirm the new certificates are loaded and no warnings occur:
```spl
`s2f_logs` ("Loaded enterprise CA cert" OR "Could not load cert")
| stats count by host, _raw
```

### 4.3 Verify No TLS / SSL Interception Errors
Check the **System Health & Diagnostics** dashboard or execute:
```spl
`s2f_logs` status=failure ("SSLError" OR "certificate")
| stats count by host, error_msg
```
If the search returns **0 events**, the certificate rotation was successful and the proxy trust chain is healthy.

---

## 5. Rollback Procedure
If a corrupted certificate is pushed and causes immediate TLS failures (`[X509] PEM lib` or `CERTIFICATE_VERIFY_FAILED`):
1. On the Deployer, restore the previous known-good PEM bundle:
   ```bash
   cp /var/backup/certs/corp_ca_previous.pem $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   chmod 644 $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   ```
2. Re-apply the cluster bundle:
   ```bash
   $SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://<sh_member>:8089
   ```
