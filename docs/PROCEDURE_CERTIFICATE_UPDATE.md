# Standard Operating Procedure (SOP): Corporate CA Certificate Management
**Document ID:** SOP-S2F-001  
**Target Audience:** Splunk Platform Administrators, Network Security Engineers  
**App:** TA-splunk_to_fusion

---

## 1. Purpose
In an enterprise network with TLS interception (SSL inspection) proxies, outbound HTTPS connections from Splunk to CrowdStrike (`https://api.<region>.crowdstrike.com`) are dynamically re-signed using internal Enterprise Certificate Authority (CA) certificates.

This procedure outlines how to install, verify, and rotate Enterprise Public Root and Intermediate CA certificates within `TA-splunk_to_fusion` to maintain continuous, secure communication (TLS 1.2+) without service disruption.

---

## 2. Requirements & Standards
- **Bank Security Standard:** Certificate verification must **never** be disabled (`verify_mode = CERT_NONE` is strictly prohibited for external traffic). Minimum protocol version `TLSv1.2` is enforced.
- **Format:** Certificates must be Base64-encoded ASCII X.509 format (**PEM format** with extension `.pem` or `.crt`).
- **Scope:** Includes all active Enterprise Root CAs and any issuing Intermediate CAs.

---

## 3. Step-by-Step Certificate Installation / Rotation

### Step 3.1: Obtain the Current Enterprise Public CA Bundle
1. Export the active enterprise Root CA and Intermediate CA public certificates from the internal PKI repository or proxy management portal.
2. If multiple certificates exist, combine them into a single bundle file (e.g., `corp_ca_bundle.pem`):
   ```bash
   cat corp_root_ca.pem corp_intermediate_ca.pem > corp_ca_bundle.pem
   ```
3. Validate certificate format and expiry using OpenSSL:
   ```bash
   openssl x509 -in corp_ca_bundle.pem -text -noout | grep -E "Issuer:|Subject:|Not After"
   ```

### Step 3.2: Place Certificate on Deployer
1. Log in to the Splunk Search Head Deployer.
2. Copy the updated certificate bundle into the app's `certs/` directory:
   ```bash
   cp /path/to/corp_ca_bundle.pem $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   chmod 644 $SPLUNK_HOME/etc/shcluster/apps/TA-splunk_to_fusion/certs/corp_ca.pem
   ```
   *(Note: `CrowdStrikeClient` automatically discovers and loads all `.pem` and `.crt` files in `certs/` in deterministic order. If an explicit `ca_bundle_path` is configured in `ta_splunk_to_fusion.conf`, ensure that file path exists, as the client fails closed with `CrowdStrikeError` if a configured `ca_bundle_path` is missing).*

### Step 3.3: Deploy to Search Head Cluster (SHC)
Push the updated cluster bundle to all search head cluster members:
```bash
splunk apply shcluster-bundle -target https://<sh_member>:8089
```

---

## 4. Verification & Health Check

### 4.1 Run Connection Test in Splunk Web
1. Open **Apps > Splunk to CrowdStrike Fusion > Configuration**.
2. Click **Test CrowdStrike Connection** and verify authentication succeeds.

### 4.2 Check App Internal Logs
Run the following search in Splunk to confirm the new certificates are loaded and no TLS errors occur:
```spl
`s2f_logs` "Loaded enterprise CA cert"
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
   splunk apply shcluster-bundle -target https://<sh_member>:8089
   ```
