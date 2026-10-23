Corporate Enterprise CA Certificates
====================================

Why is this folder here?
------------------------
If your corporate network uses an SSL-inspecting proxy (TLS interception), outbound HTTPS
connections from Splunk to CrowdStrike (https://api.<region>.crowdstrike.com) are intercepted
and re-signed by your company's internal Root or Intermediate Certificate Authority (CA).

Without your company's public CA certificate, Python will reject the proxy's re-signed
certificate with an "SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]" error.

How to add your corporate CA certificates:
------------------------------------------
1. Export your Enterprise PUBLIC Root and Intermediate CA certificates in Base64 PEM text
   format (files ending in .pem or .crt that begin with "-----BEGIN CERTIFICATE-----").
   NOTE: Never place private keys in this directory.
2. Copy the .pem or .crt file(s) directly into this directory (`certs/`).
3. On a Search Head Cluster, place the files in `certs/` on the Deployer and push the bundle.
4. As long as `ca_bundle_path` in `ta_splunk_to_fusion.conf` is left blank (the default),
   the add-on automatically discovers and loads every `.pem` and `.crt` file in this folder.

Alternative (System-wide CA Bundle):
------------------------------------
If you prefer to point to a certificate bundle stored elsewhere on the server filesystem,
set `ca_bundle_path` under Advanced on the Configuration page in Splunk Web or in
`local/ta_splunk_to_fusion.conf`:

    [settings]
    ca_bundle_path = /etc/pki/tls/certs/corp_ca_bundle.pem

See `docs/PROCEDURE_CERTIFICATE_UPDATE.md` (SOP-S2F-001) for full rotation and verification steps.
