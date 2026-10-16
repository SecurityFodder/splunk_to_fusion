Corporate Enterprise CA Certificates
======================================

If your network uses an SSL-inspecting proxy (TLS interception), outbound HTTPS
connections to CrowdStrike (api.crowdstrike.com) will be re-signed by the enterprise's
internal enterprise Root or Intermediate Certificate Authority.

To enable trusted connectivity without disabling TLS verification:
1. Export the Enterprise Public Root/Intermediate CA certificates in PEM format (.pem or .crt).
2. Place the PEM file(s) directly into this directory (`certs/`).
3. The app will automatically discover and load all `.pem` and `.crt` files found here.

Alternatively, you can specify an absolute path to a corporate CA bundle in
`local/ta_splunk_to_fusion.conf`:
    [settings]
    ca_bundle_path = /etc/ssl/certs/corp_ca_bundle.pem
