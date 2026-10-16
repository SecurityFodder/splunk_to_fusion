[settings]
falcon_cloud = <string>
* CrowdStrike Falcon cloud region (us-1, us-2, eu-1, us-gov-1, us-gov-2) or base URL.
client_id = <string>
* CrowdStrike OAuth2 API Client ID.
default_workflow = <string>
* Default CrowdStrike Fusion SOAR on-demand workflow definition_id or name.
delivery_method = <string>
* Default delivery target: fusion_workflow, ngsiem_hec, or both.
ngsiem_hec_url = <string>
* CrowdStrike Next-Gen SIEM HTTP Event Collector URL.
ngsiem_hec_auth_scheme = <string>
* Authorization header scheme for NG-SIEM HEC: Bearer or Splunk.
proxy_url = <string>
* Optional corporate HTTP/HTTPS proxy URL (e.g. http://proxy.example.com:8080).
ca_bundle_path = <string>
* Optional full path to a custom PEM CA bundle for SSL-intercepting proxies.
