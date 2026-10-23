[settings]
* Default CrowdStrike tenant. The alert action uses this tenant when its cid parameter is empty.
falcon_cloud = <string>
* CrowdStrike Falcon API region or base URL.
* Valid regions: us-1, us-2, eu-1, us-gov-1, us-gov-2. Default: eu-1.
client_id = <string>
* CrowdStrike OAuth2 API Client ID.
* The matching client secret is stored in storage/passwords under this client ID.
default_workflow = <string>
* Fusion SOAR on-demand workflow definition ID (recommended) or workflow name.
* Used when the alert action does not set its workflow parameter.
ngsiem_hec_url = <string>
* Full HTTPS URL of the CrowdStrike Next-Gen SIEM HEC collector.
* Required only when the alert action's delivery_method is ngsiem_hec or both.
* Example: https://hec.eu-1.crowdstrike.com/services/collector
proxy_url = <string>
* Optional corporate HTTP/HTTPS proxy URL for this tenant.
* Example: http://proxy.example.com:8080
* Include proxy credentials in the URL if the proxy requires them.
ca_bundle_path = <string>
* Optional full path to a custom PEM CA bundle for SSL-intercepting proxies.
* When empty, the app loads every .pem and .crt file from its certs/ directory.

[cid:<name>]
* Additional CrowdStrike tenant. One stanza per CID.
* <name> is the value used in the alert action's cid parameter.
* Any [settings] key can be overridden here. Unset keys fall back to [settings].
* The client secret is stored under this tenant's client_id.
* The HEC token is stored as hec_token:<name>.
falcon_cloud = <string>
* CrowdStrike Falcon API region or base URL for this tenant.
client_id = <string>
* CrowdStrike OAuth2 API Client ID for this tenant.
default_workflow = <string>
* Default Fusion workflow for this tenant.
ngsiem_hec_url = <string>
* Next-Gen SIEM HEC URL for this tenant.
proxy_url = <string>
* Optional corporate proxy URL for this tenant.
ca_bundle_path = <string>
* Optional custom CA bundle path for this tenant.
