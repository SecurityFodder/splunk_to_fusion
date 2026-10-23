[send_to_fusion]
* Sends notable events to CrowdStrike.
* Each parameter below can be set per alert action; unset values use the tenant configuration.
param.delivery_method = <string>
* Where the notable goes. Default: fusion_workflow.
* fusion_workflow: Trigger a Fusion SOAR workflow.
* ngsiem_hec: Send the finding to Falcon Next-Gen SIEM over HEC.
* both: Send to the workflow and Next-Gen SIEM.
* none: Skip workflow and HEC (use when only create_case or ioc_fields is set).
param.workflow = <string>
* Optional Fusion workflow definition ID or name override.
* Empty uses the default_workflow from the tenant configuration.
param.cid = <string>
* Selects the CrowdStrike tenant for this action.
* Must match a [cid:<name>] stanza in ta_splunk_to_fusion.conf.
* Empty uses the default [settings] tenant.
param.create_case = <string>
* Create a CrowdStrike case for this notable. Default: none.
* none: Do not create a case.
* always: Create a case.
param.case_name = <string>
* Optional case name. Empty uses the notable's rule name.
param.case_tags = <string>
* Optional comma-separated case tags. Empty uses "splunk, notable".
param.ioc_action = <string>
* Save IOCs extracted from this notable. Default: none.
* none: Do not save IOCs.
* detect: Add the IOC in detect mode (alert only).
* prevent: Add the IOC in prevent mode (block the indicator).
param.ioc_fields = <string>
* Comma-separated result fields whose values become IOCs.
* The value determines the CrowdStrike IOC type (IPv4/IPv6, hash, or domain).
* Empty disables IOC extraction. Example: sha256, src_ip, dest_ip
param.comment = <string>
* Optional context from the analyst or detection rule.
* Included in the case or workflow payload.
param._cam = <json>
* Splunk Enterprise Security Common Action Model JSON definition.
