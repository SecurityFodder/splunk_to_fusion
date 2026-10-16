#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk Modular Alert Action / Adaptive Response Action:
Sends Splunk ES 8 notable events to CrowdStrike Fusion SOAR and/or NG-SIEM HEC.
"""

import configparser
import csv
import gzip
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(__file__))
from crowdstrike import CrowdStrikeClient, CrowdStrikeError

APP_NAME = "TA-splunk_to_fusion"
CONF_NAME = "ta_splunk_to_fusion"
CRED_REALM = "ta_splunk_to_fusion"

LOG_FILE = os.path.join(
    os.environ.get("SPLUNK_HOME", "/opt/splunk"),
    "var", "log", "splunk", "send_to_fusion.log",
)
_handlers = [logging.StreamHandler(sys.stderr)]
if os.path.isdir(os.path.dirname(LOG_FILE)):
    try:
        _handlers.append(logging.FileHandler(LOG_FILE, encoding="utf-8"))
    except OSError:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [send_to_fusion] %(message)s",
    handlers=_handlers,
)
logger = logging.getLogger("send_to_fusion")


def _clean_kv(val):
    """Sanitizes a value for quoted key="value" Splunk log output."""
    return str(val or "").replace("\\", "\\\\").replace('"', "'").replace("\n", " ").replace("\r", " ")


def local_splunk_urlopen(req, timeout=10):
    """Opens a request to local splunkd (127.0.0.1:8089), bypassing ambient HTTP proxies."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )
    return opener.open(req, timeout=timeout)


def parse_alert_input(stdin_data):
    """Parses JSON or XML payload delivered by Splunk on stdin."""
    stdin_data = stdin_data.strip()
    if not stdin_data:
        raise ValueError("Empty alert payload received on stdin.")

    if stdin_data.startswith("{"):
        try:
            return json.loads(stdin_data)
        except json.JSONDecodeError as err:
            logger.warning("JSON decode failed: %s. Attempting XML...", err)

    try:
        root = ET.fromstring(stdin_data)
        payload = {}
        for elem in root:
            if elem.tag in ("configuration", "result"):
                payload[elem.tag] = {sub.tag: (sub.text or "") for sub in elem}
            else:
                payload[elem.tag] = elem.text or ""
        return payload
    except ET.ParseError as err:
        raise ValueError(f"Failed to parse alert input as JSON or XML: {err}") from err


def extract_alert_results(alert_data):
    """Extracts event dicts from results_file (.csv.gz/.csv) or falls back to single 'result'."""
    results = []
    results_file = alert_data.get("results_file")
    if results_file and os.path.isfile(results_file):
        try:
            open_fn = gzip.open if results_file.endswith(".gz") else open
            with open_fn(results_file, "rt", encoding="utf-8", errors="replace") as fh:
                results = [dict(row) for row in csv.DictReader(fh) if row]
        except Exception as exc:
            logger.warning("Failed reading results_file %s: %s", results_file, exc)

    if not results and isinstance(alert_data.get("result"), dict) and alert_data["result"]:
        results.append(alert_data["result"])
    return results


def get_splunk_conf(session_key, app_name=APP_NAME, conf_name=CONF_NAME, stanza="settings"):
    """Reads app configuration from default/local conf files (default first, then local) and Splunk REST."""
    config_dict = {}
    app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")

    seen = set()
    for root in (app_root, os.path.join(splunk_home, "etc", "apps", app_name)):
        for subdir in ("default", "local"):
            cp = os.path.abspath(os.path.join(root, subdir, f"{conf_name}.conf"))
            if cp not in seen and os.path.isfile(cp):
                seen.add(cp)
                parser = configparser.ConfigParser(interpolation=None)
                parser.read(cp, encoding="utf-8")
                if parser.has_section(stanza):
                    for k, v in parser.items(stanza):
                        if subdir == "default" or v != "":
                            config_dict[k] = v

    if session_key:
        try:
            url = f"https://127.0.0.1:8089/servicesNS/nobody/{app_name}/configs/conf-{conf_name}/{stanza}?output_mode=json"
            req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
            with local_splunk_urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for entry in data.get("entry", []):
                    for k, v in entry.get("content", {}).items():
                        if not k.startswith("eai:") and v not in (None, ""):
                            config_dict[k] = v
        except Exception as exc:
            logger.debug("REST config lookup skipped or failed: %s", exc)

    return config_dict


def get_stored_credential(session_key, realm, username, app_name=APP_NAME):
    """Retrieves decrypted secret from Splunk storage/passwords."""
    if not session_key or not realm or not username:
        return None
    try:
        enc_realm = urllib.parse.quote(str(realm), safe="")
        enc_user = urllib.parse.quote(str(username), safe="")
        url = f"https://127.0.0.1:8089/servicesNS/nobody/{app_name}/storage/passwords/{enc_realm}:{enc_user}?output_mode=json"
        req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
        with local_splunk_urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data.get("entry", []):
                clear = entry.get("content", {}).get("clear_password")
                if clear:
                    return clear
    except Exception as exc:
        logger.debug("Could not retrieve credential for %s:%s: %s", realm, username, exc)
    return None


def writeback_notable_comment(session_key, finding_id, comment):
    """Tries ES 8 Findings/Investigations REST note endpoints first, then falls back to /services/notable_update."""
    if not session_key or not finding_id or finding_id == "unknown_event":
        return False

    enc_id = urllib.parse.quote(str(finding_id), safe="")
    es8_urls = (
        f"https://127.0.0.1:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/public/v2/findings/{enc_id}/notes",
        f"https://127.0.0.1:8089/servicesNS/nobody/missioncontrol/public/v2/investigations/{enc_id}/notes",
    )
    note_bytes = json.dumps({"content": comment}).encode("utf-8")
    for url in es8_urls:
        req = urllib.request.Request(
            url,
            data=note_bytes,
            headers={"Authorization": f"Splunk {session_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with local_splunk_urlopen(req, timeout=10):
                logger.info("Successfully added ES8 finding note to %s", finding_id)
                return True
        except urllib.error.HTTPError as err:
            err.close()
        except Exception:
            pass

    req = urllib.request.Request(
        "https://127.0.0.1:8089/services/notable_update",
        data=urllib.parse.urlencode({"ruleUIDs": finding_id, "comment": comment}).encode("utf-8"),
        headers={"Authorization": f"Splunk {session_key}"},
        method="POST",
    )
    try:
        with local_splunk_urlopen(req, timeout=10):
            logger.info("Successfully added comment to notable %s via notable_update", finding_id)
            return True
    except Exception as exc:
        logger.warning("Failed to write comment to notable %s: %s", finding_id, exc)
        return False


def build_finding_payload(result, config):
    """Formats the notable event into a structured payload for CrowdStrike."""
    return {
        "event_id": result.get("event_id") or result.get("rule_id") or "unknown",
        "rule_name": result.get("rule_name") or result.get("search_name") or "ES Notable Event",
        "urgency": result.get("urgency") or "unknown",
        "severity": result.get("severity") or "unknown",
        "security_domain": result.get("security_domain") or "threat",
        "status": result.get("status_label") or result.get("status") or "unknown",
        "owner": result.get("owner") or "",
        "analyst_comment": config.get("comment") or "",
        "src": result.get("src") or result.get("src_ip") or "",
        "dest": result.get("dest") or result.get("dest_ip") or "",
        "user": result.get("user") or result.get("src_user") or "",
        "details": {k: v for k, v in result.items() if not k.startswith("_") and v not in (None, "")},
    }


def dispatch_finding(result, config, session_key=None, app_conf=None, client=None):
    """Dispatches a single notable event dict to CrowdStrike Fusion and/or NG-SIEM HEC."""
    if app_conf is None:
        app_conf = get_splunk_conf(session_key)

    cloud = config.get("falcon_cloud") or app_conf.get("falcon_cloud") or "eu-1"
    client_id = (config.get("client_id") or app_conf.get("client_id") or "").strip()
    proxy_url = (
        config.get("proxy_url")
        or get_stored_credential(session_key, CRED_REALM, "proxy_url")
        or app_conf.get("proxy_url")
    )
    ca_bundle = config.get("ca_bundle_path") or app_conf.get("ca_bundle_path")
    delivery_method = config.get("delivery_method") or app_conf.get("delivery_method") or "fusion_workflow"
    workflow_id = (config.get("workflow") or app_conf.get("default_workflow") or "").strip()

    finding_id = result.get("event_id") or result.get("rule_id") or "unknown_event"
    payload = build_finding_payload(result, config)
    rule_name = payload.get("rule_name", "unknown")

    if client is None:
        client_secret = (
            get_stored_credential(session_key, CRED_REALM, client_id)
            or get_stored_credential(session_key, CRED_REALM, "client_secret")
            or app_conf.get("client_secret")
        )
        client = CrowdStrikeClient(
            cloud=cloud,
            client_id=client_id,
            client_secret=client_secret,
            proxy_url=proxy_url,
            ca_bundle=ca_bundle,
        )

    hec_url = (config.get("ngsiem_hec_url") or app_conf.get("ngsiem_hec_url") or "").strip()
    hec_token = get_stored_credential(session_key, CRED_REALM, "hec_token") or app_conf.get("ngsiem_hec_token")
    hec_auth_scheme = config.get("ngsiem_hec_auth_scheme") or app_conf.get("ngsiem_hec_auth_scheme") or "Bearer"

    success_messages = []
    exec_id = ""
    start_time = time.time()

    if delivery_method in ("fusion_workflow", "both"):
        if not workflow_id:
            logger.error(
                'status=failure action=execute_workflow reason="No workflow ID or name specified" '
                'delivery_method="%s" event_id="%s" rule_name="%s"',
                _clean_kv(delivery_method), _clean_kv(finding_id), _clean_kv(rule_name),
            )
            return False, ["No workflow ID or name specified"], ""
        try:
            exec_id = client.execute_workflow(workflow_id, payload, dedup_key=finding_id)
            duration_ms = int((time.time() - start_time) * 1000)
            logger.info(
                'status=success action=execute_workflow delivery_method="%s" event_id="%s" '
                'rule_name="%s" exec_id="%s" duration_ms=%d',
                _clean_kv(delivery_method), _clean_kv(finding_id),
                _clean_kv(rule_name), _clean_kv(exec_id), duration_ms,
            )
            success_messages.append(f"CrowdStrike Fusion workflow triggered successfully (Execution ID: {exec_id})")
        except CrowdStrikeError as err:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(
                'status=failure action=execute_workflow delivery_method="%s" event_id="%s" '
                'rule_name="%s" status_code=%s error_msg="%s" duration_ms=%d',
                _clean_kv(delivery_method), _clean_kv(finding_id), _clean_kv(rule_name),
                getattr(err, "status_code", None) or "unknown", _clean_kv(err), duration_ms,
            )
            return False, [str(err)], ""

    if delivery_method in ("ngsiem_hec", "both"):
        hec_start = time.time()
        try:
            client.send_hec(hec_url, hec_token, payload, auth_scheme=hec_auth_scheme)
            hec_duration = int((time.time() - hec_start) * 1000)
            logger.info(
                'status=success action=send_hec delivery_method="%s" event_id="%s" '
                'rule_name="%s" duration_ms=%d',
                _clean_kv(delivery_method), _clean_kv(finding_id), _clean_kv(rule_name), hec_duration,
            )
            success_messages.append("CrowdStrike Next-Gen SIEM HEC event ingested successfully")
        except CrowdStrikeError as err:
            hec_duration = int((time.time() - hec_start) * 1000)
            logger.error(
                'status=failure action=send_hec delivery_method="%s" event_id="%s" '
                'rule_name="%s" status_code=%s error_msg="%s" duration_ms=%d',
                _clean_kv(delivery_method), _clean_kv(finding_id), _clean_kv(rule_name),
                getattr(err, "status_code", None) or "unknown", _clean_kv(err), hec_duration,
            )
            return False, [str(err)], exec_id

    if session_key and finding_id != "unknown_event" and success_messages:
        writeback_notable_comment(session_key, finding_id, f"Sent to CrowdStrike: {' | '.join(success_messages)}")

    total_duration = int((time.time() - start_time) * 1000)
    logger.info(
        'status=success action=alert_action_complete delivery_method="%s" event_id="%s" '
        'rule_name="%s" total_duration_ms=%d',
        _clean_kv(delivery_method), _clean_kv(finding_id), _clean_kv(rule_name), total_duration,
    )
    return True, success_messages, exec_id


def try_broker_dispatch(session_key, result, config):
    """Dispatches via local s2f_broker (passSystemAuth=true) so analysts do not need list_storage_passwords."""
    if not session_key:
        return None
    req = urllib.request.Request(
        "https://127.0.0.1:8089/services/ta_s2f/broker",
        data=json.dumps({"op": "dispatch", "result": result, "configuration": config}).encode("utf-8"),
        headers={"Authorization": f"Splunk {session_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with local_splunk_urlopen(req, timeout=35) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        code, reason, body = err.code, err.reason, err.read().decode("utf-8", errors="replace")
        err.close()
        if code == 404:
            return None
        try:
            return json.loads(body)
        except Exception:
            return {"ok": False, "error": f"Broker HTTP {code}: {reason}"}
    except Exception:
        return None


def main():
    if len(sys.argv) > 1 and sys.argv[1] != "--execute":
        sys.exit(0)

    raw_input = sys.stdin.read()
    if not raw_input:
        logger.error("No input data received on stdin.")
        sys.exit(2)

    try:
        alert_data = parse_alert_input(raw_input)
    except Exception as err:
        logger.error("Fatal input parsing error: %s", err)
        sys.exit(2)

    session_key = alert_data.get("session_key")
    config = alert_data.get("configuration", {})
    results = extract_alert_results(alert_data) or [{}]
    app_conf = get_splunk_conf(session_key)
    any_failure = False

    for result in results:
        broker_res = try_broker_dispatch(session_key, result, config)
        if broker_res is not None:
            if not broker_res.get("ok"):
                any_failure = True
            continue

        ok, _, _ = dispatch_finding(result, config, session_key=session_key, app_conf=app_conf)
        if not ok:
            any_failure = True

    sys.exit(1 if any_failure else 0)


if __name__ == "__main__":
    main()
