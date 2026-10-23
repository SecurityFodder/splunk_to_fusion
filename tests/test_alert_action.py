# -*- coding: utf-8 -*-
"""
Unit tests for bin/send_to_fusion.py, bin/s2f_broker.py, and app packaging structure.
"""

import ast
import configparser
import csv
import glob
import gzip
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import xml.etree.ElementTree as ET
from unittest import mock

APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(APP_ROOT, "bin"))

import send_to_fusion
from send_to_fusion import (
    build_case_payload,
    build_finding_payload,
    dispatch_finding,
    extract_alert_results,
    extract_iocs,
    get_splunk_conf,
    list_cids,
    parse_alert_input,
    writeback_notable_comment,
)
from crowdstrike import CrowdStrikeError
from s2f_broker import S2FBrokerHandler


class TestAlertAction(unittest.TestCase):

    def test_parse_alert_input_json(self):
        json_payload = """
        {
            "session_key": "test_session_123",
            "configuration": {
                "delivery_method": "fusion_workflow",
                "workflow": "wf-custom",
                "comment": "Escalation to Fusion"
            },
            "result": {
                "event_id": "12345@@notable@@es",
                "rule_name": "Endpoint Suspicious Activity",
                "urgency": "critical",
                "src_ip": "10.1.2.3",
                "dest_ip": "192.168.1.50",
                "user": "alice"
            }
        }
        """
        parsed = parse_alert_input(json_payload)
        self.assertEqual(parsed.get("session_key"), "test_session_123")
        self.assertEqual(parsed["configuration"]["workflow"], "wf-custom")
        self.assertEqual(parsed["result"]["event_id"], "12345@@notable@@es")

    def test_parse_alert_input_xml(self):
        xml_payload = """
        <alert>
            <session_key>test_session_456</session_key>
            <configuration>
                <delivery_method>ngsiem_hec</delivery_method>
                <comment>Automated XML trigger</comment>
            </configuration>
            <result>
                <event_id>xml-999@@notable@@es</event_id>
                <rule_name>XML Alert</rule_name>
                <urgency>high</urgency>
            </result>
        </alert>
        """
        parsed = parse_alert_input(xml_payload)
        self.assertEqual(parsed.get("session_key"), "test_session_456")
        self.assertEqual(parsed["configuration"]["delivery_method"], "ngsiem_hec")
        self.assertEqual(parsed["result"]["event_id"], "xml-999@@notable@@es")

    def test_extract_alert_results_from_csv_gz(self):
        with tempfile.NamedTemporaryFile(suffix=".csv.gz", delete=False) as tf:
            gz_path = tf.name

        try:
            with gzip.open(gz_path, "wt", encoding="utf-8", newline="") as gz_file:
                writer = csv.DictWriter(gz_file, fieldnames=["event_id", "rule_name", "urgency"])
                writer.writeheader()
                writer.writerow({"event_id": "evt-1", "rule_name": "Rule One", "urgency": "high"})
                writer.writerow({"event_id": "evt-2", "rule_name": "Rule Two", "urgency": "critical"})

            results = extract_alert_results({"results_file": gz_path})
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["event_id"], "evt-1")
            self.assertEqual(results[1]["event_id"], "evt-2")
        finally:
            if os.path.exists(gz_path):
                os.remove(gz_path)

    def test_build_finding_payload(self):
        result = {
            "event_id": "finding-abc",
            "rule_name": "Lateral Movement Detected",
            "urgency": "high",
            "severity": "critical",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "user": "bob",
            "_raw": "internal splunk raw event",
            "_time": "1729012345"
        }
        config = {"comment": "Investigate immediately"}
        payload = build_finding_payload(result, config)

        self.assertEqual(payload["event_id"], "finding-abc")
        self.assertEqual(payload["rule_name"], "Lateral Movement Detected")
        self.assertEqual(payload["analyst_comment"], "Investigate immediately")
        self.assertEqual(payload["src"], "10.0.0.1")
        self.assertEqual(payload["user"], "bob")
        self.assertNotIn("_raw", payload["details"])
        self.assertNotIn("_time", payload["details"])
        self.assertIn("dest_ip", payload["details"])

    def test_extract_iocs(self):
        result = {
            "sha256": "a" * 64,
            "src_ip": "10.0.0.1",
            "dest": "example.com",
            "md5": "",
        }
        self.assertEqual(extract_iocs(result, "sha256"), [("sha256", "a" * 64, "sha256")])
        self.assertEqual(extract_iocs(result, "src_ip"), [("ipv4", "10.0.0.1", "src_ip")])
        # The value, not the field name, decides the type.
        self.assertEqual(extract_iocs(result, "dest"), [("domain", "example.com", "dest")])
        self.assertEqual(extract_iocs(result, "md5"), [])
        self.assertEqual(extract_iocs({}, ""), [])
        self.assertEqual(len(extract_iocs(result, "sha256, src_ip, dest")), 3)
        # A value that is not a supported indicator type is skipped, not sent.
        self.assertEqual(extract_iocs({"dest": "not an indicator"}, "dest"), [])

    def test_build_case_payload(self):
        payload = build_case_payload({"rule_name": "Test Rule", "urgency": "critical"})
        self.assertEqual(payload["name"], "Test Rule")
        self.assertEqual(payload["severity"], 90)
        self.assertEqual(payload["status"], "New")
        self.assertEqual(payload["tags"], ["splunk", "notable"])

        custom = build_case_payload(
            {"rule_name": "Test Rule", "urgency": "low"},
            {"case_name": "Custom Case", "case_tags": "alpha, beta"},
        )
        self.assertEqual(custom["name"], "Custom Case")
        self.assertEqual(custom["severity"], 30)
        self.assertEqual(custom["tags"], ["alpha", "beta"])

    def test_get_splunk_conf_reads_default_conf(self):
        conf = get_splunk_conf(session_key=None)
        self.assertEqual(conf.get("falcon_cloud"), "eu-1")
        self.assertEqual(conf.get("default_workflow"), "")

    def test_list_cids_includes_default(self):
        self.assertIn("default", list_cids(session_key=None))

    def test_writeback_es8_rest_fallback_to_notable_update(self):
        called_urls = []

        class DummyResp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                return b'{"success": true}'

        def fake_urlopen(req, timeout=10):
            called_urls.append(req.full_url)
            if "/public/v2/" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))
            return DummyResp()

        with mock.patch.object(send_to_fusion, "local_splunk_urlopen", side_effect=fake_urlopen):
            ok = writeback_notable_comment("tok", "finding-99", "Sent to CS")
            self.assertTrue(ok)
            self.assertEqual(len(called_urls), 3)
            self.assertTrue(called_urls[-1].endswith("/services/notable_update"))

    def test_broker_get_config_and_dispatch(self):
        broker = S2FBrokerHandler()
        get_resp = broker.handle(json.dumps({
            "method": "GET",
            "session": {"authtoken": "analyst_token"},
            "system_authtoken": ""
        }))
        self.assertEqual(get_resp["status"], 200)
        body = json.loads(get_resp["payload"])
        self.assertTrue(body["ok"])
        self.assertEqual(body["config"]["falcon_cloud"], "eu-1")

        # Verify non-admin cannot call save_config
        save_resp = broker.handle(json.dumps({
            "method": "POST",
            "session": {"authtoken": ""},
            "payload": json.dumps({"op": "save_config", "falcon_cloud": "us-1"})
        }))
        self.assertEqual(save_resp["status"], 403)

        # CID list is readable, CID config is readable, save_cid is admin-only
        cids_resp = broker.handle(json.dumps({
            "method": "POST",
            "session": {"authtoken": ""},
            "payload": json.dumps({"op": "get_cids"})
        }))
        self.assertEqual(cids_resp["status"], 200)
        self.assertIn("default", json.loads(cids_resp["payload"])["cids"])

        cid_resp = broker.handle(json.dumps({
            "method": "POST",
            "session": {"authtoken": ""},
            "payload": json.dumps({"op": "get_cid", "cid": "default"})
        }))
        self.assertEqual(cid_resp["status"], 200)
        self.assertEqual(json.loads(cid_resp["payload"])["config"]["falcon_cloud"], "eu-1")

        save_cid_resp = broker.handle(json.dumps({
            "method": "POST",
            "session": {"authtoken": ""},
            "payload": json.dumps({"op": "save_cid", "cid": "tenant-a", "client_id": "abc", "client_secret": "xyz"})
        }))
        self.assertEqual(save_cid_resp["status"], 403)

    def test_broker_save_cid_requires_admin(self):
        broker = S2FBrokerHandler()
        with mock.patch("s2f_broker._user_has_admin_capability", return_value=False):
            resp = broker.handle(json.dumps({
                "method": "POST",
                "session": {"authtoken": "analyst_token"},
                "system_authtoken": "system_token",
                "payload": json.dumps({
                    "op": "save_cid", "cid": "tenant-b",
                    "client_id": "cid-b", "client_secret": "secret-b"
                })
            }))
        self.assertEqual(resp["status"], 403)

    def test_broker_save_cid_admin_stores_config_and_secret(self):
        broker = S2FBrokerHandler()
        with mock.patch("s2f_broker._user_has_admin_capability", return_value=True), \
             mock.patch("s2f_broker.save_splunk_conf") as save_conf, \
             mock.patch("s2f_broker.upsert_stored_credential") as save_cred:
            resp = broker.handle(json.dumps({
                "method": "POST",
                "session": {"authtoken": "admin_token"},
                "system_authtoken": "system_token",
                "payload": json.dumps({
                    "op": "save_cid", "cid": "tenant-a",
                    "client_id": "cid-a", "client_secret": "secret-a"
                })
            }))
        self.assertEqual(resp["status"], 200)
        save_conf.assert_called_once()
        self.assertEqual(save_conf.call_args.kwargs["stanza"], "cid:tenant-a")
        save_cred.assert_called_once_with("system_token", "ta_splunk_to_fusion", "cid-a", "secret-a")

    def _broker_request(self, op, body):
        return json.dumps({
            "method": "POST",
            "session": {"authtoken": "admin_token"},
            "payload": json.dumps({"op": op, **body}),
        })

    def test_broker_test_connection_validation(self):
        broker = S2FBrokerHandler()
        base = {"falcon_cloud": "eu-1", "client_id": "a" * 32, "client_secret": "secret"}
        cases = [
            ({"falcon_cloud": "eu-1", "client_id": "", "client_secret": ""},
             "Client ID and Client Secret are required"),
            ({"falcon_cloud": "eu1", "client_id": "a" * 32, "client_secret": "secret"},
             "Cloud Region is not recognized"),
            ({**base, "proxy_url": "proxy.example.com:8080"}, "Proxy URL must start with"),
            ({**base, "ca_bundle_path": "/nonexistent/ca.pem"}, "Custom CA Bundle Path"),
        ]
        with mock.patch("s2f_broker._user_has_admin_capability", return_value=True), \
             mock.patch("s2f_broker.get_stored_credential", return_value=None):
            for body, expected in cases:
                resp = broker.handle(self._broker_request("test_connection", body))
                self.assertEqual(resp["status"], 400, body)
                self.assertIn(expected, json.loads(resp["payload"])["error"])

    def test_broker_test_connection_error_messages(self):
        broker = S2FBrokerHandler()
        body = {"falcon_cloud": "eu-1", "client_id": "a" * 32, "client_secret": "secret"}
        cases = [
            (CrowdStrikeError("CrowdStrike API error 401: Unauthorized", status_code=401), "HTTP 401"),
            (CrowdStrikeError("CrowdStrike API error 403: Forbidden", status_code=403), "HTTP 403"),
            (CrowdStrikeError("Connection to CrowdStrike failed: certificate verify failed"),
             "TLS certificate verification failed"),
            (CrowdStrikeError("Connection to CrowdStrike failed: timed out"), "timed out"),
            (CrowdStrikeError("Connection to CrowdStrike failed: Name or service not known"),
             "Could not resolve"),
            (RuntimeError("super-secret-value"), "RuntimeError"),
        ]
        for error, expected in cases:
            client = mock.Mock()
            client.get_token.side_effect = error
            with mock.patch("s2f_broker._user_has_admin_capability", return_value=True), \
                 mock.patch("s2f_broker.CrowdStrikeClient", return_value=client):
                resp = broker.handle(self._broker_request("test_connection", body))
            self.assertEqual(resp["status"], 400)
            message = json.loads(resp["payload"])["error"]
            self.assertIn(expected, message)
            self.assertNotIn("super-secret-value", message)

    def test_broker_test_connection_success_warnings(self):
        broker = S2FBrokerHandler()
        client = mock.Mock()
        client.get_token.return_value = "token"
        with mock.patch("s2f_broker._user_has_admin_capability", return_value=True), \
             mock.patch("s2f_broker.CrowdStrikeClient", return_value=client):
            resp = broker.handle(self._broker_request("test_connection", {
                "falcon_cloud": "eu-1", "client_id": "short", "client_secret": "secret",
            }))
        self.assertEqual(resp["status"], 200)
        data = json.loads(resp["payload"])
        self.assertTrue(data["ok"])
        self.assertIn("usually 32", data["warnings"][0])

    def test_app_structure_py39_ast_and_xml_validity(self):
        # 1. Verify all Python files parse cleanly under Python 3.9 syntax rules
        py_files = glob.glob(os.path.join(APP_ROOT, "bin", "*.py")) + glob.glob(os.path.join(APP_ROOT, "tests", "*.py"))
        self.assertGreaterEqual(len(py_files), 4)
        for py_file in py_files:
            with open(py_file, "r", encoding="utf-8") as fh:
                ast.parse(fh.read(), filename=py_file, feature_version=(3, 9))

        # 2. Verify all XML and HTML UI files are well-formed XML
        xml_files = (
            glob.glob(os.path.join(APP_ROOT, "default", "data", "ui", "**", "*.xml"), recursive=True)
            + glob.glob(os.path.join(APP_ROOT, "default", "data", "ui", "**", "*.html"), recursive=True)
        )
        self.assertGreaterEqual(len(xml_files), 5)
        for xf in xml_files:
            ET.parse(xf)

        # 3. Verify alert_actions.conf has valid param._cam JSON and icon exists
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(os.path.join(APP_ROOT, "default", "alert_actions.conf"), encoding="utf-8")
        cam_raw = parser.get("send_to_fusion", "param._cam")
        cam = json.loads(cam_raw)
        self.assertTrue(cam.get("supports_adhoc"))
        self.assertEqual(parser.get("send_to_fusion", "python.version"), "python3")
        self.assertTrue(os.path.isfile(os.path.join(APP_ROOT, "appserver", "static", "alerticon.png")))
        self.assertTrue(os.path.isfile(os.path.join(APP_ROOT, "README", "alert_actions.conf.spec")))
        self.assertTrue(os.path.isfile(os.path.join(APP_ROOT, "README", "ta_splunk_to_fusion.conf.spec")))

    def test_appinspect_compliance(self):
        # 1. Verify default/app.conf stanzas and ID matching
        app_conf = configparser.ConfigParser(interpolation=None)
        app_conf.read(os.path.join(APP_ROOT, "default", "app.conf"), encoding="utf-8")
        self.assertEqual(app_conf.get("id", "name"), "TA-splunk_to_fusion")
        self.assertEqual(app_conf.get("package", "id"), "TA-splunk_to_fusion")
        self.assertEqual(app_conf.get("id", "version"), app_conf.get("launcher", "version"))
        self.assertEqual(app_conf.get("install", "is_configured"), "0")

        # 2. Verify savedsearches.conf stanzas are disabled/unscheduled by default and have dispatch bounds
        ss_conf = configparser.ConfigParser(interpolation=None)
        ss_conf.read(os.path.join(APP_ROOT, "default", "savedsearches.conf"), encoding="utf-8")
        self.assertGreaterEqual(len(ss_conf.sections()), 5)
        for sec in ss_conf.sections():
            self.assertEqual(ss_conf.get(sec, "disabled"), "1", f"{sec} must have disabled = 1")
            self.assertEqual(ss_conf.get(sec, "enableSched"), "0", f"{sec} must have enableSched = 0")
            self.assertTrue(ss_conf.get(sec, "dispatch.earliest_time"), f"{sec} missing earliest_time")
            self.assertTrue(ss_conf.get(sec, "dispatch.latest_time"), f"{sec} missing latest_time")

        # 3. Verify restmap.conf specifies python.version = python3
        rm_conf = configparser.ConfigParser(interpolation=None)
        rm_conf.read(os.path.join(APP_ROOT, "default", "restmap.conf"), encoding="utf-8")
        for sec in rm_conf.sections():
            self.assertEqual(rm_conf.get(sec, "python.version"), "python3")

        # 4. Verify every setting in default/ta_splunk_to_fusion.conf is documented in README/*.conf.spec
        ta_conf = configparser.ConfigParser(interpolation=None)
        ta_conf.read(os.path.join(APP_ROOT, "default", "ta_splunk_to_fusion.conf"), encoding="utf-8")
        with open(os.path.join(APP_ROOT, "README", "ta_splunk_to_fusion.conf.spec"), "r", encoding="utf-8") as fh:
            spec_text = fh.read()
        for key in ta_conf.options("settings"):
            self.assertIn(f"{key} =", spec_text, f"{key} missing from ta_splunk_to_fusion.conf.spec")

        # 5. Verify all SimpleXML views declare version="1.1"
        for xml_view in glob.glob(os.path.join(APP_ROOT, "default", "data", "ui", "views", "*.xml")):
            root = ET.parse(xml_view).getroot()
            self.assertEqual(root.attrib.get("version"), "1.1", f"{xml_view} missing version='1.1'")

        # 6. Verify static icons exist
        for icon in ("appIcon.png", "appIcon_2x.png", "appIconAlt.png", "appIconAlt_2x.png", "appLogo.png", "appLogo_2x.png"):
            self.assertTrue(os.path.isfile(os.path.join(APP_ROOT, "static", icon)), f"Missing static/{icon}")

        # 7. Verify SHC custom conf replication in default/server.conf
        srv_conf = configparser.ConfigParser(interpolation=None)
        srv_conf.read(os.path.join(APP_ROOT, "default", "server.conf"), encoding="utf-8")
        self.assertEqual(srv_conf.get("shclustering", "conf_replication_include.ta_splunk_to_fusion"), "true")


if __name__ == "__main__":
    unittest.main()


