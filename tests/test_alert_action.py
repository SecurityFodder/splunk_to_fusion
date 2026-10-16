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
    build_finding_payload,
    dispatch_finding,
    extract_alert_results,
    get_splunk_conf,
    parse_alert_input,
    writeback_notable_comment,
)
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

    def test_get_splunk_conf_reads_default_conf(self):
        conf = get_splunk_conf(session_key=None)
        self.assertEqual(conf.get("falcon_cloud"), "eu-1")
        self.assertEqual(conf.get("delivery_method"), "fusion_workflow")

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


