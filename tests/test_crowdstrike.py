# -*- coding: utf-8 -*-
"""
Unit tests for bin/crowdstrike.py using standard library unittest and http.server.
"""

import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse

# Ensure bin is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin")))
from crowdstrike import (
    CrowdStrikeClient,
    CrowdStrikeError,
    resolve_workflow_ref_type,
)


class MockCrowdStrikeHandler(http.server.BaseHTTPRequestHandler):
    """Mock server simulating CrowdStrike Falcon OAuth2, Fusion execute, and HEC."""

    def log_message(self, format, *args):
        pass  # Quiet logging during test runs

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        # 1. OAuth2 Token endpoint
        if parsed_path.path == "/oauth2/token":
            form = urllib.parse.parse_qs(post_body)
            if form.get("client_id") == ["bad_client"]:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"errors": [{"message": "Invalid client"}]}')
                return

            self.server.token_counter = getattr(self.server, "token_counter", 0) + 1
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "access_token": f"mock-token-xyz-{self.server.token_counter}",
                "expires_in": 1800
            }).encode("utf-8"))
            return

        # 2. Fusion Workflow execute endpoint
        if parsed_path.path == "/workflows/entities/execute/v1":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self.send_response(401)
                self.end_headers()
                return

            query = urllib.parse.parse_qs(parsed_path.query)
            self.server.last_workflow_query = query
            self.server.last_workflow_body = json.loads(post_body) if post_body else {}

            # Simulate expired token on first call
            if query.get("name") == ["trigger_401_once"]:
                if not getattr(self.server, "reauthed", False):
                    self.server.reauthed = True
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"errors": [{"message": "Token expired"}]}')
                    return

            # Check transient 429 error simulation
            if query.get("name") == ["trigger_rate_limit"]:
                if not getattr(self.server, "retried", False):
                    self.server.retried = True
                    self.send_response(429)
                    self.send_header("Retry-After", "1")
                    self.end_headers()
                    self.wfile.write(b'{"errors": [{"message": "Rate limited"}]}')
                    return

            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resources": ["exec-456-uuid-789"]
            }).encode("utf-8"))
            return

        # 3. NG-SIEM HEC endpoint
        if parsed_path.path == "/services/collector":
            auth = self.headers.get("Authorization", "")
            if not (auth.startswith("Bearer ") or auth.startswith("Splunk ")):
                self.send_response(401)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"text": "Success", "code": 0}')
            return

        self.send_response(404)
        self.end_headers()


class TestCrowdStrikeClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockCrowdStrikeHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.server.token_counter = 0
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.client = CrowdStrikeClient(
            cloud=self.base_url,
            client_id="test_id",
            client_secret="test_secret",
            timeout=5
        )

    def test_oauth2_token_success(self):
        token = self.client.get_token()
        self.assertEqual(token, "mock-token-xyz-1")
        # Ensure token is cached
        cached = self.client.get_token()
        self.assertEqual(cached, token)

    def test_oauth2_token_failure(self):
        bad_client = CrowdStrikeClient(
            cloud=self.base_url,
            client_id="bad_client",
            client_secret="bad_secret",
            timeout=5
        )
        with self.assertRaises(CrowdStrikeError) as ctx:
            bad_client.get_token()
        self.assertEqual(ctx.exception.status_code, 401)

    def test_resolve_workflow_ref_type_and_execution(self):
        hex_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        uuid_id = "12345678-1234-1234-1234-123456789abc"
        wf_name = "ES Incident Intake"

        self.assertEqual(resolve_workflow_ref_type(hex_id), "id")
        self.assertEqual(resolve_workflow_ref_type(uuid_id), "id")
        self.assertEqual(resolve_workflow_ref_type(wf_name), "name")

        # Execute by 32-char hex ID -> sends ?definition_id=
        exec_id = self.client.execute_workflow(
            workflow_ref=hex_id,
            payload={"event_id": "finding-123"},
            dedup_key="finding-123"
        )
        self.assertEqual(exec_id, "exec-456-uuid-789")
        self.assertEqual(self.server.last_workflow_query.get("definition_id"), [hex_id])

        # Execute by workflow name -> sends ?name=
        exec_id_2 = self.client.execute_workflow(
            workflow_ref=wf_name,
            payload={"event_id": "finding-124"},
            dedup_key="finding-124"
        )
        self.assertEqual(exec_id_2, "exec-456-uuid-789")
        self.assertEqual(self.server.last_workflow_query.get("name"), [wf_name])

    def test_payload_truncation_does_not_mutate_caller(self):
        large_details = {"huge_field": "A" * 260000}
        payload = {"event_id": "finding-large", "details": large_details}
        exec_id = self.client.execute_workflow(
            workflow_ref="wf-intake-1",
            payload=payload,
            dedup_key="finding-large"
        )
        self.assertEqual(exec_id, "exec-456-uuid-789")
        # Caller's dictionary must NOT be mutated in-place
        self.assertIn("huge_field", payload["details"])
        # Sent body must have replaced details with truncation notice
        sent_details = self.server.last_workflow_body.get("details", {})
        self.assertTrue(sent_details.get("truncated"))

    def test_retry_on_429(self):
        self.server.retried = False
        exec_id = self.client.execute_workflow(
            workflow_ref="trigger_rate_limit",
            payload={"event_id": "test_retry"},
            dedup_key="retry-1"
        )
        self.assertEqual(exec_id, "exec-456-uuid-789")
        self.assertTrue(self.server.retried)

    def test_reauth_on_401(self):
        self.server.reauthed = False
        exec_id = self.client.execute_workflow(
            workflow_ref="trigger_401_once",
            payload={"event_id": "test_401"},
            dedup_key="reauth-1"
        )
        self.assertEqual(exec_id, "exec-456-uuid-789")
        self.assertTrue(self.server.reauthed)
        self.assertEqual(self.server.token_counter, 2)

    def test_send_hec_bearer_and_splunk(self):
        hec_url = f"{self.base_url}/services/collector"
        res_bearer = self.client.send_hec(hec_url, "my-hec-token", {"event_id": "hec-1"}, auth_scheme="Bearer")
        self.assertEqual(res_bearer.get("code"), 0)

        res_splunk = self.client.send_hec(hec_url, "my-hec-token", {"event_id": "hec-2"}, auth_scheme="Splunk")
        self.assertEqual(res_splunk.get("code"), 0)

    def test_ca_bundle_loading_and_missing_error(self):
        with self.assertRaises(CrowdStrikeError):
            CrowdStrikeClient(
                cloud=self.base_url,
                client_id="test_id",
                client_secret="test_secret",
                ca_bundle="/nonexistent/path/to/corp_ca.pem"
            )

        valid_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDDzCCAfegAwIBAgIUe43smUeCoag2r6y8LxuBE3jsxAIwDQYJKoZIhvcNAQEL\n"
            "BQAwFzEVMBMGA1UEAwwMQ29ycCBUZXN0IENBMB4XDTI2MTAxNjEwNDkwNloXDTI3\n"
            "MTAxNjEwNDkwNlowFzEVMBMGA1UEAwwMQ29ycCBUZXN0IENBMIIBIjANBgkqhkiG\n"
            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1iqSQJeQ7wskg5Yi+uplxtCdo1TjeqmNik9d\n"
            "rqKRjkgaVu6xOsAloXkwNjyl/CoG/pRxN7dUrC3A+1vcssak4BvWgDf070k59D39\n"
            "YiJMMg8IKuLMAlye1L1K9KaAGXMRhIbiNEcmNzWYqtL/krI757rPQUoSRmRza2nZ\n"
            "3MbMKA+Pq7i4R3EQxscMTEjgPUnMFY9nfbRk1x3TwrwiZnOZs3LxTwMnlfbq9l1o\n"
            "MdMT5N7HrJgQdfIdy4OvqIE93fVEneDBqABRp1J3vIS6WsMHtxY8xAv0OXqAwH7V\n"
            "OGn8LzXtJIRYE4BIBE0CeP9o/EMf6qs3JLb6VcwXeC0oHlXDjQIDAQABo1MwUTAd\n"
            "BgNVHQ4EFgQUk5QE2T6pNiMbzxyr+56ja2fq0eUwHwYDVR0jBBgwFoAUk5QE2T6p\n"
            "NiMbzxyr+56ja2fq0eUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
            "AQEAqhhyGKYfdjokHBp9PtzpOKP9M0mWFkva6Um4roRiysZ69KA5nN8COM/tKpIt\n"
            "fwmJr/wvZFF4sqwXSbZ/mEO59qKsbs44/nHuYZyu6jnf7AZXKOZxRPGBkBHTmU5+\n"
            "0yYKhfHkk++IjnXkpkgMIZQbZDX2ECL+RvvF5b3TVJNJqmHoHKo99fZVakrM7rWM\n"
            "XHjynE1hJhVT7Cx5slWY0L1NcrejMSI9hcjqGQqT/FpGf7dCp/CZRoi582CxmD2T\n"
            "SAndOBZyJ+BTLrOl5iRQ/uzREa/fx3SMJsMTtuA/g/GEGNihSorjwmUPNgk7wNc7\n"
            "A85Bhgf1yMALaBLD+A3RQTiRTA==\n"
            "-----END CERTIFICATE-----\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(valid_pem)
            temp_pem = tf.name

        try:
            client_with_ca = CrowdStrikeClient(
                cloud=self.base_url,
                client_id="test_id",
                client_secret="test_secret",
                ca_bundle=temp_pem
            )
            self.assertIsNotNone(client_with_ca._opener)
        finally:
            if os.path.exists(temp_pem):
                os.remove(temp_pem)


if __name__ == "__main__":
    unittest.main()

