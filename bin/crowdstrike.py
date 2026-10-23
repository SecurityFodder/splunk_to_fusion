# -*- coding: utf-8 -*-
"""
CrowdStrike Falcon Fusion SOAR and Next-Gen SIEM Client.
Pure Python standard library implementation (Python 3.9+).
Supports HTTP proxies, SSL-intercepting CAs, OAuth2, and automatic retries.
"""

import glob
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("send_to_fusion.crowdstrike")

CLOUD_URLS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

_UUID_OR_HEX32_RE = re.compile(
    r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


class CrowdStrikeError(Exception):
    """Base exception for CrowdStrike API interactions."""
    def __init__(self, message, status_code=None, response_body=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def resolve_workflow_ref_type(workflow_ref):
    """Returns 'id' if workflow_ref is a 32-char hex ID or UUID, otherwise 'name'."""
    return "id" if _UUID_OR_HEX32_RE.match(str(workflow_ref or "").strip()) else "name"


class CrowdStrikeClient:
    """Lightweight client for CrowdStrike OAuth2, Fusion SOAR, and NG-SIEM HEC."""

    def __init__(self, cloud="eu-1", client_id=None, client_secret=None,
                 proxy_url=None, ca_bundle=None, timeout=30):
        self.base_url = CLOUD_URLS.get(cloud, cloud).rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.proxy_url = proxy_url.strip() if isinstance(proxy_url, str) else proxy_url
        self.ca_bundle = ca_bundle.strip() if isinstance(ca_bundle, str) else ca_bundle
        self.timeout = int(timeout or 30)

        self._token_lock = threading.Lock()
        self._access_token = None
        self._token_expiry = 0
        self._opener = self._build_opener()

    def _build_ssl_context(self):
        """Constructs an SSLContext enforcing TLS 1.2+ with enterprise CA certs loaded if present."""
        ctx = ssl.create_default_context()
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.ca_bundle:
            if not os.path.isfile(self.ca_bundle):
                raise CrowdStrikeError(f"Configured CA bundle file not found: {self.ca_bundle}")
            try:
                ctx.load_verify_locations(cafile=self.ca_bundle)
            except Exception as exc:
                raise CrowdStrikeError(f"Failed to load CA bundle {self.ca_bundle}: {exc}") from exc
            return ctx

        certs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "certs"))
        if os.path.isdir(certs_dir):
            cert_files = sorted(
                glob.glob(os.path.join(certs_dir, "*.pem")) + glob.glob(os.path.join(certs_dir, "*.crt"))
            )
            for cert_file in cert_files:
                try:
                    ctx.load_verify_locations(cafile=cert_file)
                    logger.info("Loaded enterprise CA cert: %s", os.path.basename(cert_file))
                except Exception as exc:
                    logger.warning("Could not load cert %s: %s", cert_file, exc)

        return ctx

    def _build_opener(self):
        """Constructs an urllib opener configured for proxy and TLS."""
        proxy_map = {"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else {}
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._build_ssl_context()),
            urllib.request.ProxyHandler(proxy_map),
        )

    def _request_with_retry(self, req, max_retries=3):
        """Executes an HTTP request with exponential backoff on transient errors (429, 5xx)."""
        backoff = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body) if body else {}
            except urllib.error.HTTPError as err:
                status = err.code
                err_body = err.read().decode("utf-8", errors="replace")
                retry_after = err.headers.get("Retry-After") if err.headers else None
                err.close()

                if status in (429, 502, 503, 504) and attempt < max_retries:
                    sleep_time = float(retry_after) if retry_after and retry_after.isdigit() else backoff
                    logger.warning("CrowdStrike HTTP %d (attempt %d/%d). Retrying in %.1fs...",
                                   status, attempt, max_retries, sleep_time)
                    time.sleep(sleep_time)
                    backoff *= 2.0
                    continue

                raise CrowdStrikeError(
                    f"CrowdStrike API error {status}: {err.reason}",
                    status_code=status,
                    response_body=err_body,
                ) from err
            except urllib.error.URLError as err:
                if attempt < max_retries:
                    logger.warning("Network connection failed (attempt %d/%d). Retrying in %.1fs: %s",
                                   attempt, max_retries, backoff, err.reason)
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue
                raise CrowdStrikeError(f"Connection to CrowdStrike failed: {err.reason}") from err

    def get_token(self, force_refresh=False):
        """Retrieves and caches OAuth2 access token in a thread-safe manner."""
        with self._token_lock:
            if not force_refresh and self._access_token and time.time() < self._token_expiry:
                return self._access_token

            if not self.client_id or not self.client_secret:
                raise CrowdStrikeError("client_id and client_secret are required for OAuth2 authentication.")

            token_url = urllib.parse.urljoin(self.base_url, "/oauth2/token")
            req = urllib.request.Request(
                token_url,
                data=urllib.parse.urlencode({
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                }).encode("utf-8"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            res = self._request_with_retry(req)
            access_token = res.get("access_token")
            if not access_token:
                raise CrowdStrikeError(f"OAuth2 response missing access_token: {res}")

            self._access_token = access_token
            self._token_expiry = time.time() + float(res.get("expires_in", 1799)) - 60.0
            return self._access_token

    def _authorized_json(self, url, payload, method="POST"):
        """Sends a JSON body with a bearer token, refreshing once on 401."""
        data = json.dumps(payload).encode("utf-8")

        def _send(bearer_token):
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"},
                method=method,
            )
            return self._request_with_retry(req)

        token = self.get_token()
        try:
            return _send(token)
        except CrowdStrikeError as err:
            if err.status_code == 401:
                return _send(self.get_token(force_refresh=True))
            raise

    def execute_workflow(self, workflow_ref, payload, dedup_key=None):
        """
        Executes an on-demand Fusion workflow.
        CrowdStrike enforces a 256KB body ceiling and server-side dedup via ?key=.
        """
        if not workflow_ref:
            raise CrowdStrikeError("workflow_ref (workflow definition_id or name) is required.")

        param_key = "definition_id" if resolve_workflow_ref_type(workflow_ref) == "id" else "name"
        params = {param_key: workflow_ref}
        if dedup_key:
            params["key"] = str(dedup_key)[:256]

        url = f"{self.base_url}/workflows/entities/execute/v1?{urllib.parse.urlencode(params)}"

        # Cap payload at 240 KB without mutating caller's dict
        if len(json.dumps(payload).encode("utf-8")) > 245760 and isinstance(payload, dict):
            logger.warning("Payload exceeds 240KB; truncating details.")
            payload = {
                **payload,
                "details": {"truncated": True, "notice": "Event details exceeded 240KB limit."},
            }

        res = self._authorized_json(url, payload)
        resources = res.get("resources", [])
        return resources[0] if resources else res.get("execution_id", "unknown")

    def create_case(self, name, description="", severity=50, status="New", tags=None, evidence=None):
        """Creates a Falcon Fusion SOAR case."""
        if not name:
            raise CrowdStrikeError("Case name is required.")
        body = {
            "name": name,
            "description": description,
            "severity": int(severity),
            "status": status,
        }
        if tags:
            body["tags"] = tags
        if evidence:
            body["evidence"] = evidence
        res = self._authorized_json(f"{self.base_url}/cases/entities/cases/v2", body, method="PUT")
        resources = res.get("resources", [])
        return resources[0] if resources else res

    def save_ioc(self, ioc_type, value, action="detect", platforms=None,
                 severity="medium", description="", source="Splunk ES"):
        """Saves a custom IOC with detect, prevent, or no_action."""
        if action not in ("detect", "prevent", "no_action"):
            raise CrowdStrikeError(f"Invalid IOC action: {action}. Use detect, prevent, or no_action.")
        if not ioc_type or not value:
            raise CrowdStrikeError("ioc_type and value are required.")
        indicator = {
            "type": ioc_type,
            "value": value,
            "action": action,
            "severity": severity,
            "platforms": platforms or ["windows", "linux", "mac"],
            "description": description,
            "source": source,
        }
        body = {"indicators": [indicator]}
        if description:
            body["comment"] = f"Splunk ES: {description}"[:1000]
        res = self._authorized_json(f"{self.base_url}/iocs/entities/indicators/v1", body)
        resources = res.get("resources", [])
        return resources[0] if resources else res

    def send_hec(self, hec_url, token, event_payload):
        """Sends finding to CrowdStrike Next-Gen SIEM HEC."""
        if not hec_url or not token:
            raise CrowdStrikeError("hec_url and token are required for NG-SIEM HEC transmission.")

        data = json.dumps({
            "event": event_payload,
            "sourcetype": "splunk:es:finding",
            "source": "splunk_es",
        }).encode("utf-8")

        req = urllib.request.Request(
            hec_url,
            data=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        return self._request_with_retry(req)
