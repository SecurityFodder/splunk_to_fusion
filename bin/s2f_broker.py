# -*- coding: utf-8 -*-
"""
Persistent REST Broker for TA-splunk_to_fusion.
Runs under splunkd with passSystemAuth=true so:
1. Analysts with 's2f_send' capability can trigger CrowdStrike dispatches without 'list_storage_passwords'.
2. OAuth2 bearer tokens are cached in memory across alert invocations.
3. Administrators can save configuration/encrypted secrets and test connectivity from the Setup page.
"""

import json
import logging
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:
    class PersistentServerConnectionApplication:  # pragma: no cover
        def __init__(self):
            pass

from crowdstrike import CrowdStrikeClient, CrowdStrikeError
from send_to_fusion import (
    APP_NAME,
    CONF_NAME,
    CRED_REALM,
    dispatch_finding,
    get_splunk_conf,
    get_stored_credential,
    list_cids,
    local_splunk_urlopen,
)

logger = logging.getLogger("send_to_fusion.broker")

_CLIENT_LOCK = threading.Lock()
_CLIENT_CACHE = {}

ALLOWED_CONF_KEYS = (
    "falcon_cloud",
    "client_id",
    "default_workflow",
    "ngsiem_hec_url",
    "proxy_url",
    "ca_bundle_path",
)


def _json_response(status, body_dict):
    return {"status": status, "headers": {"Content-Type": "application/json"}, "payload": json.dumps(body_dict)}


def _splunk_post(token, path, form_dict):
    req = urllib.request.Request(
        f"https://127.0.0.1:8089{path}",
        data=urllib.parse.urlencode(form_dict).encode("utf-8"),
        headers={"Authorization": f"Splunk {token}"},
        method="POST",
    )
    with local_splunk_urlopen(req, timeout=10) as resp:
        return resp.read()


def _get_cached_client(cloud, client_id, client_secret, proxy_url, ca_bundle):
    cache_key = (cloud, client_id, client_secret, proxy_url, ca_bundle)
    with _CLIENT_LOCK:
        if cache_key not in _CLIENT_CACHE:
            _CLIENT_CACHE.clear()
            _CLIENT_CACHE[cache_key] = CrowdStrikeClient(
                cloud=cloud,
                client_id=client_id,
                client_secret=client_secret,
                proxy_url=proxy_url,
                ca_bundle=ca_bundle,
            )
        return _CLIENT_CACHE[cache_key]


def _user_has_admin_capability(user_token):
    if not user_token:
        return False
    req = urllib.request.Request(
        "https://127.0.0.1:8089/services/authentication/current-context?output_mode=json",
        headers={"Authorization": f"Splunk {user_token}"},
    )
    try:
        with local_splunk_urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            caps = data.get("entry", [{}])[0].get("content", {}).get("capabilities", [])
            return "admin_all_objects" in caps or "s2f_admin" in caps
    except Exception:
        return False


def upsert_stored_credential(system_token, realm, username, secret):
    """Creates or updates an encrypted credential in Splunk storage/passwords."""
    if not system_token or not username or not secret:
        return
    enc_realm = urllib.parse.quote(str(realm), safe="")
    enc_user = urllib.parse.quote(str(username), safe="")
    base = f"/servicesNS/nobody/{APP_NAME}/storage/passwords"
    try:
        _splunk_post(system_token, f"{base}/{enc_realm}:{enc_user}?output_mode=json", {"password": secret})
    except urllib.error.HTTPError as err:
        err.close()
        _splunk_post(system_token, f"{base}?output_mode=json", {"realm": realm, "name": username, "password": secret})


def save_splunk_conf(system_token, settings_dict, stanza="settings"):
    """Saves key-value settings to local/ta_splunk_to_fusion.conf and marks app configured."""
    filtered = {k: str(v) for k, v in settings_dict.items() if k in ALLOWED_CONF_KEYS and v is not None}
    if filtered:
        base = f"/servicesNS/nobody/{APP_NAME}/configs/conf-{CONF_NAME}"
        try:
            _splunk_post(system_token, f"{base}/{stanza}?output_mode=json", filtered)
        except urllib.error.HTTPError as err:
            err.close()
            _splunk_post(system_token, f"{base}?output_mode=json", {**filtered, "name": stanza})
    if stanza == "settings":
        try:
            _splunk_post(system_token, f"/servicesNS/nobody/{APP_NAME}/configs/conf-app/install?output_mode=json", {"is_configured": "1"})
        except Exception:
            pass


class S2FBrokerHandler(PersistentServerConnectionApplication):
    """Splunk persistent REST handler for /services/ta_s2f/broker."""

    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            req = json.loads(in_string) if isinstance(in_string, str) else json.loads(in_string.decode("utf-8"))
        except Exception as err:
            return _json_response(400, {"ok": False, "error": f"Invalid request: {err}"})

        method = req.get("method", "GET").upper()
        user_token = req.get("session", {}).get("authtoken")
        system_token = req.get("system_authtoken") or user_token

        body = {}
        if req.get("payload"):
            try:
                body = json.loads(req["payload"])
            except Exception:
                body = {k: v[0] for k, v in urllib.parse.parse_qs(req["payload"]).items()}

        op = body.get("op") or ("get_config" if method == "GET" else "dispatch")
        app_conf = get_splunk_conf(system_token)

        if op == "get_config":
            cid = app_conf.get("client_id", "")
            safe_conf = {k: app_conf.get(k, "") for k in ALLOWED_CONF_KEYS}
            safe_conf["has_client_secret"] = bool(
                (cid and get_stored_credential(system_token, CRED_REALM, cid))
                or get_stored_credential(system_token, CRED_REALM, "client_secret")
            )
            safe_conf["has_hec_token"] = bool(get_stored_credential(system_token, CRED_REALM, "hec_token"))
            return _json_response(200, {"ok": True, "config": safe_conf})

        if op == "get_cids":
            return _json_response(200, {"ok": True, "cids": list_cids(system_token)})

        if op == "get_cid":
            cid = (body.get("cid") or "default").strip() or "default"
            stanza = "settings" if cid == "default" else f"cid:{cid}"
            conf = get_splunk_conf(system_token, stanza="settings")
            if stanza != "settings":
                conf = {**conf, **get_splunk_conf(system_token, stanza=stanza)}
            safe_conf = {k: conf.get(k, "") for k in ALLOWED_CONF_KEYS}
            cid_client_id = conf.get("client_id", "")
            safe_conf["has_client_secret"] = bool(
                (cid_client_id and get_stored_credential(system_token, CRED_REALM, cid_client_id))
                or get_stored_credential(system_token, CRED_REALM, "client_secret")
            )
            safe_conf["has_hec_token"] = bool(
                get_stored_credential(system_token, CRED_REALM, f"hec_token:{cid}")
                or get_stored_credential(system_token, CRED_REALM, "hec_token")
            )
            return _json_response(200, {"ok": True, "cid": cid, "config": safe_conf})

        if op == "save_cid":
            if not _user_has_admin_capability(user_token):
                return _json_response(403, {"ok": False, "error": "Forbidden: admin capability required."})
            cid = (body.get("cid") or "").strip()
            if not cid:
                return _json_response(400, {"ok": False, "error": "cid is required."})
            settings = body.get("settings") if isinstance(body.get("settings"), dict) else body
            stanza = "settings" if cid == "default" else f"cid:{cid}"
            try:
                save_splunk_conf(system_token, settings, stanza=stanza)
                cid_client_id = (settings.get("client_id") or "").strip()
                if settings.get("client_secret") and cid_client_id:
                    upsert_stored_credential(system_token, CRED_REALM, cid_client_id, settings["client_secret"])
                if settings.get("hec_token"):
                    upsert_stored_credential(system_token, CRED_REALM, f"hec_token:{cid}", settings["hec_token"])
                with _CLIENT_LOCK:
                    _CLIENT_CACHE.clear()
                return _json_response(200, {"ok": True, "message": f"Configuration saved for CID '{cid}'."})
            except Exception as err:
                return _json_response(500, {"ok": False, "error": str(err)})

        if op == "dispatch":
            config = body.get("configuration") or {}
            cloud = config.get("falcon_cloud") or app_conf.get("falcon_cloud") or "eu-1"
            cid = (config.get("client_id") or app_conf.get("client_id") or "").strip()
            secret = (
                get_stored_credential(system_token, CRED_REALM, cid)
                or get_stored_credential(system_token, CRED_REALM, "client_secret")
                or app_conf.get("client_secret")
            )
            proxy = (
                config.get("proxy_url")
                or get_stored_credential(system_token, CRED_REALM, "proxy_url")
                or app_conf.get("proxy_url")
            )
            ca_bundle = config.get("ca_bundle_path") or app_conf.get("ca_bundle_path")
            try:
                client = _get_cached_client(cloud, cid, secret, proxy, ca_bundle)
                ok, messages, exec_id = dispatch_finding(
                    body.get("result") or {}, config, session_key=system_token, app_conf=app_conf, client=client
                )
                return _json_response(200 if ok else 502, {"ok": ok, "messages": messages, "exec_id": exec_id})
            except Exception as err:
                return _json_response(500, {"ok": False, "error": str(err)})

        if op in ("save_config", "test_connection"):
            if not _user_has_admin_capability(user_token):
                return _json_response(403, {"ok": False, "error": "Forbidden: admin capability required."})

            if op == "save_config":
                try:
                    settings = body.get("settings") if isinstance(body.get("settings"), dict) else body
                    save_splunk_conf(system_token, settings)
                    cid = (settings.get("client_id") or "").strip()
                    if settings.get("client_secret"):
                        if cid:
                            upsert_stored_credential(system_token, CRED_REALM, cid, settings["client_secret"])
                        upsert_stored_credential(system_token, CRED_REALM, "client_secret", settings["client_secret"])
                    if settings.get("hec_token"):
                        upsert_stored_credential(system_token, CRED_REALM, "hec_token", settings["hec_token"])
                    with _CLIENT_LOCK:
                        _CLIENT_CACHE.clear()
                    return _json_response(200, {"ok": True, "message": "Configuration and secrets saved."})
                except Exception as err:
                    return _json_response(500, {"ok": False, "error": str(err)})

            cloud = body.get("falcon_cloud") or app_conf.get("falcon_cloud") or "eu-1"
            cid = (body.get("client_id") or app_conf.get("client_id") or "").strip()
            secret = (
                body.get("client_secret")
                or get_stored_credential(system_token, CRED_REALM, cid)
                or get_stored_credential(system_token, CRED_REALM, "client_secret")
            )
            proxy = body.get("proxy_url") if "proxy_url" in body else app_conf.get("proxy_url")
            ca_bundle = body.get("ca_bundle_path") if "ca_bundle_path" in body else app_conf.get("ca_bundle_path")
            try:
                CrowdStrikeClient(
                    cloud=cloud, client_id=cid, client_secret=secret, proxy_url=proxy, ca_bundle=ca_bundle, timeout=15
                ).get_token(force_refresh=True)
                return _json_response(200, {"ok": True, "message": f"Successfully authenticated with CrowdStrike ({cloud})."})
            except Exception as err:
                return _json_response(400, {"ok": False, "error": str(err)})

        return _json_response(400, {"ok": False, "error": f"Unsupported operation: {op}"})

    def handleStream(self, handle, in_string):
        pass

    def done(self):
        pass
