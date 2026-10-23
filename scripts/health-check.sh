#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-changeme}"
APP="TA-splunk_to_fusion"
EXIT=0

section() {
    echo ""
    echo "=== $1 ==="
}

# Detect whether Docker needs sudo in this session.
if docker info >/dev/null 2>&1; then
    DOCKER="docker"
    DOCKER_COMPOSE="docker compose"
elif sudo docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
    DOCKER_COMPOSE="sudo docker compose"
else
    echo "ERROR: Docker is not accessible. Run 'newgrp docker' or log out/in if you just installed it."
    exit 1
fi

section "Container status"
$DOCKER_COMPOSE ps

section "Splunk health"
if ! curl -sk -u "admin:${SPLUNK_PASSWORD}" https://localhost:8089/services/server/info >/dev/null 2>&1; then
    echo "ERROR: Splunk REST API is not responding on https://localhost:8089"
    echo "       The container may still be starting. Run 'make logs' and wait."
    EXIT=1
else
    echo "OK: Splunk REST API is responding"
fi

section "App list"
if $DOCKER_COMPOSE exec splunk sudo -u splunk /opt/splunk/bin/splunk display app -auth "admin:${SPLUNK_PASSWORD}" 2>/dev/null | grep -q "^${APP}"; then
    echo "OK: ${APP} is installed"
else
    echo "ERROR: ${APP} is NOT installed"
    EXIT=1
fi

section "Custom capabilities"
if $DOCKER_COMPOSE exec splunk grep -qE "^\[capability::s2f_(send|admin)\]" "/opt/splunk/etc/apps/${APP}/default/authorize.conf" 2>/dev/null; then
    echo "OK: s2f_send and s2f_admin capabilities are declared in authorize.conf"
else
    echo "WARNING: s2f_send / s2f_admin capabilities not found in authorize.conf"
fi

section "REST handler endpoint"
# Test from inside the container; the free license blocks remote management auth
# for some endpoints when called from outside the container.
HTTP_CODE=$($DOCKER_COMPOSE exec splunk curl -sk -o /dev/null -w "%{http_code}" \
    -u "admin:${SPLUNK_PASSWORD}" \
    "https://localhost:8089/servicesNS/nobody/${APP}/ta_s2f/broker" || true)
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "OK: /services/ta_s2f/broker returned 200"
else
    echo "WARNING: /services/ta_s2f/broker returned HTTP ${HTTP_CODE}"
fi

section "Setup page"
# Splunk Web in this container uses HTTP by default.
HTTP_CODE=$(curl -sL -o /dev/null -w "%{http_code}" -u "admin:${SPLUNK_PASSWORD}" \
    "http://localhost:8000/en-US/app/${APP}/fusion_setup" || true)
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "OK: setup page returned 200"
else
    echo "WARNING: setup page returned HTTP ${HTTP_CODE}"
fi

section "Splunk Web"
HTTP_CODE=$(curl -sL -o /dev/null -w "%{http_code}" -u "admin:${SPLUNK_PASSWORD}" \
    "http://localhost:8000/en-US/app/${APP}/fusion_overview" || true)
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "OK: overview dashboard returned 200"
else
    echo "WARNING: overview dashboard returned HTTP ${HTTP_CODE}"
fi

section "Summary"
if [[ "$EXIT" -eq 0 ]]; then
    echo "App appears to be working. Review any warnings above."
else
    echo "App has errors. Review the output above."
fi

exit "$EXIT"
