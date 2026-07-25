#!/usr/bin/env bash
# Cron wrapper for an unattended netaudit run.
#
# Exit codes: 0 clean, 1 backup failure, 2 critical/high findings.
#
# Example crontab entry (see scripts/netaudit.cron.example):
#   30 2 * * * /opt/netaudit/scripts/scheduled-backup.sh >> /var/log/netaudit/cron.log 2>&1

set -uo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LOG_DIR="${LOG_DIR:-${PROJECT_ROOT}/logs}"
KEEP_LOGS="${KEEP_LOGS:-30}"
RETRIES="${RETRIES:-2}"
RETRY_DELAY="${RETRY_DELAY:-10}"
WAZUH_FILE="${WAZUH_FILE:-/var/log/netaudit/wazuh-netaudit.json}"
WAZUH_SYSLOG="${WAZUH_SYSLOG:-}"
WAZUH_SYSLOG_PORT="${WAZUH_SYSLOG_PORT:-514}"
TAG="${TAG:-}"

cd "${PROJECT_ROOT}" || exit 1
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/netaudit-$(date +%Y%m%d-%H%M%S).log"

# Keep the log directory bounded
ls -1t "${LOG_DIR}"/netaudit-*.log 2>/dev/null | tail -n "+$((KEEP_LOGS + 1))" | xargs -r rm -f

if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
    PYTHON="${PROJECT_ROOT}/.venv/bin/python"
else
    PYTHON="$(command -v python3 || command -v python)"
fi

ARGS=(-m netaudit.cli run --retries "${RETRIES}" --retry-delay "${RETRY_DELAY}")
[[ -n "${TAG}" ]] && ARGS+=(--tag "${TAG}")
[[ -n "${WAZUH_FILE}" ]] && ARGS+=(--wazuh-file "${WAZUH_FILE}")
[[ -n "${WAZUH_SYSLOG}" ]] && ARGS+=(--wazuh-syslog "${WAZUH_SYSLOG}" --wazuh-syslog-port "${WAZUH_SYSLOG_PORT}")

export PYTHONIOENCODING=utf-8

echo "[$(date -Is)] netaudit run starting: ${ARGS[*]}" | tee -a "${LOG_FILE}"
"${PYTHON}" "${ARGS[@]}" 2>&1 | tee -a "${LOG_FILE}"
EXIT_CODE="${PIPESTATUS[0]}"

case "${EXIT_CODE}" in
    0) STATUS="clean" ;;
    1) STATUS="BACKUP FAILURE" ;;
    2) STATUS="critical/high findings" ;;
    *) STATUS="unexpected exit ${EXIT_CODE}" ;;
esac
echo "[$(date -Is)] netaudit run finished: ${STATUS} (exit ${EXIT_CODE})" | tee -a "${LOG_FILE}"

exit "${EXIT_CODE}"
