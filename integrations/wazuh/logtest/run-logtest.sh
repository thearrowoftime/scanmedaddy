#!/usr/bin/env bash
# Validate the netaudit decoder + rules on a Wazuh manager using wazuh-logtest.
#
# Usage (on the manager, as root):
#   ./run-logtest.sh                # uses samples.log next to this script
#   ./run-logtest.sh my-samples.log
#
# Regenerate samples from real audit output at any time:
#   netaudit wazuh-samples --file samples/fg-120g-01.cfg

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES="${1:-${SCRIPT_DIR}/samples.log}"
WAZUH_PATH="${WAZUH_PATH:-/var/ossec}"
LOGTEST="${WAZUH_PATH}/bin/wazuh-logtest"

if [[ ! -x "${LOGTEST}" ]]; then
    echo "wazuh-logtest not found at ${LOGTEST} (set WAZUH_PATH)" >&2
    exit 1
fi
if [[ ! -f "${SAMPLES}" ]]; then
    echo "sample file not found: ${SAMPLES}" >&2
    exit 1
fi

pass=0
fail=0
line_no=0

while IFS= read -r line; do
    line_no=$((line_no + 1))
    [[ -z "${line}" ]] && continue

    echo "=== line ${line_no} ==============================================="
    output="$(printf '%s\n' "${line}" | "${LOGTEST}" -q 2>&1)"
    echo "${output}"

    if grep -qE "id: '1005[0-9][0-9]'" <<<"${output}"; then
        pass=$((pass + 1))
    else
        echo ">>> no netaudit rule (1005xx) matched this line" >&2
        fail=$((fail + 1))
    fi
    echo
done <"${SAMPLES}"

echo "=================================================================="
echo "matched netaudit rules: ${pass}   unmatched: ${fail}"
[[ "${fail}" -eq 0 ]] || exit 1
