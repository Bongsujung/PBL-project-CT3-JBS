#!/usr/bin/env bash
# Run the scenarios and save the audit log segment of each run.
# Usage (from the project root): ./category3/detector/collect.sh <scenario|all>
# Output: category3/results/raw/<scenario>.jsonl. The file name prefix is the label.
# Run one scenario at a time. Parallel runs mix the log segments.
set -euo pipefail
cd "$(dirname "$0")/.."

CP="${CP:-pbl-security-control-plane}"
LOG="${LOG:-/var/log/kubernetes/audit.log}"
ALL=(normal normal_2 abnormal_1 abnormal_2 abnormal_3 abnormal_4 abnormal_5 abnormal_6)

if [[ "${1:-}" == "all" ]]; then
  SCENARIOS=("${ALL[@]}")
elif [[ -n "${1:-}" && -f "./${1}.sh" ]]; then
  SCENARIOS=("$1")
else
  echo "usage: $0 <normal|normal_2|abnormal_1..6|all>" >&2
  exit 2
fi

mkdir -p results/raw
for s in "${SCENARIOS[@]}"; do
  out="results/raw/${s}.jsonl"
  before="$(docker exec "${CP}" sh -c "wc -l < ${LOG}")"
  echo "==> [collect] ${s} audit.log line=${before}"
  bash "./${s}.sh" || echo "    [collect] ${s} exited non-zero (continuing)"
  # Wait for the API server to write the last events.
  sleep 2
  docker exec "${CP}" sh -c "tail -n +$((before + 1)) ${LOG}" > "${out}"
  echo "    [collect] saved ${out} ($(wc -l < "${out}") lines)"
done
