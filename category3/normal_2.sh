#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
SA="pbl-crypto-platform-app"
ensure_lab_identity() {
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pbl-crypto-platform-app
  namespace: ${NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pbl-crypto-platform-reader
  namespace: ${NS}
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pbl-crypto-platform-reader
  namespace: ${NS}
subjects:
  - kind: ServiceAccount
    name: pbl-crypto-platform-app
    namespace: ${NS}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pbl-crypto-platform-reader
YAML
  TOKEN="$(kubectl -n "${NS}" create token "${SA}" --duration=10m)"
  SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  K=(kubectl --kubeconfig=/dev/null --server="${SERVER}" --insecure-skip-tls-verify --token="${TOKEN}" -n "${NS}")
}

ensure_lab_identity

# Normal monitoring: list the pods every INTERVAL seconds, COUNT times.
# Use this scenario to test rule D4 for false positives.
COUNT="${COUNT:-30}"
INTERVAL="${INTERVAL:-2}"
echo "[Crypto-platform:normal_2] Monitoring loop: get pods every ${INTERVAL}s x ${COUNT}."
for i in $(seq 1 "${COUNT}"); do
  "${K[@]}" get pods >/dev/null
  sleep "${INTERVAL}"
done
echo "Monitoring loop completed. Audit identity: system:serviceaccount:${NS}:${SA}"
