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

# Low-rate enumeration: list the allowed resources ROUNDS times, INTERVAL seconds apart.
# A 10 s window contains a maximum of 3 requests. Rule D4 does not apply.
ROUNDS="${ROUNDS:-6}"
INTERVAL="${INTERVAL:-15}"
echo "[Crypto-platform:abnormal_5] Low-and-slow enumeration: ${ROUNDS} rounds, ${INTERVAL}s apart."
for i in $(seq 1 "${ROUNDS}"); do
  echo "round=${i}/${ROUNDS}"
  "${K[@]}" get pods >/dev/null
  "${K[@]}" get services >/dev/null
  "${K[@]}" get configmaps >/dev/null
  if [[ "${i}" -lt "${ROUNDS}" ]]; then sleep "${INTERVAL}"; fi
done
echo "Slow enumeration completed. Audit identity: system:serviceaccount:${NS}:${SA}"
