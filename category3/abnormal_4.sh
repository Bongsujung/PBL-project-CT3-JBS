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

# Permission discovery: ask the API server which actions the token can do.
# The API server accepts these requests (201). Rule D3 does not apply. Rule D6 applies.
# "kubectl auth can-i" gives exit code 1 for "no". "|| true" keeps the script running.
echo "[Crypto-platform:abnormal_4] Permission discovery with the same ServiceAccount."
"${K[@]}" auth can-i --list || true
"${K[@]}" auth can-i get secrets || true
"${K[@]}" auth can-i create pods --subresource=exec || true
echo "Discovery completed. Audit identity: system:serviceaccount:${NS}:${SA}"
