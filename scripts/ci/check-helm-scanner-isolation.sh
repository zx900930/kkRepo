#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rendered="$(mktemp)"
disabled_error="$(mktemp)"
preloaded="$(mktemp)"
mirror_rendered="$(mktemp)"
no_cidr_rendered="$(mktemp)"
trap 'rm -f "$rendered" "$disabled_error" "$preloaded" "$mirror_rendered" "$no_cidr_rendered"' EXIT

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  >"$rendered"

document_with() {
  local needle="$1"
  local input="${2:-$rendered}"
  awk -v needle="$needle" '
    function flush() {
      if (found) {
        for (i = 1; i <= count; i++) print lines[i]
      }
      delete lines
      count = 0
      found = 0
    }
    /^---$/ { flush(); next }
    {
      lines[++count] = $0
      normalized = $0
      sub(/^[[:space:]]+/, "", normalized)
      if (normalized == needle) found = 1
    }
    END { flush() }
  ' "$input"
}

scanner_statefulset="$(document_with "kind: StatefulSet")"
updater_cronjob="$(document_with "kind: CronJob")"
scanner_policy="$(document_with "name: security-check-kkrepo-scanner")"
updater_policy="$(document_with "app.kubernetes.io/component: security-scanner-db-updater")"

grep -A2 -F "name: KKREPO_SCANNER_DB_AUTO_UPDATE" <<<"$scanner_statefulset" \
  | grep -Fq 'value: "false"'
grep -A2 -F "mountPath: /var/lib/kkrepo-scanner/grype" <<<"$scanner_statefulset" \
  | grep -Fq 'readOnly: true'
grep -Fq "KKREPO_SCANNER_DATABASE_UPDATE_ONLY" <<<"$updater_cronjob"
grep -A1 -F "KKREPO_SCANNER_DATABASE_UPDATE_ONLY" <<<"$updater_cronjob" \
  | grep -Fq 'value: "true"'
grep -A1 -F "KKREPO_SCANNER_DATABASE_UPDATE_LOCK_TIMEOUT" <<<"$updater_cronjob" \
  | grep -Fq 'value: "10m"'
if grep -Fq "KKREPO_SCANNER_SERVICE_CREDENTIAL" <<<"$updater_cronjob"; then
  echo "database updater must not receive the scanner service credential" >&2
  exit 1
fi
if grep -A2 -F "mountPath: /var/lib/kkrepo-scanner/grype" <<<"$updater_cronjob" \
  | grep -Fq 'readOnly: true'; then
  echo "database updater requires the only writable database mount" >&2
  exit 1
fi
if grep -Fq "cidr: 0.0.0.0/0" <<<"$scanner_policy"; then
  echo "scan-serving pods must not receive public HTTPS egress" >&2
  exit 1
fi
if grep -Fq "namespaceSelector: {}" "$rendered"; then
  echo "scanner DNS egress must not target every namespace" >&2
  exit 1
fi
for policy in "$scanner_policy" "$updater_policy"; do
  grep -Fq "kubernetes.io/metadata.name: kube-system" <<<"$policy"
  grep -Fq "k8s-app: kube-dns" <<<"$policy"
done
grep -Fq "cidr: 0.0.0.0/0" <<<"$updater_policy"

if helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.scannerDatabase.autoUpdate=false \
  >/dev/null 2>"$disabled_error"; then
  echo "disabling automatic database updates without a pre-populated claim must fail" >&2
  exit 1
fi
grep -Fq \
  "autoUpdate=false requires scannerDatabase.persistence.existingClaim pre-populated" \
  "$disabled_error"

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.scannerDatabase.autoUpdate=false \
  --set securityScanning.scannerDatabase.persistence.existingClaim=preloaded-scanner-db \
  >"$preloaded"

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.scannerDatabase.updateUrl=https://192.168.1.100/grype-db \
  --set securityScanning.scannerDatabase.caCert.existingSecret=grype-mirror-ca \
  --set securityScanning.scannerDatabase.caCert.key=ca.crt \
  --set securityScanning.networkPolicy.databaseMirror.enabled=true \
  --set securityScanning.networkPolicy.databaseMirror.cidr=192.168.1.100/32 \
  >"$mirror_rendered"

mirror_updater_cronjob="$(document_with "kind: CronJob" "$mirror_rendered")"
mirror_updater_policy="$(document_with "app.kubernetes.io/component: security-scanner-db-updater" "$mirror_rendered")"
grep -A1 -F "KKREPO_SCANNER_DB_UPDATE_URL" <<<"$mirror_updater_cronjob" \
  | grep -Fq 'https://192.168.1.100/grype-db'
grep -A1 -F "KKREPO_SCANNER_DB_CA_CERT" <<<"$mirror_updater_cronjob" \
  | grep -Fq '/etc/kkrepo-ca/ca.crt'
grep -A2 -F "name: scanner-db-ca" <<<"$mirror_updater_cronjob" \
  | grep -Fq 'secretName: grype-mirror-ca'
grep -Fq 'cidr: 192.168.1.100/32' <<<"$mirror_updater_policy"

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.networkPolicy.databaseMirror.enabled=true \
  >"$no_cidr_rendered"
if grep -Fq 'cidr: ""' "$no_cidr_rendered"; then
  echo "database mirror must not render an empty CIDR rule" >&2
  exit 1
fi

if grep -Fq "kind: CronJob" "$preloaded"; then
  echo "automatic database updater must not render when autoUpdate=false" >&2
  exit 1
fi
grep -A2 -F "claimName: preloaded-scanner-db" "$preloaded" >/dev/null
grep -A2 -F "mountPath: /var/lib/kkrepo-scanner/grype" "$preloaded" \
  | grep -Fq "readOnly: true"
