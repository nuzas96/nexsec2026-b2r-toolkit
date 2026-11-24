#!/usr/bin/env bash
set -u

if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0"
  echo "Example: $0"
  echo 'Runs the recovery audit and displays account, SSH-key, cron, startup-service, and autostart indicators.'
  exit 0
fi
if (($# != 0)); then echo "Usage: $0 (try --help)" >&2; exit 2; fi
for dependency in date timeout awk dirname; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "Missing required command: $dependency" >&2
    exit 2
  fi
done

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
auditor=$script_dir/recovery_audit.sh
if [[ ! -x $auditor ]]; then echo "Recovery auditor unavailable: $auditor" >&2; exit 2; fi

printf 'FORMAT|NEXSEC-PERSISTENCE-CHECK-v2\n'
printf 'CAPTURED_AT|%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'ASSESSMENT|Indicators require validation. This script is read-only and does not confirm compromise.\n'
report=$(timeout 75 "$auditor")
status=$?
if ((status != 0)); then
  echo "Recovery audit failed or timed out with status $status" >&2
  exit "$status"
fi
printf '%s\n' "$report" | awk -F'|' '
  /^FINDING\|/ && ($3 == "account" || $3 == "admin_group" || $3 == "ssh" || $3 == "authorized_key" || $3 == "cron" || $3 == "systemd" || $3 == "sysv" || $3 == "startup" || $3 == "persistence") {print}
  /^OBSERVATION\|authorized_keys_metadata\|/ {print}
  /^CHECK\|/ && ($2 == "accounts" || $2 == "ssh" || $2 == "sudo") {print}
'
