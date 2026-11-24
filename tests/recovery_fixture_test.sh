#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
if ! command -v bwrap >/dev/null 2>&1; then
  echo 'NOT TESTED: bwrap is required for isolated persistence fixtures' >&2
  exit 77
fi
awk_target=$(readlink -f "$(command -v awk)")

run_fixture() {
  local kind=$1
  timeout 45 bwrap --unshare-all --uid 0 --gid 0 \
    --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --dir /tmp/toolkit --ro-bind "$root/scripts" /tmp/toolkit \
    --dir /tmp/test --ro-bind "$root/tests/recovery_fixture_inner.sh" /tmp/test/fixture.sh \
    --tmpfs /etc --tmpfs /home --tmpfs /usr/local/bin --tmpfs /opt --tmpfs /var/spool \
    --dir /etc/alternatives --ro-bind "$awk_target" /etc/alternatives/awk \
    /usr/bin/bash /tmp/test/fixture.sh "$kind"
}

positive=$(run_fixture positive)
required=(unexpected_uid0 membership ssh_setting key_file_present scheduled_command_in_writable_area cron_path_contains_writable_area \
  writable_cron_file writable_scheduled_executable writable_unit writable_startup_script nonstandard_privileged_binary)
for indicator in "${required[@]}"; do
  if ! printf '%s\n' "$positive" | grep -Eq "^FINDING\\|[^|]+\\|[^|]+\\|${indicator}\\|"; then
    echo "FAIL: positive fixture missed $indicator" >&2
    printf '%s\n' "$positive" >&2
    exit 1
  fi
done

persistence_positive=$(run_fixture persistence-positive)
for indicator in unexpected_uid0 key_file_present scheduled_command_in_writable_area writable_unit; do
  if ! printf '%s\n' "$persistence_positive" | grep -Eq "^FINDING\\|[^|]+\\|[^|]+\\|${indicator}\\|"; then
    echo "FAIL: persistence check missed $indicator" >&2
    printf '%s\n' "$persistence_positive" >&2
    exit 1
  fi
done

negative=$(run_fixture negative)
if printf '%s\n' "$negative" | grep -q '^FINDING|'; then
  echo 'FAIL: negative fixture produced findings' >&2
  printf '%s\n' "$negative" | grep '^FINDING|' >&2
  exit 1
fi

benign=$(run_fixture benign)
if ! printf '%s\n' "$benign" | grep -q '^GROUND_TRUTH|authorized_key|approved fixture key, mode=600$'; then
  echo 'FAIL: benign SSH fixture ground truth was not recorded' >&2
  exit 1
fi
for expected in 'FINDING|REVIEW|authorized_key|key_file_present|' 'FINDING|REVIEW|systemd|unit_file|'; do
  if ! printf '%s\n' "$benign" | grep -Fq "$expected"; then
    echo "FAIL: benign artifact was not classified as a review indicator: $expected" >&2
    exit 1
  fi
done
if printf '%s\n' "$benign" | grep -q 'FINDING|HIGH|'; then
  echo 'FAIL: benign key/service fixture was escalated to HIGH' >&2
  exit 1
fi
if printf '%s\n' "$benign" | grep -q 'AAAATEST'; then
  echo 'FAIL: authorized_keys content leaked into report' >&2
  exit 1
fi

process_positive=$(run_fixture process-positive)
if ! printf '%s\n' "$process_positive" | grep -q '^GROUND_TRUTH|process|euid=0|mode=777|path=/tmp/odd-process|'; then
  echo 'FAIL: process fixture ground truth was not established before audit' >&2
  exit 1
fi
if ! printf '%s\n' "$process_positive" | grep -q 'OBSERVATION|process_identity|.*euid=0|name=odd-process'; then
  echo 'FAIL: process owner identity was not reported' >&2
  exit 1
fi
if ! printf '%s\n' "$process_positive" | grep -q '^FINDING|REVIEW|process|privileged_process_from_nonstandard_path|'; then
  echo 'FAIL: privileged process path fixture was missed' >&2
  printf '%s\n' "$process_positive" >&2
  exit 1
fi
if ! printf '%s\n' "$process_positive" | grep -q '^FINDING|HIGH|process|privileged_process_writable_executable|'; then
  echo 'FAIL: suspicious root process fixture was missed' >&2
  printf '%s\n' "$process_positive" >&2
  exit 1
fi
process_audit=$(mktemp)
process_plan=$(mktemp)
printf '%s\n' "$process_positive" > "$process_audit"
"$root/scripts/hardening_plan.sh" "$process_audit" > "$process_plan"
if ! grep -q 'An unexpected privileged process' "$process_plan"; then
  echo 'FAIL: planner used only generic guidance for a process finding' >&2
  exit 1
fi
if printf '%s\n' "$negative" | grep -q '^FINDING|.*|process|'; then
  echo 'FAIL: clean process fixture produced a process finding' >&2
  exit 1
fi

firewall_positive=$(run_fixture firewall-positive)
if ! printf '%s\n' "$firewall_positive" | grep -q '^GROUND_TRUTH|firewall|backend=nft|default_policy=accept$'; then
  echo 'FAIL: firewall accept fixture ground truth was not recorded' >&2
  exit 1
fi
if ! printf '%s\n' "$firewall_positive" | grep -q '^FINDING|REVIEW|firewall|default_accept_policy|backend=nft base_chains=1'; then
  echo 'FAIL: nft accept-policy fixture was missed' >&2
  exit 1
fi
firewall_audit=$(mktemp)
firewall_plan=$(mktemp)
printf '%s\n' "$firewall_positive" > "$firewall_audit"
"$root/scripts/hardening_plan.sh" "$firewall_audit" > "$firewall_plan"
if ! grep -q 'An unexpected listener or firewall policy' "$firewall_plan"; then
  echo 'FAIL: planner missed firewall-specific guidance' >&2
  exit 1
fi
firewall_negative=$(run_fixture firewall-negative)
if ! printf '%s\n' "$firewall_negative" | grep -q '^GROUND_TRUTH|firewall|backend=nft|default_policy=drop$'; then
  echo 'FAIL: firewall drop fixture ground truth was not recorded' >&2
  exit 1
fi
if printf '%s\n' "$firewall_negative" | grep -q '^FINDING|.*|firewall|'; then
  echo 'FAIL: nft drop-policy fixture produced a firewall finding' >&2
  exit 1
fi

persistence_negative=$(run_fixture persistence-negative)
if printf '%s\n' "$persistence_negative" | grep -q '^FINDING|'; then
  echo 'FAIL: persistence negative fixture produced findings' >&2
  printf '%s\n' "$persistence_negative" | grep '^FINDING|' >&2
  exit 1
fi
missing_config=$(run_fixture missing-config)
if ! printf '%s\n' "$missing_config" | grep -q '^CHECK|ssh|unavailable|'; then
  echo 'FAIL: missing SSH config was not reported' >&2
  exit 1
fi

audit_report=$(mktemp)
plan=$(mktemp)
printf '%s\n' "$positive" >"$audit_report"
"$root/scripts/hardening_plan.sh" "$audit_report" >"$plan"
for heading in 'Security impact:' 'Recommended remediation:' 'Change risk:' 'Backup requirements:' 'Verification procedure:' 'Rollback procedure:'; do
  if ! grep -q "$heading" "$plan"; then echo "FAIL: plan missing $heading" >&2; exit 1; fi
done
printf 'PASS: recovery positives=%d, persistence positives=%d; process executable anomaly detected; nft accept REVIEW/drop no finding; benign key/unit REVIEW only; negatives and planner passed\n' \
  "$(printf '%s\n' "$positive" | grep -c '^FINDING|' || true)" \
  "$(printf '%s\n' "$persistence_positive" | grep -c '^FINDING|' || true)"
