#!/usr/bin/env bash
set -u

if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0 RECOVERY_AUDIT_REPORT"
  echo "Example: $0 recovery-audit.txt"
  echo 'Generates recommendations only; it never applies changes.'
  exit 0
fi
if (($# != 1)) || [[ -z ${1:-} ]]; then
  echo "Usage: $0 RECOVERY_AUDIT_REPORT (try --help)" >&2
  exit 2
fi
report=$1
if [[ ! -r $report ]]; then echo "Cannot read audit report: $report" >&2; exit 2; fi
for dependency in grep date; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "Missing required command: $dependency" >&2
    exit 2
  fi
done
if ! grep -q '^FORMAT|NEXSEC-RECOVERY-AUDIT-v1$' "$report"; then
  echo 'Unsupported or malformed recovery audit report' >&2
  exit 2
fi

plan_for() {
  local category=$1 indicator=$2 evidence=$3 severity=$4 assessment=$5 impact remediation risk backup verify rollback
  case $category in
    account|admin_group|sudo)
      impact='Unapproved administrative access can enable system-wide changes and persistence.'
      remediation='Verify the account or grant with its owner and approved access inventory. For confirmed excess privilege, amend only the specific group membership or sudo rule through the account-change process. Do not remove an account solely because it is unfamiliar.'
      risk='May interrupt administration, automation, or service ownership if the grant is required.'
      backup='Record current account/group membership and preserve the relevant sudo configuration with restricted access.'
      verify='Re-query the account groups and run visudo -c. Test required and denied operations with a non-production account where possible.'
      rollback='Restore the recorded membership or sudo rule and rerun visudo -c.' ;;
    ssh|authorized_key)
      impact='Weak SSH policy or an unapproved key may allow remote access or account takeover.'
      remediation='Confirm the setting or key with the account owner and access records. Change only the confirmed SSH directive or unauthorized key entry. Retain a separate working administrative session.'
      risk='A syntax error or restrictive setting can lock out administrators and automation.'
      backup='Save a permission-restricted copy of the SSH configuration or authorized_keys metadata and content in an approved secure location. Do not place private keys in the audit report.'
      verify='Run sshd -t, reload the SSH service using the host service manager, and establish a fresh authorized connection before closing the existing session.'
      rollback='Restore the protected backup, rerun sshd -t, reload SSH, and verify a fresh connection.' ;;
    cron|scheduled_task|persistence)
      impact='An unapproved or writable scheduled task can repeatedly run commands with the scheduler account privileges.'
      remediation='Identify the task owner and purpose. Preserve evidence, then remove only the confirmed unauthorized command or correct the specific unsafe path and permissions. Do not delete a job based only on an unfamiliar name.'
      risk='Changing a legitimate task can stop backups, maintenance, monitoring, or application work.'
      backup='Record the file hash, ownership, mode, and a restricted backup of the exact job file before editing.'
      verify='Inspect the edited schedule and referenced executable permissions. Confirm expected scheduler status and review the next normal run.'
      rollback='Restore the original file and metadata, then verify the scheduler reloads and the expected job is present.' ;;
    service|systemd|sysv|startup)
      impact='An unauthorized or writable startup unit can run code with service or root privileges and may affect availability.'
      remediation='Confirm the service with its owner and package inventory. For a confirmed unauthorized unit, preserve it for investigation, then isolate or disable it only with approval and an availability plan. Correct unsafe file ownership and permissions.'
      risk='Stopping or disabling a legitimate service can interrupt users or dependent services.'
      backup='Record unit/script hashes, metadata, enablement state, dependencies, and a restricted copy of the configuration.'
      verify='Run systemd-analyze verify for systemd units or the service-specific syntax check. Check service state, listener state, logs, and dependent application health.'
      rollback='Restore the saved unit/script and metadata, reload the manager if needed, restore prior enablement, and verify service health.' ;;
    process)
      impact='An unexpected privileged process or executable may indicate unauthorized code execution or a modified privileged program.'
      remediation='Preserve process identity and executable metadata, then verify the parent, package provenance, and owner. Contain or stop a confirmed unauthorized process only with incident authority and a service impact plan.'
      risk='Stopping a legitimate privileged process can interrupt system boot, remote access, or application services.'
      backup='Record PID, real/effective UID, executable path, owner, mode, hash, parent, and relevant logs in a restricted evidence store. Avoid collecting command-line arguments that may contain secrets.'
      verify='Repeat the process/executable audit and confirm the approved process set, required service health, logs, and listeners.'
      rollback='Restore the approved executable/configuration from a trusted backup and restart only the owner-approved service; verify service health.' ;;
    writable_file|file_permission|suid|sgid|suid_sgid|capability|sensitive_file)
      impact='Unsafe permissions, privilege bits, or capabilities may let an untrusted account alter or execute privileged code.'
      remediation='Confirm package ownership, intended mode, effective group access, and execution path. Correct only the verified file metadata or capability using the package or configuration owner baseline. Do not strip privilege bits or capabilities from unfamiliar binaries without validation.'
      risk='Changing modes or capabilities can break package behavior, service startup, or recovery tools.'
      backup='Record owner, group, mode, ACLs, capabilities, package ownership, and hash before any change.'
      verify='Recheck stat, ACLs, getcap, package verification, and the intended non-privileged/privileged behavior.'
      rollback='Restore recorded owner, group, mode, ACLs, and capabilities, then repeat verification.' ;;
    listener|firewall)
      impact='An unexpected listener or firewall policy may expose a service or block essential traffic.'
      remediation='Identify the owning process and approved network requirement. Restrict exposure only after confirming dependencies and a maintenance path. Do not close a port or replace rules solely because it is unfamiliar.'
      risk='Firewall or listener changes can cause lockout, outage, or failed monitoring and application traffic.'
      backup='Save the current firewall ruleset and service configuration securely, plus the active listener/process inventory.'
      verify='Check the resulting ruleset, local listeners, service health, and required connectivity from an authorized test point.'
      rollback='Restore the captured ruleset/configuration from a console or out-of-band session and verify required connectivity.' ;;
    *)
      impact='The indicator may represent unauthorized access or a legitimate local configuration difference.'
      remediation='Validate the evidence against the approved system baseline and responsible owner. Preserve evidence and take no change until the finding is confirmed.'
      risk='An unverified change can interrupt legitimate access or services.'
      backup='Preserve the relevant metadata, hash, and approved evidence before any change.'
      verify='Repeat the audit check and validate expected access and service behavior.'
      rollback='Restore the recorded original metadata or configuration and repeat verification.' ;;
  esac
  printf 'FINDING: %s / %s (%s)\n' "$category" "$indicator" "$severity"
  printf 'Assessment: %s\n' "$assessment"
  printf 'Evidence: %s\n' "$evidence"
  printf 'Security impact: %s\n' "$impact"
  printf 'Recommended remediation: %s\n' "$remediation"
  printf 'Change risk: %s\n' "$risk"
  printf 'Backup requirements: %s\n' "$backup"
  printf 'Verification procedure: %s\n' "$verify"
  printf 'Rollback procedure: %s\n\n' "$rollback"
}

printf 'NEXSEC2026 recovery hardening plan\nSource: %s\nGenerated: %s\n' "$report" "$(date -Is)"
findings=0
while IFS='|' read -r record severity category indicator evidence assessment; do
  [[ $record == FINDING ]] || continue
  plan_for "$category" "$indicator" "$evidence" "$severity" "$assessment"
  ((findings += 1))
done < "$report"
if ((findings == 0)); then
  echo 'No FINDING records were present. This is not proof that the system is clean.'
fi
printf 'Plans generated: %d. No remediation was applied.\n' "$findings"
