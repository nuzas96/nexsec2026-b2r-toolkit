# NEXSEC2026 Recovery and Hardening Guide

This guide describes a cautious workflow for an authorized Linux incident or post-compromise assessment. The toolkit collects evidence and recommendations; it does not automatically remove access, alter permissions, disable services, or change firewall rules.

## 1. Establish scope and preserve evidence

1. Confirm the system owner, incident authority, affected host, and approved response window.
2. Record UTC time, operator, current account, host identity, and whether the session is privileged. Avoid placing passwords, private keys, access tokens, or challenge flags in reports.
3. Keep a trusted administrative session and an out-of-band console path available. For a suspected live compromise, coordinate isolation decisions with the owner because network changes can interrupt evidence collection and service availability.
4. Capture the initial baseline and audit before changing configuration. Restrict report permissions because account, service, and schedule metadata can be sensitive.

```bash
umask 077
date -u +%Y-%m-%dT%H:%M:%SZ
id
hostname
./scripts/baseline_capture.sh > baseline-before.txt
./scripts/recovery_audit.sh > recovery-audit.txt
sha256sum baseline-before.txt recovery-audit.txt
```

Keep original reports unchanged. Record follow-up observations in separate timestamped files. The baseline hashes selected configuration files, but the recovery audit intentionally avoids collecting SSH key contents, private keys, or full service/cron configuration contents.

## 2. Assess access and persistence indicators

Run `linux_triage.sh` for system context, `privesc_check.sh` for local escalation checks, and `persistence_check.sh` for focused account, SSH, scheduled-task, and startup indicators. Run `recovery_audit.sh` for the wider review.

Review at least:

- UID 0 accounts, administrative group membership, and sudo policy metadata. Compare them with the owner’s current approved access inventory. A familiar account name or group is not proof of authorization.
- SSH effective policy and `authorized_keys` file metadata. A key file’s presence is not proof that a key was used. Have the owner validate fingerprints through a protected process; do not paste key material into an audit report.
- System and per-user cron entries, including `@reboot` entries and PATH values. Validate the scheduler context, executable owner/mode, and whether the referenced job is approved.
- Systemd units, SysV startup scripts, writable privileged paths, standard-location SUID/SGID observations, and nonstandard SUID/SGID candidates. Compare service names, ownership, hashes, enablement, and package provenance with a trusted baseline.
- Listening sockets, process real/effective UIDs, executable paths/ownership where visible, and firewall query results. Compare them with approved application and network requirements; do not label an unfamiliar port, process, accept policy, or empty firewall result malicious by itself.

The scripts emit findings as indicators with evidence and an assessment field. Corroborate suspected access using authorized authentication/service logs, change records, endpoint monitoring, package verification, and the system owner. The toolkit does not collect or analyze full logs, volatile memory, or disk images.

## 3. Regain administrative control safely

If approved administrative access is missing or suspect, use the organization’s documented console, recovery environment, cloud control plane, or break-glass account. Validate the recovery route before changing SSH, sudo, groups, or firewall policy. Preserve at least one known-good session and a second administrative path.

Rotate potentially exposed credentials from a trusted endpoint and through the owner’s identity process. Revoke only access confirmed as unauthorized. Do not delete an account, key, service, or scheduled task merely because it is unfamiliar; identify the owner, dependencies, and business purpose first.

## 4. Plan and apply manual remediation

Generate a plan from a saved audit report:

```bash
./scripts/hardening_plan.sh recovery-audit.txt > hardening-plan.txt
```

For every confirmed issue, preserve evidence, record a secure backup, make one approved change at a time, and document the exact before/after state.

### SSH and account access

- Confirm the required access policy with the system owner before editing SSH directives or key files.
- Back up the exact configuration with restricted permissions. Validate syntax with `sshd -t`, reload (do not blindly restart) the correct SSH service, and establish a fresh authorized connection before ending the existing session.
- For confirmed excess access, change only the approved key, group membership, account state, or sudo rule. Do not remove users based only on a UID or username. Validate sudoers with `visudo -c`.

### Cron and startup persistence

- Preserve the job file’s hash, owner, mode, scheduler location, and referenced executable metadata. Check system and per-user schedules and any inherited PATH.
- Remove or correct only the confirmed unauthorized entry or unsafe permission. Avoid deleting an entire cron file or disabling a service when a narrow change is sufficient.
- Validate the edited schedule and referenced paths, confirm the scheduler/service manager loaded the intended state, and observe the next expected run when practical.

### File permissions and services

- Confirm package ownership, ACLs, capabilities, expected mode, and the service’s execution context before changing a privileged file.
- For a confirmed unauthorized service, preserve its unit/script and dependencies first. Disable or isolate it only with owner approval and an availability plan. Validate systemd units with `systemd-analyze verify` when available, then check service state, logs, listeners, and dependent applications.
- Do not strip SUID/SGID bits or capabilities from unfamiliar files without package/configuration owner confirmation.

## 5. Verify service availability and rollback

Capture and compare a baseline around each approved change:

```bash
./scripts/baseline_capture.sh > baseline-after.txt
./scripts/service_verify.sh baseline-before.txt baseline-after.txt
```

`PASS` means comparable service/listener records match. `DIFFERENCE` means review the changed rows; it does not by itself indicate failure. Separately check required application health, logs, listeners, and authorized connectivity. If a remote-access change is involved, verify a new connection from an authorized test point before closing the old session.

If verification fails, use the console or retained session to restore the protected backup and original metadata, service enablement, and firewall rules. Validate configuration syntax and service health again. Keep both the original and rollback evidence for the incident record.

## 6. Validation boundaries

The recovery audit and persistence checks were exercised locally against isolated, disposable fixtures with a read-only host filesystem, separate temporary `/etc`, `/home`, `/tmp`, `/opt`, and `/usr/local/bin` filesystems, and an unshared network namespace. A known process running as UID 0 inside the isolated namespace and executing a mode-777 binary under `/tmp` was verified with `ps` and `stat` before the audit; it produced a REVIEW path indicator and a HIGH writable-executable indicator. A fake `nft` command supplied known accept/drop rule fixtures: accept produced a REVIEW indicator and drop produced none. These tests validate parsing and classification, not the host kernel firewall or packet filtering. Clean, benign key/unit and negative fixtures were checked. No fixture was created on RootMe, Linux PrivEsc Arena, or the development host’s system paths.

No real remediation or restoration test was performed because a disposable VM with a known-good snapshot was not available. No shared TryHackMe system or host configuration was changed. The fixture tests verify indicator output and report structure, not full incident-response coverage or the maliciousness of real-world entries.

Known limitations include permission-dependent visibility, a bounded search limited to selected paths, no content review of private keys or service configuration, no authentication-log or memory/disk forensic collection, no automatic baseline trust, and no automated decision that an indicator is malicious. Root and package-manager access improve coverage. Always validate findings against an approved system baseline and responsible owner.
