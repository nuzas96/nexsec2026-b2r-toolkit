# NEXSEC2026 B2R Toolkit Usage

These scripts collect investigation evidence. Findings are leads to verify against the host, not proof of exploitability. Run local checks from an authorized shell on the machine being assessed. The scripts make no configuration changes. `service_verify.sh` uses temporary files locally and removes its generated snapshot.

## Network and web discovery

### `scripts/network_enum.sh TARGET`

Use from the assessment machine to find common TCP services and versions. Requires `nmap`; `showmount` adds NFS export results when installed. Run only against an authorized target.

```bash
./scripts/network_enum.sh 192.0.2.10
```

Expected output includes Nmap's top-100 TCP results and, when available, the NFS export list. This is a bounded TCP scan and can miss UDP services or ports outside the top 100.

### `scripts/web_enum.sh URL`

Use when HTTP or HTTPS is in scope. Requires `curl`. It requests `/`, `/robots.txt`, `/server-status`, `/uploads/`, and `/icons/` on the supplied origin, then prints root response headers.

```bash
./scripts/web_enum.sh http://192.0.2.10
```

Expected output gives status, response size, content type, and selected headers. Requests have connection and total time limits. Redirects are reported without following them, keeping requests on the supplied origin. The path list is shallow and does not replace application mapping.

## Local host checks

### `scripts/linux_triage.sh`

Run after obtaining an authorized shell. Root is not required. It summarizes identity, local accounts, processes, listeners, routes, and services. It supports systemd and SysV service reporting.

```bash
./scripts/linux_triage.sh
```

Missing commands are reported. Non-root users may see incomplete process/socket details.

### `scripts/privesc_check.sh`

Run as the low-privilege account. Root is not required. It checks common SUID/SGID locations, sudo grants, capabilities, cron configuration and command paths, selected sensitive-file modes, writable privileged files, PATH directories, and selected SUID command/library references.

```bash
./scripts/privesc_check.sh
```

Searches are bounded by path and timeout. A timeout or permission denial means that part of the inventory is incomplete. A writable file, unusual mode, SUID bit, capability, or command string is a lead. Confirm ownership, effective group membership, execution context, and whether a privileged service actually uses it before classifying it as exploitable. It does not perform exploitation or read secret file contents.

### `scripts/persistence_check.sh`

Run during authorized post-access review or recovery assessment. Root is not required, though access to root-owned metadata may be limited. It filters the recovery audit for account, administrative group, SSH key, cron, service, startup, and autostart indicators. Key contents are omitted. It never installs persistence or modifies startup state.

```bash
./scripts/persistence_check.sh
```

This is an indicator inventory. It does not decide whether an entry is malicious or modify or remove it.

## Service comparison

### `scripts/service_verify.sh BASELINE_FILE [CURRENT_FILE]`

Use before and after an authorized service change, or after recovery. Root is not required. Prefer a structured snapshot from `baseline_capture.sh`; older normalized text snapshots remain supported. If the second file is omitted, the script captures current listeners and service state using the baseline format.

```bash
umask 077
./scripts/baseline_capture.sh > before.txt
./scripts/service_verify.sh before.txt
```

`baseline_capture.sh` records service/listener state, privileged accounts, administrative groups, scheduled-task and selected configuration hashes, and firewall status. It does not copy configuration contents. `PASS` and exit 0 mean comparable service/listener state matches. `DIFFERENCE` and exit 1 mean it changed and requires review. Other nonzero exits indicate an input or execution error. A difference alone does not prove a service is unhealthy or compromised.

## Recovery and hardening

### `scripts/recovery_audit.sh`

Run on the authorized system during initial incident assessment. Use root for fuller process, key, firewall, and file metadata visibility; an unprivileged run reports access gaps where it can detect them. The report is pipe-delimited and contains indicator metadata, not private key material or configuration contents.

```bash
umask 077
./scripts/recovery_audit.sh > recovery-audit.txt
```

It checks account IDs and administrative groups, current-user sudo listing and sudoers metadata, SSH policy and authorized-key metadata, cron jobs including per-user and `@reboot` schedules, startup units/scripts, writable privileged files, standard-location SUID/SGID observations and nonstandard SUID/SGID candidates, process real/effective UIDs and executable metadata where visible, listeners, basic firewall default-policy indicators, and autostart entries. Default-accept policy and root processes from nonstandard paths are REVIEW leads, not proof of compromise. It does not prove that an account, key, service, or job is unauthorized. Validate each indicator against a trusted inventory and owner.

### `scripts/hardening_plan.sh AUDIT_REPORT`

Use after reviewing the audit output. It prints impact, remediation guidance, change risk, backup needs, verification, and rollback steps for supported findings. It never changes configuration.

```bash
./scripts/hardening_plan.sh recovery-audit.txt
```

Only apply a recommendation after confirming the finding and its owner. Preserve a working administrative session and a rollback route before changing remote access, privileges, startup tasks, or firewall rules.

### `scripts/baseline_capture.sh`

Run before authorized remediation and again after changes. Root improves visibility. Save snapshots securely because host, service, account, schedule, and configuration metadata may be operationally sensitive.

```bash
umask 077
./scripts/baseline_capture.sh > baseline-before.txt
./scripts/service_verify.sh baseline-before.txt
```

The baseline has UTC capture time and stable line-oriented records. Selected configuration files are represented by metadata and SHA-256 hashes. Hashes support comparison; they do not establish file safety or contents.

### Safe interpretation and offline limits

These scripts do not delete accounts, keys, jobs, services, or files. Custom services, authorized keys, administrative membership, executable paths, and listeners are review leads, not proof of compromise. A non-root run can miss data it cannot traverse; look for `CHECK` records and repeat from an approved privileged shell if needed. No new script requires internet connectivity. Network/web discovery still needs an authorized route by design. Recovery indicators do not replace log review, package verification, memory/disk forensics, or a trusted configuration baseline.

## Offline use and requirements

`linux_triage.sh`, `privesc_check.sh`, `persistence_check.sh`, `recovery_audit.sh`, `hardening_plan.sh`, `baseline_capture.sh`, and `service_verify.sh` inspect local files and service state and do not require internet access. `network_enum.sh` and `web_enum.sh` require a route to the authorized target by design. Common dependencies include Bash, GNU core utilities, `awk`, `find`, `stat`, `timeout`, and `diff`. Optional tools are checked or skipped where practical. Use `--help` on each script for its short usage line and example.
