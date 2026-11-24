# NEXSEC2026 B2R Quick Start

This offline guide assumes `scripts/` is the current directory’s child and the target is explicitly authorized. Run network tools from Kali or another assessment host. Run local audit tools inside an authorized shell on the Linux target. Findings are leads; none of the scripts exploits, deletes, or remediates anything.

## 1. Reconnaissance from Kali

Check each command before using it; the forms below match each script’s `--help` output.

```bash
./scripts/network_enum.sh 192.0.2.10
./scripts/web_enum.sh http://192.0.2.10
```

`network_enum.sh TARGET` requires `nmap`, performs a bounded top-100 TCP service scan, and optionally queries NFS exports with `showmount`. `web_enum.sh URL` requires `curl` and checks a fixed short list of paths on that origin. It has request time limits and does not follow redirects. These scans can miss services and routes; they do not prove a host is safe.

Replace `192.0.2.10` only with an in-scope address. Never broaden the target list based on a scan result.

## 2. Obtain authorized local access

After connecting through the lab’s provided SSH or console access, run from the toolkit directory on the target:

```bash
./scripts/linux_triage.sh
./scripts/privesc_check.sh
./scripts/persistence_check.sh
```

These take no arguments. `linux_triage.sh` summarizes identity, accounts, processes, listeners/routes, and services. `privesc_check.sh` checks common local privilege escalation indicators. `persistence_check.sh` filters the recovery audit for access and startup indicators.

If the toolkit is not installed on the target, an authorized user can stream a script over SSH and save its output locally without copying the script onto the target:

```bash
umask 077
ssh USER@AUTHORIZED_TARGET 'bash -s' < scripts/linux_triage.sh > target-triage.txt
ssh USER@AUTHORIZED_TARGET 'bash -s' < scripts/privesc_check.sh > target-privesc.txt
```

This requires valid room-provided SSH access and a Bash-capable target. It does not elevate privileges. Run again through an approved root shell only when broader visibility is necessary; do not put a password in a command line or this repository.

## 3. Investigate persistence and capture evidence

Root is recommended for a fuller audit. Protect generated reports because system metadata can be sensitive.

```bash
umask 077
./scripts/recovery_audit.sh > recovery-audit.txt
./scripts/baseline_capture.sh > baseline-before.txt
```

To execute these locally on a target using SSH while storing reports on Kali:

```bash
umask 077
ssh USER@AUTHORIZED_TARGET 'bash -s' < scripts/recovery_audit.sh > recovery-audit.txt
ssh USER@AUTHORIZED_TARGET 'bash -s' < scripts/baseline_capture.sh > baseline-before.txt
```

`recovery_audit.sh` emits pipe-delimited `OBSERVATION`, `FINDING`, `CHECK`, and `ASSESSMENT` records. It reports metadata, not private key contents or full configuration files. `CHECK` means coverage may be incomplete. A review-level key, group membership, custom service, or default firewall policy is not proof it is unauthorized.

`baseline_capture.sh` records a UTC timestamp, active services or SysV scripts, normalized listeners, selected account/group and schedule metadata, selected configuration hashes, and firewall query status. Hashes identify changes; they do not prove integrity or reveal file content.

## 4. Plan, remediate manually, and verify

Generate a plan from the saved audit report. The command is local and does not need root:

```bash
./scripts/hardening_plan.sh recovery-audit.txt > hardening-plan.txt
```

Confirm each finding with the system owner. Back up the exact configuration and metadata in a protected location. Apply one approved change at a time; do not remove unfamiliar users, keys, jobs, or services solely because they appear in the report.

After an approved change, capture a new baseline and compare it:

```bash
./scripts/baseline_capture.sh > baseline-after.txt
./scripts/service_verify.sh baseline-before.txt baseline-after.txt
```

`service_verify.sh BASELINE_FILE [CURRENT_FILE]` returns `PASS`/0 when comparable service/listener rows match and `DIFFERENCE`/1 when they differ. Review differences and independently check essential services, application health, logs, listeners, and authorized connectivity. A difference is not automatically an outage.

If a change breaks access or service, use a known-good console/session and restore the protected backup, original metadata, service enablement, or firewall rules. Verify service health again. Do not test remediation or rollback on shared TryHackMe infrastructure.

## Script map, permissions, and dependencies

| Script | Where to run | Permission | Main requirements |
|---|---|---|---|
| `network_enum.sh TARGET` | Kali / assessment host | Ordinary user usually works | `nmap`; optional `showmount`; route to target |
| `web_enum.sh URL` | Kali / assessment host | Ordinary user | `curl`; route to target |
| `linux_triage.sh` | Linux target shell | Ordinary user; root improves process/socket visibility | Bash, `awk`, `date`, `timeout`, `head`; `ps`, `ss`, `ip`, service manager are optional |
| `privesc_check.sh` | Linux target shell | Run as the low-privilege account; no root required | Bash, `find`, `timeout`, `sed`, `head`, `ls`, `stat`, `grep`, `dirname`; optional `sudo`, `getcap`, `strings` |
| `persistence_check.sh` | Linux target shell | Ordinary user; root improves coverage | Bash, `date`, `timeout`, `awk`, `dirname`, plus `recovery_audit.sh` requirements |
| `recovery_audit.sh` | Linux target shell | Root recommended for complete visibility | Bash, `awk`, `find`, `stat`, `timeout`, `date`, `hostname`, `tr`, `head`, `wc`; optional `ps`, `readlink`, firewall tools |
| `hardening_plan.sh REPORT` | Kali or target | Ordinary user | Bash, `grep`, `date`; readable recovery audit report |
| `baseline_capture.sh` | Linux target shell | Root recommended | Bash, `awk`, `find`, `stat`, `timeout`, `date`, `hostname`, `tr`, `wc`, `sort`; optional `sha256sum`, service manager, `ss`, firewall tool |
| `service_verify.sh BASELINE [CURRENT]` | Kali or target | Ordinary user | Bash, `grep`, `diff`, `sed`, `sort`, `date`, `mktemp`, `timeout`, `awk`; structured baseline or normalized legacy snapshots |

Common utilities should be installed from the target’s approved offline package source if missing. Never copy binaries or install packages on a shared challenge target without authorization.

## Common results and errors

- `Missing required command(s)` / `Missing dependency`: install or provide the named standard tool through an approved method; rerun the command. The script exits 2 and does not claim a complete assessment.
- `CHECK|...|partial` or a timeout note: the associated area is incomplete. Use an approved privileged shell, inspect the relevant path manually, or repeat on a less-loaded system.
- `Cannot read audit report` / `Cannot read baseline`: verify the path and read permissions; avoid loosening sensitive report permissions.
- `No comparable service or listener records`: the structured baseline lacks comparison data. Capture it again with a functioning service manager or `ss`.
- `DIFFERENCE`: investigate changed rows and service dependencies. It is not proof of compromise or failure.
- `FINDING|REVIEW`: validate against an approved host and access inventory before acting. `HIGH` describes a potentially risky configuration, not confirmed exploitation.

## Offline and safety notes

All local assessment, recovery planning, baseline, and comparison scripts work without internet access when their local utilities are available. Only network and web enumeration require connectivity to an authorized target. No script automatically exploits, installs persistence, deletes data, edits configuration, or remediates findings. Store output with restrictive permissions and do not commit flags, credentials, private keys, or target-specific reports.
