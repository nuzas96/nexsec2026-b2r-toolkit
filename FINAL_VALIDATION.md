# NEXSEC2026 B2R Toolkit — Phase 4 Validation

Validation date: 2026-11-24. This report distinguishes prior authorized lab results, current development-host runs, and isolated fixtures. RootMe and Linux PrivEsc Arena were not scanned or modified during this phase.

## Current status by script

| Script | Status | Evidence and limits |
|---|---|---|
| `network_enum.sh` | PASS | Prior authorized RootMe and Arena scans, including the Arena NFS export query. This phase checked help and missing-`nmap` behavior only; no live scan was repeated. Top-100 TCP coverage can miss other ports and UDP. |
| `web_enum.sh` | PASS | Prior authorized RootMe/Arena requests and loopback HTTP fixture. This phase checked help and missing-`curl` behavior only; no target request was repeated. The route list is intentionally shallow. |
| `linux_triage.sh` | PASS | Prior target-side RootMe/Arena runs and current unprivileged offline host execution. This phase added a required-tool check; live target behavior was not rerun. |
| `privesc_check.sh` | PASS | Prior RootMe/Arena detections and current unprivileged offline host execution. Required-tool errors were simulated. Findings still require contextual validation. |
| `persistence_check.sh` | PASS | Prior target-side read-only runs plus current unprivileged host execution and isolated positive/negative fixtures. The filter surfaced 17 planted indicators; the clean fixture had no findings. It cannot determine authorization by itself. |
| `service_verify.sh` | PASS | Structured identical snapshots returned PASS/0; a deliberate service row returned DIFFERENCE/1. Automatic-current mode, invalid/missing baseline, required-tool failure, and no-systemd SysV snapshots were exercised. |
| `recovery_audit.sh` | PARTIAL | Host and isolated runs; 21 core fixture findings, process and firewall-parser fixtures, clean negatives, permission gaps, and missing SSH config checked. Actual firewall state and process executable ownership were incomplete on the host; see details below. |
| `hardening_plan.sh` | PASS | Consumed structured audit fixtures and emitted impact, remediation, risk, backup, verification, and rollback fields. Process and firewall findings received category-specific guidance. No remediation was applied. |
| `baseline_capture.sh` | PASS | Current host output had UTC time, 22 service rows, two normalized listeners, and 70 selected schedule/config hashes. The isolated no-systemd path emitted SysV records. A hash is not proof of file safety. |

PASS here means the listed behavior was exercised with evidence; it does not mean complete coverage of Linux or a real compromised machine.

## Recovery-audit validation and classification

The fixture suite is `tests/recovery_fixture_test.sh`. It creates isolated Bubblewrap namespaces with the host filesystem read-only and temporary fixture filesystems. The network namespace is unshared. Fixture setup is in `tests/recovery_fixture_inner.sh`; tests do not write to RootMe, Linux PrivEsc Arena, or host system paths.

| Test | Ground truth established before audit | Expected and observed result | Classification and limit |
|---|---|---|---|
| UID 0 and admin group | Fixture account `shadow` has UID 0; fixture user `alice` is in `sudo`. | `unexpected_uid0` HIGH and `admin_group membership` REVIEW appeared. | True positive for reporting the configured conditions. The script cannot infer whether an actual account is unauthorized without an approved access inventory. |
| SSH | One fixture has permissive SSH directives and a writable key file. A separate benign fixture contains an approved mode-600 key. | Weak directives and unsafe key metadata were found. The approved key was REVIEW only; its key contents were absent from output. | True positive for metadata/policy indicators. Key presence is a potential false positive if mistaken for unauthorized access. |
| Cron | Fixture contains a writable system cron file and executable, system and per-user `@reboot` jobs, and a PATH candidate under `/tmp`. | Cron file, executable, command, and PATH indicators appeared. | True positive for the configured conditions. The report does not prove a job ran. |
| Services/startup | Fixture includes a world-writable systemd unit and SysV startup script. A benign mode-644 custom unit is tested separately. | Unsafe permissions were reported; the benign unit was REVIEW only. | True positive for writable configuration. Custom service presence alone is an expected review lead, not confirmed compromise. |
| SUID/SGID | Fixture copies a standard binary into `/tmp` and sets mode 4755. | A nonstandard privileged-binary REVIEW record appeared. Standard system locations are inventoried as observations for comparison. | True positive for locating the planted candidate; normal SUID files require package/baseline comparison. |
| Process ownership | Before audit, fixture `ps` showed an EUID-0 `odd-process`, and `stat` showed its `/tmp/odd-process` executable mode 777. | The audit emitted REVIEW for a privileged process from a nonstandard path and HIGH for its group/other-writable executable. The clean fixture had no process finding. | True positive for the planted condition. UID 0 was inside a user namespace; this does not demonstrate host-root execution. |
| Firewall policy parser | A fake `nft` executable returned a known base-chain `policy accept`; a separate fixture returned `policy drop`. | Accept generated a REVIEW `default_accept_policy`; drop generated no firewall finding. | Parser fixture passed. This is not a test of active kernel rules, packet filtering, or real nftables configuration. iptables/UFW parsing remains untested. |
| Clean negative | Default fixture has no planted extra UID 0, admin membership, key, cron job, custom service, or nonstandard SUID file. | Zero `FINDING` records. | Negative fixture passed for those conditions; this is not proof that all clean systems produce no review indicators. |

The core recovery fixture emitted 21 findings and the persistence filter emitted 17. A benign approved key and a benign custom service generated REVIEW records only. These are deliberate potential false positives when interpreted as malicious. A permissive default-accept firewall policy is also a REVIEW indicator, not an assertion of compromise.

On the real development host, independent `ps` output identified PID 1 as UID/EUID 0 `systemd`, matching the audit’s process identity record. The unprivileged audit could not inspect executable metadata for 139 process entries and emitted a partial-coverage `CHECK`; it emitted no suspicious-process finding. Its `nft` query exited with status 1 and was reported as `CHECK`. Therefore, actual host firewall state and most host executable ownership remain NOT TESTED. No unexpected account or process was asserted from these observations.

No seeded fixture condition remained missed after fixing cron PATH parsing. Unmodeled false negatives remain possible, especially where `/proc`, home directories, or service configuration is inaccessible, outside the bounded search paths, or requires comparison with an owner-approved baseline.

## Regression and offline checks

The following checks were run during this phase:

- `bash -n` on all nine scripts and both fixture scripts.
- `shellcheck scripts/*.sh tests/*.sh` with no findings.
- `--help` on all nine scripts; examples match their actual help output.
- Missing-required-command simulations for all nine scripts. Each exited 2 with a clear message. Network and web tests failed on the missing dependency before making a request.
- Unprivileged offline execution of `linux_triage.sh`, `privesc_check.sh`, `persistence_check.sh`, `recovery_audit.sh`, and `baseline_capture.sh` on the development Linux host.
- Positive and negative isolated persistence/audit fixtures, benign key/service classification, process and firewall parser fixtures, and hardening-plan field checks.
- Service comparison of identical structured snapshots, a deliberate difference, automatic current capture, a missing baseline, and an isolated no-systemd SysV snapshot.
- Sensitive-value scan of release candidate paths for target lab IPs, supplied room password, and challenge flag format; no matches. Machine reports and `PROGRESS.md` are excluded from the release candidate.

Network and web scripts were not run against a target in this phase. Their PASS statuses rely on the prior documented authorized RootMe/Arena tests; those historical tests were not repeated here. The preserved machine reports remain the evidence for those target assessments.

## Recovery, remediation, and rollback

No suitable disposable VM with a known-good snapshot was available. QEMU is installed, but no VM manager, running QEMU guest, or disk image was found in the checked locations. The Docker daemon was unavailable; no Docker container was treated as a VM. Bubblewrap was used only for isolated parsing/detection fixtures, not as a substitute for a VM, systemd boot, firewall kernel state, or reboot validation.

Accordingly, capturing a VM snapshot, applying an actual remediation, confirming service health after a change, and restoring the snapshot are **NOT TESTED**. No system configuration was changed on the development host or either TryHackMe machine.

## GitHub preparation

The local project directory had no Git metadata. The private remote `nuzas96/nexsec2026-b2r-toolkit` was inspected before integration: `main` was at `fbdf493`, with five commits; its README and `cheatsheets/README.md` were retained. A fresh clone is on local branch `codex/phase4-validation` for review; its machine-local filesystem path is not part of the release files.

The release candidate includes scripts, tests, general-use guides, `README.md`, `.gitignore`, and this report. `README.md` appends toolkit documentation after the existing cheatsheet section. The cheatsheet file was copied byte-for-byte and is not replaced in the staging clone. `PROGRESS.md` and `labs/*_TEST.md` remain local and ignored because they contain machine-specific evidence, target addresses, or flags. A credential/target scan of candidate source and docs found no target IPs, room password, or flag-format strings.

Files are staged on the local branch only. No commit was made and nothing was pushed. Remote `main` remains at its existing history; no force-push or remote branch change was performed. GitHub integration is ready for review, with publish still pending explicit approval.

## Remaining blockers

- Real firewall state and iptables/UFW behavior need an authorized environment with inspectable firewall permissions.
- Process executable ownership was incomplete on the unprivileged development host; repeat with approved root access or a disposable VM.
- Actual remediation, service-availability verification after a change, and rollback need a disposable VM snapshot.
- No new RootMe or Arena live scans/runs were made in Phase 4; their prior report evidence is preserved, not refreshed.
- Push to GitHub remains intentionally unperformed.
