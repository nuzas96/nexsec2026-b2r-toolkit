# Manual usage — NEXSEC2026 B2R Toolkit

This quick reference is based on the **actual `--help` output of the nine scripts** captured during local manual testing on 24 November 2026. For deeper instructions and limitations, read `B2R_QUICK_START.md`, `OFFLINE_USAGE.md`, and `FINAL_VALIDATION.md` **after those files have been pushed**.

> **Scope:** Run only against systems expressly assigned to you, through permitted access paths. These scripts do not automatically exploit, clean, or harden a system. The audit findings are indicators requiring human verification. Follow the event's instructions regarding tools, AI and offline materials.

## 1. Start in the project directory

```bash
cd ~/Desktop/ctf-codex/nexsec2026-rootme-toolkit
pwd
ls -lah scripts/
```

If the project was cloned elsewhere, change the first command to its actual path.

Prepare **local, private** output storage *outside the Git repository*:

```bash
umask 077
OUT="$HOME/nexsec2026-outputs/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
chmod 700 "$OUT"
printf 'Reports directory: %s\n' "$OUT"
```

Keep findings, logs, tokens, credentials and exercise evidence out of GitHub. Treat reports as potentially sensitive.

## 2. Read help and verify Bash syntax

```bash
for script in scripts/*.sh; do
    echo "==== $(basename "$script") ===="
    bash -n "$script" && echo "[PASS] Bash syntax"
    bash "$script" --help
done
```

A successful syntax check **does not** prove the script's findings are correct.

## 3. Network and web reconnaissance (run from an authorized assessment host)

```bash
# Replace with the assigned target, and do not scan other hosts.
bash scripts/network_enum.sh AUTHORIZED_TARGET_IP | tee "$OUT/network.txt"

# Only if HTTP testing of this origin is authorized.
bash scripts/web_enum.sh http://AUTHORIZED_TARGET_IP | tee "$OUT/web.txt"
```

- `network_enum.sh TARGET`: bounded top-100 TCP service scan and optional NFS export check.
- `web_enum.sh URL`: checks a short list of paths on the supplied HTTP origin; **not** a comprehensive vulnerability scanner.
- A reachable path or open port is **not**, by itself, proof of vulnerability.
- The target must be reachable through the access path approved by the exercise organisers.

**Don't stop at HTTP status codes.** Follow [Manual Web B2R Workflow](WEB_MANUAL_WORKFLOW.md) for exact commands to save and grep HTML, identify possible `.thm` hostnames, and compare the HTTP `Host` header on the same assigned IP. Those are **manual** actions; `web_enum.sh` does not automatically discover virtual hosts.

## 4. Linux host inspection (requires authorized local shell)

Run these **on the Linux host being inspected**, not on Kali, if you want findings about that target. First use a non-root shell; repeat with the required privileges only where permitted and justified.

```bash
bash scripts/linux_triage.sh > "$OUT/linux-triage.txt"
bash scripts/privesc_check.sh > "$OUT/privesc.txt"
bash scripts/persistence_check.sh > "$OUT/persistence.txt"
bash scripts/recovery_audit.sh > "$OUT/recovery-audit.txt"
```

- `linux_triage.sh`: local identity, accounts, processes, listeners, routes and services.
- `privesc_check.sh`: time-bounded privilege escalation indicators; **does not prove** exploitability.
- `persistence_check.sh`: selected account, SSH, cron, service and autostart indicators.
- `recovery_audit.sh`: structured, pipe-delimited, read-only indicators. Missing access to privileged locations can reduce coverage; custom services and authorized keys can legitimately trigger **REVIEW**.
- These examples assume the script files and writable output folder are available **within the authorized environment**; do not introduce unapproved transfer methods, tunnels or remote connections.

## 5. Generate a remediation plan (recommendations only)

```bash
bash scripts/hardening_plan.sh "$OUT/recovery-audit.txt" > "$OUT/hardening-plan.txt"
```

This plan recommends investigation, remediation, backup, verification and rollback steps; **it does not change the system**. Review findings manually and avoid deleting accounts, keys, or services based on labels alone.

## 6. Capture and compare system state

Capture an initial baseline **before changes** (in the authorized Linux environment):

```bash
bash scripts/baseline_capture.sh > "$OUT/before.txt"
```

If permitted maintenance or remediation occurs, capture another snapshot:

```bash
bash scripts/baseline_capture.sh > "$OUT/after.txt"
bash scripts/service_verify.sh "$OUT/before.txt" "$OUT/after.txt"
```

Alternatively, use automatic current-state capture:

```bash
bash scripts/service_verify.sh "$OUT/before.txt"
```

Documented return codes for `service_verify.sh`:
- `0`: snapshots match / PASS.
- `1`: difference detected / DIFFERENCE.
- `2`: baseline missing, empty, or otherwise invalid.

These comparisons alone do **not** establish that an application is healthy; perform authorized service-specific functional checks. The recovery/rollback process has **not** been validated on a disposable VM as of the last project report.

## 7. Suggested end-to-end order

1. Confirm assigned host and approved access method.
2. Run `network_enum.sh` and, if relevant, `web_enum.sh`.
3. On an authorized Linux shell, run `linux_triage.sh` and `privesc_check.sh`.
4. Record a baseline; inspect persistence and recovery audit indicators.
5. Generate and review the hardening plan; preserve original evidence and backups.
6. Apply any necessary authorized changes carefully and individually (not automatically via these scripts).
7. Capture another baseline; run `service_verify.sh` and check essential service functionality.
8. Keep findings and changes in team-controlled storage according to organiser rules.

## 8. Current validation limits

At the last reported audit:
- **PASS:** `network_enum.sh`, `web_enum.sh`, `linux_triage.sh`, `privesc_check.sh`, `persistence_check.sh`, `service_verify.sh`, `hardening_plan.sh`, `baseline_capture.sh`.
- **PARTIAL:** `recovery_audit.sh` — incomplete real-firewall/process-owner coverage.
- Full remediation, service-health checks after changes, and rollback on a disposable VM were **not tested**.
- Earlier RootMe and Linux PrivEsc Arena runs are documented separately; do not mistake them for current live verification.

## References

- [Cheatsheet library](../cheatsheets/README.md) (external references, not offline copies).
- Local project docs once uploaded: `B2R_QUICK_START.md`, `OFFLINE_USAGE.md`, `RECOVERY_HARDENING.md`, `FINAL_VALIDATION.md`.
