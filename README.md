# nexsec2026-b2r-toolkit

Offline Boot2Root, Linux security assessment, incident response, and recovery toolkit.

## Cheatsheet references

- [B2R & CTF Cheatsheet Library](cheatsheets/README.md) — **14 curated external resources** grouped into core B2R, supplemental, Windows/AD, and original references, with attribution and offline-use notes.
**Practical Web commands:** [Directory & File Enumeration — ffuf/Gobuster](cheatsheets/directory-enumeration.md) for authorized directory brute-force after basic reconnaissance. The repository also includes an [original 120-entry quick web wordlist](wordlists/b2r-quick.txt), usable offline.

## Project purpose

The nine Bash scripts support authorized investigation from reconnaissance through local privilege assessment, persistence review, recovery planning, baseline capture, and service verification. Scripts are read-only by default. Network and web enumeration require an authorized target; local checks require an authorized shell on the system being assessed.

## Requirements

- Bash and common Linux utilities (`awk`, `find`, `stat`, `timeout`, `date`, `grep`, `diff`, `sort`).
- `nmap` for `network_enum.sh`; `showmount` adds an optional NFS export query.
- `curl` for `web_enum.sh`.
- Local checks use available tools such as `ps`, `ss`, `systemctl` or SysV `service`, `getcap`, `sudo`, `nft`, `iptables-save`, and `ufw`. Missing optional tools are reported or skipped where supported.
- `ShellCheck` and `bwrap` are only needed for development validation and isolated recovery fixtures.

No Python packages, internet access, or AI service is required for local Linux checks. Network and web scripts require connectivity to the specifically authorized target.

## Advanced Forensics Toolkit

- [Forensics Workbench v0.1](forensics/README.md) — separate question-driven forensic tooling, example artifacts, offline guides and synthetic regression tests in [`forensics/`](forensics/). This does not modify the existing Boot2Root scripts.

## Quick start

Read [B2R_QUICK_START.md](B2R_QUICK_START.md) for command examples, permissions, output handling, and recovery workflow. For manual HTML inspection, hostname clues and virtual-host checks after a web scan, read [Manual Web B2R Workflow](docs/WEB_MANUAL_WORKFLOW.md). For incident response and manual rollback, see [RECOVERY_HARDENING.md](RECOVERY_HARDENING.md); for the short script reference, see [OFFLINE_USAGE.md](OFFLINE_USAGE.md).

```bash
./scripts/network_enum.sh 192.0.2.10
./scripts/web_enum.sh http://192.0.2.10

# Optional reconnaissance modes for authorized targets:
./scripts/network_enum.sh --full 192.0.2.10
./scripts/web_enum.sh --host lab.example.test http://192.0.2.10
./scripts/linux_triage.sh
./scripts/privesc_check.sh
./scripts/recovery_audit.sh > recovery-audit.txt
./scripts/hardening_plan.sh recovery-audit.txt
./scripts/baseline_capture.sh > baseline-before.txt
./scripts/service_verify.sh baseline-before.txt
```

The example address is from the documentation-only range; `lab.example.test` is a placeholder hostname. Replace both only with an authorized lab target. `--full` checks all TCP ports subject to a 300-second timeout; `--host` sends an HTTP Host header but does not discover virtual hosts automatically. Network scripts do not exploit the target. Local scripts require shell access on the assessed Linux machine.

## Validation

Run syntax and static checks from the project root:

```bash
for script in scripts/*.sh tests/*.sh; do bash -n "$script"; done
shellcheck scripts/*.sh tests/*.sh
tests/recovery_fixture_test.sh
bash tests/recon_options_test.sh
```

The fixture suite requires Bubblewrap/user namespaces and modifies only isolated temporary filesystems. It does not modify the host or a shared challenge system. See [FINAL_VALIDATION.md](FINAL_VALIDATION.md) for tested coverage and known gaps.

## Findings and limitations

An indicator is not proof of exploitation or compromise. Confirm ownership, service use, approved inventories, and effective permissions before changing anything. Root improves local visibility. The recovery audit does not collect private keys, full configuration contents, authentication logs, or memory/disk images. It cannot decide whether a custom unit, key, account, or firewall policy is authorized. Hardening output is advisory and never applies remediation.

The RootMe and Linux PrivEsc Arena reports contain machine-specific lab evidence and are intentionally excluded from this repository preparation. Do not commit credentials, flags, target-specific logs, or generated assessment output.
