# B2R & CTF Cheatsheet References

Curated quick links for **authorized** Boot2Root (B2R), Linux/Windows security assessment, web testing, incident response, and recovery. **14 total references**: the original two plus 12 additional resources.

> These are links and short annotations, **not copies** of third-party material or proof that every command is suitable for a particular system. Prioritize the resources below based on the assigned exercise scope.

## Start here — Core B2R references (7)

| Resource | Main use | Best time to consult |
| --- | --- | --- |
| [GTFOBins](https://gtfobins.org/) | Unix binaries and dangerous sudo/SUID/capability contexts | After spotting a privileged executable |
| [HackTricks — Linux Privilege Escalation Checklist](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/linux-hardening/main-system-information/linux-privilege-escalation-checklist.md) | Systematic manual Linux privilege escalation assessment | After acquiring authorized shell access |
| [PEASS-ng (LinPEAS / WinPEAS)](https://github.com/peass-ng/PEASS-ng) | Automated local enumeration **tools**; not merely a written cheatsheet | To cross-check results from our own checker |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Web vulnerability testing examples and payload reference | During authorized web application assessment |
| [OWASP Web Security Testing Guide — Checklist](https://github.com/OWASP/wstg/blob/master/checklists/checklist.md) | Structured web test coverage | When planning or reviewing web assessment |
| [DFIR Handbook — Linux Persistence](https://dfidwiz-sketch.github.io/dfir-handbook/linux/persistence/) | Cron, systemd, SSH keys, profiles, accounts, and integrity inspection | When investigating possible unauthorized access |
| [SANS — Intrusion Discovery Cheat Sheet for Linux](https://www.sans.org/posters/intrusion-discovery-cheat-sheet-for-linux) | Signs of Linux compromise and initial investigation | During incident triage and recovery assessment |

## Supplemental references (3)

| Resource | Main use | Why supplementary |
| --- | --- | --- |
| [HackTricks — Full Knowledge Base](https://github.com/HackTricks-wiki/hacktricks) | Detailed Linux, Windows, service, and web security topics | Broad; overlaps with the focused Linux checklist |
| [LOLBAS](https://lolbas-project.github.io/) | Catalog of Windows built-in binaries, scripts, and libraries that could be misused | Most useful when the assigned target is Windows |
| [SANS — Linux Incident Response and Threat Hunting Poster](https://www.sans.org/posters/linux-incident-response-threat-hunting-poster) | Investigation and Linux threat-hunting workflow | Poster download may require access or sign-in |

## Optional Windows / Active Directory references (2)

| Resource | Main use | When relevant |
| --- | --- | --- |
| [WADComs](https://wadcoms.github.io/) | Interactive Windows and Active Directory command references | If Windows / AD systems are in scope |
| [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) | Internal penetration testing and Active Directory knowledge | For multi-host or AD-specific authorized labs |

## Original references (previously saved)

### Boot2Root Cheatsheet — amirr0r

- **Author:** [amirr0r](https://github.com/amirr0r)
- **Source:** [Boot2Root cheatsheet](https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md)
- **Coverage:** Network/service reconnaissance, web testing, Linux and Windows techniques, privilege escalation, shells, and common commands.

### Awesome CTF Cheatsheet — uppusaikiran

- **Author:** [uppusaikiran](https://github.com/uppusaikiran)
- **Repository:** [awesome-ctf-cheatsheet](https://github.com/uppusaikiran/awesome-ctf-cheatsheet)
- **Main cheatsheet:** [readme.md](https://github.com/uppusaikiran/awesome-ctf-cheatsheet/blob/master/readme.md)
- **Source license:** [MIT License](https://github.com/uppusaikiran/awesome-ctf-cheatsheet/blob/master/LICENSE)
- **Coverage:** General CTF tools, methods, and related references.

## Suggested workflow

1. **Recon / services:** Our `network_enum.sh` and `web_enum.sh`; consult HackTricks and OWASP as needed.
2. **Authorized local shell:** Run `linux_triage.sh` and `privesc_check.sh`; investigate findings using GTFOBins and HackTricks.
3. **Web weaknesses:** Use OWASP WSTG to guide coverage and PayloadsAllTheThings for technical reference.
4. **Compromise investigation:** Use `persistence_check.sh`; corroborate findings with DFIR Handbook and SANS.
5. **Recovery and validation:** Document evidence, backups, remediation, rollback, and service verification; do not assume a privilege-escalation checklist replaces a recovery plan.

## Attribution, safety and offline readiness

- **External links only:** The copyrighted source material and tool binaries are **not mirrored** here. Each project retains its own authorship, license, and update schedule.
- Some references describe offensive techniques. Use them only inside systems and networks explicitly authorized for assessment.
- A link is **not** an offline copy. For restricted environments, prepare any permitted local copies **before** the event, review licenses and event rules, and do not rely on access to external sites during the event.
- Findings are indications requiring validation, not automatic proof of a vulnerability or compromise.
- Do not store access credentials, flags, or sensitive exercise evidence in this repository.
