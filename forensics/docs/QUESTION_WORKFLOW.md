# Question-Driven Forensics — Deep Investigation Workflow

This guide is for stepwise CTF forensics where Q2 may depend on Q1. **Do not conclude from filename alone.** Evidence questions are usually about a precise fact and a required format, not broad threat narrative.

## The seven-step loop

1. **Parse the question:** Extract answer type (UTC timestamp, filename, SID, username, IPv4, SHA-256, registry key, URL, process PID, command, byte sequence), required precision, and temporal scope. If the prompt says *last*, determine whether it means most recent execution, download, access, write or artifact creation.
2. **Identify the strongest artifact:** Map activity to event and data source. Example: Windows Prefetch is a better candidate for run time than a file's `mtime`.
3. **Preserve/prove provenance:** Intake SHA-256, note original location, filename, parser version and exact record ID. Work on copies.
4. **Parse with specialist tool:** Use a parser matching actual signatures, version and compression. A generic `strings` output is not a trustworthy Prefetch timestamp parser.
5. **Cross-check when possible:** Compare one or more independent sources without conflating a clue with proof. Consider logs disabled/overwritten, journal partial, memory image missing.
6. **Normalize deliberately:** UTC vs local time, milliseconds vs seconds, Windows FILETIME vs browser WebKit, DST ambiguity. Keep original raw timestamp.
7. **Answer then verify:** Verify format, evidence source, date, exact filename capitalization, and whether the question expects one answer or multiple. Record and move on.

## Artifact selection cheatsheet

| Wording in question | Start with | Common error |
| --- | --- | --- |
| "Last executed" | Prefetch / process creation logs / BAM | Mistaking `mtime` for execution |
| "Who logged on?" | Security 4624/4625, SID, logon ID | Counting service/remote logon as interactive |
| "Which file was deleted?" | MFT/USN journal, Recycle Bin | Assuming deleted data can still be carved |
| "USB device user" | Registry USBSTOR, MountedDevices, MountPoints2 | Plugged-in USB != exfiltrated files |
| "Command used" | Sysmon 1 / 4688 / PowerShell logs / memory | Assuming process exists => full CLI known |
| "Attacker IP/domain" | PCAP/logs and event sources | DNS resolution != C2 session |
| "Transferred data" | PCAP sessions, reassembled objects | TCP handshake != file transfer |
| "Hidden config/persistence" | Run keys, Services, Tasks, cron/systemd | Installed entry != executed payload |
| "When did file open" | LNK/Jump Lists/app records | File `mtime` != user open |

## Evidence tracking template

| Q | Answer candidate | Raw source/reference | Tool/version | Raw time | UTC time | Verification | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Q1 | TBD | exact file / row / event | TBD | original value | only if justified | pending | hypothesis |

For every question, capture an alternative interpretation: "what else could produce this artifact?" Use `finding-add` after observing actual source evidence. It stores the matched input file SHA-256 at intake to support later cross-checks.

## If stuck

- Check format and timezone before rerunning broad tools.
- Check file magic vs extension, compressed wrappers, hidden streams and missing WAL or sidecars.
- Check tool support/version, parser errors and whether a **copy** was truncated or corrupted.
- Find a different supporting artifact; an absent log can reflect disabled logging, not absence of activity.
- Don't expand scope beyond provided artifacts or make unverifiable claims.
