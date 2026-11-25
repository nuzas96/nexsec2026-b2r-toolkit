# Advanced Windows Artifact CTF Playbook

This is a **manual** playbook. The Python workbench does **not** parse EVTX, Prefetch records, Registry cells or `$MFT` directly. Use the relevant specialist parser on an authorized forensic copy.

## A. Windows execution evidence (Prefetch)

- Locate `Windows/Prefetch/*.pf` in extracted or provided evidence. Modern compressed files may begin `MAM\x04` rather than containing plain `SCCA`; use a parser that handles compressed Prefetch.
- Identify executable name/hash, file paths, run count, recorded run times and Windows version. Distinguish "last run" from source file creation and modified times.
- If execution needs user attribution, correlate with Sysmon Event 1, Security 4688, UserAssist, BAM and login records. Prefetch itself does not always identify the responsible user.

**Example on Windows, from an evidence copy:**

```powershell
PECmd.exe -d "C:\EvidenceCopy\Prefetch" --csv "C:\CaseOut\Prefetch"
```

Check your installed version's `PECmd.exe --help`. Never process original evidence in-place as a repair operation.

## B. Windows event logs

**Relevant starting Event IDs (meaning depends on provider and audit configuration):**

| Log/event | Relevance | Important check |
| --- | --- | --- |
| Security 4624 | Successful logon | Logon type, account, SID, logon ID, source address |
| Security 4625 | Failed logon | Reason/status and attempt count |
| Security 4634/4647 | Logoff | Session reference; not always equal to last process termination |
| Security 4672 | Special privileges assigned to logon | Not necessarily a compromise |
| Security 4688 | Process creation (if auditing enabled) | Command-line field often missing; parent process |
| Sysmon 1 | Process create | Image, command line, parent, process GUID |
| Sysmon 3 | Network connection (if enabled) | Process GUID and endpoint details |
| Sysmon 11 | File creation | Creation != file content exfiltration |
| Sysmon 22 | DNS query | Query != successful C2 connection |
| PowerShell 4104 | Script block logging (if enabled) | Encoded/assembled commands; record fragments |

**Example:**

```powershell
EvtxECmd.exe -f "C:\EvidenceCopy\Security.evtx" --csv "C:\CaseOut\EVTX"
```

The generated CSV can be combined with other parsed exports using `timeline-build` after inspecting column names and specifying their time semantics explicitly.

## C. NTFS and deleted files

- `$MFT`: file records, names, metadata, resident/nonresident data pointers.
- `$UsnJrnl:$J`: journaled filesystem changes, where available.
- `$LogFile`: transaction records; a distinct artifact from USN.
- `$Recycle.Bin`: original path and deletion metadata, where retained.
- LNK / Jump Lists: opened/recent-linked file associations, not a proof of exact execution.

**Example:**

```powershell
MFTECmd.exe -f 'C:\EvidenceCopy\$MFT' --csv 'C:\CaseOut\MFT'
```

In PowerShell the quoted path preserves the literal `$MFT` differently depending on quotation style; **use single quotes when constructing a literal `$MFT` path** to avoid variable expansion, for example `-f 'C:\EvidenceCopy\$MFT'`.

## D. Registry / application compatibility

Look at SYSTEM, SOFTWARE, SAM, NTUSER.DAT and UsrClass.dat as appropriate. Run keys and tasks suggest persistence candidates. ShimCache/Amcache entries by themselves do not prove execution. The user hive may indicate file associations or application use. Cross-check with Prefetch/process events.

## E. Timeline integrity

- Confirm UTC vs local and parser version; do not assume all CSV export times are in local time.
- Preserve original event record ID, provider/channel, SID/logon ID, raw timestamp and input artifact SHA-256.
- Be careful with images/copies created later; acquisition `mtime` is not the original event time.

Official tool references:

- https://github.com/EricZimmerman/PECmd
- https://github.com/EricZimmerman/evtx
- https://github.com/EricZimmerman/MFTECmd
