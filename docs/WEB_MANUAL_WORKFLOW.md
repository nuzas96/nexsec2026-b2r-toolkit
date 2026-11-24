# Manual Web B2R Workflow — After `web_enum.sh`

**Purpose:** A step-by-step reference for what to do **after** the basic web enumeration script runs. The script itself checks five predefined paths and HTTP headers; it does **not** automatically read page source, discover virtual hosts, confirm vulnerabilities, or obtain a shell.

All commands below are for **your explicitly authorized lab target** only. Replace placeholders with the actual assigned target. Do not follow hints into unassigned domains or external services.

## 1. Run the existing script

From the toolkit root on Kali / the approved assessment host:

```bash
./scripts/network_enum.sh AUTHORIZED_IP
./scripts/web_enum.sh http://AUTHORIZED_IP

# Only if required and approved (all TCP ports, time-bounded):
./scripts/network_enum.sh --full AUTHORIZED_IP
```

Typical output and what it means:

| Result | Interpretation | Next check |
| --- | --- | --- |
| HTTP 200 | Page/path is reachable | Read HTML and inspect links/forms/comments |
| HTTP 301/302 | Redirect | Inspect `Location:` and confirm destination is in scope |
| HTTP 403 | Resource denies access | Document it; **not proof of a bypass** |
| HTTP 404 | This specific path was not found | Continue to other relevant paths; **not a full scan** |
| Connection timeout | Uncertain service/connectivity state | Recheck route, VPN, and one request with a bounded timeout |
| Open SSH/HTTP | Service reachable | Does **not** prove any vulnerability |

The script only tests `/`, `/robots.txt`, `/server-status`, `/uploads/` and `/icons/`.

## 2. Save and inspect the homepage HTML

```bash
mkdir -p "$HOME/b2r-manual"
curl -sS --connect-timeout 5 --max-time 15 \
  http://AUTHORIZED_IP/ -o "$HOME/b2r-manual/index.html"

grep -Ein 'title|href=|src=|action=|mailto:|@|<!--|TODO|admin|login' \
  "$HOME/b2r-manual/index.html" | head -n 80
```

Look for **domain names, e-mail domains, comments, forms, links and script paths**. A domain in a footer can be a useful clue, but does not automatically establish authorization or vulnerability.

## 3. Extract potential TryHackMe hostname clues

This example looks only for `.thm` names; adapt to the authorized lab's domain format.

```bash
grep -Eoi '[A-Za-z0-9.-]+\.thm' "$HOME/b2r-manual/index.html" | sort -u
```

If there is **no match**, do not assume the site lacks virtual hosts. Inspect the content and exercise description manually.

## 4. Check name-based virtual hosting on the same authorized IP

A web server can serve different content on one IP depending on the HTTP `Host` header. Once a hostname is observed **and confirmed to be in scope**, compare the two requests:

```bash
# Default site:
curl -sS -i --connect-timeout 5 --max-time 15 \
  http://AUTHORIZED_IP/ | head -n 45

# Same IP, discovered hostname supplied explicitly:
curl -sS -i --connect-timeout 5 --max-time 15 \
  -H 'Host: DISCOVERED_HOSTNAME' http://AUTHORIZED_IP/ | head -n 45
```

Compare page title, response body, status, `Content-Length`, and redirects. A different response can indicate a **separate virtual host**, not necessarily a vulnerability.

**New toolkit option:** Once the hostname is confirmed in scope, you can check the script's five paths and response headers against that virtual host directly:

```bash
./scripts/web_enum.sh --host DISCOVERED_HOSTNAME http://AUTHORIZED_IP
```

This uses an HTTP Host header, not hostname discovery. HTTPS virtual hosts may also require matching TLS SNI (see `curl --resolve` below).

To make requests using the hostname without changing `/etc/hosts`, you may use `curl --resolve` on that same approved IP:

```bash
curl -sS --resolve 'DISCOVERED_HOSTNAME:80:AUTHORIZED_IP' \
  'http://DISCOVERED_HOSTNAME/'
```

Replace `DISCOVERED_HOSTNAME` and `AUTHORIZED_IP` first. Do **not** copy this literal placeholder command as-is.

## 5. Optional directory and file discovery (authorized scope only)

After confirming the site and virtual host, use a bounded wordlist scan with `ffuf` or `gobuster` when necessary. The full copy-paste examples (including Archangel's `Host` header) are in **[Directory Enumeration Cheatsheet](../cheatsheets/directory-enumeration.md)**. The repo includes its own [120-entry lightweight wordlist](../wordlists/b2r-quick.txt), and the cheatsheet explains Kali DIRB and SecLists locations, installation and fallback commands. This step is manual; `web_enum.sh` does not automatically perform directory brute-force.

## 6. Investigate the newly discovered site

If the hostname routes to a different app:

- Record the URL, HTTP response and how you found it.
- Read the new page source, links, forms, scripts, `robots.txt` and any authorized in-scope paths.
- Check the intended workflow and authentication before drawing conclusions.
- Do not call a 403, login form or version string an exploit by itself.
- Move to local Linux scripts **only when a valid, explicitly authorized shell is available**.

Our `web_enum.sh` now accepts `--host HOSTNAME` along with the assigned IP URL to check the five predefined paths on a named virtual host. It does **not** perform wordlist enumeration, discover the hostname automatically, or confirm vulnerabilities.

## 7. Practical B2R decision path

```text
Authorized IP
   |
   +-- network_enum.sh: what ports and services?
   |
   +-- web_enum.sh: which of the 5 quick-check paths respond?
   |
   +-- Save and inspect HTML
         |
         +-- Clues: hostname/email/domain? --> Confirm scope --> Host-header comparison
         |
         +-- Discovered authorized site? --> Bounded ffuf/Gobuster directory enumeration
         |
         +-- Links/forms/scripts? --> Inspect the authorized app workflow
         |
         +-- No useful clues? --> Manual enumeration within the assigned scope
   |
   +-- Authorized target shell obtained --> linux_triage.sh / privesc_check.sh
   |
   +-- Investigation/recovery --> persistence_check.sh / recovery_audit.sh
```

## 8. Offline use and boundaries

- Keep a local copy of this guide before a connectivity-restricted exercise, if organizers permit notes.
- The current repository is private but **reports containing credentials, flags, and incident evidence should still be kept out of Git**.
- This document describes **manual investigative steps**, not automated capabilities already implemented in the Bash script.
- Always comply with the organiser-provided access path and scope. Do not use external callback infrastructure, unapproved proxies or redirects.
