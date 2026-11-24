# Directory & File Enumeration — Copy-Paste B2R Cheatsheet

**Purpose:** Find in-scope web paths by trying words from a directory/file **wordlist**. This is **not** password brute-forcing. An HTTP 200/403/redirect is a clue, not proof of a security flaw.

**Scope:** Authorized TryHackMe rooms or explicitly assigned machines only. Keep scans bounded and avoid redirected or shared infrastructure.

## A. Fastest option — ready-to-run Archangel scan (no SecLists required)

This repository now includes its own **original 120-entry lightweight wordlist**:

**[wordlists/b2r-quick.txt](../wordlists/b2r-quick.txt)**

The following block can be pasted **inside a current clone of this repository** on Kali. It assumes that the lab instance is still **10.48.153.204**, and that the `mafialive.thm` hostname is in scope. Change the two assignments if TryHackMe reassigns the IP or you use a different lab.

```bash
# Run from the ROOT of this GitHub repository
IP="10.48.153.204"
HOST="mafialive.thm"
WL="$PWD/wordlists/b2r-quick.txt"
OUT="$HOME/nexsec-manual/archangel"

umask 077
mkdir -p "$OUT"

command -v ffuf
ls -l "$WL"

# Scan virtual host confirmed by manual HTML investigation:
ffuf -u "http://$IP/FUZZ" \
  -H "Host: $HOST" \
  -w "$WL" \
  -t 5 -rate 10 -timeout 10 -maxtime 120 -ac \
  -of json -o "$OUT/ffuf-quick-vhost.json"
```

**If `ffuf` is not installed**, install it before the event using an approved Kali package source (`sudo apt install ffuf`). If the wordlist file is missing, use the [latest GitHub clone](https://github.com/nuzas96/nexsec2026-b2r-toolkit) or follow the self-contained fallback in section D.

**Want to scan the plain IP homepage instead?** Run the same command without `-H "Host: $HOST"`, saving to a different output filename. The IP homepage and the virtual host may return **different websites**.

## B. Wordlist choices — which one should I use?

| Wordlist | Typical Kali location | Practical use |
| --- | --- | --- |
| **Our B2R quick list** | `wordlists/b2r-quick.txt` (within this repo) | Fast first pass; no extra wordlist package |
| **DIRB common** | `/usr/share/wordlists/dirb/common.txt` | General-purpose first pass |
| **SecLists common** | `/usr/share/seclists/Discovery/Web-Content/common.txt` | Alternative short/mid list |
| **SecLists RAFT small directories** | `/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt` | More directory names |
| **SecLists DirBuster medium** | `/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` | Much larger; avoid if short time |
| **DirBuster package variant** | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Alternative install-dependent path |

**Do not assume these paths all exist on your Kali.** The SecLists medium filename differs from the older DirBuster package filename. Check before selecting one.

```bash
# Find wordlists already installed:
for path in \
  "$PWD/wordlists/b2r-quick.txt" \
  /usr/share/wordlists/dirb/common.txt \
  /usr/share/seclists/Discovery/Web-Content/common.txt \
  /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
  /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
do
  if [ -f "$path" ]; then
    printf 'FOUND: %s (%s lines)\n' "$path" "$(wc -l < "$path")"
  else
    printf 'MISSING: %s\n' "$path"
  fi
done
```

**Install wordlists on Kali (only when internet/package access is permitted):**

```bash
sudo apt update
sudo apt install -y ffuf gobuster dirb
# Optional: a LARGE collection; download and store BEFORE an offline event:
sudo apt install -y seclists

# Check the actual locations after installation:
ls -lh /usr/share/wordlists/dirb/common.txt
ls -lh /usr/share/seclists/Discovery/Web-Content/common.txt
```

References: [Kali DIRB package](https://www.kali.org/tools/dirb/), [Kali SecLists package](https://www.kali.org/tools/seclists/), [SecLists web wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content).

## C. One-click upgrade from quick to common/medium (copy-paste)

From the project root, following section A (so `IP`, `HOST`, `OUT` are already set):

**DIRB common scan** — choose this first, if installed.

```bash
WL="/usr/share/wordlists/dirb/common.txt"
if [ -f "$WL" ]; then
  ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
    -w "$WL" -t 5 -rate 10 -timeout 10 -maxtime 600 -ac \
    -of json -o "$OUT/ffuf-dirb-common.json"
else
  echo "DIRB common not installed; use the bundled wordlists/b2r-quick.txt"
fi
```

**SecLists common scan** — alternative if already installed.

```bash
WL="/usr/share/seclists/Discovery/Web-Content/common.txt"
if [ -f "$WL" ]; then
  ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
    -w "$WL" -t 5 -rate 10 -timeout 10 -maxtime 600 -ac \
    -of json -o "$OUT/ffuf-seclists-common.json"
else
  echo "SecLists missing; see section B to install before the event"
fi
```

**SecLists medium scan** — only if the small scans do not find what you need. The runtime is capped and **may not exhaust the entire list**.

```bash
WL="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
if [ -f "$WL" ]; then
  ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
    -w "$WL" -t 5 -rate 10 -timeout 10 -maxtime 600 -ac \
    -of json -o "$OUT/ffuf-medium-partial.json"
else
  echo "Medium SecLists wordlist not found at this path"
fi
```

Use `-rate 10` and limited concurrency to avoid unnecessarily stressing the lab. **No script automatically uses a medium list.**

## D. Fallback — create a tiny custom wordlist from the terminal

If you do not have this repository copy or system wordlists, this short list can be created **without internet** and used immediately with an already-installed `ffuf`.

```bash
mkdir -p "$HOME/nexsec-wordlists" "$HOME/nexsec-manual/archangel"
cat > "$HOME/nexsec-wordlists/quick-web.txt" <<'EOF'
admin
admin.php
login
login.php
panel
dashboard
portal
uploads
upload
upload.php
backup
backups
config
config.php
api
dev
test
test.php
robots.txt
sitemap.xml
assets
static
images
index.php
.git
.env
EOF

ffuf -u "http://10.48.153.204/FUZZ" \
  -H "Host: mafialive.thm" \
  -w "$HOME/nexsec-wordlists/quick-web.txt" \
  -t 5 -rate 10 -timeout 10 -maxtime 120 -ac \
  -of json -o "$HOME/nexsec-manual/archangel/ffuf-custom.json"
```

## E. Search extensions after you find relevant directories

For PHP/HTML/text apps, this appends extensions to your selected list. It increases the number of requests.

```bash
WL="$PWD/wordlists/b2r-quick.txt"
ffuf -u "http://$IP/FUZZ" -H "Host: $HOST" \
  -w "$WL" -e .php,.html,.txt \
  -t 5 -rate 10 -timeout 10 -maxtime 300 -ac \
  -of json -o "$OUT/ffuf-extensions.json"
```

## F. Gobuster — alternative (choose one tool, not both by default)

To use the bundled local wordlist on the named virtual host:

```bash
IP="10.48.153.204"
HOST="mafialive.thm"
WL="$PWD/wordlists/b2r-quick.txt"
OUT="$HOME/nexsec-manual/archangel"
mkdir -p "$OUT"

gobuster dir \
  -u "http://$IP/" \
  -H "Host: $HOST" \
  -w "$WL" \
  -t 5 --timeout 10s \
  -o "$OUT/gobuster-vhost.txt"
```

For file extensions, add `-x php,html,txt` if it is relevant and the room allows the extra traffic. Confirm options with `gobuster dir --help` on your installed version. The `gobuster` example has no global request-rate option; keep the wordlist short and concurrency low.

## G. What to do with results

| HTTP result | Meaning | Next action |
| --- | --- | --- |
| 200 | Page/file returned | Manually open and inspect its body |
| 301 / 302 | Redirect | Review `Location` and stay in approved scope |
| 401 | Authentication required | Review intended login flow (do not guess passwords) |
| 403 | Access denied | Record as an observation, not a vulnerability |
| 404 | Path absent | Expected for most guesses |
| 500 | Server failure | Reduce/stop probing; investigate conservatively |

Some sites return **200 for every invalid path**. Check one made-up URL to find the normal "not found" response before interpreting mass-scan results. ffuf `-ac` can help filter noise but can also hide interesting responses.

Manually verify a real hit on the authorized host:

```bash
# Replace PATH_FROM_SCAN with a real path discovered in output.
curl -sS -i --connect-timeout 5 --max-time 15 \
  -H "Host: mafialive.thm" \
  "http://10.48.153.204/PATH_FROM_SCAN" | head -n 45
```

## H. Troubleshooting and workflow

- **Wordlist missing:** use our bundled `wordlists/b2r-quick.txt`, choose an actually-installed SecLists/DIRB path, or create a short custom list (section D).
- **`ffuf: command not found` / `gobuster: command not found`:** install from Kali's approved repository **before** the exercise; these tools are not provided by the Bash scripts.
- **Too many hits:** inspect wildcard/default responses and output sizes; don't call every 200 an exposed admin page.
- **No hits:** inspect HTML, JavaScript, login forms and hostname clues. A wordlist cannot find every app route.
- **Time-outs / packet loss:** verify VPN connectivity, reduce request rate, and avoid repeated aggressive scans.

Workflow:

```text
network_enum.sh -> web_enum.sh -> read HTML and discover hostname
                 -> choose quick wordlist -> ffuf OR gobuster
                 -> confirm interesting URL paths manually
                 -> investigate authorized web application
                 -> obtain authorized target shell, then Linux triage and priv-esc checks
```

**Safety and tooling:** `web_enum.sh` does **not** automatically run ffuf or gobuster. Wordlist files and third-party binaries should be prepared offline through approved methods. Do not commit target responses, challenge flags, or credentials into this GitHub repository.

### Documentation

- [ffuf official repository](https://github.com/ffuf/ffuf)
- [ffuf CLI flags](https://github.com/ffuf/ffuf/wiki/CLI-flags)
- [Gobuster official repository](https://github.com/OJ/gobuster)
