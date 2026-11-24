# Directory & File Enumeration — B2R Cheatsheet

Use this **after** basic network/web checks to look for additional *in-scope* directories and files. This is **wordlist-based directory discovery**, not password guessing. Neither an HTTP status nor a discovered path automatically proves a vulnerability.

**Scope:** Run only against a TryHackMe machine or system assigned to you. Use a short, controlled scan. Do not recursively bombard shared services, use unapproved targets, or follow an out-of-scope redirect.

## 0. Check tools and wordlist on Kali

```bash
command -v ffuf
command -v gobuster
ls -lh /usr/share/wordlists/dirb/common.txt
```

Use a wordlist **already available locally**. If the example file is absent, find one in your approved offline wordlist collection and change `WL` accordingly. Both tools are alternatives; **you usually need only one**.

## 1. Set up the authorized target and private results folder

Example for the **authorized TryHackMe Archangel lab** used in manual testing (the IP may change when you redeploy):

```bash
IP="10.48.153.204"
HOST="mafialive.thm"
WL="/usr/share/wordlists/dirb/common.txt"

umask 077
OUT="$HOME/nexsec-manual/archangel"
mkdir -p "$OUT"

test -f "$WL" && echo "[OK] Wordlist found" || echo "[ERROR] Wordlist missing; set WL to an existing file before scanning"
```

If you're using a different room, **replace the IP, hostname, and output folder** with values verified to belong to that room.

## 2. ffuf — directory brute-force on the IP website

```bash
ffuf -u "http://$IP/FUZZ" \
  -w "$WL" \
  -t 5 -rate 10 -timeout 10 \
  -ac \
  -of json -o "$OUT/ffuf-ip.json"
```

- `FUZZ`: place in the URL where entries from the wordlist are substituted.
- `-w`: wordlist; `-t 5`: five concurrent workers; `-rate 10`: cap at 10 requests/sec; `-timeout 10`: request timeout in seconds.
- `-ac`: automatic calibration of similar noise responses. **Review unexpected/empty output** because calibration can suppress interesting responses.
- `-o/-of`: save JSON results outside GitHub.

## 3. ffuf — discover directories on the named virtual host

When a hostname such as `mafialive.thm` is explicitly discovered in the HTML **and confirmed in scope**, specify the `Host` header while keeping the request on the same IP:

```bash
ffuf -u "http://$IP/FUZZ" \
  -H "Host: $HOST" \
  -w "$WL" \
  -t 5 -rate 10 -timeout 10 \
  -ac \
  -of json -o "$OUT/ffuf-vhost.json"
```

This matters because the default IP website and the named site can serve **different content**. It works even if `mafialive.thm` is not in `/etc/hosts`.

## 4. ffuf — look for common file extensions

Try this **after** initial directory discovery if the application appears to use PHP/HTML/text files:

```bash
ffuf -u "http://$IP/FUZZ" \
  -H "Host: $HOST" \
  -w "$WL" \
  -e .php,.html,.txt \
  -t 5 -rate 10 -timeout 10 \
  -ac
```

Extensions multiply the number of requests; keep them limited to formats that make sense for the assigned app.

## 5. Gobuster — alternative to ffuf

On the IP-based site:

```bash
gobuster dir \
  -u "http://$IP/" \
  -w "$WL" \
  -t 5 --timeout 10s \
  -o "$OUT/gobuster-ip.txt"
```

On the named virtual host:

```bash
gobuster dir \
  -u "http://$IP/" \
  -H "Host: $HOST" \
  -w "$WL" \
  -t 5 --timeout 10s \
  -o "$OUT/gobuster-vhost.txt"
```

For a focused file scan, add `-x php,html,txt` only if relevant. Check `gobuster dir --help` in your installed version for available options.

## 6. Read the results carefully

| Status | Meaning | Next step |
| --- | --- | --- |
| `200` | Content returned | Visit or inspect the path and response body |
| `301/302` | Redirect | Review `Location`; stay in scope |
| `401` | Authentication required | Identify the intended authentication workflow; do not guess credentials |
| `403` | Access forbidden | Record finding; not automatically exploitable |
| `404` | Not found | Typically noise unless the app responds unusually |
| `500` | Server error | Stop aggressive probing; investigate cautiously |

A large set of paths with identical status/size may reflect a wildcard or custom error page. Compare with a made-up path before trusting results.

## 7. Verify individual hits manually (same assigned IP)

```bash
# Replace DISCOVERED_PATH with the path actually reported.
curl -sS -i --connect-timeout 5 --max-time 15 \
  -H "Host: $HOST" "http://$IP/DISCOVERED_PATH" | head -n 40
```

Inspect links, forms and scripts relevant to the app. An open directory, forbidden path or version string is only a clue, not evidence of compromise.

## 8. Common errors

- `ffuf: command not found` or `gobuster: command not found`: tool is not installed on the assessment host. Install only through an approved method and before any offline event.
- `Wordlist not found`: verify `WL` and local wordlist location.
- Too many identical results: inspect wildcard responses; compare scans with and without `-ac`, or use a response-size filter **after** confirming a baseline.
- Timeouts/packet loss: check VPN route and target health; reduce concurrency, don't increase it blindly.
- `404` for every guess: the selected wordlist may not match the app, or the paths may genuinely be absent.

## 9. Where this fits into the toolkit

```text
network_enum.sh -> web_enum.sh -> inspect HTML / hostnames
                         |
                         +-> ffuf or gobuster on authorized host
                                  |
                                  +-> verify interesting paths manually
                                  +-> assess the app
```

Our `web_enum.sh` **does not invoke ffuf or gobuster**. These are separate optional manual commands, so the Bash toolkit remains predictable and read-only by default.

### Upstream tool documentation

- [ffuf — official README](https://github.com/ffuf/ffuf)
- [ffuf — CLI flags](https://github.com/ffuf/ffuf/wiki/CLI-flags)
- [Gobuster — official repository](https://github.com/OJ/gobuster)
