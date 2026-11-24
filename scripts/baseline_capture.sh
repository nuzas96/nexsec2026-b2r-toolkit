#!/usr/bin/env bash
set -u -o pipefail

if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0"
  echo "Example: $0 > baseline-$(date -u +%Y%m%dT%H%M%SZ).txt"
  echo 'Writes a timestamped, line-oriented inventory to standard output.'
  exit 0
fi
if (($# != 0)); then echo "Usage: $0 (try --help)" >&2; exit 2; fi
missing=()
for dependency in awk find stat timeout date hostname tr wc sort; do
  command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
done
if ((${#missing[@]})); then
  printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
  exit 2
fi

clean() { printf '%s' "$1" | tr '\n\r|' '   '; }
record() { printf '%s\n' "$*"; }
file_record() {
  local category=$1 path=$2 metadata hash
  metadata=$(stat -c '%a|%U:%G' "$path" 2>/dev/null) || return
  hash=$(sha256sum "$path" 2>/dev/null | awk '{print $1}') || hash=unavailable
  record "$category|$(clean "$path")|$(clean "$metadata")|$hash"
}

record 'FORMAT|NEXSEC-B2R-BASELINE-v1'
record "CAPTURED_AT|$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record "HOST|$(clean "$(hostname 2>/dev/null || echo unavailable)")"

if command -v systemctl >/dev/null && timeout 5 systemctl show-environment >/dev/null 2>&1; then
  timeout 8 systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
    | awk '{print "SERVICE|" $1 "|" $3 "|" $4}'
elif [[ -d /etc/init.d ]]; then
  timeout 8 find /etc/init.d -maxdepth 1 -type f -printf 'INIT_SCRIPT|%f|%m|%u:%g\n' 2>/dev/null | sort
fi

if command -v ss >/dev/null; then
  timeout 5 ss -lntup 2>/dev/null | awk 'NR > 1 {print "LISTENER|" $1 "|" $2 "|" $5 "|" $6}'
else
  record 'CHECK|listeners|unavailable|ss not installed'
fi

if [[ -r /etc/passwd ]]; then
  awk -F: '$3 == 0 || $3 >= 1000 {print "PRIVILEGED_ACCOUNT|" $3 "|" $1 "|" $4}' /etc/passwd
fi
if [[ -r /etc/group ]]; then
  awk -F: '$1 == "sudo" || $1 == "wheel" || $1 == "admin" || $1 == "docker" || $1 == "lxd" {print "ADMIN_GROUP|" $1 "|" $4}' /etc/group
fi

for path in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
  [[ -f $path ]] && file_record SCHEDULE "$path"
done
for path in /etc/ssh/sshd_config /etc/sudoers /etc/exports /etc/init.d/rc.local /etc/rc.local; do
  [[ -f $path ]] && file_record CONFIG "$path"
done
for directory in /etc/systemd/system /usr/local/lib/systemd/system /etc/init.d; do
  [[ -d $directory ]] || continue
  timeout 8 find "$directory" -maxdepth 3 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -path '*/init.d/*' \) -print 2>/dev/null \
    | while IFS= read -r path; do file_record CONFIG "$path"; done
done

if command -v nft >/dev/null; then
  count=$(timeout 5 nft list ruleset 2>/dev/null | wc -l)
  record "FIREWALL|nft|available|ruleset_lines=$count"
elif command -v iptables-save >/dev/null; then
  count=$(timeout 5 iptables-save 2>/dev/null | wc -l)
  record "FIREWALL|iptables|available|ruleset_lines=$count"
elif command -v ufw >/dev/null; then
  state=$(timeout 5 ufw status 2>/dev/null | awk -F': ' '/^Status:/ {print $2; exit}')
  record "FIREWALL|ufw|available|status=${state:-unknown}"
else
  record 'FIREWALL|unknown|unavailable|no supported firewall query tool found'
fi
