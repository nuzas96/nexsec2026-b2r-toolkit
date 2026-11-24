#!/usr/bin/env bash
set -u
if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0"
  echo "Example: $0"
  echo 'Read-only summary of local identity, accounts, processes, listeners, routes, and services.'
  exit 0
fi
if (($# != 0)); then echo "Usage: $0 (try --help)" >&2; exit 2; fi
missing=()
for dependency in awk date timeout head; do
  command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
done
if ((${#missing[@]})); then
  printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
  exit 2
fi
printf 'Timestamp: '; date -Is
for cmd in id uname hostname; do
  if command -v "$cmd" >/dev/null; then
    "$cmd"
  else
    printf 'Unavailable command: %s\n' "$cmd"
  fi
done
printf '\n== accounts ==\n'; awk -F: '$3==0 || $3>=1000 {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
printf '\n== processes ==\n'
if command -v ps >/dev/null; then timeout 5 ps -eo user,pid,comm --sort=user 2>&1 | head -60; else echo 'ps unavailable'; fi
printf '\n== listeners/routes ==\n'; command -v ss >/dev/null && timeout 5 ss -lntup 2>&1 || echo 'ss unavailable or timed out'; command -v ip >/dev/null && timeout 5 ip route 2>&1 || echo 'ip unavailable or timed out'
printf '\n== services ==\n'
if command -v systemctl >/dev/null; then
  timeout 8 systemctl --no-pager --type=service --state=running 2>&1 | head -60
elif command -v service >/dev/null; then
  timeout 8 service --status-all 2>&1 | head -60
else
  echo 'No supported service manager command found'
fi
