#!/usr/bin/env bash
set -u
if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0 TARGET"
  echo "Example: $0 192.0.2.10"
  echo 'Runs a bounded top-100 TCP service scan and, when available, an NFS export query.'
  exit 0
fi
if (($# != 1)) || [[ -z ${1:-} ]]; then
  echo "Usage: $0 TARGET (try --help)" >&2
  exit 2
fi
target=$1
for dependency in nmap date timeout; do
  command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 2; }
done
printf 'Timestamp: '; date -Is
nmap -n -Pn -sT -sV --version-light --top-ports 100 --max-retries 1 --host-timeout 60s "$target"
if command -v showmount >/dev/null; then
  printf '\n== NFS exports ==\n'
  timeout 5 showmount -e "$target" 2>&1 || echo 'NFS export query unavailable or timed out'
else
  echo 'showmount unavailable; skipped NFS export query'
fi
